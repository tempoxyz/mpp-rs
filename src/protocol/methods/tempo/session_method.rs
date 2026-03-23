//! Server-side session payment verification for Tempo.
//!
//! Implements the `SessionMethod` trait for Tempo session payments (pay-as-you-go).
//! Handles four channel lifecycle actions: open, topUp, voucher, close.
//!
//! Ported from the TypeScript SDK's `Session.ts`.

use alloy::network::ReceiptResponse;
use alloy::primitives::{Address, Bytes, B256};
use std::future::Future;
use std::sync::Arc;

use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use super::session::{SessionCredentialPayload, TempoSessionMethodDetails};
use super::voucher::verify_voucher;
use super::{INTENT_SESSION, METHOD_NAME};
use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::SessionRequest;
use crate::protocol::traits::{SessionMethod as SessionMethodTrait, VerificationError};

// ==================== ChannelStore ====================

/// State for an on-chain payment channel, including per-session accounting.
///
/// Tracks the channel's identity, on-chain balance, the highest voucher
/// the server has accepted, and the current session's spend counters.
///
/// Mirrors the TypeScript `ChannelStore.State` interface.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChannelState {
    pub channel_id: String,
    pub chain_id: u64,
    pub escrow_contract: Address,
    pub payer: Address,
    pub payee: Address,
    pub token: Address,
    pub authorized_signer: Address,
    pub deposit: u128,
    pub settled_on_chain: u128,
    pub highest_voucher_amount: u128,
    /// Serialized signature bytes of the highest voucher (hex-encoded).
    pub highest_voucher_signature: Option<Vec<u8>>,
    pub spent: u128,
    pub units: u64,
    pub finalized: bool,
    pub created_at: String,
}

/// Trait for channel state persistence.
///
/// Implementations must provide atomic read-modify-write semantics for
/// `update_channel`. The callback receives the current state (or `None`)
/// and returns the next state (or `None` to delete).
///
/// Object-safe so it can be used as `Arc<dyn ChannelStore>`.
///
/// # Note
///
/// This is a minimal trait defined inline. It should be consolidated with
/// a shared store abstraction in a future refactor.
pub trait ChannelStore: Send + Sync {
    fn get_channel(
        &self,
        channel_id: &str,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    >;

    #[allow(clippy::type_complexity)]
    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<
            dyn FnOnce(Option<ChannelState>) -> Result<Option<ChannelState>, VerificationError>
                + Send,
        >,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    >;

    /// Wait for the next update to a channel.
    /// Default implementation returns immediately (poll-based fallback).
    fn wait_for_update(
        &self,
        _channel_id: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

/// Atomically deduct `amount` from a channel's available balance.
///
/// Returns `Ok(state)` on success, `Err` if insufficient balance or channel not found.
pub async fn deduct_from_channel(
    store: &dyn ChannelStore,
    channel_id: &str,
    amount: u128,
) -> Result<ChannelState, VerificationError> {
    let result = store
        .update_channel(
            channel_id,
            Box::new(move |current| {
                let state = current
                    .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                let available = state.highest_voucher_amount.saturating_sub(state.spent);
                if available >= amount {
                    Ok(Some(ChannelState {
                        spent: state.spent + amount,
                        units: state.units + 1,
                        ..state
                    }))
                } else {
                    Err(VerificationError::insufficient_balance(format!(
                        "requested {}, available {}",
                        amount, available
                    )))
                }
            }),
        )
        .await?;

    result.ok_or_else(|| VerificationError::channel_not_found("channel not found"))
}

// ==================== On-chain channel reading ====================

/// On-chain channel state from the escrow contract.
#[derive(Debug, Clone)]
pub struct OnChainChannel {
    pub payer: Address,
    pub payee: Address,
    pub token: Address,
    pub authorized_signer: Address,
    pub deposit: u128,
    pub settled: u128,
    pub close_requested_at: u64,
    pub finalized: bool,
}

/// Read channel state from the escrow contract.
///
/// Uses the `getChannel` view function on the escrow contract.
async fn get_on_chain_channel<P: Provider<TempoNetwork>>(
    provider: &P,
    escrow_contract: Address,
    channel_id: B256,
) -> Result<OnChainChannel, VerificationError> {
    use alloy::sol;

    sol! {
        #[sol(rpc)]
        interface IEscrow {
            function getChannel(bytes32 channelId) external view returns (
                bool finalized,
                uint64 closeRequestedAt,
                address payer,
                address payee,
                address token,
                address authorizedSigner,
                uint128 deposit,
                uint128 settled
            );
        }
    }

    let escrow = IEscrow::new(escrow_contract, provider);
    let result = escrow.getChannel(channel_id).call().await.map_err(|e| {
        VerificationError::network_error(format!("Failed to read on-chain channel: {}", e))
    })?;

    Ok(OnChainChannel {
        payer: result.payer,
        payee: result.payee,
        token: result.token,
        deposit: result.deposit,
        settled: result.settled,
        finalized: result.finalized,
        authorized_signer: result.authorizedSigner,
        close_requested_at: result.closeRequestedAt,
    })
}

// ==================== TempoSessionMethod ====================

/// Configuration for the Tempo session method.
#[derive(Debug, Clone)]
pub struct SessionMethodConfig {
    /// Default escrow contract address.
    pub escrow_contract: Address,
    /// Default chain ID.
    pub chain_id: u64,
    /// Minimum voucher delta to accept (in base units). Default: 0.
    pub min_voucher_delta: u128,
}

/// Tempo session method for server-side session payment verification.
///
/// Handles four channel lifecycle actions:
/// - `open`: broadcast open tx, verify initial voucher, create channel in store
/// - `topUp`: broadcast topUp tx, update deposit in store
/// - `voucher`: verify voucher signature, check monotonicity/bounds/delta, update store
/// - `close`: verify final voucher, close on-chain, finalize in store
#[derive(Clone)]
pub struct SessionMethod<P> {
    provider: Arc<P>,
    store: Arc<dyn ChannelStore>,
    config: SessionMethodConfig,
    /// Optional signer for submitting on-chain close transactions.
    close_signer: Option<Arc<alloy::signers::local::PrivateKeySigner>>,
}

impl<P> SessionMethod<P> {
    /// Parse a hex channel ID string to B256.
    fn parse_channel_id(channel_id: &str) -> Result<B256, VerificationError> {
        channel_id
            .parse::<B256>()
            .map_err(|e| VerificationError::invalid_payload(format!("Invalid channel ID: {}", e)))
    }

    /// Parse a hex signature string to bytes.
    fn parse_signature(signature: &str) -> Result<Vec<u8>, VerificationError> {
        let s = signature.strip_prefix("0x").unwrap_or(signature);
        hex::decode(s).map_err(|e| {
            VerificationError::invalid_payload(format!("Invalid signature hex: {}", e))
        })
    }

    /// Parse an address string.
    fn parse_address(addr: &str) -> Result<Address, VerificationError> {
        addr.parse::<Address>()
            .map_err(|e| VerificationError::invalid_payload(format!("Invalid address: {}", e)))
    }
}

impl<P> SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Create a new Tempo session method.
    pub fn new(provider: P, store: Arc<dyn ChannelStore>, config: SessionMethodConfig) -> Self {
        Self {
            provider: Arc::new(provider),
            store,
            config,
            close_signer: None,
        }
    }

    /// Set the signer used for submitting on-chain close transactions.
    pub fn with_close_signer(mut self, signer: alloy::signers::local::PrivateKeySigner) -> Self {
        self.close_signer = Some(Arc::new(signer));
        self
    }

    /// Get the session method configuration.
    pub fn config(&self) -> &SessionMethodConfig {
        &self.config
    }

    /// Get the method details from the session request, with fallbacks to config.
    fn resolve_method_details(
        &self,
        request: &SessionRequest,
    ) -> Result<TempoSessionMethodDetails, VerificationError> {
        use super::session::TempoSessionExt;

        match request.tempo_session_details() {
            Ok(details) => Ok(details),
            Err(_) => Ok(TempoSessionMethodDetails {
                escrow_contract: format!("{:#x}", self.config.escrow_contract),
                chain_id: Some(self.config.chain_id),
                channel_id: None,
                min_voucher_delta: None,
                fee_payer: None,
            }),
        }
    }

    /// Resolve the escrow contract address from method details or config.
    fn resolve_escrow(
        &self,
        details: &TempoSessionMethodDetails,
    ) -> Result<Address, VerificationError> {
        Self::parse_address(&details.escrow_contract)
    }

    /// Resolve the chain ID from method details or config.
    fn resolve_chain_id(&self, details: &TempoSessionMethodDetails) -> u64 {
        details.chain_id.unwrap_or(self.config.chain_id)
    }

    /// Resolve the effective minimum voucher delta.
    fn resolve_min_delta(&self, details: &TempoSessionMethodDetails) -> u128 {
        details
            .min_voucher_delta
            .as_ref()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(self.config.min_voucher_delta)
    }

    /// Handle 'open' action.
    async fn handle_open(
        &self,
        _credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
    ) -> Result<Receipt, VerificationError> {
        let (
            channel_id_str,
            cumulative_amount_str,
            signature_str,
            _authorized_signer_str,
            transaction_str,
        ) = match payload {
            SessionCredentialPayload::Open {
                channel_id,
                cumulative_amount,
                signature,
                authorized_signer,
                transaction,
                ..
            } => (
                channel_id,
                cumulative_amount,
                signature,
                authorized_signer,
                transaction,
            ),
            _ => unreachable!(),
        };

        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let escrow = self.resolve_escrow(details)?;
        let chain_id = self.resolve_chain_id(details);

        // Broadcast the client's signed open transaction (approve + escrow.open).
        let tx_bytes: Bytes = transaction_str.parse().map_err(|e| {
            VerificationError::invalid_payload(format!("invalid open transaction hex: {}", e))
        })?;
        let pending = self
            .provider
            .send_raw_transaction(&tx_bytes)
            .await
            .map_err(|e| {
                VerificationError::network_error(format!("failed to broadcast open tx: {}", e))
            })?;
        let tx_receipt = pending
            .get_receipt()
            .await
            .map_err(|e| VerificationError::network_error(format!("open tx failed: {}", e)))?;
        if !tx_receipt.status() {
            return Err(VerificationError::transaction_failed(format!(
                "open transaction reverted (tx: {})",
                tx_receipt.transaction_hash()
            )));
        }
        let open_tx_hash = tx_receipt.transaction_hash().to_string();

        let on_chain = get_on_chain_channel(&*self.provider, escrow, channel_id_b256).await?;

        // Validate on-chain state.
        if on_chain.deposit == 0 {
            return Err(VerificationError::channel_not_found(
                "channel not funded on-chain",
            ));
        }
        if on_chain.finalized {
            return Err(VerificationError::channel_closed(
                "channel is finalized on-chain",
            ));
        }
        if on_chain.close_requested_at != 0 {
            return Err(VerificationError::channel_closed(
                "channel has a pending close request",
            ));
        }

        let authorized_signer = if on_chain.authorized_signer == Address::ZERO {
            on_chain.payer
        } else {
            on_chain.authorized_signer
        };

        let cumulative_amount: u128 = cumulative_amount_str
            .parse()
            .map_err(|_| VerificationError::invalid_payload("invalid cumulativeAmount"))?;

        if cumulative_amount > on_chain.deposit {
            return Err(VerificationError::amount_exceeds_deposit(
                "voucher amount exceeds on-chain deposit",
            ));
        }
        if cumulative_amount < on_chain.settled {
            return Err(VerificationError::new(
                "voucher cumulativeAmount is below on-chain settled amount",
            ));
        }

        let sig_bytes = Self::parse_signature(signature_str)?;
        let is_valid = verify_voucher(
            escrow,
            chain_id,
            channel_id_b256,
            cumulative_amount,
            &sig_bytes,
            authorized_signer,
        );

        if !is_valid {
            return Err(VerificationError::invalid_signature(
                "invalid voucher signature",
            ));
        }

        // Create or update channel in store.
        let channel_id_for_key = channel_id_str.clone();
        let channel_id_for_state = channel_id_str.clone();
        let updated = self
            .store
            .update_channel(
                &channel_id_for_key,
                Box::new(move |existing| {
                    if let Some(existing) = existing {
                        // Channel already exists — update if higher.
                        if cumulative_amount > existing.highest_voucher_amount {
                            Ok(Some(ChannelState {
                                deposit: on_chain.deposit,
                                highest_voucher_amount: cumulative_amount,
                                highest_voucher_signature: Some(sig_bytes),
                                authorized_signer,
                                ..existing
                            }))
                        } else {
                            Ok(Some(ChannelState {
                                deposit: on_chain.deposit,
                                authorized_signer,
                                ..existing
                            }))
                        }
                    } else {
                        // New channel.
                        Ok(Some(ChannelState {
                            channel_id: channel_id_for_state,
                            chain_id,
                            escrow_contract: escrow,
                            payer: on_chain.payer,
                            payee: on_chain.payee,
                            token: on_chain.token,
                            authorized_signer,
                            deposit: on_chain.deposit,
                            settled_on_chain: 0,
                            highest_voucher_amount: cumulative_amount,
                            highest_voucher_signature: Some(sig_bytes),
                            spent: 0,
                            units: 0,
                            finalized: false,
                            created_at: now_iso8601(),
                        }))
                    }
                }),
            )
            .await?;

        let _state = updated.ok_or_else(|| VerificationError::new("failed to create channel"))?;

        Ok(Receipt::success(METHOD_NAME, &open_tx_hash))
    }

    /// Handle 'topUp' action.
    async fn handle_top_up(
        &self,
        _credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
    ) -> Result<Receipt, VerificationError> {
        let (channel_id_str, _additional_deposit_str, transaction_str) = match payload {
            SessionCredentialPayload::TopUp {
                channel_id,
                additional_deposit,
                transaction,
                ..
            } => (channel_id, additional_deposit, transaction),
            _ => unreachable!(),
        };

        let channel = self
            .store
            .get_channel(channel_id_str)
            .await?
            .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;

        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let escrow = self.resolve_escrow(details)?;

        // Broadcast the client's signed topUp transaction.
        let tx_bytes: Bytes = transaction_str.parse().map_err(|e| {
            VerificationError::invalid_payload(format!("invalid topUp transaction hex: {}", e))
        })?;
        let pending = self
            .provider
            .send_raw_transaction(&tx_bytes)
            .await
            .map_err(|e| {
                VerificationError::network_error(format!("failed to broadcast topUp tx: {}", e))
            })?;
        let tx_receipt = pending
            .get_receipt()
            .await
            .map_err(|e| VerificationError::network_error(format!("topUp tx failed: {}", e)))?;
        if !tx_receipt.status() {
            return Err(VerificationError::transaction_failed(
                "topUp transaction reverted",
            ));
        }

        // Re-read on-chain state after topUp tx is broadcast.
        let on_chain = get_on_chain_channel(&*self.provider, escrow, channel_id_b256).await?;

        if on_chain.deposit <= channel.deposit {
            return Err(VerificationError::new(
                "channel deposit did not increase after topUp",
            ));
        }

        // Update deposit in store.
        let new_deposit = on_chain.deposit;
        let channel_id_owned = channel_id_str.clone();
        let updated = self
            .store
            .update_channel(
                &channel_id_owned,
                Box::new(move |current| {
                    let state = current
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                    Ok(Some(ChannelState {
                        deposit: new_deposit,
                        ..state
                    }))
                }),
            )
            .await?;

        let state = updated.unwrap_or(channel);
        Ok(Receipt::success(METHOD_NAME, &state.channel_id))
    }

    /// Handle 'voucher' action.
    async fn handle_voucher(
        &self,
        _credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
    ) -> Result<Receipt, VerificationError> {
        let (channel_id_str, cumulative_amount_str, signature_str) = match payload {
            SessionCredentialPayload::Voucher {
                channel_id,
                cumulative_amount,
                signature,
            } => (channel_id, cumulative_amount, signature),
            _ => unreachable!(),
        };

        let channel = self
            .store
            .get_channel(channel_id_str)
            .await?
            .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;

        if channel.finalized {
            return Err(VerificationError::channel_closed("channel is finalized"));
        }

        let cumulative_amount: u128 = cumulative_amount_str
            .parse()
            .map_err(|_| VerificationError::invalid_payload("invalid cumulativeAmount"))?;

        let escrow = self.resolve_escrow(details)?;
        let chain_id = self.resolve_chain_id(details);
        let min_delta = self.resolve_min_delta(details);

        // Use cached channel state (verified during open/topUp) instead of
        // reading on-chain for every voucher. This avoids an RPC round-trip
        // per voucher, critical for high-frequency sessions.
        self.verify_and_accept_voucher(
            channel_id_str,
            &channel,
            cumulative_amount,
            signature_str,
            escrow,
            chain_id,
            min_delta,
            channel.deposit,
            channel.settled_on_chain,
            false, // not finalized (checked above)
            0,     // no close request
        )
        .await
    }

    /// Handle 'close' action.
    async fn handle_close(
        &self,
        _credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
    ) -> Result<Receipt, VerificationError> {
        let (channel_id_str, cumulative_amount_str, signature_str) = match payload {
            SessionCredentialPayload::Close {
                channel_id,
                cumulative_amount,
                signature,
            } => (channel_id, cumulative_amount, signature),
            _ => unreachable!(),
        };

        let channel = self
            .store
            .get_channel(channel_id_str)
            .await?
            .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;

        if channel.finalized {
            return Err(VerificationError::channel_closed(
                "channel is already finalized",
            ));
        }

        let cumulative_amount: u128 = cumulative_amount_str
            .parse()
            .map_err(|_| VerificationError::invalid_payload("invalid cumulativeAmount"))?;

        if cumulative_amount < channel.highest_voucher_amount {
            return Err(VerificationError::new(
                "close voucher amount must be >= highest accepted voucher",
            ));
        }

        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let escrow = self.resolve_escrow(details)?;
        let chain_id = self.resolve_chain_id(details);

        // For close, always re-read on-chain state.
        let on_chain = get_on_chain_channel(&*self.provider, escrow, channel_id_b256).await?;

        if on_chain.finalized {
            return Err(VerificationError::channel_closed(
                "channel is finalized on-chain",
            ));
        }
        if cumulative_amount < on_chain.settled {
            return Err(VerificationError::new(
                "close voucher cumulativeAmount is below on-chain settled amount",
            ));
        }
        if cumulative_amount > on_chain.deposit {
            return Err(VerificationError::amount_exceeds_deposit(
                "close voucher amount exceeds on-chain deposit",
            ));
        }

        let sig_bytes = Self::parse_signature(signature_str)?;
        let is_valid = verify_voucher(
            escrow,
            chain_id,
            channel_id_b256,
            cumulative_amount,
            &sig_bytes,
            channel.authorized_signer,
        );

        if !is_valid {
            return Err(VerificationError::invalid_signature(
                "invalid voucher signature",
            ));
        }

        // Submit close transaction on-chain if we have a signer.
        let close_tx_hash = if let Some(ref signer) = self.close_signer {
            use alloy::eips::Encodable2718;
            use alloy::primitives::Bytes;
            use alloy::signers::SignerSync;
            use alloy::sol_types::SolCall;
            use tempo_primitives::transaction::Call;
            use tempo_primitives::TempoTransaction;

            alloy::sol! {
                interface IEscrowClose {
                    function close(bytes32 channelId, uint128 cumulativeAmount, bytes calldata signature) external;
                }
            }

            let close_data = IEscrowClose::closeCall::new((
                channel_id_b256,
                cumulative_amount,
                Bytes::from(sig_bytes.clone()),
            ))
            .abi_encode();

            let nonce = self
                .provider
                .get_transaction_count(signer.address())
                .await
                .map_err(|e| {
                    VerificationError::network_error(format!("failed to get nonce: {}", e))
                })?;
            let gas_price = self.provider.get_gas_price().await.map_err(|e| {
                VerificationError::network_error(format!("failed to get gas price: {}", e))
            })?;

            let tempo_tx = TempoTransaction {
                chain_id,
                nonce,
                gas_limit: 2_000_000,
                max_fee_per_gas: gas_price,
                max_priority_fee_per_gas: gas_price,
                calls: vec![Call {
                    to: alloy::primitives::TxKind::Call(escrow),
                    value: alloy::primitives::U256::ZERO,
                    input: Bytes::from(close_data),
                }],
                ..Default::default()
            };

            let sig_hash = tempo_tx.signature_hash();
            let signature = signer.sign_hash_sync(&sig_hash).map_err(|e| {
                VerificationError::network_error(format!("failed to sign close tx: {}", e))
            })?;
            let signed_tx = tempo_tx.into_signed(signature.into());
            let tx_bytes = Bytes::from(signed_tx.encoded_2718());

            let pending = self
                .provider
                .send_raw_transaction(&tx_bytes)
                .await
                .map_err(|e| {
                    VerificationError::network_error(format!("failed to send close tx: {}", e))
                })?;
            let receipt = pending
                .get_receipt()
                .await
                .map_err(|e| VerificationError::network_error(format!("close tx failed: {}", e)))?;

            Some(receipt.transaction_hash.to_string())
        } else {
            None
        };

        // Finalize in store.
        let channel_id_owned = channel_id_str.clone();
        let updated = self
            .store
            .update_channel(
                &channel_id_owned,
                Box::new(move |current| {
                    let state = match current {
                        Some(s) => s,
                        None => return Ok(None),
                    };
                    Ok(Some(ChannelState {
                        deposit: on_chain.deposit,
                        highest_voucher_amount: cumulative_amount,
                        highest_voucher_signature: Some(sig_bytes),
                        finalized: true,
                        ..state
                    }))
                }),
            )
            .await?;

        let reference = close_tx_hash.unwrap_or_else(|| {
            updated
                .map(|s| s.channel_id)
                .unwrap_or_else(|| channel.channel_id.clone())
        });
        Ok(Receipt::success(METHOD_NAME, &reference))
    }

    /// Shared logic for verifying an incremental voucher and updating channel state.
    #[allow(clippy::too_many_arguments)]
    async fn verify_and_accept_voucher(
        &self,
        channel_id_str: &str,
        channel: &ChannelState,
        cumulative_amount: u128,
        signature_str: &str,
        escrow: Address,
        chain_id: u64,
        min_delta: u128,
        deposit: u128,
        settled: u128,
        finalized: bool,
        close_requested_at: u64,
    ) -> Result<Receipt, VerificationError> {
        if finalized {
            return Err(VerificationError::channel_closed(
                "channel is finalized on-chain",
            ));
        }
        if close_requested_at != 0 {
            return Err(VerificationError::channel_closed(
                "channel has a pending close request",
            ));
        }
        if cumulative_amount < settled {
            return Err(VerificationError::new(
                "voucher cumulativeAmount is below on-chain settled amount",
            ));
        }
        if cumulative_amount > deposit {
            return Err(VerificationError::amount_exceeds_deposit(
                "voucher amount exceeds on-chain deposit",
            ));
        }

        // If voucher is not higher than what we already have, accept idempotently
        // but still verify the signature to prevent channel hijacking via stale
        // vouchers with forged signatures. Skip ecrecover only for exact replays
        // of the already-verified highest voucher.
        if cumulative_amount <= channel.highest_voucher_amount {
            let sig_bytes = Self::parse_signature(signature_str)?;
            let is_exact_replay =
                channel
                    .highest_voucher_signature
                    .as_ref()
                    .is_some_and(|stored_sig| {
                        stored_sig == &sig_bytes
                            && cumulative_amount == channel.highest_voucher_amount
                    });
            if !is_exact_replay {
                let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
                let is_valid = verify_voucher(
                    escrow,
                    chain_id,
                    channel_id_b256,
                    cumulative_amount,
                    &sig_bytes,
                    channel.authorized_signer,
                );
                if !is_valid {
                    return Err(VerificationError::invalid_signature(
                        "invalid voucher signature",
                    ));
                }
            }
            return Ok(Receipt::success(METHOD_NAME, &channel.channel_id));
        }

        let delta = cumulative_amount - channel.highest_voucher_amount;
        if delta < min_delta {
            return Err(VerificationError::delta_too_small(format!(
                "voucher delta {} below minimum {}",
                delta, min_delta
            )));
        }

        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let sig_bytes = Self::parse_signature(signature_str)?;

        let is_valid = verify_voucher(
            escrow,
            chain_id,
            channel_id_b256,
            cumulative_amount,
            &sig_bytes,
            channel.authorized_signer,
        );

        if !is_valid {
            return Err(VerificationError::invalid_signature(
                "invalid voucher signature",
            ));
        }

        // Update store with new highest voucher.
        let channel_id_owned = channel_id_str.to_string();
        let updated = self
            .store
            .update_channel(
                &channel_id_owned,
                Box::new(move |current| {
                    let state = current
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                    if cumulative_amount > state.highest_voucher_amount {
                        Ok(Some(ChannelState {
                            highest_voucher_amount: cumulative_amount,
                            highest_voucher_signature: Some(sig_bytes),
                            deposit,
                            ..state
                        }))
                    } else {
                        Ok(Some(state))
                    }
                }),
            )
            .await?;

        let state =
            updated.ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
        Ok(Receipt::success(METHOD_NAME, &state.channel_id))
    }
}

impl<P> SessionMethodTrait for SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn challenge_method_details(&self) -> Option<serde_json::Value> {
        let details = super::session::TempoSessionMethodDetails {
            escrow_contract: format!("{:#x}", self.config.escrow_contract),
            chain_id: Some(self.config.chain_id),
            min_voucher_delta: Some(self.config.min_voucher_delta.to_string()),
            channel_id: None,
            fee_payer: None,
        };
        serde_json::to_value(details).ok()
    }

    fn respond(
        &self,
        credential: &PaymentCredential,
        _receipt: &Receipt,
    ) -> Option<serde_json::Value> {
        // Management actions (open, topUp, close) short-circuit normal response handling.
        // Only voucher actions proceed to content delivery.
        let payload: SessionCredentialPayload = credential.payload_as().ok()?;
        match payload {
            SessionCredentialPayload::Voucher { .. } => None,
            _ => Some(serde_json::json!({ "status": "ok" })),
        }
    }

    fn verify_session(
        &self,
        credential: &PaymentCredential,
        request: &SessionRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let credential = credential.clone();
        let request = request.clone();
        let provider = Arc::clone(&self.provider);
        let store = Arc::clone(&self.store);
        let config = self.config.clone();
        let close_signer = self.close_signer.clone();

        async move {
            let this = SessionMethod {
                provider,
                store,
                config,
                close_signer,
            };

            if credential.challenge.method.as_str() != METHOD_NAME {
                return Err(VerificationError::credential_mismatch(format!(
                    "Method mismatch: expected {}, got {}",
                    METHOD_NAME, credential.challenge.method
                )));
            }
            if credential.challenge.intent.as_str() != INTENT_SESSION {
                return Err(VerificationError::credential_mismatch(format!(
                    "Intent mismatch: expected {}, got {}",
                    INTENT_SESSION, credential.challenge.intent
                )));
            }

            let details = this.resolve_method_details(&request)?;

            let payload: SessionCredentialPayload = credential.payload_as().map_err(|e| {
                VerificationError::invalid_payload(format!("Expected session payload: {}", e))
            })?;

            match &payload {
                SessionCredentialPayload::Open { .. } => {
                    this.handle_open(&credential, &payload, &details).await
                }
                SessionCredentialPayload::TopUp { .. } => {
                    this.handle_top_up(&credential, &payload, &details).await
                }
                SessionCredentialPayload::Voucher { .. } => {
                    this.handle_voucher(&credential, &payload, &details).await
                }
                SessionCredentialPayload::Close { .. } => {
                    this.handle_close(&credential, &payload, &details).await
                }
            }
        }
    }
}

fn now_iso8601() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

// ==================== In-memory store for testing ====================

/// In-memory channel store for testing.
///
/// Uses a `Mutex<HashMap>` for thread-safe access.
pub struct InMemoryChannelStore {
    channels: std::sync::Mutex<std::collections::HashMap<String, ChannelState>>,
    notifiers: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Notify>>>,
}

impl Default for InMemoryChannelStore {
    fn default() -> Self {
        Self {
            channels: std::sync::Mutex::new(std::collections::HashMap::new()),
            notifiers: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl InMemoryChannelStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of a channel (for test assertions).
    pub fn get_channel_sync(&self, channel_id: &str) -> Option<ChannelState> {
        self.channels.lock().unwrap().get(channel_id).cloned()
    }
}

impl InMemoryChannelStore {
    /// Insert a channel directly (for test setup).
    pub fn insert(&self, channel_id: &str, state: ChannelState) {
        self.channels
            .lock()
            .unwrap()
            .insert(channel_id.to_string(), state);
    }
}

impl ChannelStore for InMemoryChannelStore {
    fn get_channel(
        &self,
        channel_id: &str,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    > {
        let result = self.channels.lock().unwrap().get(channel_id).cloned();
        Box::pin(async move { Ok(result) })
    }

    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<
            dyn FnOnce(Option<ChannelState>) -> Result<Option<ChannelState>, VerificationError>
                + Send,
        >,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    > {
        let mut map = self.channels.lock().unwrap();
        let current = map.get(channel_id).cloned();
        let result = updater(current);
        let channel_id = channel_id.to_string();
        match result {
            Ok(Some(state)) => {
                map.insert(channel_id.clone(), state.clone());
                // Notify waiters that the channel was updated
                if let Some(notify) = self.notifiers.lock().unwrap().get(&channel_id) {
                    notify.notify_waiters();
                }
                Box::pin(async move { Ok(Some(state)) })
            }
            Ok(None) => {
                map.remove(&channel_id);
                Box::pin(async { Ok(None) })
            }
            Err(e) => Box::pin(async { Err(e) }),
        }
    }

    fn wait_for_update(
        &self,
        channel_id: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let notify = self
            .notifiers
            .lock()
            .unwrap()
            .entry(channel_id.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Notify::new()))
            .clone();
        Box::pin(async move {
            notify.notified().await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::traits::ErrorCode;

    fn test_channel_state(channel_id: &str) -> ChannelState {
        ChannelState {
            channel_id: channel_id.to_string(),
            chain_id: 42431,
            escrow_contract: "0x5555555555555555555555555555555555555555"
                .parse()
                .unwrap(),
            payer: "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            payee: "0x2222222222222222222222222222222222222222"
                .parse()
                .unwrap(),
            token: "0x3333333333333333333333333333333333333333"
                .parse()
                .unwrap(),
            authorized_signer: "0x4444444444444444444444444444444444444444"
                .parse()
                .unwrap(),
            deposit: 100_000,
            settled_on_chain: 0,
            highest_voucher_amount: 0,
            highest_voucher_signature: None,
            spent: 0,
            units: 0,
            finalized: false,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_in_memory_store_insert_and_get() {
        let store = InMemoryChannelStore::new();
        let state = test_channel_state("0xchannel1");
        store.insert("0xchannel1", state.clone());

        let retrieved = store.get_channel_sync("0xchannel1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().deposit, 100_000);

        assert!(store.get_channel_sync("0xnonexistent").is_none());
    }

    #[tokio::test]
    async fn test_in_memory_store_update() {
        let store = InMemoryChannelStore::new();
        let state = test_channel_state("0xchannel1");
        store.insert("0xchannel1", state);

        let updated = store
            .update_channel(
                "0xchannel1",
                Box::new(|current| {
                    let mut s = current.unwrap();
                    s.highest_voucher_amount = 5000;
                    Ok(Some(s))
                }),
            )
            .await
            .unwrap();

        assert_eq!(updated.unwrap().highest_voucher_amount, 5000);
        assert_eq!(
            store
                .get_channel_sync("0xchannel1")
                .unwrap()
                .highest_voucher_amount,
            5000
        );
    }

    #[tokio::test]
    async fn test_in_memory_store_update_nonexistent() {
        let store = InMemoryChannelStore::new();

        let result = store
            .update_channel(
                "0xmissing",
                Box::new(|current| {
                    assert!(current.is_none());
                    Ok(None)
                }),
            )
            .await
            .unwrap();

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_deduct_from_channel_success() {
        let store = InMemoryChannelStore::new();
        let mut state = test_channel_state("0xchannel1");
        state.highest_voucher_amount = 10_000;
        state.spent = 0;
        store.insert("0xchannel1", state);

        let result = deduct_from_channel(&store, "0xchannel1", 3_000).await;
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert_eq!(updated.spent, 3_000);
        assert_eq!(updated.units, 1);
    }

    #[tokio::test]
    async fn test_deduct_from_channel_insufficient() {
        let store = InMemoryChannelStore::new();
        let mut state = test_channel_state("0xchannel1");
        state.highest_voucher_amount = 10_000;
        state.spent = 9_000;
        store.insert("0xchannel1", state);

        let result = deduct_from_channel(&store, "0xchannel1", 5_000).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::InsufficientBalance));
    }

    #[tokio::test]
    async fn test_deduct_from_channel_not_found() {
        let store = InMemoryChannelStore::new();
        let result = deduct_from_channel(&store, "0xmissing", 1_000).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::ChannelNotFound));
    }

    #[test]
    fn test_parse_channel_id_valid() {
        let _id = "0xabababababababababababababababababababababababababababababababab";
        // 32 bytes = 64 hex chars + 0x prefix
        let padded = format!("0x{}", "ab".repeat(32));
        let result = SessionMethod::<()>::parse_channel_id(&padded);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_channel_id_invalid() {
        let result = SessionMethod::<()>::parse_channel_id("not-a-hex");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_valid() {
        let sig_hex = format!("0x{}", "ab".repeat(65));
        let result = SessionMethod::<()>::parse_signature(&sig_hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 65);
    }

    #[test]
    fn test_parse_signature_no_prefix() {
        let sig_hex = "ab".repeat(65);
        let result = SessionMethod::<()>::parse_signature(&sig_hex);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_signature_invalid() {
        let result = SessionMethod::<()>::parse_signature("not-hex!");
        assert!(result.is_err());
    }

    #[test]
    fn test_channel_state_clone() {
        let state = test_channel_state("0xchannel1");
        let cloned = state.clone();
        assert_eq!(cloned.channel_id, "0xchannel1");
        assert_eq!(cloned.deposit, 100_000);
    }

    #[test]
    fn test_session_method_config() {
        let config = SessionMethodConfig {
            escrow_contract: "0x5555555555555555555555555555555555555555"
                .parse()
                .unwrap(),
            chain_id: 42431,
            min_voucher_delta: 100,
        };
        assert_eq!(config.chain_id, 42431);
        assert_eq!(config.min_voucher_delta, 100);
    }

    #[tokio::test]
    async fn test_deduct_sequential_deductions() {
        let store = InMemoryChannelStore::new();
        let mut state = test_channel_state("0xchannel1");
        state.highest_voucher_amount = 10_000;
        store.insert("0xchannel1", state);

        // First deduction
        let r1 = deduct_from_channel(&store, "0xchannel1", 3_000)
            .await
            .unwrap();
        assert_eq!(r1.spent, 3_000);
        assert_eq!(r1.units, 1);

        // Second deduction
        let r2 = deduct_from_channel(&store, "0xchannel1", 2_000)
            .await
            .unwrap();
        assert_eq!(r2.spent, 5_000);
        assert_eq!(r2.units, 2);

        // Third deduction that exactly exhausts balance
        let r3 = deduct_from_channel(&store, "0xchannel1", 5_000)
            .await
            .unwrap();
        assert_eq!(r3.spent, 10_000);
        assert_eq!(r3.units, 3);

        // Fourth deduction should fail (no balance left)
        let r4 = deduct_from_channel(&store, "0xchannel1", 1).await;
        let err = r4.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::InsufficientBalance));
    }

    #[tokio::test]
    async fn test_deduct_zero_amount() {
        let store = InMemoryChannelStore::new();
        let mut state = test_channel_state("0xchannel1");
        state.highest_voucher_amount = 0;
        store.insert("0xchannel1", state);

        let result = deduct_from_channel(&store, "0xchannel1", 0).await;
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.spent, 0);
        assert_eq!(r.units, 1);

        // Verify store state is consistent
        let ch = store.get_channel_sync("0xchannel1").unwrap();
        assert_eq!(ch.spent, 0);
        assert_eq!(ch.units, 1);
        assert_eq!(ch.highest_voucher_amount, 0);
    }

    #[tokio::test]
    async fn test_store_update_delete() {
        let store = InMemoryChannelStore::new();
        store.insert("0xchannel1", test_channel_state("0xchannel1"));
        assert!(store.get_channel_sync("0xchannel1").is_some());

        let result = store
            .update_channel("0xchannel1", Box::new(|_current| Ok(None)))
            .await
            .unwrap();
        assert!(result.is_none());
        assert!(store.get_channel_sync("0xchannel1").is_none());
    }

    #[tokio::test]
    async fn test_store_update_error_preserves_state() {
        let store = InMemoryChannelStore::new();
        let mut state = test_channel_state("0xchannel1");
        state.highest_voucher_amount = 5000;
        store.insert("0xchannel1", state);

        let result = store
            .update_channel(
                "0xchannel1",
                Box::new(|_current| Err(VerificationError::new("intentional test error"))),
            )
            .await;
        assert!(result.is_err());

        // Original state should be unchanged
        let ch = store.get_channel_sync("0xchannel1").unwrap();
        assert_eq!(ch.highest_voucher_amount, 5000);
    }

    #[tokio::test]
    async fn test_store_multiple_channels_independent() {
        let store = InMemoryChannelStore::new();
        let mut state1 = test_channel_state("0xchannel1");
        state1.highest_voucher_amount = 10_000;
        let mut state2 = test_channel_state("0xchannel2");
        state2.highest_voucher_amount = 20_000;
        store.insert("0xchannel1", state1);
        store.insert("0xchannel2", state2);

        // Deduct from channel 1
        let r1 = deduct_from_channel(&store, "0xchannel1", 5_000)
            .await
            .unwrap();
        assert_eq!(r1.spent, 5_000);

        // Channel 2 should be unaffected
        let ch2 = store.get_channel_sync("0xchannel2").unwrap();
        assert_eq!(ch2.spent, 0);
        assert_eq!(ch2.highest_voucher_amount, 20_000);
    }

    #[tokio::test]
    async fn test_store_get_channel_async() {
        let store = InMemoryChannelStore::new();
        store.insert("0xchannel1", test_channel_state("0xchannel1"));

        let result = store.get_channel("0xchannel1").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().channel_id, "0xchannel1");

        let missing = store.get_channel("0xmissing").await.unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_channel_state_serialization() {
        let state = test_channel_state("0xchannel1");
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: ChannelState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.channel_id, "0xchannel1");
        assert_eq!(deserialized.deposit, 100_000);
        assert_eq!(deserialized.chain_id, 42431);
        assert!(!deserialized.finalized);
    }

    #[tokio::test]
    async fn test_deduct_from_finalized_channel_succeeds() {
        let store = InMemoryChannelStore::new();
        let mut state = test_channel_state("0xchannel1");
        state.highest_voucher_amount = 10_000;
        state.finalized = true;
        store.insert("0xchannel1", state);

        // NOTE: deduct_from_channel intentionally ignores the finalized flag.
        // Finalization is an on-chain concern; the server-side deduction only
        // tracks spend against the highest voucher amount.
        let result = deduct_from_channel(&store, "0xchannel1", 1_000)
            .await
            .unwrap();
        assert_eq!(result.spent, 1_000);
        assert!(result.finalized, "finalized flag should be preserved");
    }

    #[tokio::test]
    async fn test_store_wait_for_update_notifies() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        store.insert("0xchannel1", test_channel_state("0xchannel1"));

        let store2 = store.clone();
        let handle = tokio::spawn(async move {
            store2.wait_for_update("0xchannel1").await;
            true
        });

        // Yield to let the spawned task start waiting
        tokio::task::yield_now().await;

        // Trigger an update
        store
            .update_channel(
                "0xchannel1",
                Box::new(|current| {
                    let mut s = current.unwrap();
                    s.highest_voucher_amount = 9999;
                    Ok(Some(s))
                }),
            )
            .await
            .unwrap();

        // The wait should complete within a reasonable time
        let result = tokio::time::timeout(tokio::time::Duration::from_secs(1), handle)
            .await
            .expect("wait_for_update should have been notified within timeout")
            .expect("spawned task should not panic");
        assert!(result);
    }

    /// Create a SessionMethod with a dummy provider for testing voucher logic
    /// (which doesn't touch the provider).
    fn test_session_method(
        store: Arc<InMemoryChannelStore>,
    ) -> SessionMethod<crate::server::TempoProvider> {
        let provider =
            crate::server::tempo_provider("https://rpc.test.invalid").expect("valid URL");
        let config = SessionMethodConfig {
            escrow_contract: "0x5555555555555555555555555555555555555555"
                .parse()
                .unwrap(),
            chain_id: 42431,
            min_voucher_delta: 0,
        };
        SessionMethod::new(provider, store, config)
    }

    #[tokio::test]
    async fn test_stale_voucher_with_garbage_signature_rejected() {
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let store = Arc::new(InMemoryChannelStore::new());
        let channel_id = format!("0x{}", "ab".repeat(32));

        // Set up channel with a known highest_voucher_amount and valid signature
        let mut state = test_channel_state(&channel_id);
        state.authorized_signer = signer.address();
        state.highest_voucher_amount = 1_000;
        state.highest_voucher_signature = Some(vec![0xAA; 65]);
        state.deposit = 100_000;
        store.insert(&channel_id, state.clone());

        let method = test_session_method(store);

        // Submit a stale voucher (cumulative_amount=0 <= highest=1000) with garbage signature.
        // This should be REJECTED because the signature is invalid.
        let garbage_sig = format!("0x{}", "ff".repeat(65));
        let result = method
            .verify_and_accept_voucher(
                &channel_id,
                &state,
                0,            // cumulative_amount <= highest_voucher_amount
                &garbage_sig, // garbage signature
                state.escrow_contract,
                42431,
                0,       // min_delta
                100_000, // deposit
                0,       // settled
                false,   // not finalized
                0,       // no close request
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::InvalidSignature));
    }

    #[tokio::test]
    async fn test_stale_voucher_same_amount_different_signature_rejected() {
        use crate::protocol::methods::tempo::voucher::sign_voucher;
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let store = Arc::new(InMemoryChannelStore::new());
        let channel_id_hex = format!("0x{}", "ab".repeat(32));
        let channel_id_b256 = channel_id_hex.parse::<alloy::primitives::B256>().unwrap();
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        // Sign a real voucher for amount=1000
        let real_sig = sign_voucher(&signer, channel_id_b256, 1000u128, escrow, 42431)
            .await
            .unwrap();

        let mut state = test_channel_state(&channel_id_hex);
        state.authorized_signer = signer.address();
        state.highest_voucher_amount = 1000;
        state.highest_voucher_signature = Some(real_sig.to_vec());
        state.deposit = 100_000;
        store.insert(&channel_id_hex, state.clone());

        let method = test_session_method(store);

        // Submit same amount but forged signature — should be rejected
        let forged_sig = format!("0x{}", "cd".repeat(65));
        let result = method
            .verify_and_accept_voucher(
                &channel_id_hex,
                &state,
                1000,        // same amount as highest
                &forged_sig, // different signature
                escrow,
                42431,
                0,
                100_000,
                0,
                false,
                0,
            )
            .await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, Some(ErrorCode::InvalidSignature));
    }

    #[tokio::test]
    async fn test_exact_replay_of_highest_voucher_allowed() {
        use crate::protocol::methods::tempo::voucher::sign_voucher;
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let store = Arc::new(InMemoryChannelStore::new());
        let channel_id_hex = format!("0x{}", "ab".repeat(32));
        let channel_id_b256 = channel_id_hex.parse::<alloy::primitives::B256>().unwrap();
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let real_sig = sign_voucher(&signer, channel_id_b256, 1000u128, escrow, 42431)
            .await
            .unwrap();
        let sig_hex = format!("0x{}", alloy::primitives::hex::encode(&real_sig));

        let mut state = test_channel_state(&channel_id_hex);
        state.authorized_signer = signer.address();
        state.highest_voucher_amount = 1000;
        state.highest_voucher_signature = Some(real_sig.to_vec());
        state.deposit = 100_000;
        store.insert(&channel_id_hex, state.clone());

        let method = test_session_method(store);

        // Exact replay: same amount AND same signature — should be accepted (idempotent)
        let result = method
            .verify_and_accept_voucher(
                &channel_id_hex,
                &state,
                1000,
                &sig_hex,
                escrow,
                42431,
                0,
                100_000,
                0,
                false,
                0,
            )
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stale_voucher_with_forged_keychain_envelope_rejected() {
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let store = Arc::new(InMemoryChannelStore::new());
        let channel_id = format!("0x{}", "ab".repeat(32));

        let mut state = test_channel_state(&channel_id);
        state.authorized_signer = signer.address();
        state.highest_voucher_amount = 1_000;
        state.highest_voucher_signature = Some(vec![0xAA; 65]);
        state.deposit = 100_000;
        store.insert(&channel_id, state.clone());

        let method = test_session_method(store);

        // Forge a keychain envelope: 0x03 + authorized_signer address + garbage inner sig.
        // This previously would have passed verify_voucher because it only checked the
        // embedded address against expected_signer without verifying the inner signature.
        let mut forged_envelope = vec![0x03u8];
        forged_envelope.extend_from_slice(signer.address().as_slice());
        forged_envelope.extend_from_slice(&[0xBB; 65]);
        let forged_sig = alloy::hex::encode_prefixed(&forged_envelope);

        let result = method
            .verify_and_accept_voucher(
                &channel_id,
                &state,
                500, // stale: below highest_voucher_amount of 1000
                &forged_sig,
                state.escrow_contract,
                42431,
                0,
                100_000,
                0,
                false,
                0,
            )
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.code,
            Some(crate::protocol::traits::ErrorCode::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn test_concurrent_deductions_different_channels() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let mut s1 = test_channel_state("0xchannel1");
        s1.highest_voucher_amount = 10_000;
        let mut s2 = test_channel_state("0xchannel2");
        s2.highest_voucher_amount = 10_000;
        store.insert("0xchannel1", s1);
        store.insert("0xchannel2", s2);

        let store1 = store.clone();
        let store2 = store.clone();
        let (r1, r2) = tokio::join!(
            deduct_from_channel(&*store1, "0xchannel1", 3_000),
            deduct_from_channel(&*store2, "0xchannel2", 5_000),
        );

        assert_eq!(r1.unwrap().spent, 3_000);
        assert_eq!(r2.unwrap().spent, 5_000);
    }
}
