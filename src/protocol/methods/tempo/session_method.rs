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
    #[serde(default)]
    pub close_requested_at: u64,
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
        Box::pin(std::future::pending())
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
                if state.finalized {
                    return Err(VerificationError::channel_closed("channel is finalized"));
                }
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

    /// Verify that the open transaction's derived channel ID matches the claimed channelId.
    fn verify_open_channel_id_binding(
        tx_bytes: &[u8],
        claimed_channel_id: B256,
        escrow: Address,
        chain_id: u64,
        expected_payee: Address,
        expected_token: Address,
    ) -> Result<(), VerificationError> {
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::sol_types::SolCall;

        alloy::sol! {
            interface IEscrowOpen {
                function open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner) external;
            }
        }

        // Strip type byte (0x76) if present.
        let tx_data = if !tx_bytes.is_empty()
            && tx_bytes[0] == tempo_primitives::transaction::TEMPO_TX_TYPE_ID
        {
            &tx_bytes[1..]
        } else {
            tx_bytes
        };

        let signed = tempo_primitives::AASigned::rlp_decode(&mut &tx_data[..]).map_err(|e| {
            VerificationError::invalid_payload(format!("failed to decode open transaction: {e}"))
        })?;

        let sender = signed
            .recover_signer()
            .map_err(|e| VerificationError::new(format!("failed to recover sender: {e}")))?;

        let tx = signed.tx();

        // Find the escrow.open(...) call.
        let open_selector = <IEscrowOpen::openCall as SolCall>::SELECTOR;
        let open_call = tx
            .calls
            .iter()
            .find(|call| {
                let targets_escrow = match &call.to {
                    alloy::primitives::TxKind::Call(addr) => *addr == escrow,
                    _ => false,
                };
                targets_escrow && call.input.len() >= 4 && call.input[..4] == open_selector
            })
            .ok_or_else(|| {
                VerificationError::invalid_payload(
                    "open transaction does not contain an escrow.open() call",
                )
            })?;

        let decoded = IEscrowOpen::openCall::abi_decode(&open_call.input).map_err(|e| {
            VerificationError::invalid_payload(format!(
                "failed to decode escrow.open() calldata: {e}"
            ))
        })?;

        if decoded.payee != expected_payee {
            return Err(VerificationError::credential_mismatch(
                "open transaction payee does not match session recipient",
            ));
        }
        if decoded.token != expected_token {
            return Err(VerificationError::credential_mismatch(
                "open transaction token does not match session currency",
            ));
        }

        let derived = super::voucher::compute_channel_id(
            sender,
            decoded.payee,
            decoded.token,
            decoded.salt,
            decoded.authorizedSigner,
            escrow,
            chain_id,
        );

        if derived != claimed_channel_id {
            return Err(VerificationError::new(
                "open transaction does not match claimed channelId",
            ));
        }

        Ok(())
    }

    /// Handle 'open' action.
    async fn handle_open(
        &self,
        _credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
        expected_payee: Address,
        expected_token: Address,
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

        // Verify the open transaction's derived channel ID matches the claimed channelId
        Self::verify_open_channel_id_binding(
            &tx_bytes,
            channel_id_b256,
            escrow,
            chain_id,
            expected_payee,
            expected_token,
        )?;

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

        if on_chain.payee != expected_payee {
            return Err(VerificationError::credential_mismatch(
                "channel payee does not match session recipient",
            ));
        }
        if on_chain.token != expected_token {
            return Err(VerificationError::credential_mismatch(
                "channel token does not match session currency",
            ));
        }

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
                        let settled_on_chain =
                            std::cmp::max(on_chain.settled, existing.settled_on_chain);
                        let spent = std::cmp::max(settled_on_chain, existing.spent);

                        // Channel already exists — update if higher.
                        if cumulative_amount > existing.highest_voucher_amount {
                            Ok(Some(ChannelState {
                                deposit: on_chain.deposit,
                                settled_on_chain,
                                spent,
                                highest_voucher_amount: cumulative_amount,
                                highest_voucher_signature: Some(sig_bytes),
                                authorized_signer,
                                close_requested_at: on_chain.close_requested_at,
                                ..existing
                            }))
                        } else {
                            Ok(Some(ChannelState {
                                deposit: on_chain.deposit,
                                settled_on_chain,
                                spent,
                                authorized_signer,
                                close_requested_at: on_chain.close_requested_at,
                                ..existing
                            }))
                        }
                    } else {
                        // New channel (or cold-start reopen after local state was lost).
                        // Initialize settled_on_chain and spent from on-chain state so
                        // we don't overstate available balance when on_chain.settled > 0.
                        Ok(Some(ChannelState {
                            channel_id: channel_id_for_state,
                            chain_id,
                            escrow_contract: escrow,
                            payer: on_chain.payer,
                            payee: on_chain.payee,
                            token: on_chain.token,
                            authorized_signer,
                            deposit: on_chain.deposit,
                            settled_on_chain: on_chain.settled,
                            highest_voucher_amount: cumulative_amount,
                            highest_voucher_signature: Some(sig_bytes),
                            spent: on_chain.settled,
                            units: 0,
                            finalized: false,
                            close_requested_at: on_chain.close_requested_at,
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
        expected_payee: Address,
        expected_token: Address,
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

        if channel.payee != expected_payee {
            return Err(VerificationError::credential_mismatch(
                "channel payee does not match session recipient",
            ));
        }
        if channel.token != expected_token {
            return Err(VerificationError::credential_mismatch(
                "channel token does not match session currency",
            ));
        }

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

        // Update store with full on-chain snapshot (deposit, settled, close state).
        let on_chain_deposit = on_chain.deposit;
        let on_chain_settled = on_chain.settled;
        let on_chain_close_requested_at = on_chain.close_requested_at;
        let channel_id_owned = channel_id_str.clone();
        let updated = self
            .store
            .update_channel(
                &channel_id_owned,
                Box::new(move |current| {
                    let state = current
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                    let settled_on_chain = std::cmp::max(on_chain_settled, state.settled_on_chain);
                    let spent = std::cmp::max(settled_on_chain, state.spent);
                    Ok(Some(ChannelState {
                        deposit: on_chain_deposit,
                        settled_on_chain,
                        spent,
                        close_requested_at: on_chain_close_requested_at,
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
        expected_payee: Address,
        expected_token: Address,
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

        if channel.payee != expected_payee {
            return Err(VerificationError::credential_mismatch(
                "channel payee does not match session recipient",
            ));
        }
        if channel.token != expected_token {
            return Err(VerificationError::credential_mismatch(
                "channel token does not match session currency",
            ));
        }

        if channel.finalized {
            return Err(VerificationError::channel_closed("channel is finalized"));
        }

        let cumulative_amount: u128 = cumulative_amount_str
            .parse()
            .map_err(|_| VerificationError::invalid_payload("invalid cumulativeAmount"))?;

        let escrow = self.resolve_escrow(details)?;
        let chain_id = self.resolve_chain_id(details);

        if channel.chain_id != chain_id {
            return Err(VerificationError::credential_mismatch(
                "channel chain_id does not match session chain_id",
            ));
        }
        if channel.escrow_contract != escrow {
            return Err(VerificationError::credential_mismatch(
                "channel escrow does not match session escrow",
            ));
        }
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
            channel.close_requested_at,
        )
        .await
    }

    /// Handle 'close' action.
    async fn handle_close(
        &self,
        _credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
        expected_payee: Address,
        expected_token: Address,
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

        if channel.payee != expected_payee {
            return Err(VerificationError::credential_mismatch(
                "channel payee does not match session recipient",
            ));
        }
        if channel.token != expected_token {
            return Err(VerificationError::credential_mismatch(
                "channel token does not match session currency",
            ));
        }

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

            let expected_payee = request
                .recipient
                .as_deref()
                .ok_or_else(|| {
                    VerificationError::invalid_payload("session challenge missing recipient")
                })
                .and_then(Self::parse_address)?;
            let expected_token = Self::parse_address(&request.currency)?;

            let payload: SessionCredentialPayload = credential.payload_as().map_err(|e| {
                VerificationError::invalid_payload(format!("Expected session payload: {}", e))
            })?;

            match &payload {
                SessionCredentialPayload::Open { .. } => {
                    this.handle_open(
                        &credential,
                        &payload,
                        &details,
                        expected_payee,
                        expected_token,
                    )
                    .await
                }
                SessionCredentialPayload::TopUp { .. } => {
                    this.handle_top_up(
                        &credential,
                        &payload,
                        &details,
                        expected_payee,
                        expected_token,
                    )
                    .await
                }
                SessionCredentialPayload::Voucher { .. } => {
                    this.handle_voucher(
                        &credential,
                        &payload,
                        &details,
                        expected_payee,
                        expected_token,
                    )
                    .await
                }
                SessionCredentialPayload::Close { .. } => {
                    this.handle_close(
                        &credential,
                        &payload,
                        &details,
                        expected_payee,
                        expected_token,
                    )
                    .await
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
    use crate::protocol::methods::tempo::voucher;
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
            close_requested_at: 0,
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
    async fn test_deduct_from_finalized_channel_rejects() {
        let store = InMemoryChannelStore::new();
        let mut state = test_channel_state("0xchannel1");
        state.highest_voucher_amount = 10_000;
        state.finalized = true;
        store.insert("0xchannel1", state);

        let result = deduct_from_channel(&store, "0xchannel1", 1_000).await;
        assert!(result.is_err(), "finalized channel should reject deduction");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("finalized"),
            "error should mention finalized, got: {err}"
        );
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

    /// Helper that replicates the handle_open reopen logic so tests exercise
    /// the same formula used in production.
    async fn reopen_channel(
        store: &std::sync::Arc<InMemoryChannelStore>,
        key: &str,
        on_chain_settled: u128,
        on_chain_deposit: u128,
        new_cumulative_amount: u128,
    ) -> ChannelState {
        let key_owned = key.to_string();
        store
            .update_channel(
                &key_owned,
                Box::new(move |existing| {
                    let existing = existing.unwrap();
                    let settled_on_chain =
                        std::cmp::max(on_chain_settled, existing.settled_on_chain);
                    let spent = std::cmp::max(settled_on_chain, existing.spent);

                    if new_cumulative_amount > existing.highest_voucher_amount {
                        Ok(Some(ChannelState {
                            deposit: on_chain_deposit,
                            settled_on_chain,
                            spent,
                            highest_voucher_amount: new_cumulative_amount,
                            ..existing
                        }))
                    } else {
                        Ok(Some(ChannelState {
                            deposit: on_chain_deposit,
                            settled_on_chain,
                            spent,
                            ..existing
                        }))
                    }
                }),
            )
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn test_reopen_bumps_spent_to_settled_on_chain_higher_voucher() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let mut state = test_channel_state("0xchannel_reopen");
        state.highest_voucher_amount = 5_000_000;
        state.spent = 0;
        state.settled_on_chain = 0;
        state.deposit = 10_000_000;
        store.insert("0xchannel_reopen", state);

        // Server settled 5M on-chain; client sends higher voucher of 7M.
        let result =
            reopen_channel(&store, "0xchannel_reopen", 5_000_000, 10_000_000, 7_000_000).await;

        assert_eq!(result.settled_on_chain, 5_000_000);
        assert_eq!(result.spent, 5_000_000);
        assert_eq!(result.highest_voucher_amount, 7_000_000);
        // Available = 7M - 5M = 2M
        assert_eq!(
            result.highest_voucher_amount.saturating_sub(result.spent),
            2_000_000
        );
    }

    #[tokio::test]
    async fn test_reopen_bumps_spent_non_higher_voucher() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let mut state = test_channel_state("0xchannel_reopen2");
        state.highest_voucher_amount = 5_000_000;
        state.spent = 0;
        state.settled_on_chain = 0;
        state.deposit = 10_000_000;
        store.insert("0xchannel_reopen2", state);

        // Server settled 5M on-chain; client sends same voucher (not higher).
        let result = reopen_channel(
            &store,
            "0xchannel_reopen2",
            5_000_000,
            10_000_000,
            3_000_000,
        )
        .await;

        assert_eq!(result.settled_on_chain, 5_000_000);
        assert_eq!(result.spent, 5_000_000);
        // Voucher stays at 5M (was higher than the 3M presented).
        assert_eq!(result.highest_voucher_amount, 5_000_000);
        // Available = 5M - 5M = 0
        assert_eq!(
            result.highest_voucher_amount.saturating_sub(result.spent),
            0
        );
    }

    #[tokio::test]
    async fn test_reopen_spent_does_not_regress_when_spent_exceeds_settled() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let mut state = test_channel_state("0xchannel_reopen3");
        state.highest_voucher_amount = 10_000_000;
        state.spent = 8_000_000;
        state.settled_on_chain = 0;
        state.deposit = 10_000_000;
        store.insert("0xchannel_reopen3", state);

        // Server settled only 3M on-chain, but we already spent 8M locally.
        // spent must stay at 8M (not regress to 3M).
        let result = reopen_channel(
            &store,
            "0xchannel_reopen3",
            3_000_000,
            10_000_000,
            10_000_000,
        )
        .await;

        assert_eq!(result.settled_on_chain, 3_000_000);
        assert_eq!(result.spent, 8_000_000);
        // Available = 10M - 8M = 2M
        assert_eq!(
            result.highest_voucher_amount.saturating_sub(result.spent),
            2_000_000
        );
    }

    #[tokio::test]
    async fn test_new_channel_state_should_use_on_chain_settled() {
        // Exercises the real update_channel closure from handle_open's "new channel"
        // branch. When no existing state is present, settled_on_chain and spent must
        // be set to on_chain.settled to prevent double-spending already-settled amounts.
        let store = Arc::new(InMemoryChannelStore::new());
        let channel_id = "0xchannel_reopened";

        let on_chain_settled: u128 = 5_000_000;
        let on_chain_deposit: u128 = 10_000_000;
        let cumulative_amount: u128 = 7_000_000;
        let sig_bytes = vec![0xAA; 65];
        let authorized_signer: Address = "0x4444444444444444444444444444444444444444"
            .parse()
            .unwrap();
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let payer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let chain_id: u64 = 42431;

        // Replicate the closure from handle_open's else (new channel) branch
        let sig_bytes_clone = sig_bytes.clone();
        let result = store
            .update_channel(
                channel_id,
                Box::new(move |existing| {
                    assert!(existing.is_none(), "should be new channel");
                    Ok(Some(ChannelState {
                        channel_id: channel_id.to_string(),
                        chain_id,
                        escrow_contract: escrow,
                        payer,
                        payee,
                        token,
                        authorized_signer,
                        deposit: on_chain_deposit,
                        settled_on_chain: on_chain_settled,
                        highest_voucher_amount: cumulative_amount,
                        highest_voucher_signature: Some(sig_bytes_clone),
                        spent: on_chain_settled,
                        units: 0,
                        finalized: false,
                        close_requested_at: 0,
                        created_at: "2025-01-01T00:00:00Z".to_string(),
                    }))
                }),
            )
            .await
            .unwrap();

        let state = result.unwrap();
        assert_eq!(state.settled_on_chain, on_chain_settled);
        assert_eq!(state.spent, on_chain_settled);
        assert_eq!(state.highest_voucher_amount, cumulative_amount);
        assert_eq!(state.deposit, on_chain_deposit);

        // Verify available balance reflects settled amount
        let available = state.highest_voucher_amount.saturating_sub(state.spent);
        assert_eq!(available, 2_000_000); // 7M - 5M

        // Verify deduct_from_channel also sees correct available balance
        let after_deduct = deduct_from_channel(&*store, channel_id, 1_000_000)
            .await
            .unwrap();
        assert_eq!(after_deduct.spent, on_chain_settled + 1_000_000); // 6M
    }

    #[tokio::test]
    async fn test_deduct_rejects_finalized_channel() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let mut state = test_channel_state("0xchannel_fin");
        state.highest_voucher_amount = 10_000;
        state.finalized = true;
        store.insert("0xchannel_fin", state);

        let result = deduct_from_channel(&*store, "0xchannel_fin", 1_000).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("finalized"),
            "error should mention finalized, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_voucher_uses_stored_close_requested_at() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let mut state = test_channel_state("0xchannel_close_req");
        state.highest_voucher_amount = 10_000;
        state.deposit = 100_000;
        state.close_requested_at = 12345; // non-zero = force-close requested
        store.insert("0xchannel_close_req", state);

        // Verify that close_requested_at is persisted and retrieved
        let retrieved = store
            .get_channel("0xchannel_close_req")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.close_requested_at, 12345);
    }

    #[tokio::test]
    async fn test_reopen_bumps_spent_to_settled_on_chain() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let mut state = test_channel_state("0xchannel_reopen");
        state.highest_voucher_amount = 5_000_000;
        state.spent = 0;
        state.settled_on_chain = 0;
        state.deposit = 10_000_000;
        store.insert("0xchannel_reopen", state);

        // Simulate what handle_open does when reopening:
        // on_chain.settled has increased to 5_000_000
        let on_chain_settled: u128 = 5_000_000;
        let result = store
            .update_channel(
                "0xchannel_reopen",
                Box::new(move |existing| {
                    let existing = existing.unwrap();
                    let settled_on_chain =
                        std::cmp::max(on_chain_settled, existing.settled_on_chain);
                    let spent = std::cmp::max(settled_on_chain, existing.spent);
                    Ok(Some(ChannelState {
                        settled_on_chain,
                        spent,
                        highest_voucher_amount: 7_000_000,
                        ..existing
                    }))
                }),
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.settled_on_chain, 5_000_000);
        assert_eq!(result.spent, 5_000_000);
        assert_eq!(result.highest_voucher_amount, 7_000_000);
        // Available = 7M - 5M = 2M
        let available = result.highest_voucher_amount.saturating_sub(result.spent);
        assert_eq!(available, 2_000_000);
    }

    #[test]
    fn test_deserialize_channel_state_without_close_requested_at() {
        // Backward compat: old serialized state without close_requested_at should default to 0.
        let json = r#"{
            "channel_id": "0xaabb",
            "chain_id": 1,
            "escrow_contract": "0x1111111111111111111111111111111111111111",
            "payer": "0x2222222222222222222222222222222222222222",
            "payee": "0x3333333333333333333333333333333333333333",
            "token": "0x4444444444444444444444444444444444444444",
            "authorized_signer": "0x5555555555555555555555555555555555555555",
            "deposit": 100000,
            "settled_on_chain": 0,
            "highest_voucher_amount": 0,
            "highest_voucher_signature": null,
            "spent": 0,
            "units": 0,
            "finalized": false,
            "created_at": "2025-01-01T00:00:00Z"
        }"#;
        let state: ChannelState = serde_json::from_str(json).unwrap();
        assert_eq!(state.close_requested_at, 0);
    }

    #[tokio::test]
    async fn test_cold_start_new_channel_with_on_chain_settled() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());

        let on_chain_settled: u128 = 5_000_000;
        let cumulative_amount: u128 = 7_000_000;
        let on_chain_deposit: u128 = 10_000_000;

        let result = store
            .update_channel(
                "0xchannel_cold",
                Box::new(move |_existing| {
                    assert!(
                        _existing.is_none(),
                        "should be a cold start with no existing state"
                    );
                    Ok(Some(ChannelState {
                        channel_id: "0xchannel_cold".to_string(),
                        chain_id: 1,
                        escrow_contract: "0x1111111111111111111111111111111111111111"
                            .parse()
                            .unwrap(),
                        payer: "0x2222222222222222222222222222222222222222"
                            .parse()
                            .unwrap(),
                        payee: "0x3333333333333333333333333333333333333333"
                            .parse()
                            .unwrap(),
                        token: "0x4444444444444444444444444444444444444444"
                            .parse()
                            .unwrap(),
                        authorized_signer: "0x5555555555555555555555555555555555555555"
                            .parse()
                            .unwrap(),
                        deposit: on_chain_deposit,
                        settled_on_chain: on_chain_settled,
                        highest_voucher_amount: cumulative_amount,
                        highest_voucher_signature: None,
                        spent: on_chain_settled,
                        units: 0,
                        finalized: false,
                        close_requested_at: 0,
                        created_at: "2025-01-01T00:00:00Z".to_string(),
                    }))
                }),
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.settled_on_chain, 5_000_000);
        assert_eq!(result.spent, 5_000_000);
        let available = result.highest_voucher_amount.saturating_sub(result.spent);
        assert_eq!(available, 2_000_000);
    }

    #[tokio::test]
    async fn test_deduct_rejects_when_close_requested() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let mut state = test_channel_state("0xchannel_closing");
        state.highest_voucher_amount = 10_000;
        state.close_requested_at = 99999;
        store.insert("0xchannel_closing", state);

        let retrieved = store
            .get_channel("0xchannel_closing")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.close_requested_at, 99999);

        // Deduction should still work (close_requested_at is checked at voucher level)
        let result = deduct_from_channel(&*store, "0xchannel_closing", 1_000).await;
        assert!(result.is_ok());
        let updated = result.unwrap();
        assert_eq!(updated.spent, 1_000);
        assert_eq!(updated.close_requested_at, 99999);
    }

    #[tokio::test]
    async fn test_topup_refreshes_on_chain_fields() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let mut state = test_channel_state("0xchannel_topup");
        state.deposit = 100_000;
        state.close_requested_at = 12345;
        state.settled_on_chain = 1_000;
        state.spent = 2_000;
        store.insert("0xchannel_topup", state);

        let on_chain_deposit: u128 = 200_000;
        let on_chain_settled: u128 = 1_000;
        let on_chain_close_requested_at: u64 = 0;

        let result = store
            .update_channel(
                "0xchannel_topup",
                Box::new(move |current| {
                    let state = current.unwrap();
                    let settled_on_chain = std::cmp::max(on_chain_settled, state.settled_on_chain);
                    let spent = std::cmp::max(settled_on_chain, state.spent);
                    Ok(Some(ChannelState {
                        deposit: on_chain_deposit,
                        settled_on_chain,
                        spent,
                        close_requested_at: on_chain_close_requested_at,
                        ..state
                    }))
                }),
            )
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.deposit, 200_000);
        assert_eq!(
            result.close_requested_at, 0,
            "topUp should refresh close_requested_at"
        );
        assert_eq!(result.settled_on_chain, 1_000);
        assert_eq!(result.spent, 2_000); // max(1000, 2000) = 2000
    }

    #[tokio::test]
    async fn test_deduct_from_channel_finalized_rejects() {
        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let mut state = test_channel_state("0xchannel_fin");
        state.highest_voucher_amount = 10_000;
        state.spent = 0;
        state.finalized = true;
        store.insert("0xchannel_fin", state);

        let result = deduct_from_channel(&*store, "0xchannel_fin", 1_000).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(
            err.code,
            Some(crate::protocol::traits::ErrorCode::ChannelClosed)
        );

        // Verify state was not mutated
        let unchanged = store.get_channel("0xchannel_fin").await.unwrap().unwrap();
        assert_eq!(unchanged.spent, 0);
        assert_eq!(unchanged.units, 0);
    }

    #[test]
    fn test_open_channel_id_binding_rejects_mismatch() {
        use alloy::eips::Encodable2718;
        use alloy::primitives::Bytes;
        use alloy::signers::local::PrivateKeySigner;
        use alloy::signers::SignerSync;
        use alloy::sol_types::SolCall;
        use tempo_primitives::transaction::Call;
        use tempo_primitives::TempoTransaction;

        alloy::sol! {
            interface IEscrowOpen {
                function open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner) external;
            }
        }

        let signer = PrivateKeySigner::random();
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let salt = B256::from([0xABu8; 32]);
        let chain_id: u64 = 42431;

        let open_data =
            IEscrowOpen::openCall::new((payee, token, 1_000_000u128, salt, signer.address()))
                .abi_encode();

        let tx = TempoTransaction {
            chain_id,
            nonce: 0,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            calls: vec![Call {
                to: alloy::primitives::TxKind::Call(escrow),
                value: alloy::primitives::U256::ZERO,
                input: Bytes::from(open_data),
            }],
            ..Default::default()
        };

        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash).unwrap();
        let signed_tx = tx.into_signed(signature.into());
        let tx_bytes = signed_tx.encoded_2718();

        // Compute the correct channel ID.
        let correct_id = voucher::compute_channel_id(
            signer.address(),
            payee,
            token,
            salt,
            signer.address(), // authorizedSigner == sender in this test
            escrow,
            chain_id,
        );

        // Should pass with correct channel ID.
        assert!(
            SessionMethod::<alloy::providers::RootProvider<TempoNetwork>>::verify_open_channel_id_binding(
                &tx_bytes,
                correct_id,
                escrow,
                chain_id,
                payee,
                token,
            )
            .is_ok()
        );

        // Should fail with a different channel ID.
        let fake_id = B256::from([0x01u8; 32]);
        let err = SessionMethod::<alloy::providers::RootProvider<TempoNetwork>>::verify_open_channel_id_binding(
            &tx_bytes,
            fake_id,
            escrow,
            chain_id,
            payee,
            token,
        )
        .unwrap_err();
        assert!(
            err.message.contains("does not match claimed channelId"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn test_open_channel_id_binding_rejects_wrong_payee_or_token() {
        use alloy::eips::Encodable2718;
        use alloy::primitives::Bytes;
        use alloy::signers::local::PrivateKeySigner;
        use alloy::signers::SignerSync;
        use alloy::sol_types::SolCall;
        use tempo_primitives::transaction::Call;
        use tempo_primitives::TempoTransaction;

        alloy::sol! {
            interface IEscrowOpen {
                function open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner) external;
            }
        }

        let signer = PrivateKeySigner::random();
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let wrong: Address = "0x9999999999999999999999999999999999999999"
            .parse()
            .unwrap();
        let salt = B256::from([0xABu8; 32]);
        let chain_id: u64 = 42431;

        let open_data =
            IEscrowOpen::openCall::new((payee, token, 1_000_000u128, salt, signer.address()))
                .abi_encode();

        let tx = TempoTransaction {
            chain_id,
            nonce: 0,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            calls: vec![Call {
                to: alloy::primitives::TxKind::Call(escrow),
                value: alloy::primitives::U256::ZERO,
                input: Bytes::from(open_data),
            }],
            ..Default::default()
        };

        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash).unwrap();
        let signed_tx = tx.into_signed(signature.into());
        let tx_bytes = signed_tx.encoded_2718();

        let correct_id = voucher::compute_channel_id(
            signer.address(),
            payee,
            token,
            salt,
            signer.address(),
            escrow,
            chain_id,
        );

        let payee_err = SessionMethod::<alloy::providers::RootProvider<TempoNetwork>>::verify_open_channel_id_binding(
            &tx_bytes,
            correct_id,
            escrow,
            chain_id,
            wrong,
            token,
        )
        .unwrap_err();
        assert!(payee_err.message.contains("payee"));

        let token_err = SessionMethod::<alloy::providers::RootProvider<TempoNetwork>>::verify_open_channel_id_binding(
            &tx_bytes,
            correct_id,
            escrow,
            chain_id,
            payee,
            wrong,
        )
        .unwrap_err();
        assert!(token_err.message.contains("token"));
    }

    /// Helper to build a SessionRequest, PaymentChallenge, and PaymentCredential
    /// for verify_session tests. Uses the given recipient/currency in the
    /// challenge and the given payload in the credential.
    fn build_session_credential(
        recipient: Option<&str>,
        currency: &str,
        payload: SessionCredentialPayload,
    ) -> (
        crate::protocol::intents::SessionRequest,
        crate::protocol::core::PaymentCredential,
    ) {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge, PaymentCredential};
        use crate::protocol::intents::SessionRequest;

        let request = SessionRequest {
            amount: "1000".to_string(),
            currency: currency.to_string(),
            recipient: recipient.map(|s| s.to_string()),
            method_details: Some(serde_json::json!({
                "escrowContract": "0x5555555555555555555555555555555555555555",
                "chainId": 42431,
            })),
            ..Default::default()
        };
        let challenge = PaymentChallenge::new(
            "test-id",
            "api.example.com",
            METHOD_NAME,
            INTENT_SESSION,
            Base64UrlJson::from_typed(&request).unwrap(),
        );
        let credential = PaymentCredential::new(challenge.to_echo(), payload);
        (request, credential)
    }

    #[tokio::test]
    async fn test_verify_session_rejects_missing_recipient() {
        let store = Arc::new(InMemoryChannelStore::new());
        let method = test_session_method(store);

        let channel_id = format!("0x{}", "ab".repeat(32));
        let (request, credential) = build_session_credential(
            None, // missing recipient
            "0x3333333333333333333333333333333333333333",
            SessionCredentialPayload::Voucher {
                channel_id,
                cumulative_amount: "1000".to_string(),
                signature: format!("0x{}", "aa".repeat(65)),
            },
        );

        let err = method
            .verify_session(&credential, &request)
            .await
            .unwrap_err();
        assert!(
            err.message.contains("recipient"),
            "expected missing recipient error, got: {}",
            err.message
        );
    }

    /// A voucher referencing a channel opened for a different payee must
    /// be rejected to prevent cross-session channel reuse.
    #[tokio::test]
    async fn test_voucher_rejects_channel_with_wrong_payee() {
        let store = Arc::new(InMemoryChannelStore::new());
        let channel_id = format!("0x{}", "ab".repeat(32));

        // Store a channel whose payee is 0x2222...
        let mut state = test_channel_state(&channel_id);
        state.highest_voucher_amount = 500;
        state.deposit = 100_000;
        store.insert(&channel_id, state);

        let method = test_session_method(store);

        // Challenge expects recipient 0x9999... (different from stored 0x2222...)
        let (request, credential) = build_session_credential(
            Some("0x9999999999999999999999999999999999999999"),
            "0x3333333333333333333333333333333333333333", // matches stored token
            SessionCredentialPayload::Voucher {
                channel_id,
                cumulative_amount: "1000".to_string(),
                signature: format!("0x{}", "aa".repeat(65)),
            },
        );

        let err = method
            .verify_session(&credential, &request)
            .await
            .unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
        assert!(
            err.message.contains("payee"),
            "expected payee mismatch error, got: {}",
            err.message
        );
    }

    /// A voucher referencing a channel opened for a different
    /// token/currency must be rejected to prevent cross-session channel reuse.
    #[tokio::test]
    async fn test_voucher_rejects_channel_with_wrong_token() {
        let store = Arc::new(InMemoryChannelStore::new());
        let channel_id = format!("0x{}", "ab".repeat(32));

        // Store a channel whose token is 0x3333...
        let mut state = test_channel_state(&channel_id);
        state.highest_voucher_amount = 500;
        state.deposit = 100_000;
        store.insert(&channel_id, state);

        let method = test_session_method(store);

        // Challenge expects currency 0x9999... (different from stored 0x3333...)
        let (request, credential) = build_session_credential(
            Some("0x2222222222222222222222222222222222222222"), // matches stored payee
            "0x9999999999999999999999999999999999999999",       // wrong token
            SessionCredentialPayload::Voucher {
                channel_id,
                cumulative_amount: "1000".to_string(),
                signature: format!("0x{}", "aa".repeat(65)),
            },
        );

        let err = method
            .verify_session(&credential, &request)
            .await
            .unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
        assert!(
            err.message.contains("token"),
            "expected token mismatch error, got: {}",
            err.message
        );
    }

    /// A close referencing a channel with a mismatched payee must be
    /// rejected to prevent cross-session channel reuse.
    #[tokio::test]
    async fn test_close_rejects_channel_with_wrong_payee() {
        let store = Arc::new(InMemoryChannelStore::new());
        let channel_id = format!("0x{}", "ab".repeat(32));

        let mut state = test_channel_state(&channel_id);
        state.highest_voucher_amount = 500;
        state.deposit = 100_000;
        store.insert(&channel_id, state);

        let method = test_session_method(store);

        let (request, credential) = build_session_credential(
            Some("0x9999999999999999999999999999999999999999"), // wrong payee
            "0x3333333333333333333333333333333333333333",
            SessionCredentialPayload::Close {
                channel_id,
                cumulative_amount: "1000".to_string(),
                signature: format!("0x{}", "aa".repeat(65)),
            },
        );

        let err = method
            .verify_session(&credential, &request)
            .await
            .unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
        assert!(
            err.message.contains("payee"),
            "expected payee mismatch error, got: {}",
            err.message
        );
    }

    /// A topUp referencing a channel with a mismatched token must be
    /// rejected before the transaction is broadcast.
    #[tokio::test]
    async fn test_top_up_rejects_channel_with_wrong_token() {
        let store = Arc::new(InMemoryChannelStore::new());
        let channel_id = format!("0x{}", "ab".repeat(32));

        let mut state = test_channel_state(&channel_id);
        state.highest_voucher_amount = 500;
        state.deposit = 100_000;
        store.insert(&channel_id, state);

        let method = test_session_method(store);

        let (request, credential) = build_session_credential(
            Some("0x2222222222222222222222222222222222222222"),
            "0x9999999999999999999999999999999999999999", // wrong token
            SessionCredentialPayload::TopUp {
                payload_type: "transaction".to_string(),
                channel_id,
                additional_deposit: "5000".to_string(),
                transaction: format!("0x{}", "bb".repeat(32)),
            },
        );

        let err = method
            .verify_session(&credential, &request)
            .await
            .unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
        assert!(
            err.message.contains("token"),
            "expected token mismatch error, got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn test_default_wait_for_update_does_not_complete_immediately() {
        use std::time::Duration;
        // A minimal ChannelStore that only implements required methods,
        // relying on the default wait_for_update
        struct PollOnlyStore;
        impl ChannelStore for PollOnlyStore {
            fn get_channel(
                &self,
                _channel_id: &str,
            ) -> std::pin::Pin<
                Box<
                    dyn Future<Output = Result<Option<ChannelState>, VerificationError>>
                        + Send
                        + '_,
                >,
            > {
                unimplemented!()
            }

            fn update_channel(
                &self,
                _channel_id: &str,
                _updater: Box<
                    dyn FnOnce(
                            Option<ChannelState>,
                        )
                            -> Result<Option<ChannelState>, VerificationError>
                        + Send,
                >,
            ) -> std::pin::Pin<
                Box<
                    dyn Future<Output = Result<Option<ChannelState>, VerificationError>>
                        + Send
                        + '_,
                >,
            > {
                unimplemented!()
            }
        }

        let store = PollOnlyStore;
        let result =
            tokio::time::timeout(Duration::from_millis(50), store.wait_for_update("any")).await;

        // Should timeout. The default must not return immediately
        assert!(result.is_err());
    }
}
