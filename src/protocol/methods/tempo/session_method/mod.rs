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
use super::session_receipt::SessionReceipt;
use super::voucher::{canonical_voucher_signature, verify_voucher};
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
    /// Immutable machine-token settlement route accepted at open.
    #[serde(default)]
    pub settlement_route: Option<super::session::SettlementRoute>,
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
    pub closing: bool,
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
/// The session method and the SSE/WebSocket helpers lowercase channel IDs
/// before calling the store. Implementations that are also called with
/// client-supplied IDs should key by the lowercase form too.
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

/// Normalize a channel ID to the lowercase form that channel state is keyed by.
///
/// Channel IDs are hex strings, so clients may send them in any case.
pub(crate) fn normalize_channel_id(channel_id: &str) -> String {
    channel_id.to_ascii_lowercase()
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
                if state.closing {
                    return Err(VerificationError::channel_closed("channel is closing"));
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

/// Validate the close voucher amount against spent, on-chain settled, and deposit.
/// Matches mppx handleClose:
/// https://github.com/wevm/mppx/blob/c526ea6/src/tempo/server/Session.ts#L837-L846
///
/// The amount must exceed the on-chain settled amount: a settled voucher is
/// public on-chain and must not close the channel when presented again
/// (GHSA-mv9j-8jvg-j8mr). The one exception is a funded channel nothing was
/// ever settled on, which can be closed at zero to refund the payer.
fn validate_close_amount(
    cumulative_amount: u128,
    spent: u128,
    on_chain_settled: u128,
    on_chain_deposit: u128,
) -> Result<(), VerificationError> {
    if cumulative_amount < spent {
        return Err(VerificationError::new(format!(
            "close voucher amount must be >= {} (spent)",
            spent,
        )));
    }
    let refunds_untouched = cumulative_amount == 0 && on_chain_settled == 0 && on_chain_deposit > 0;
    if cumulative_amount <= on_chain_settled && !refunds_untouched {
        return Err(VerificationError::new(format!(
            "close voucher amount must be > {} (on-chain settled)",
            on_chain_settled,
        )));
    }
    if cumulative_amount > on_chain_deposit {
        return Err(VerificationError::amount_exceeds_deposit(
            "close voucher amount exceeds on-chain deposit",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn machine_session_close_calls(
    chain_id: u64,
    escrow: Address,
    descriptor: &super::session::ChannelDescriptor,
    route: &super::session::SettlementRoute,
    cumulative_amount: u128,
    deposit: u128,
    settled: u128,
    signature: &[u8],
) -> Result<Vec<tempo_alloy::primitives::transaction::Call>, VerificationError> {
    use alloy::{
        primitives::{Bytes, TxKind, U256},
        sol_types::SolCall,
    };
    if cumulative_amount != deposit {
        return Err(VerificationError::invalid_payload(
            "machine-token sessions cannot close with a nonzero refund",
        ));
    }
    let cumulative_amount = alloy::primitives::Uint::<96, 2>::from(cumulative_amount);
    let parse_address = |value: &str| {
        value
            .parse::<Address>()
            .map_err(|_| VerificationError::invalid_payload("invalid channel descriptor address"))
    };
    let descriptor_wire =
        tempo_alloy::contracts::precompiles::ITIP20ChannelReserve::ChannelDescriptor {
            payer: parse_address(&descriptor.payer)?,
            payee: parse_address(&descriptor.payee)?,
            operator: parse_address(&descriptor.operator)?,
            token: parse_address(&descriptor.token)?,
            salt: descriptor
                .salt
                .parse()
                .map_err(|_| VerificationError::invalid_payload("invalid descriptor salt"))?,
            authorizedSigner: parse_address(&descriptor.authorized_signer)?,
            expiringNonceHash: descriptor.expiring_nonce_hash.parse().map_err(|_| {
                VerificationError::invalid_payload("invalid descriptor expiringNonceHash")
            })?,
        };
    let settle = tempo_alloy::contracts::precompiles::ITIP20ChannelReserve::settleCall::new((
        descriptor_wire.clone(),
        cumulative_amount,
        Bytes::copy_from_slice(signature),
    ));
    let close = tempo_alloy::contracts::precompiles::ITIP20ChannelReserve::closeCall::new((
        descriptor_wire,
        cumulative_amount,
        cumulative_amount,
        Bytes::copy_from_slice(signature),
    ));
    let swap = crate::protocol::methods::tempo::machine_token::settle_session_call(
        chain_id, descriptor, route,
    )
    .map_err(|error| VerificationError::invalid_payload(error.to_string()))?;
    let close_call = tempo_alloy::primitives::transaction::Call {
        to: TxKind::Call(escrow),
        value: U256::ZERO,
        input: Bytes::from(close.abi_encode()),
    };
    if settled == deposit {
        return Ok(vec![close_call]);
    }
    Ok(vec![
        tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(escrow),
            value: U256::ZERO,
            input: Bytes::from(settle.abi_encode()),
        },
        swap,
        close_call,
    ])
}

fn validate_settlement_route(
    channel: &ChannelState,
    details: &TempoSessionMethodDetails,
    route: Option<&super::session::SettlementRoute>,
) -> Result<(), VerificationError> {
    if details.machine_token_enabled != Some(true) {
        return Ok(());
    }
    let route = route.ok_or_else(|| {
        VerificationError::invalid_payload("machine-token credential is missing settlementRoute")
    })?;
    if channel.settlement_route.as_ref() != Some(route)
        || details.settlement_adapter.as_deref() != Some(&route.adapter)
        || details.settlement_recipient.as_deref() != Some(&route.recipient)
        || details.settlement_token.as_deref() != Some(&route.target_token)
    {
        return Err(VerificationError::credential_mismatch(
            "settlement route does not match the opened channel",
        ));
    }
    Ok(())
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
/// - `open`: verify open tx and initial voucher, broadcast, create channel in store
/// - `topUp`: verify topUp tx, broadcast, update deposit in store
/// - `voucher`: verify voucher signature, check monotonicity/bounds/delta, update store
/// - `close`: verify final voucher, close on-chain, finalize in store
///
/// Every action returns a session receipt: the [`Receipt`] references the
/// channel and carries the [`SessionReceipt`] fields (`challengeId`,
/// `acceptedCumulative`, `spent`, `txHash`, ...) as extension fields.
#[derive(Clone)]
pub struct SessionMethod<P> {
    provider: Arc<P>,
    store: Arc<dyn ChannelStore>,
    config: SessionMethodConfig,
    /// Signer for submitting on-chain close transactions. `close` is rejected
    /// when unset.
    close_signer: Option<Arc<super::DynSigner>>,
}

impl<P> SessionMethod<P> {
    /// Parse a hex channel ID string to B256.
    fn parse_channel_id(channel_id: &str) -> Result<B256, VerificationError> {
        channel_id
            .parse::<B256>()
            .map_err(|e| VerificationError::invalid_payload(format!("Invalid channel ID: {}", e)))
    }

    /// Parse a hex voucher signature into its canonical 65-byte encoding.
    ///
    /// The returned bytes are what gets stored and submitted on-chain, so
    /// encodings the escrow contract cannot settle are rejected here.
    fn parse_signature(signature: &str) -> Result<Vec<u8>, VerificationError> {
        let s = signature.strip_prefix("0x").unwrap_or(signature);
        let bytes = hex::decode(s).map_err(|e| {
            VerificationError::invalid_payload(format!("Invalid signature hex: {}", e))
        })?;
        canonical_voucher_signature(&bytes)
            .map(Vec::from)
            .ok_or_else(|| {
                VerificationError::invalid_signature("voucher signature is not canonical")
            })
    }

    /// Parse an address string.
    fn parse_address(addr: &str) -> Result<Address, VerificationError> {
        addr.parse::<Address>()
            .map_err(|e| VerificationError::invalid_payload(format!("Invalid address: {}", e)))
    }

    /// Parse the base-unit amount in the payload field `field`: decimal
    /// digits only, without the sign `u128::from_str` would accept.
    fn parse_amount(amount: &str, field: &str) -> Result<u128, VerificationError> {
        crate::protocol::intents::base_unit_digits(amount)
            .and_then(|digits| digits.parse().ok())
            .ok_or_else(|| VerificationError::invalid_payload(format!("invalid {field}")))
    }
}

impl<P> SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Create a new Tempo session method.
    ///
    /// Call [`with_close_signer`](Self::with_close_signer) to let the method
    /// settle `close` credentials on-chain; without it they are rejected.
    pub fn new(provider: P, store: Arc<dyn ChannelStore>, config: SessionMethodConfig) -> Self {
        Self {
            provider: Arc::new(provider),
            store,
            config,
            close_signer: None,
        }
    }

    /// Set the signer used for submitting on-chain close transactions.
    ///
    /// Required to accept `close` credentials: a channel is only finalized
    /// once its close transaction succeeded on-chain.
    pub fn with_close_signer<S>(mut self, signer: S) -> Self
    where
        S: alloy::signers::Signer + Send + Sync + 'static,
    {
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
                machine_token_enabled: None,
                settlement_adapter: None,
                settlement_recipient: None,
                settlement_token: None,
                operator: None,
                session_protocol: None,
                session_snapshot: None,
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
    ///
    /// Returns the address that signs the channel's vouchers and the deposit
    /// the transaction opens it with.
    fn verify_open_channel_id_binding(
        tx_bytes: &[u8],
        claimed_channel_id: B256,
        escrow: Address,
        chain_id: u64,
        expected_payee: Address,
        expected_token: Address,
    ) -> Result<(Address, u128), VerificationError> {
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::sol_types::SolCall;

        alloy::sol! {
            interface IEscrowOpen {
                function open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner) external;
            }
        }

        let (signed, input) = Self::decode_escrow_call(
            tx_bytes,
            escrow,
            <IEscrowOpen::openCall as SolCall>::SELECTOR,
            "open",
        )?;

        let sender = signed
            .recover_signer()
            .map_err(|e| VerificationError::new(format!("failed to recover sender: {e}")))?;

        let decoded = IEscrowOpen::openCall::abi_decode(&input).map_err(|e| {
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

        let voucher_signer = if decoded.authorizedSigner == Address::ZERO {
            sender
        } else {
            decoded.authorizedSigner
        };

        Ok((voucher_signer, decoded.deposit))
    }

    /// Verify that the topUp transaction tops up the claimed channel by the
    /// declared amount.
    fn verify_top_up_transaction(
        tx_bytes: &[u8],
        claimed_channel_id: B256,
        escrow: Address,
        additional_deposit: u128,
    ) -> Result<(), VerificationError> {
        use alloy::sol_types::SolCall;

        alloy::sol! {
            interface IEscrowTopUp {
                function topUp(bytes32 channelId, uint256 additionalDeposit) external;
            }
        }

        let (_, input) = Self::decode_escrow_call(
            tx_bytes,
            escrow,
            <IEscrowTopUp::topUpCall as SolCall>::SELECTOR,
            "topUp",
        )?;

        let decoded = IEscrowTopUp::topUpCall::abi_decode(&input).map_err(|e| {
            VerificationError::invalid_payload(format!(
                "failed to decode escrow.topUp() calldata: {e}"
            ))
        })?;

        if decoded.channelId != claimed_channel_id {
            return Err(VerificationError::new(
                "topUp transaction does not match claimed channelId",
            ));
        }
        if decoded.additionalDeposit != alloy::primitives::U256::from(additional_deposit) {
            return Err(VerificationError::new(
                "topUp transaction amount does not match additionalDeposit",
            ));
        }

        Ok(())
    }

    /// Decode a client-signed Tempo transaction and return it together with
    /// the input of its call to `selector` on the escrow contract.
    fn decode_escrow_call(
        tx_bytes: &[u8],
        escrow: Address,
        selector: [u8; 4],
        action: &str,
    ) -> Result<(tempo_alloy::primitives::AASigned, Bytes), VerificationError> {
        // Strip type byte (0x76) if present.
        let tx_data = if !tx_bytes.is_empty()
            && tx_bytes[0] == tempo_alloy::primitives::transaction::TEMPO_TX_TYPE_ID
        {
            &tx_bytes[1..]
        } else {
            tx_bytes
        };

        let signed =
            tempo_alloy::primitives::AASigned::rlp_decode(&mut &tx_data[..]).map_err(|e| {
                VerificationError::invalid_payload(format!(
                    "failed to decode {action} transaction: {e}"
                ))
            })?;

        let input = signed
            .tx()
            .calls
            .iter()
            .find(|call| {
                let targets_escrow = match &call.to {
                    alloy::primitives::TxKind::Call(addr) => *addr == escrow,
                    _ => false,
                };
                targets_escrow && call.input.len() >= 4 && call.input[..4] == selector
            })
            .map(|call| call.input.clone())
            .ok_or_else(|| {
                VerificationError::invalid_payload(format!(
                    "{action} transaction does not contain an escrow.{action}() call"
                ))
            })?;

        Ok((signed, input))
    }

    /// Handle 'open' action.
    async fn handle_open(
        &self,
        credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
        expected_payee: Address,
        expected_token: Address,
        amount: u128,
    ) -> Result<Receipt, VerificationError> {
        let (
            channel_id_str,
            descriptor,
            settlement_route,
            cumulative_amount_str,
            signature_str,
            _authorized_signer_str,
            transaction_str,
        ) = match payload {
            SessionCredentialPayload::Open {
                channel_id,
                descriptor,
                settlement_route,
                cumulative_amount,
                signature,
                authorized_signer,
                transaction,
                ..
            } => (
                channel_id,
                descriptor.as_ref(),
                settlement_route.as_ref(),
                cumulative_amount,
                signature,
                authorized_signer,
                transaction,
            ),
            _ => unreachable!(),
        };
        let channel_id_str = &normalize_channel_id(channel_id_str);

        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let escrow = self.resolve_escrow(details)?;
        let chain_id = self.resolve_chain_id(details);

        if details.machine_token_enabled == Some(true) {
            let descriptor = descriptor.ok_or_else(|| {
                VerificationError::invalid_payload(
                    "machine-token open credential is missing its channel descriptor",
                )
            })?;
            let route = settlement_route.ok_or_else(|| {
                VerificationError::invalid_payload(
                    "machine-token open credential is missing its settlement route",
                )
            })?;
            let recipient = Self::parse_address(&route.recipient)?;
            let target_token = Self::parse_address(&route.target_token)?;
            let route_salt = route
                .route_salt
                .parse()
                .map_err(|_| VerificationError::invalid_payload("invalid settlement routeSalt"))?;
            let expected_salt =
                crate::protocol::methods::tempo::machine_token::compute_session_salt(
                    recipient,
                    target_token,
                    route_salt,
                );
            if descriptor.salt != expected_salt.to_string()
                || details.settlement_adapter.as_deref() != Some(&route.adapter)
                || details.settlement_recipient.as_deref() != Some(&route.recipient)
                || details.settlement_token.as_deref() != Some(&route.target_token)
            {
                return Err(VerificationError::credential_mismatch(
                    "machine-token settlement route is not bound to the descriptor",
                ));
            }
        }
        let accepted_settlement_route = settlement_route.cloned();

        // Broadcast the client's signed open transaction (approve + escrow.open).
        let tx_bytes: Bytes = transaction_str.parse().map_err(|e| {
            VerificationError::invalid_payload(format!("invalid open transaction hex: {}", e))
        })?;

        // Verify the open transaction's derived channel ID matches the claimed channelId
        let (voucher_signer, open_deposit) = Self::verify_open_channel_id_binding(
            &tx_bytes,
            channel_id_b256,
            escrow,
            chain_id,
            expected_payee,
            expected_token,
        )?;

        // Check the voucher against the transaction before broadcasting it:
        // once the channel is funded, rejecting the credential would leave the
        // deposit in a channel the server never recorded.
        let cumulative_amount = Self::parse_amount(cumulative_amount_str, "cumulativeAmount")?;
        if cumulative_amount > open_deposit {
            return Err(VerificationError::amount_exceeds_deposit(
                "voucher amount exceeds open deposit",
            ));
        }
        if open_deposit < amount {
            return Err(VerificationError::insufficient_balance(
                "open deposit is less than the session amount",
            ));
        }
        let sig_bytes = Self::parse_signature(signature_str)?;
        if !verify_voucher(
            escrow,
            chain_id,
            channel_id_b256,
            cumulative_amount,
            &sig_bytes,
            voucher_signer,
        ) {
            return Err(VerificationError::invalid_signature(
                "invalid voucher signature",
            ));
        }

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
        if on_chain.deposit.saturating_sub(on_chain.settled) < amount {
            return Err(VerificationError::insufficient_balance(
                "channel available balance is less than the session amount",
            ));
        }

        let authorized_signer = if on_chain.authorized_signer == Address::ZERO {
            on_chain.payer
        } else {
            on_chain.authorized_signer
        };

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

        // The signature was verified against the transaction's signer above;
        // only a channel that reports a different one needs another check.
        if authorized_signer != voucher_signer
            && !verify_voucher(
                escrow,
                chain_id,
                channel_id_b256,
                cumulative_amount,
                &sig_bytes,
                authorized_signer,
            )
        {
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
                                settlement_route: existing
                                    .settlement_route
                                    .or_else(|| accepted_settlement_route.clone()),
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
                            settlement_route: accepted_settlement_route,
                            authorized_signer,
                            deposit: on_chain.deposit,
                            settled_on_chain: on_chain.settled,
                            highest_voucher_amount: cumulative_amount,
                            highest_voucher_signature: Some(sig_bytes),
                            spent: on_chain.settled,
                            units: 0,
                            finalized: false,
                            closing: false,
                            close_requested_at: on_chain.close_requested_at,
                            created_at: now_iso8601(),
                        }))
                    }
                }),
            )
            .await?;

        let state =
            updated.ok_or_else(|| VerificationError::internal("failed to create channel"))?;

        Ok(session_receipt(
            &credential.challenge.id,
            &state,
            Some(open_tx_hash),
        ))
    }

    /// Handle 'topUp' action.
    async fn handle_top_up(
        &self,
        credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
        expected_payee: Address,
        expected_token: Address,
    ) -> Result<Receipt, VerificationError> {
        let (channel_id_str, settlement_route, additional_deposit_str, transaction_str) =
            match payload {
                SessionCredentialPayload::TopUp {
                    channel_id,
                    settlement_route,
                    additional_deposit,
                    transaction,
                    ..
                } => (
                    channel_id,
                    settlement_route.as_ref(),
                    additional_deposit,
                    transaction,
                ),
                _ => unreachable!(),
            };
        let channel_id_str = &normalize_channel_id(channel_id_str);

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
        validate_settlement_route(&channel, details, settlement_route)?;

        if channel.finalized {
            return Err(VerificationError::channel_closed("channel is finalized"));
        }

        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let escrow = self.resolve_escrow(details)?;

        let additional_deposit = Self::parse_amount(additional_deposit_str, "additionalDeposit")?;

        // Broadcast the client's signed topUp transaction.
        let tx_bytes: Bytes = transaction_str.parse().map_err(|e| {
            VerificationError::invalid_payload(format!("invalid topUp transaction hex: {}", e))
        })?;
        Self::verify_top_up_transaction(&tx_bytes, channel_id_b256, escrow, additional_deposit)?;

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
        let top_up_tx_hash = tx_receipt.transaction_hash().to_string();

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
                        deposit: std::cmp::max(on_chain_deposit, state.deposit),
                        settled_on_chain,
                        spent,
                        close_requested_at: on_chain_close_requested_at,
                        ..state
                    }))
                }),
            )
            .await?;

        let state = updated.unwrap_or(channel);
        Ok(session_receipt(
            &credential.challenge.id,
            &state,
            Some(top_up_tx_hash),
        ))
    }

    /// Handle 'voucher' action.
    async fn handle_voucher(
        &self,
        credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
        expected_payee: Address,
        expected_token: Address,
    ) -> Result<Receipt, VerificationError> {
        let (channel_id_str, settlement_route, cumulative_amount_str, signature_str) = match payload
        {
            SessionCredentialPayload::Voucher {
                channel_id,
                settlement_route,
                cumulative_amount,
                signature,
                ..
            } => (
                channel_id,
                settlement_route.as_ref(),
                cumulative_amount,
                signature,
            ),
            _ => unreachable!(),
        };
        let channel_id_str = &normalize_channel_id(channel_id_str);

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
        validate_settlement_route(&channel, details, settlement_route)?;

        if channel.finalized {
            return Err(VerificationError::channel_closed("channel is finalized"));
        }
        if channel.closing {
            return Err(VerificationError::channel_closed("channel is closing"));
        }

        let cumulative_amount = Self::parse_amount(cumulative_amount_str, "cumulativeAmount")?;

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
        let channel_id_b256 = Self::parse_channel_id(channel_id_str)?;
        let on_chain = get_on_chain_channel(&*self.provider, escrow, channel_id_b256).await?;

        if on_chain.payee != expected_payee {
            return Err(VerificationError::credential_mismatch(
                "on-chain channel payee does not match session recipient",
            ));
        }
        if on_chain.token != expected_token {
            return Err(VerificationError::credential_mismatch(
                "on-chain channel token does not match session currency",
            ));
        }

        let on_chain_deposit = on_chain.deposit;
        let on_chain_settled = on_chain.settled;
        let on_chain_close_requested_at = on_chain.close_requested_at;
        let on_chain_finalized = on_chain.finalized;
        let channel_id_owned = channel_id_str.clone();
        let refreshed = self
            .store
            .update_channel(
                &channel_id_owned,
                Box::new(move |current| {
                    let state = current
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                    let settled_on_chain = std::cmp::max(on_chain_settled, state.settled_on_chain);
                    let spent = std::cmp::max(settled_on_chain, state.spent);
                    Ok(Some(ChannelState {
                        deposit: std::cmp::max(on_chain_deposit, state.deposit),
                        settled_on_chain,
                        spent,
                        finalized: state.finalized || on_chain_finalized,
                        close_requested_at: on_chain_close_requested_at,
                        ..state
                    }))
                }),
            )
            .await?
            .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;

        let state = self
            .verify_and_accept_voucher(
                channel_id_str,
                &refreshed,
                cumulative_amount,
                signature_str,
                escrow,
                chain_id,
                min_delta,
                refreshed.deposit,
                refreshed.settled_on_chain,
                refreshed.finalized,
                refreshed.close_requested_at,
            )
            .await?;

        Ok(session_receipt(&credential.challenge.id, &state, None))
    }

    /// Handle 'close' action.
    async fn handle_close(
        &self,
        credential: &PaymentCredential,
        payload: &SessionCredentialPayload,
        details: &TempoSessionMethodDetails,
        expected_payee: Address,
        expected_token: Address,
    ) -> Result<Receipt, VerificationError> {
        let (channel_id_str, descriptor, settlement_route, cumulative_amount_str, signature_str) =
            match payload {
                SessionCredentialPayload::Close {
                    channel_id,
                    descriptor,
                    settlement_route,
                    cumulative_amount,
                    signature,
                    ..
                } => (
                    channel_id,
                    descriptor.as_ref(),
                    settlement_route.as_ref(),
                    cumulative_amount,
                    signature,
                ),
                _ => unreachable!(),
            };
        let channel_id_str = &normalize_channel_id(channel_id_str);

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
        validate_settlement_route(&channel, details, settlement_route)?;

        if channel.finalized {
            return Err(VerificationError::channel_closed(
                "channel is already finalized",
            ));
        }

        let cumulative_amount = Self::parse_amount(cumulative_amount_str, "cumulativeAmount")?;

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

        validate_close_amount(
            cumulative_amount,
            channel.spent,
            on_chain.settled,
            on_chain.deposit,
        )?;

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

        let signer = self.close_signer.as_ref().ok_or_else(|| {
            VerificationError::new(
                "cannot close channel: no close signer configured (see `with_close_signer`)",
            )
        })?;

        let channel_id_for_lock = channel_id_str.clone();
        self.store
            .update_channel(
                &channel_id_for_lock,
                Box::new(move |current| {
                    let state = current
                        .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                    if state.finalized {
                        return Err(VerificationError::channel_closed("channel is finalized"));
                    }
                    if state.closing {
                        return Err(VerificationError::channel_closed("channel is closing"));
                    }
                    // `spent` can still grow until `closing` is set, so the amount
                    // validated against the snapshot above may no longer cover it.
                    if cumulative_amount < state.spent {
                        return Err(VerificationError::new(format!(
                            "close voucher amount must be >= {} (spent)",
                            state.spent,
                        )));
                    }
                    Ok(Some(ChannelState {
                        closing: true,
                        ..state
                    }))
                }),
            )
            .await?;

        // Submit the close transaction on-chain. Failures are collected so the
        // `closing` flag can be reset below.
        let close_tx_result: Result<String, VerificationError> = async {
            use alloy::eips::Encodable2718;
            use alloy::primitives::Bytes;
            use alloy::sol_types::SolCall;
            use tempo_alloy::primitives::transaction::Call;
            use tempo_alloy::primitives::TempoTransaction;

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

            let mut calls = vec![Call {
                to: alloy::primitives::TxKind::Call(escrow),
                value: alloy::primitives::U256::ZERO,
                input: Bytes::from(close_data),
            }];
            if details.machine_token_enabled == Some(true) {
                let descriptor = descriptor.ok_or_else(|| {
                    VerificationError::invalid_payload(
                        "machine-token close credential is missing its channel descriptor",
                    )
                })?;
                let route = settlement_route.ok_or_else(|| {
                    VerificationError::invalid_payload(
                        "machine-token close credential is missing its settlement route",
                    )
                })?;
                calls = machine_session_close_calls(
                    chain_id,
                    escrow,
                    descriptor,
                    route,
                    cumulative_amount,
                    on_chain.deposit,
                    on_chain.settled,
                    &sig_bytes,
                )?;
            }

            let tempo_tx = TempoTransaction {
                chain_id,
                nonce,
                gas_limit: 2_000_000,
                max_fee_per_gas: gas_price,
                max_priority_fee_per_gas: gas_price,
                calls,
                ..Default::default()
            };

            let sig_hash = tempo_tx.signature_hash();
            let signature = signer.sign_hash(&sig_hash).await.map_err(|e| {
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
            if !receipt.status() {
                return Err(VerificationError::transaction_failed(format!(
                    "close transaction reverted (tx: {})",
                    receipt.transaction_hash()
                )));
            }

            Ok(receipt.transaction_hash().to_string())
        }
        .await;

        let close_tx_hash = match close_tx_result {
            Ok(hash) => hash,
            Err(err) => {
                let _ = self
                    .store
                    .update_channel(
                        &channel_id_for_lock,
                        Box::new(|current| {
                            let Some(state) = current else {
                                return Ok(None);
                            };
                            if state.finalized {
                                return Ok(Some(state));
                            }
                            Ok(Some(ChannelState {
                                closing: false,
                                ..state
                            }))
                        }),
                    )
                    .await;
                return Err(err);
            }
        };

        // Finalize in store.
        let channel_id_owned = channel_id_str.clone();
        let finalized = self
            .store
            .update_channel(
                &channel_id_owned,
                Box::new(move |current| {
                    let state = match current {
                        Some(s) => s,
                        None => return Ok(None),
                    };
                    let update_voucher = cumulative_amount > state.highest_voucher_amount;
                    Ok(Some(ChannelState {
                        deposit: on_chain.deposit,
                        highest_voucher_amount: if update_voucher {
                            cumulative_amount
                        } else {
                            state.highest_voucher_amount
                        },
                        highest_voucher_signature: if update_voucher {
                            Some(sig_bytes)
                        } else {
                            state.highest_voucher_signature
                        },
                        finalized: true,
                        closing: false,
                        ..state
                    }))
                }),
            )
            .await?;

        Ok(session_receipt(
            &credential.challenge.id,
            finalized.as_ref().unwrap_or(&channel),
            Some(close_tx_hash),
        ))
    }

    /// Shared logic for verifying an incremental voucher and updating channel state.
    ///
    /// Returns the channel state with the voucher applied.
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
    ) -> Result<ChannelState, VerificationError> {
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

        // If voucher is not higher than what we already have, verify the
        // signature and reject it as a replay. A successful voucher must add new
        // funds for the current metered request.
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
            return Err(VerificationError::delta_too_small(
                "voucher does not add new funds",
            ));
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
                    if cumulative_amount <= state.highest_voucher_amount {
                        return Err(VerificationError::delta_too_small(
                            "voucher does not add new funds",
                        ));
                    }
                    let delta = cumulative_amount - state.highest_voucher_amount;
                    if delta < min_delta {
                        return Err(VerificationError::delta_too_small(format!(
                            "voucher delta {} below minimum {}",
                            delta, min_delta
                        )));
                    }
                    Ok(Some(ChannelState {
                        highest_voucher_amount: cumulative_amount,
                        highest_voucher_signature: Some(sig_bytes),
                        ..state
                    }))
                }),
            )
            .await?;

        updated.ok_or_else(|| VerificationError::channel_not_found("channel not found"))
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
            machine_token_enabled: None,
            settlement_adapter: None,
            settlement_recipient: None,
            settlement_token: None,
            operator: None,
            session_protocol: None,
            session_snapshot: None,
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

            let merchant = request
                .recipient
                .as_deref()
                .ok_or_else(|| {
                    VerificationError::invalid_payload("session challenge missing recipient")
                })
                .and_then(Self::parse_address)?;
            let target_token = Self::parse_address(&request.currency)?;
            let (expected_payee, expected_token) = if details.machine_token_enabled == Some(true) {
                let (_, swapper) =
                    crate::protocol::methods::tempo::machine_token::session_addresses(
                        this.resolve_chain_id(&details),
                    )
                    .ok_or_else(|| {
                        VerificationError::invalid_payload(
                            "machine tokens are unsupported on the session chain",
                        )
                    })?;
                if details.settlement_adapter.as_deref() != Some(&swapper.to_string())
                    || details.settlement_recipient.as_deref() != Some(&merchant.to_string())
                    || details.settlement_token.as_deref() != Some(&target_token.to_string())
                {
                    return Err(VerificationError::credential_mismatch(
                        "machine-token settlement route does not match the session request",
                    ));
                }
                crate::protocol::methods::tempo::machine_token::session_addresses(
                    this.resolve_chain_id(&details),
                )
                .map(|(token, swapper)| (swapper, token))
                .ok_or_else(|| {
                    VerificationError::invalid_payload(
                        "machine tokens are unsupported on the session chain",
                    )
                })?
            } else {
                (merchant, target_token)
            };

            let payload: SessionCredentialPayload = credential.payload_as().map_err(|e| {
                VerificationError::invalid_payload(format!("Expected session payload: {}", e))
            })?;

            match &payload {
                SessionCredentialPayload::Open { .. } => {
                    let amount = request.parse_amount().map_err(|_| {
                        VerificationError::invalid_challenge(format!(
                            "invalid session amount: {}",
                            request.amount
                        ))
                    })?;
                    this.handle_open(
                        &credential,
                        &payload,
                        &details,
                        expected_payee,
                        expected_token,
                        amount,
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

/// Build the receipt of a session action from the channel state it left
/// behind. `tx_hash` is the transaction the action settled on-chain, if any.
fn session_receipt(challenge_id: &str, state: &ChannelState, tx_hash: Option<String>) -> Receipt {
    let mut receipt = SessionReceipt::new(
        now_iso8601(),
        challenge_id,
        &state.channel_id,
        state.highest_voucher_amount.to_string(),
        state.spent.to_string(),
    );
    receipt.units = Some(state.units);
    receipt.tx_hash = tx_hash;
    receipt.to_base_receipt()
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
        self.channels
            .lock()
            .unwrap()
            .get(&normalize_channel_id(channel_id))
            .cloned()
    }
}

impl InMemoryChannelStore {
    /// Insert a channel directly (for test setup).
    pub fn insert(&self, channel_id: &str, state: ChannelState) {
        self.channels
            .lock()
            .unwrap()
            .insert(normalize_channel_id(channel_id), state);
    }
}

impl ChannelStore for InMemoryChannelStore {
    fn get_channel(
        &self,
        channel_id: &str,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    > {
        let result = self.get_channel_sync(channel_id);
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
        let channel_id = normalize_channel_id(channel_id);
        let mut map = self.channels.lock().unwrap();
        let current = map.get(&channel_id).cloned();
        let result = updater(current);
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
            .entry(normalize_channel_id(channel_id))
            .or_insert_with(|| Arc::new(tokio::sync::Notify::new()))
            .clone();
        Box::pin(async move {
            notify.notified().await;
        })
    }
}

#[cfg(test)]
mod tests;
