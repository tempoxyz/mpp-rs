//! Shared client-side channel operations for Tempo session payments.
//!
//! Provides low-level helpers for escrow resolution, channel ID computation,
//! voucher/close/open payload construction, channel recovery from on-chain state,
//! and credential serialization.
//!
//! Ported from the TypeScript SDK's `ChannelOps.ts`.

use alloy::consensus::SignableTransaction;
use alloy::primitives::{keccak256, Address, Bytes, TxKind, Uint, B256, U256};
use alloy::providers::Provider;
use alloy::signers::Signer;
use alloy::sol_types::{SolCall, SolValue};
use tempo_alloy::contracts::precompiles::{ITIP20ChannelReserve, TIP20_CHANNEL_RESERVE_ADDRESS};
use tempo_alloy::TempoNetwork;
use tempo_primitives::transaction::{Call, TempoTransaction};

use crate::client::tempo::charge::tx_builder::{build_tempo_tx, TempoTxOptions};
use crate::error::{MppError, ResultExt};
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use crate::protocol::intents::SessionRequest;
use crate::protocol::methods::tempo::precompile_voucher::{
    compute_precompile_channel_id, compute_precompile_channel_id_with_escrow,
    sign_precompile_voucher, sign_precompile_voucher_primitive,
    sign_precompile_voucher_primitive_with_escrow, sign_precompile_voucher_with_escrow,
    PRECOMPILE_MAX_CUMULATIVE_AMOUNT,
};
use crate::protocol::methods::tempo::session::{
    ChannelDescriptor, SessionCredentialPayload, TempoSessionExt,
};
use crate::protocol::methods::tempo::voucher::{compute_channel_id, sign_voucher};
use crate::protocol::methods::tempo::CHAIN_ID;

#[cfg(feature = "tempo")]
const FEE_PAYER_VALID_BEFORE_SECS: u64 = 25;

/// Default escrow contract addresses per chain ID.
pub fn default_escrow_contract(chain_id: u64) -> Option<Address> {
    match chain_id {
        4217 => Some(
            "0x33b901018174DDabE4841042ab76ba85D4e24f25"
                .parse()
                .unwrap(),
        ),
        42431 => Some(
            "0xe1c4d3dce17bc111181ddf716f75bae49e61a336"
                .parse()
                .unwrap(),
        ),
        _ => None,
    }
}

/// Client-side channel entry tracking channel state.
#[derive(Debug, Clone)]
pub struct ChannelEntry {
    /// On-chain channel ID (keccak256 of channel parameters).
    pub channel_id: B256,
    /// Random salt used during channel creation.
    pub salt: B256,
    /// Running cumulative amount of all vouchers issued.
    pub cumulative_amount: u128,
    /// Latest known channel deposit.
    pub deposit: u128,
    /// Full TIP-1034 descriptor. Legacy contract channels do not have one.
    pub descriptor: Option<ChannelDescriptor>,
    /// Escrow contract address.
    pub escrow_contract: Address,
    /// Chain ID where the escrow contract is deployed.
    pub chain_id: u64,
    /// Whether the channel has been opened on-chain.
    pub opened: bool,
}

/// Resolve chain ID from a session challenge's methodDetails.
pub fn resolve_chain_id(challenge: &PaymentChallenge) -> u64 {
    let session: Result<SessionRequest, _> = challenge.request.decode();
    session.ok().and_then(|r| r.chain_id()).unwrap_or(CHAIN_ID)
}

/// Resolve escrow contract address from an override, challenge hints, or defaults.
pub fn resolve_escrow(
    challenge: &PaymentChallenge,
    chain_id: u64,
    escrow_override: Option<Address>,
) -> Result<Address, MppError> {
    // Match MPPx: an explicit client override wins over server hints.
    if let Some(addr) = escrow_override {
        return Ok(addr);
    }

    if let Ok(req) = challenge.request.decode::<SessionRequest>() {
        if let Some(details) = req.method_details.as_ref() {
            for key in ["escrowContract", "escrow"] {
                if let Some(addr) = details
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .and_then(|value| value.parse::<Address>().ok())
                {
                    return Ok(addr);
                }
            }
        }
        if req.is_tip1034_session() {
            return Ok(TIP20_CHANNEL_RESERVE_ADDRESS);
        }
    }

    // Legacy sessions retain their chain-specific escrow fallback.
    default_escrow_contract(chain_id).ok_or_else(|| {
        MppError::InvalidConfig(
            "No escrowContract available. Provide it in parameters or ensure the server challenge includes it.".to_string(),
        )
    })
}

/// Build a `PaymentCredential` from a challenge and session payload.
pub fn build_credential(
    challenge: &PaymentChallenge,
    payload: SessionCredentialPayload,
    chain_id: u64,
    signer_address: Address,
) -> PaymentCredential {
    let echo = challenge.to_echo();
    let source = PaymentCredential::evm_did(chain_id, &signer_address.to_string());
    PaymentCredential::with_source(echo, source, payload)
}

/// Create a voucher payload by signing a voucher.
pub async fn create_voucher_payload(
    signer: &impl Signer,
    channel_id: B256,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let sig = sign_voucher(
        signer,
        channel_id,
        cumulative_amount,
        escrow_contract,
        chain_id,
    )
    .await?;

    Ok(SessionCredentialPayload::Voucher {
        channel_id: channel_id.to_string(),
        descriptor: None,
        cumulative_amount: cumulative_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&sig),
    })
}

/// Voucher payload for TIP-1034 precompile escrow (EIP-712 domain pinned to
/// `TIP20_CHANNEL_RESERVE_ADDRESS`).
#[cfg(feature = "tempo")]
pub async fn create_precompile_voucher_payload(
    signer: &impl Signer,
    channel_id: B256,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let sig = sign_precompile_voucher(signer, channel_id, cumulative_amount, chain_id).await?;

    Ok(SessionCredentialPayload::Voucher {
        channel_id: channel_id.to_string(),
        descriptor: None,
        cumulative_amount: cumulative_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&sig),
    })
}

/// Native primitive-signature version of [`create_precompile_voucher_payload`].
#[cfg(feature = "tempo")]
pub async fn create_precompile_voucher_payload_primitive(
    signer: &impl Signer<tempo_primitives::transaction::PrimitiveSignature>,
    channel_id: B256,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let signature =
        sign_precompile_voucher_primitive(signer, channel_id, cumulative_amount, chain_id).await?;
    Ok(SessionCredentialPayload::Voucher {
        channel_id: channel_id.to_string(),
        descriptor: None,
        cumulative_amount: cumulative_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&signature),
    })
}

/// Voucher payload for TIP-1034 with the descriptor required for recovery.
#[cfg(feature = "tempo")]
pub async fn create_precompile_voucher_payload_with_descriptor(
    signer: &impl Signer,
    descriptor: ChannelDescriptor,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    create_precompile_voucher_payload_with_descriptor_and_escrow(
        signer,
        descriptor,
        cumulative_amount,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )
    .await
}

/// Native primitive-signature voucher payload with the descriptor required for recovery.
#[cfg(feature = "tempo")]
pub async fn create_precompile_voucher_payload_with_descriptor_primitive(
    signer: &impl Signer<tempo_primitives::transaction::PrimitiveSignature>,
    descriptor: ChannelDescriptor,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let channel_id = compute_precompile_channel_id_from_descriptor_with_escrow(
        &descriptor,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )?;
    let signature = sign_precompile_voucher_primitive_with_escrow(
        signer,
        channel_id,
        cumulative_amount,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )
    .await?;

    Ok(SessionCredentialPayload::Voucher {
        channel_id: channel_id.to_string(),
        descriptor: Some(descriptor),
        cumulative_amount: cumulative_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&signature),
    })
}

/// Voucher payload for TIP-1034 with an explicit escrow/precompile address.
#[cfg(feature = "tempo")]
pub async fn create_precompile_voucher_payload_with_descriptor_and_escrow(
    signer: &impl Signer,
    descriptor: ChannelDescriptor,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let channel_id = compute_precompile_channel_id_from_descriptor_with_escrow(
        &descriptor,
        escrow_contract,
        chain_id,
    )?;
    let sig = sign_precompile_voucher_with_escrow(
        signer,
        channel_id,
        cumulative_amount,
        escrow_contract,
        chain_id,
    )
    .await?;

    Ok(SessionCredentialPayload::Voucher {
        channel_id: channel_id.to_string(),
        descriptor: Some(descriptor),
        cumulative_amount: cumulative_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&sig),
    })
}

/// Create a close payload by signing a voucher with close action.
pub async fn create_close_payload(
    signer: &impl Signer,
    channel_id: B256,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let sig = sign_voucher(
        signer,
        channel_id,
        cumulative_amount,
        escrow_contract,
        chain_id,
    )
    .await?;

    Ok(SessionCredentialPayload::Close {
        channel_id: channel_id.to_string(),
        descriptor: None,
        cumulative_amount: cumulative_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&sig),
    })
}

/// Close payload for TIP-1034 precompile escrow.
#[cfg(feature = "tempo")]
pub async fn create_precompile_close_payload(
    signer: &impl Signer,
    channel_id: B256,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let sig = sign_precompile_voucher(signer, channel_id, cumulative_amount, chain_id).await?;

    Ok(SessionCredentialPayload::Close {
        channel_id: channel_id.to_string(),
        descriptor: None,
        cumulative_amount: cumulative_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&sig),
    })
}

/// Native primitive-signature version of [`create_precompile_close_payload`].
#[cfg(feature = "tempo")]
pub async fn create_precompile_close_payload_primitive(
    signer: &impl Signer<tempo_primitives::transaction::PrimitiveSignature>,
    channel_id: B256,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let signature =
        sign_precompile_voucher_primitive(signer, channel_id, cumulative_amount, chain_id).await?;
    Ok(SessionCredentialPayload::Close {
        channel_id: channel_id.to_string(),
        descriptor: None,
        cumulative_amount: cumulative_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&signature),
    })
}

/// Close payload for TIP-1034 with the descriptor required for recovery.
#[cfg(feature = "tempo")]
pub async fn create_precompile_close_payload_with_descriptor(
    signer: &impl Signer,
    channel_id: B256,
    descriptor: ChannelDescriptor,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    create_precompile_close_payload_with_descriptor_and_escrow(
        signer,
        channel_id,
        descriptor,
        cumulative_amount,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )
    .await
}

/// Native primitive-signature close payload with the descriptor required for recovery.
#[cfg(feature = "tempo")]
pub async fn create_precompile_close_payload_with_descriptor_primitive(
    signer: &impl Signer<tempo_primitives::transaction::PrimitiveSignature>,
    channel_id: B256,
    descriptor: ChannelDescriptor,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let expected_channel_id = compute_precompile_channel_id_from_descriptor_with_escrow(
        &descriptor,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )?;
    if expected_channel_id != channel_id {
        return Err(MppError::InvalidConfig(
            "TIP-1034 close descriptor does not match channel_id".to_string(),
        ));
    }

    let signature = sign_precompile_voucher_primitive_with_escrow(
        signer,
        channel_id,
        cumulative_amount,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )
    .await?;

    Ok(SessionCredentialPayload::Close {
        channel_id: channel_id.to_string(),
        descriptor: Some(descriptor),
        cumulative_amount: cumulative_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&signature),
    })
}

/// Close payload for TIP-1034 with a descriptor and explicit escrow/precompile verifier.
#[cfg(feature = "tempo")]
pub async fn create_precompile_close_payload_with_descriptor_and_escrow(
    signer: &impl Signer,
    channel_id: B256,
    descriptor: ChannelDescriptor,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let expected_channel_id = compute_precompile_channel_id_from_descriptor_with_escrow(
        &descriptor,
        escrow_contract,
        chain_id,
    )?;
    if expected_channel_id != channel_id {
        return Err(MppError::InvalidConfig(
            "TIP-1034 close descriptor does not match channel_id".to_string(),
        ));
    }

    let sig = sign_precompile_voucher_with_escrow(
        signer,
        channel_id,
        cumulative_amount,
        escrow_contract,
        chain_id,
    )
    .await?;

    Ok(SessionCredentialPayload::Close {
        channel_id: channel_id.to_string(),
        descriptor: Some(descriptor),
        cumulative_amount: cumulative_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&sig),
    })
}

/// Options for creating an open payload.
pub struct OpenPayloadOptions {
    pub authorized_signer: Option<Address>,
    pub escrow_contract: Address,
    pub payee: Address,
    pub currency: Address,
    pub deposit: u128,
    pub initial_amount: u128,
    pub chain_id: u64,
    pub fee_payer: bool,
}

/// Create an open payload: builds approve+open multicall transaction, signs it,
/// and signs the initial voucher.
///
/// Builds a Tempo transaction (type 0x76) containing:
/// 1. `TIP20.approve(escrow, deposit)`
/// 2. `escrow.open(payee, token, deposit, salt, authorizedSigner)`
///
/// Then signs an initial voucher for `initial_amount`.
pub async fn create_open_payload<P, S>(
    provider: &P,
    signer: &S,
    signing_mode: Option<&crate::client::tempo::signing::TempoSigningMode>,
    payer: Address,
    options: OpenPayloadOptions,
) -> Result<(ChannelEntry, SessionCredentialPayload), MppError>
where
    P: Provider<TempoNetwork>,
    S: Signer + Clone,
{
    use alloy::sol;
    use tempo_primitives::transaction::Call;

    let default_mode = crate::client::tempo::signing::TempoSigningMode::Direct;
    let signing_mode = signing_mode.unwrap_or(&default_mode);
    let authorized_signer = options.authorized_signer.unwrap_or(payer);

    // Generate random salt
    let salt = B256::random();

    // Compute channel ID
    let channel_id = compute_channel_id(
        payer,
        options.payee,
        options.currency,
        salt,
        authorized_signer,
        options.escrow_contract,
        options.chain_id,
    );

    // Build approve calldata
    use tempo_alloy::contracts::precompiles::ITIP20;

    sol! {
        interface IEscrow {
            function open(
                address payee,
                address token,
                uint128 deposit,
                bytes32 salt,
                address authorizedSigner
            ) external;
        }
    }

    let approve_data =
        ITIP20::approveCall::new((options.escrow_contract, U256::from(options.deposit)))
            .abi_encode();

    let open_data = IEscrow::openCall::new((
        options.payee,
        options.currency,
        options.deposit,
        salt,
        authorized_signer,
    ))
    .abi_encode();

    // Build Tempo multicall transaction
    let calls = vec![
        Call {
            to: TxKind::Call(options.currency),
            value: U256::ZERO,
            input: Bytes::from(approve_data),
        },
        Call {
            to: TxKind::Call(options.escrow_contract),
            value: U256::ZERO,
            input: Bytes::from(open_data),
        },
    ];

    let nonce = provider
        .get_transaction_count(payer)
        .await
        .mpp_http("failed to get nonce")?;

    let gas_price = provider
        .get_gas_price()
        .await
        .mpp_http("failed to get gas price")?;

    let tempo_tx = build_tempo_tx(TempoTxOptions {
        calls,
        chain_id: options.chain_id,
        fee_token: options.currency,
        nonce,
        nonce_key: U256::ZERO,
        gas_limit: 2_000_000,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price,
        fee_payer: options.fee_payer,
        valid_before: None,
        key_authorization: signing_mode.key_authorization().cloned(),
    });

    let tx_bytes =
        crate::client::tempo::signing::sign_and_encode_async(tempo_tx, signer, signing_mode)
            .await?;
    let signed_tx_hex = alloy::hex::encode_prefixed(&tx_bytes);

    // Sign the initial voucher
    let voucher_sig = sign_voucher(
        signer,
        channel_id,
        options.initial_amount,
        options.escrow_contract,
        options.chain_id,
    )
    .await?;

    let entry = ChannelEntry {
        channel_id,
        salt,
        cumulative_amount: options.initial_amount,
        deposit: options.deposit,
        descriptor: None,
        escrow_contract: options.escrow_contract,
        chain_id: options.chain_id,
        opened: true,
    };

    let payload = SessionCredentialPayload::Open {
        payload_type: "transaction".to_string(),
        channel_id: channel_id.to_string(),
        transaction: signed_tx_hex,
        descriptor: None,
        authorized_signer: Some(authorized_signer.to_string()),
        cumulative_amount: options.initial_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&voucher_sig),
    };

    Ok((entry, payload))
}

/// Whether `addr` is the T5 TIP-1034 reserve channel precompile.
pub fn is_precompile_escrow(addr: Address) -> bool {
    addr == TIP20_CHANNEL_RESERVE_ADDRESS
}

/// Compute the precompile's `expiringNonceHash` =
/// `keccak256(encode_for_signing(unsigned_tx) || sender)`. Must be called
/// before signing; mutating `unsigned_tx` after invalidates the channel id.
#[cfg(feature = "tempo")]
pub fn compute_expiring_nonce_hash(unsigned_tx: &TempoTransaction, sender: Address) -> B256 {
    let mut buf = Vec::with_capacity(unsigned_tx.payload_len_for_signature() + 20);
    unsigned_tx.encode_for_signing(&mut buf);
    buf.extend_from_slice(sender.as_slice());
    keccak256(buf)
}

/// Compute `expiringNonceHash` for a fee-sponsored TIP-1034 channel open.
///
/// The sender signature is verified against the submitted transaction, but
/// TIP-1034 derives channel identity from the fee-payer hash preimage that
/// marks the transaction as sponsorable.
#[cfg(feature = "tempo")]
pub fn compute_fee_payer_expiring_nonce_hash(
    unsigned_tx: &TempoTransaction,
    sender: Address,
) -> B256 {
    let mut tx = unsigned_tx.clone();
    tx.fee_payer_signature = Some(alloy::primitives::Signature::new(
        U256::ZERO,
        U256::ZERO,
        false,
    ));
    compute_expiring_nonce_hash(&tx, sender)
}

/// Build the wire descriptor for a TIP-1034 precompile channel.
#[cfg(feature = "tempo")]
#[allow(clippy::too_many_arguments)]
pub fn build_channel_descriptor(
    payer: Address,
    payee: Address,
    operator: Address,
    token: Address,
    salt: B256,
    authorized_signer: Address,
    expiring_nonce_hash: B256,
) -> ChannelDescriptor {
    ChannelDescriptor {
        payer: payer.to_string(),
        payee: payee.to_string(),
        operator: operator.to_string(),
        token: token.to_string(),
        salt: salt.to_string(),
        authorized_signer: authorized_signer.to_string(),
        expiring_nonce_hash: expiring_nonce_hash.to_string(),
    }
}

#[cfg(feature = "tempo")]
fn parse_precompile_amount(value: u128, label: &str) -> Result<Uint<96, 2>, MppError> {
    if value > PRECOMPILE_MAX_CUMULATIVE_AMOUNT {
        return Err(MppError::InvalidConfig(format!(
            "{label} {value} exceeds precompile uint96 max"
        )));
    }
    Ok(Uint::<96, 2>::from(value))
}

#[cfg(feature = "tempo")]
fn precompile_open_tx_nonce_fields(fee_payer: bool, nonce: u64) -> (u64, U256, Option<u64>) {
    if !fee_payer {
        return (nonce, U256::ZERO, None);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    (
        0,
        U256::MAX,
        Some(now.saturating_add(FEE_PAYER_VALID_BEFORE_SECS)),
    )
}

/// Returns a random past timestamp for a sponsored repeatable transaction.
///
/// MPPx adds `validAfter` to sponsored top-ups so two otherwise identical
/// top-up calls do not serialize to the same transaction.
#[cfg(feature = "tempo")]
fn random_past_valid_after() -> Option<std::num::NonZeroU64> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let latest = now.saturating_sub(60);
    if latest == 0 {
        return None;
    }

    let random = B256::random();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&random[..8]);
    let timestamp = (u64::from_be_bytes(prefix) % latest).max(1);
    std::num::NonZeroU64::new(timestamp)
}

#[cfg(feature = "tempo")]
fn add_sponsored_top_up_entropy(transaction: &mut TempoTransaction, fee_payer: bool) {
    if fee_payer {
        transaction.valid_after = random_past_valid_after();
    }
}

/// Convert a JSON wire descriptor into the generated precompile ABI tuple.
#[cfg(feature = "tempo")]
pub fn precompile_descriptor_from_wire(
    descriptor: &ChannelDescriptor,
) -> Result<ITIP20ChannelReserve::ChannelDescriptor, MppError> {
    Ok(ITIP20ChannelReserve::ChannelDescriptor {
        payer: descriptor.payer.parse().map_err(|e| {
            MppError::InvalidConfig(format!("invalid TIP-1034 descriptor payer: {e}"))
        })?,
        payee: descriptor.payee.parse().map_err(|e| {
            MppError::InvalidConfig(format!("invalid TIP-1034 descriptor payee: {e}"))
        })?,
        operator: descriptor.operator.parse().map_err(|e| {
            MppError::InvalidConfig(format!("invalid TIP-1034 descriptor operator: {e}"))
        })?,
        token: descriptor.token.parse().map_err(|e| {
            MppError::InvalidConfig(format!("invalid TIP-1034 descriptor token: {e}"))
        })?,
        salt: descriptor.salt.parse().map_err(|e| {
            MppError::InvalidConfig(format!("invalid TIP-1034 descriptor salt: {e}"))
        })?,
        authorizedSigner: descriptor.authorized_signer.parse().map_err(|e| {
            MppError::InvalidConfig(format!("invalid TIP-1034 descriptor authorizedSigner: {e}"))
        })?,
        expiringNonceHash: descriptor.expiring_nonce_hash.parse().map_err(|e| {
            MppError::InvalidConfig(format!(
                "invalid TIP-1034 descriptor expiringNonceHash: {e}"
            ))
        })?,
    })
}

/// Compute a TIP-1034 channel ID from a wire descriptor.
#[cfg(feature = "tempo")]
pub fn compute_precompile_channel_id_from_descriptor(
    descriptor: &ChannelDescriptor,
    chain_id: u64,
) -> Result<B256, MppError> {
    compute_precompile_channel_id_from_descriptor_with_escrow(
        descriptor,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )
}

/// Compute a TIP-1034 channel ID from a wire descriptor and explicit escrow.
#[cfg(feature = "tempo")]
pub fn compute_precompile_channel_id_from_descriptor_with_escrow(
    descriptor: &ChannelDescriptor,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<B256, MppError> {
    let descriptor = precompile_descriptor_from_wire(descriptor)?;
    Ok(compute_precompile_channel_id_with_escrow(
        descriptor.payer,
        descriptor.payee,
        descriptor.operator,
        descriptor.token,
        descriptor.salt,
        descriptor.authorizedSigner,
        descriptor.expiringNonceHash,
        escrow_contract,
        chain_id,
    ))
}

/// ABI-encode `open(payee, operator, token, uint96 deposit, salt, authorizedSigner)`.
#[cfg(feature = "tempo")]
pub fn encode_precompile_open_call(
    payee: Address,
    operator: Address,
    token: Address,
    deposit: u128,
    salt: B256,
    authorized_signer: Address,
) -> Result<Bytes, MppError> {
    Ok(Bytes::from(
        ITIP20ChannelReserve::openCall::new((
            payee,
            operator,
            token,
            parse_precompile_amount(deposit, "deposit")?,
            salt,
            authorized_signer,
        ))
        .abi_encode(),
    ))
}

/// ABI-encode `topUp(descriptor, uint96 additionalDeposit)`.
#[cfg(feature = "tempo")]
pub fn encode_precompile_top_up_call(
    descriptor: &ChannelDescriptor,
    additional_deposit: u128,
) -> Result<Bytes, MppError> {
    Ok(Bytes::from(
        ITIP20ChannelReserve::topUpCall::new((
            precompile_descriptor_from_wire(descriptor)?,
            parse_precompile_amount(additional_deposit, "additional_deposit")?,
        ))
        .abi_encode(),
    ))
}

/// ABI-encode `getChannel(descriptor)`.
#[cfg(feature = "tempo")]
pub fn encode_precompile_get_channel_call(
    descriptor: &ChannelDescriptor,
) -> Result<Bytes, MppError> {
    Ok(Bytes::from(
        ITIP20ChannelReserve::getChannelCall::new((precompile_descriptor_from_wire(descriptor)?,))
            .abi_encode(),
    ))
}

/// ABI-encode `getChannelState(channelId)`.
#[cfg(feature = "tempo")]
pub fn encode_precompile_get_channel_state_call(channel_id: B256) -> Bytes {
    Bytes::from(ITIP20ChannelReserve::getChannelStateCall::new((channel_id,)).abi_encode())
}

/// ABI-encode `requestClose(descriptor)`.
#[cfg(feature = "tempo")]
pub fn encode_precompile_request_close_call(
    descriptor: &ChannelDescriptor,
) -> Result<Bytes, MppError> {
    Ok(Bytes::from(
        ITIP20ChannelReserve::requestCloseCall::new(
            (precompile_descriptor_from_wire(descriptor)?,),
        )
        .abi_encode(),
    ))
}

/// ABI-encode `withdraw(descriptor)`.
#[cfg(feature = "tempo")]
pub fn encode_precompile_withdraw_call(descriptor: &ChannelDescriptor) -> Result<Bytes, MppError> {
    Ok(Bytes::from(
        ITIP20ChannelReserve::withdrawCall::new((precompile_descriptor_from_wire(descriptor)?,))
            .abi_encode(),
    ))
}

/// Build a descriptor-backed TIP-1034 top-up credential payload.
#[cfg(feature = "tempo")]
pub fn create_precompile_top_up_payload(
    channel_id: B256,
    descriptor: ChannelDescriptor,
    transaction: String,
    additional_deposit: u128,
) -> SessionCredentialPayload {
    SessionCredentialPayload::TopUp {
        payload_type: "transaction".to_string(),
        channel_id: channel_id.to_string(),
        transaction,
        descriptor: Some(descriptor),
        additional_deposit: additional_deposit.to_string(),
    }
}

/// Options for [`create_precompile_open_payload`]. Replaces `escrow_contract`
/// (always the precompile) with `operator`. `deposit` and `initial_amount`
/// must fit `uint96`.
pub struct OpenPrecompilePayloadOptions {
    /// Calls executed atomically before the channel open.
    pub prefix_calls: Vec<Call>,
    /// Optional relayer for `settle`/`close`; `Address::ZERO` = payee-only.
    pub operator: Address,
    /// Voucher signer; defaults to `payer` if `None`.
    pub authorized_signer: Option<Address>,
    pub payee: Address,
    pub currency: Address,
    pub deposit: u128,
    pub initial_amount: u128,
    pub chain_id: u64,
    pub fee_payer: bool,
}

/// Options for a descriptor-backed TIP-1034 top-up transaction.
pub struct TopUpPrecompilePayloadOptions<'a> {
    /// Calls executed atomically before the channel top-up.
    pub prefix_calls: Vec<Call>,
    /// Existing channel descriptor.
    pub descriptor: &'a ChannelDescriptor,
    /// Amount added to the existing channel deposit.
    pub additional_deposit: u128,
    /// Tempo chain ID.
    pub chain_id: u64,
    /// Whether the server may sponsor this management transaction.
    pub fee_payer: bool,
}

/// Open payload targeting the TIP-1034 reserve precompile. The escrow open
/// itself needs no approval because the precompile is on the TIP-1035 implicit
/// approvals list; optional prefix calls may acquire the deposit currency.
/// Channel id is derived against the complete unsigned tx's `expiringNonceHash`.
#[cfg(feature = "tempo")]
pub async fn create_precompile_open_payload<P, S>(
    provider: &P,
    signer: &S,
    signing_mode: Option<&crate::client::tempo::signing::TempoSigningMode>,
    payer: Address,
    options: OpenPrecompilePayloadOptions,
) -> Result<(ChannelEntry, SessionCredentialPayload), MppError>
where
    P: Provider<TempoNetwork>,
    S: Clone + Into<crate::client::tempo::signing::TempoPrimitiveSigner>,
{
    if options.deposit > PRECOMPILE_MAX_CUMULATIVE_AMOUNT {
        return Err(MppError::InvalidConfig(format!(
            "deposit {} exceeds precompile uint96 max",
            options.deposit
        )));
    }
    if options.initial_amount > PRECOMPILE_MAX_CUMULATIVE_AMOUNT {
        return Err(MppError::InvalidConfig(format!(
            "initial_amount {} exceeds precompile uint96 max",
            options.initial_amount
        )));
    }

    let default_mode = crate::client::tempo::signing::TempoSigningMode::Direct;
    let signing_mode = signing_mode.unwrap_or(&default_mode);
    let primitive_signer = signer.clone().into();

    let authorized_signer = options.authorized_signer.unwrap_or(payer);
    let salt = B256::random();

    let open_data = ITIP20ChannelReserve::openCall::new((
        options.payee,
        options.operator,
        options.currency,
        Uint::<96, 2>::from(options.deposit),
        salt,
        authorized_signer,
    ))
    .abi_encode();

    let mut calls = options.prefix_calls;
    calls.push(Call {
        to: TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS),
        value: U256::ZERO,
        input: Bytes::from(open_data),
    });

    let nonce = if options.fee_payer {
        0
    } else {
        provider
            .get_transaction_count(payer)
            .await
            .mpp_http("failed to get nonce")?
    };

    let gas_price = provider
        .get_gas_price()
        .await
        .mpp_http("failed to get gas price")?;

    let (nonce, nonce_key, valid_before) =
        precompile_open_tx_nonce_fields(options.fee_payer, nonce);

    let unsigned_tx = build_tempo_tx(TempoTxOptions {
        calls,
        chain_id: options.chain_id,
        fee_token: options.currency,
        nonce,
        nonce_key,
        gas_limit: 2_000_000,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price,
        fee_payer: options.fee_payer,
        valid_before,
        key_authorization: signing_mode.key_authorization().cloned(),
    });
    // Derive id from the unsigned tx before signing; expiringNonceHash binds
    // the signing-payload bytes.
    let expiring_nonce_hash = if options.fee_payer {
        compute_fee_payer_expiring_nonce_hash(&unsigned_tx, payer)
    } else {
        compute_expiring_nonce_hash(&unsigned_tx, payer)
    };
    let descriptor = build_channel_descriptor(
        payer,
        options.payee,
        options.operator,
        options.currency,
        salt,
        authorized_signer,
        expiring_nonce_hash,
    );
    let channel_id = compute_precompile_channel_id(
        payer,
        options.payee,
        options.operator,
        options.currency,
        salt,
        authorized_signer,
        expiring_nonce_hash,
        options.chain_id,
    );

    let tx_bytes = if options.fee_payer {
        crate::client::tempo::signing::sign_and_encode_fee_payer_envelope_primitive_async(
            unsigned_tx,
            &primitive_signer,
            signing_mode,
        )
        .await?
    } else {
        crate::client::tempo::signing::sign_and_encode_primitive_async(
            unsigned_tx,
            &primitive_signer,
            signing_mode,
        )
        .await?
    };
    let signed_tx_hex = alloy::hex::encode_prefixed(&tx_bytes);

    let voucher_sig = sign_precompile_voucher_primitive(
        &primitive_signer,
        channel_id,
        options.initial_amount,
        options.chain_id,
    )
    .await?;

    let entry = ChannelEntry {
        channel_id,
        salt,
        cumulative_amount: options.initial_amount,
        deposit: options.deposit,
        descriptor: Some(descriptor.clone()),
        escrow_contract: TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id: options.chain_id,
        opened: true,
    };

    let payload = SessionCredentialPayload::Open {
        payload_type: "transaction".to_string(),
        channel_id: channel_id.to_string(),
        transaction: signed_tx_hex,
        descriptor: Some(descriptor),
        authorized_signer: Some(authorized_signer.to_string()),
        cumulative_amount: options.initial_amount.to_string(),
        signature: alloy::hex::encode_prefixed(&voucher_sig),
    };

    Ok((entry, payload))
}

/// Prepare and sign a descriptor-backed TIP-1034 top-up transaction.
///
/// This mirrors MPPx's `createTopUpPayload`: the returned transaction is sent
/// to the MPP server as a management credential, and the server broadcasts it
/// before accepting a voucher that requires the additional headroom.
#[cfg(feature = "tempo")]
pub async fn create_precompile_top_up_transaction_payload<P, S>(
    provider: &P,
    signer: &S,
    signing_mode: Option<&crate::client::tempo::signing::TempoSigningMode>,
    payer: Address,
    options: TopUpPrecompilePayloadOptions<'_>,
) -> Result<SessionCredentialPayload, MppError>
where
    P: Provider<TempoNetwork>,
    S: Clone + Into<crate::client::tempo::signing::TempoPrimitiveSigner>,
{
    let additional_deposit =
        parse_precompile_amount(options.additional_deposit, "additional_deposit")?;
    if additional_deposit.is_zero() {
        return Err(MppError::InvalidConfig(
            "top-up amount must be greater than zero".into(),
        ));
    }

    let default_mode = crate::client::tempo::signing::TempoSigningMode::Direct;
    let signing_mode = signing_mode.unwrap_or(&default_mode);
    let primitive_signer = signer.clone().into();
    let descriptor = precompile_descriptor_from_wire(options.descriptor)?;
    let mut calls = options.prefix_calls;
    calls.push(Call {
        to: TxKind::Call(TIP20_CHANNEL_RESERVE_ADDRESS),
        value: U256::ZERO,
        input: Bytes::from(
            ITIP20ChannelReserve::topUpCall::new((descriptor, additional_deposit)).abi_encode(),
        ),
    });
    let nonce = if options.fee_payer {
        0
    } else {
        provider
            .get_transaction_count(payer)
            .await
            .mpp_http("failed to get nonce")?
    };
    let gas_price = provider
        .get_gas_price()
        .await
        .mpp_http("failed to get gas price")?;
    let (nonce, nonce_key, valid_before) =
        precompile_open_tx_nonce_fields(options.fee_payer, nonce);
    let mut unsigned_tx = build_tempo_tx(TempoTxOptions {
        calls,
        chain_id: options.chain_id,
        fee_token: options
            .descriptor
            .token
            .parse()
            .mpp_config("invalid TIP-1034 descriptor token")?,
        nonce,
        nonce_key,
        gas_limit: 2_000_000,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price,
        fee_payer: options.fee_payer,
        valid_before,
        key_authorization: signing_mode.key_authorization().cloned(),
    });
    add_sponsored_top_up_entropy(&mut unsigned_tx, options.fee_payer);
    let tx_bytes = if options.fee_payer {
        crate::client::tempo::signing::sign_and_encode_fee_payer_envelope_primitive_async(
            unsigned_tx,
            &primitive_signer,
            signing_mode,
        )
        .await?
    } else {
        crate::client::tempo::signing::sign_and_encode_primitive_async(
            unsigned_tx,
            &primitive_signer,
            signing_mode,
        )
        .await?
    };
    let channel_id =
        compute_precompile_channel_id_from_descriptor(options.descriptor, options.chain_id)?;
    Ok(create_precompile_top_up_payload(
        channel_id,
        options.descriptor.clone(),
        alloy::hex::encode_prefixed(&tx_bytes),
        options.additional_deposit,
    ))
}

/// On-chain channel state returned by the escrow contract.
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

/// Read on-chain channel state from the escrow contract.
pub async fn get_on_chain_channel<P: Provider<TempoNetwork>>(
    provider: &P,
    escrow_contract: Address,
    channel_id: B256,
) -> Result<OnChainChannel, MppError> {
    use alloy::sol;

    sol! {
        interface IEscrowRead {
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

    let call_data = IEscrowRead::getChannelCall::new((channel_id,)).abi_encode();

    use tempo_alloy::rpc::TempoTransactionRequest;

    let mut tx_req = TempoTransactionRequest::default();
    tx_req.inner =
        tx_req
            .inner
            .to(escrow_contract)
            .input(alloy::rpc::types::TransactionInput::new(Bytes::from(
                call_data,
            )));

    let result = provider
        .call(tx_req)
        .await
        .mpp_http("failed to read channel")?;

    let decoded =
        <(bool, u64, Address, Address, Address, Address, u128, u128)>::abi_decode(&result)
            .mpp_http("failed to decode channel data")?;

    Ok(OnChainChannel {
        finalized: decoded.0,
        close_requested_at: decoded.1,
        payer: decoded.2,
        payee: decoded.3,
        token: decoded.4,
        authorized_signer: decoded.5,
        deposit: decoded.6,
        settled: decoded.7,
    })
}

/// Attempt to recover an existing on-chain channel.
///
/// If the channel has a positive deposit, is not finalized, is not pending
/// close, matches the expected payer, payee, token, and authorized signer,
/// returns a [`ChannelEntry`] with `cumulative_amount` set to the on-chain
/// settled amount (the safe starting point for new vouchers).
///
/// Returns `None` if the channel doesn't exist, has zero deposit,
/// is already finalized, is pending close, or doesn't match the expected
/// payer/payee/token/authorized signer.
#[allow(clippy::too_many_arguments)]
pub async fn try_recover_channel<P: Provider<TempoNetwork>>(
    provider: &P,
    escrow_contract: Address,
    channel_id: B256,
    chain_id: u64,
    expected_payer: Address,
    expected_payee: Address,
    expected_token: Address,
    expected_authorized_signer: Address,
) -> Option<ChannelEntry> {
    let on_chain = get_on_chain_channel(provider, escrow_contract, channel_id)
        .await
        .ok()?;

    let actual_authorized_signer = if on_chain.authorized_signer == Address::ZERO {
        on_chain.payer
    } else {
        on_chain.authorized_signer
    };

    if on_chain.deposit > 0
        && !on_chain.finalized
        && on_chain.close_requested_at == 0
        && on_chain.payer == expected_payer
        && on_chain.payee == expected_payee
        && on_chain.token == expected_token
        && actual_authorized_signer == expected_authorized_signer
    {
        Some(ChannelEntry {
            channel_id,
            salt: B256::ZERO,
            cumulative_amount: on_chain.settled,
            deposit: on_chain.deposit,
            descriptor: None,
            escrow_contract,
            chain_id,
            opened: true,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_escrow_contract() {
        assert!(default_escrow_contract(4217).is_some());
        assert!(default_escrow_contract(42431).is_some());
        assert!(default_escrow_contract(1).is_none());
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_is_precompile_escrow() {
        use tempo_alloy::contracts::precompiles::TIP20_CHANNEL_RESERVE_ADDRESS;
        assert!(is_precompile_escrow(TIP20_CHANNEL_RESERVE_ADDRESS));
        assert!(is_precompile_escrow(
            "0x4D50500000000000000000000000000000000000"
                .parse()
                .unwrap()
        ));
        assert!(!is_precompile_escrow(
            default_escrow_contract(4217).unwrap()
        ));
        assert!(!is_precompile_escrow(
            default_escrow_contract(42431).unwrap()
        ));
        assert!(!is_precompile_escrow(Address::ZERO));
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_compute_expiring_nonce_hash_matches_on_chain_formula() {
        // Mirrors tempo `unique_tx_identifier_from_signable`
        // (crates/primitives/src/transaction/mod.rs L37-L45).
        use alloy::consensus::SignableTransaction;
        use alloy::primitives::keccak256;
        use tempo_primitives::transaction::TempoTransaction;

        let payer = Address::repeat_byte(0xAA);
        let calls = vec![tempo_primitives::transaction::Call {
            to: TxKind::Call(Address::repeat_byte(0x11)),
            value: U256::ZERO,
            input: alloy::primitives::Bytes::new(),
        }];

        let tx: TempoTransaction = build_tempo_tx(TempoTxOptions {
            calls,
            chain_id: 4217,
            fee_token: Address::repeat_byte(0x22),
            nonce: 7,
            nonce_key: U256::ZERO,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_payer: false,
            valid_before: None,
            key_authorization: None,
        });

        let got = compute_expiring_nonce_hash(&tx, payer);

        let mut expected_buf = Vec::with_capacity(tx.payload_len_for_signature() + 20);
        tx.encode_for_signing(&mut expected_buf);
        expected_buf.extend_from_slice(payer.as_slice());
        assert_eq!(got, keccak256(expected_buf));

        let other_sender = Address::repeat_byte(0xBB);
        assert_ne!(compute_expiring_nonce_hash(&tx, other_sender), got);
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_precompile_open_tx_nonce_fields_for_fee_payer() {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (nonce, nonce_key, valid_before) = precompile_open_tx_nonce_fields(true, 7);

        assert_eq!(nonce, 0);
        assert_eq!(nonce_key, U256::MAX);
        let valid_before = valid_before.expect("fee payer open sets valid_before");
        assert!(valid_before >= before);
        assert!(valid_before <= before + FEE_PAYER_VALID_BEFORE_SECS + 1);
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_precompile_open_tx_nonce_fields_for_direct_payer() {
        let (nonce, nonce_key, valid_before) = precompile_open_tx_nonce_fields(false, 7);

        assert_eq!(nonce, 7);
        assert_eq!(nonce_key, U256::ZERO);
        assert!(valid_before.is_none());
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn sponsored_repeatable_transactions_get_past_valid_after_entropy() {
        let mut transaction = build_tempo_tx(TempoTxOptions {
            calls: vec![],
            chain_id: 4217,
            fee_token: Address::repeat_byte(0x22),
            nonce: 0,
            nonce_key: U256::MAX,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_payer: true,
            valid_before: None,
            key_authorization: None,
        });
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        add_sponsored_top_up_entropy(&mut transaction, true);
        let valid_after = transaction
            .valid_after
            .expect("sponsored top-ups get transaction entropy");

        assert!(valid_after.get() <= now.saturating_sub(60));
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_create_precompile_open_payload_rejects_uint96_overflow() {
        use crate::protocol::methods::tempo::precompile_voucher::PRECOMPILE_MAX_CUMULATIVE_AMOUNT;
        use alloy::providers::ProviderBuilder;
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let payer = signer.address();
        // Validation runs before any network IO.
        let provider = ProviderBuilder::<_, _, TempoNetwork>::default()
            .connect_http("http://localhost:1".parse().unwrap());

        let opts = OpenPrecompilePayloadOptions {
            prefix_calls: Vec::new(),
            operator: Address::ZERO,
            authorized_signer: None,
            payee: Address::repeat_byte(0x11),
            currency: Address::repeat_byte(0x22),
            deposit: PRECOMPILE_MAX_CUMULATIVE_AMOUNT + 1,
            initial_amount: 1,
            chain_id: 4217,
            fee_payer: false,
        };
        let err = create_precompile_open_payload(&provider, &signer, None, payer, opts)
            .await
            .expect_err("deposit > uint96 must be rejected");
        assert!(matches!(err, MppError::InvalidConfig(_)));
    }

    #[test]
    fn test_channel_entry_clone() {
        let entry = ChannelEntry {
            channel_id: B256::ZERO,
            salt: B256::ZERO,
            cumulative_amount: 1000,
            deposit: 0,
            descriptor: None,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened: true,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.cumulative_amount, 1000);
        assert!(cloned.opened);
    }

    #[test]
    fn test_resolve_escrow_from_override() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let override_addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let result = resolve_escrow(&challenge, 42431, Some(override_addr)).unwrap();
        assert_eq!(result, override_addr);
    }

    #[test]
    fn test_resolve_escrow_from_default() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let result = resolve_escrow(&challenge, 42431, None).unwrap();
        assert_eq!(result, default_escrow_contract(42431).unwrap());
    }

    #[test]
    fn test_resolve_escrow_from_challenge() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let escrow_addr = "0x2222222222222222222222222222222222222222";
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123",
                "methodDetails": {
                    "escrowContract": escrow_addr
                }
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let result = resolve_escrow(&challenge, 42431, None).unwrap();
        assert_eq!(result, escrow_addr.parse::<Address>().unwrap());
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn tip1034_challenge_without_escrow_uses_canonical_precompile() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "currency": Address::repeat_byte(0x44).to_string(),
                "methodDetails": { "sessionProtocol": "v2" }
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        assert_eq!(
            resolve_escrow(&challenge, 4217, None).unwrap(),
            TIP20_CHANNEL_RESERVE_ADDRESS
        );
    }

    #[test]
    fn test_resolve_escrow_accepts_legacy_alias_hint() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let hinted = Address::repeat_byte(0x22);
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "currency": Address::repeat_byte(0x44).to_string(),
                "methodDetails": { "escrow": hinted.to_string() }
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        assert_eq!(resolve_escrow(&challenge, 4217, None).unwrap(), hinted);
    }

    #[test]
    fn test_resolve_escrow_no_source() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let result = resolve_escrow(&challenge, 9999, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_credential() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test-id".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let payload = SessionCredentialPayload::Voucher {
            channel_id: "0xabc".to_string(),
            descriptor: None,
            cumulative_amount: "5000".to_string(),
            signature: "0xdef".to_string(),
        };

        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let cred = build_credential(&challenge, payload, 42431, addr);
        assert!(cred.source.is_some());
        assert!(cred.source.unwrap().contains("42431"));
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_create_voucher_payload() {
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xAB);
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let payload = create_voucher_payload(&signer, channel_id, 1000, escrow, 42431)
            .await
            .unwrap();

        match payload {
            SessionCredentialPayload::Voucher {
                channel_id: cid,
                descriptor,
                cumulative_amount,
                signature,
            } => {
                assert!(cid.starts_with("0x"));
                assert!(descriptor.is_none());
                assert_eq!(cumulative_amount, "1000");
                assert!(signature.starts_with("0x"));
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_create_close_payload() {
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xCD);
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let payload = create_close_payload(&signer, channel_id, 2000, escrow, 42431)
            .await
            .unwrap();

        match payload {
            SessionCredentialPayload::Close {
                channel_id: cid,
                descriptor,
                cumulative_amount,
                signature,
            } => {
                assert!(cid.starts_with("0x"));
                assert!(descriptor.is_none());
                assert_eq!(cumulative_amount, "2000");
                assert!(signature.starts_with("0x"));
            }
            _ => panic!("Expected Close variant"),
        }
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_create_precompile_close_payload_rejects_descriptor_mismatch() {
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let descriptor = build_channel_descriptor(
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            Address::ZERO,
            Address::repeat_byte(0x33),
            B256::repeat_byte(0x44),
            Address::repeat_byte(0x55),
            B256::repeat_byte(0x66),
        );

        let err = create_precompile_close_payload_with_descriptor(
            &signer,
            B256::repeat_byte(0x77),
            descriptor,
            2000,
            42431,
        )
        .await
        .expect_err("descriptor/channel mismatch should fail");

        assert!(err.to_string().contains("does not match channel_id"));
    }

    #[test]
    fn test_resolve_chain_id_from_challenge() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123",
                "methodDetails": { "escrowContract": "0xabc", "chainId": 4217 }
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        assert_eq!(resolve_chain_id(&challenge), 4217);
    }

    #[test]
    fn test_resolve_chain_id_default() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        assert_eq!(resolve_chain_id(&challenge), CHAIN_ID);
    }

    #[test]
    fn test_resolve_chain_id_malformed_request_falls_back() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "not_a_valid_field": true
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        // Match MPPx's default Tempo client: mainnet when no chain is advertised.
        assert_eq!(resolve_chain_id(&challenge), CHAIN_ID);
    }

    #[test]
    fn test_resolve_escrow_challenge_has_invalid_address() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        // escrowContract present but not a valid address
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123",
                "methodDetails": {
                    "escrowContract": "not-an-address"
                }
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        // Invalid address in challenge should fall back to default
        let result = resolve_escrow(&challenge, 42431, None).unwrap();
        assert_eq!(result, default_escrow_contract(42431).unwrap());
    }

    #[test]
    fn test_resolve_escrow_override_takes_precedence_over_default() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let override_addr: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let result = resolve_escrow(&challenge, 42431, Some(override_addr)).unwrap();
        assert_eq!(
            result, override_addr,
            "override should take precedence over default"
        );
        assert_ne!(result, default_escrow_contract(42431).unwrap());
    }

    #[test]
    fn test_default_escrow_contract_known_chains() {
        let mainnet = default_escrow_contract(4217).unwrap();
        assert_eq!(
            mainnet,
            "0x33b901018174DDabE4841042ab76ba85D4e24f25"
                .parse::<Address>()
                .unwrap()
        );

        let moderato = default_escrow_contract(42431).unwrap();
        assert_eq!(
            moderato,
            "0xe1c4d3dce17bc111181ddf716f75bae49e61a336"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn test_default_escrow_contract_unknown_chain() {
        assert!(default_escrow_contract(0).is_none());
        assert!(default_escrow_contract(999999).is_none());
    }

    #[test]
    fn test_build_credential_did_format() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test-id".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let payload = SessionCredentialPayload::Voucher {
            channel_id: "0xabc".to_string(),
            descriptor: None,
            cumulative_amount: "5000".to_string(),
            signature: "0xdef".to_string(),
        };

        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let cred = build_credential(&challenge, payload, 4217, addr);
        let did = cred.source.as_ref().unwrap();
        let expected = format!("did:pkh:eip155:4217:{}", addr);
        assert_eq!(did, &expected, "DID should match exact pkh format");
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_create_voucher_payload_zero_amount() {
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xAB);
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let payload = create_voucher_payload(&signer, channel_id, 0, escrow, 42431)
            .await
            .unwrap();

        match payload {
            SessionCredentialPayload::Voucher {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, "0");
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_create_close_payload_zero_amount() {
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xCD);
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let payload = create_close_payload(&signer, channel_id, 0, escrow, 42431)
            .await
            .unwrap();

        match payload {
            SessionCredentialPayload::Close {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, "0");
            }
            _ => panic!("Expected Close variant"),
        }
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_create_voucher_payload_large_amount() {
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xAB);
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let large_amount = u128::MAX;
        let payload = create_voucher_payload(&signer, channel_id, large_amount, escrow, 42431)
            .await
            .unwrap();

        match payload {
            SessionCredentialPayload::Voucher {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, u128::MAX.to_string());
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[test]
    fn test_channel_entry_debug() {
        let entry = ChannelEntry {
            channel_id: B256::ZERO,
            salt: B256::ZERO,
            cumulative_amount: 0,
            deposit: 0,
            descriptor: None,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened: false,
        };
        let debug = format!("{:?}", entry);
        assert!(debug.contains("ChannelEntry"));
        assert!(debug.contains("42431"));
    }

    #[test]
    fn test_resolve_escrow_override_priority_order() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        // Match MPPx: an explicit caller override wins over a challenge hint.
        let escrow_addr = "0x2222222222222222222222222222222222222222";
        let override_addr: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123",
                "methodDetails": {
                    "escrowContract": escrow_addr
                }
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let result = resolve_escrow(&challenge, 42431, Some(override_addr)).unwrap();
        assert_eq!(
            result, override_addr,
            "override should take priority over challenge escrow"
        );
    }

    /// `try_recover_channel` must reject a channel whose on-chain payer,
    /// payee, token, or authorized signer doesn't match the expected values,
    /// or that is pending close.
    ///
    /// Since `try_recover_channel` calls `get_on_chain_channel` (which does
    /// an RPC call we can't mock here), we test the validation predicate
    /// directly against `OnChainChannel` values — the same struct and field
    /// comparisons used in the real function.
    ///
    /// Helper: evaluates the same predicate used by `try_recover_channel`.
    fn recovery_accepts(
        on_chain: &OnChainChannel,
        expected_payer: Address,
        expected_payee: Address,
        expected_token: Address,
        expected_authorized_signer: Address,
    ) -> bool {
        let actual_authorized_signer = if on_chain.authorized_signer == Address::ZERO {
            on_chain.payer
        } else {
            on_chain.authorized_signer
        };
        on_chain.deposit > 0
            && !on_chain.finalized
            && on_chain.close_requested_at == 0
            && on_chain.payer == expected_payer
            && on_chain.payee == expected_payee
            && on_chain.token == expected_token
            && actual_authorized_signer == expected_authorized_signer
    }

    #[test]
    fn test_recovery_rejects_wrong_payer() {
        let payer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let wrong_payer: Address = "0x9999999999999999999999999999999999999999"
            .parse()
            .unwrap();

        let on_chain = OnChainChannel {
            payer,
            payee,
            token,
            authorized_signer: Address::ZERO,
            deposit: 1_000,
            settled: 0,
            close_requested_at: 0,
            finalized: false,
        };

        assert!(
            recovery_accepts(&on_chain, payer, payee, token, payer),
            "should accept when all fields match"
        );
        assert!(
            !recovery_accepts(&on_chain, wrong_payer, payee, token, payer),
            "should reject wrong payer"
        );
    }

    #[test]
    fn test_recovery_rejects_wrong_payee() {
        let payer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let wrong_payee: Address = "0x9999999999999999999999999999999999999999"
            .parse()
            .unwrap();

        let on_chain = OnChainChannel {
            payer,
            payee,
            token,
            authorized_signer: Address::ZERO,
            deposit: 1_000,
            settled: 0,
            close_requested_at: 0,
            finalized: false,
        };

        assert!(
            !recovery_accepts(&on_chain, payer, wrong_payee, token, payer),
            "should reject wrong payee"
        );
    }

    #[test]
    fn test_recovery_rejects_wrong_token() {
        let payer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let wrong_token: Address = "0x9999999999999999999999999999999999999999"
            .parse()
            .unwrap();

        let on_chain = OnChainChannel {
            payer,
            payee,
            token,
            authorized_signer: Address::ZERO,
            deposit: 1_000,
            settled: 0,
            close_requested_at: 0,
            finalized: false,
        };

        assert!(
            !recovery_accepts(&on_chain, payer, payee, wrong_token, payer),
            "should reject wrong token"
        );
    }

    #[test]
    fn test_recovery_rejects_wrong_authorized_signer() {
        let payer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let client_signer: Address = "0x4444444444444444444444444444444444444444"
            .parse()
            .unwrap();
        let wrong_signer: Address = "0x9999999999999999999999999999999999999999"
            .parse()
            .unwrap();

        let on_chain = OnChainChannel {
            payer,
            payee,
            token,
            authorized_signer: wrong_signer,
            deposit: 1_000,
            settled: 0,
            close_requested_at: 0,
            finalized: false,
        };

        assert!(
            !recovery_accepts(&on_chain, payer, payee, token, client_signer),
            "should reject channel with wrong authorized_signer"
        );
    }

    #[test]
    fn test_recovery_accepts_zero_authorized_signer_when_payer_matches() {
        let payer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();

        let on_chain = OnChainChannel {
            payer,
            payee,
            token,
            authorized_signer: Address::ZERO,
            deposit: 1_000,
            settled: 0,
            close_requested_at: 0,
            finalized: false,
        };

        assert!(
            recovery_accepts(&on_chain, payer, payee, token, payer),
            "Address::ZERO authorized_signer should normalize to payer"
        );
    }

    #[test]
    fn test_recovery_rejects_pending_close() {
        let payer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();

        let on_chain = OnChainChannel {
            payer,
            payee,
            token,
            authorized_signer: Address::ZERO,
            deposit: 1_000,
            settled: 0,
            close_requested_at: 1_700_000_000,
            finalized: false,
        };

        assert!(
            !recovery_accepts(&on_chain, payer, payee, token, payer),
            "should reject channel pending close"
        );
    }
}
