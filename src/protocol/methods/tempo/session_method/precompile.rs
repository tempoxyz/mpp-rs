//! TIP-1034 channel reserve precompile sessions.
//!
//! When a session's escrow is the native channel reserve precompile, channels
//! are identified by a [`ChannelDescriptor`] rather than by escrow-contract
//! storage: every credential carries the descriptor, which must hash to the
//! claimed channel id, and on-chain state is read with `getChannelState`.
//! Vouchers are TIP-1020 primitive signatures (secp256k1, P-256 or WebAuthn),
//! so access keys authorized by Tempo Wallet can pay. Mirrors mppx's
//! precompile session server.

use alloy::consensus::transaction::SignerRecoverable;
use alloy::consensus::SignableTransaction;
use alloy::primitives::{keccak256, Address, Bytes, TxKind, Uint, B256, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use tempo_alloy::contracts::precompiles::{ITIP20ChannelReserve, TIP20_CHANNEL_RESERVE_ADDRESS};
use tempo_alloy::primitives::transaction::{Call, PrimitiveSignature, TempoSignature};
use tempo_alloy::TempoNetwork;

use super::chain::OnChainChannel;
use super::SessionMethod;
use crate::protocol::methods::tempo::precompile_voucher::{
    compute_precompile_channel_id_with_escrow,
    precompile_close_authorization_signing_hash_with_escrow, verify_precompile_voucher_signature,
    PRECOMPILE_MAX_CUMULATIVE_AMOUNT,
};
use crate::protocol::methods::tempo::session::ChannelDescriptor;
use crate::protocol::methods::tempo::voucher::verify_voucher;
use crate::protocol::traits::VerificationError;

impl<P> SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Read on-chain channel state from the legacy escrow or, given the
    /// channel's validated descriptor, from the TIP-1034 precompile.
    pub(super) async fn read_channel(
        &self,
        escrow: Address,
        channel_id: B256,
        descriptor: Option<&WireDescriptor>,
    ) -> Result<OnChainChannel, VerificationError> {
        if !is_precompile(escrow) {
            return super::chain::get_on_chain_channel(&*self.provider, escrow, channel_id).await;
        }
        let descriptor = descriptor.ok_or_else(|| {
            VerificationError::invalid_payload("descriptor required for TIP-1034 session action")
        })?;
        get_precompile_channel(&*self.provider, escrow, channel_id, descriptor).await
    }

    /// The operator the challenge names, or zero.
    pub(super) fn resolve_operator(
        details: &crate::protocol::methods::tempo::session::TempoSessionMethodDetails,
    ) -> Result<Address, VerificationError> {
        match details.operator.as_deref() {
            Some(op) => Self::parse_address(op),
            None => Ok(Address::ZERO),
        }
    }
}

/// Largest TIP-1020 signature accepted from a credential (WebAuthn is the largest kind).
const MAX_SIGNATURE_BYTES: usize = 2048;

pub(super) type WireDescriptor = ITIP20ChannelReserve::ChannelDescriptor;

/// Whether `escrow` is the TIP-1034 channel reserve precompile.
pub(super) fn is_precompile(escrow: Address) -> bool {
    escrow == TIP20_CHANNEL_RESERVE_ADDRESS
}

fn u96(amount: u128, field: &str) -> Result<Uint<96, 2>, VerificationError> {
    if amount > PRECOMPILE_MAX_CUMULATIVE_AMOUNT {
        return Err(VerificationError::invalid_payload(format!(
            "{field} exceeds the precompile's uint96 range"
        )));
    }
    Ok(Uint::<96, 2>::from(amount))
}

fn parse_addr(value: &str, field: &str) -> Result<Address, VerificationError> {
    value
        .parse()
        .map_err(|_| VerificationError::invalid_payload(format!("invalid descriptor {field}")))
}

fn parse_b256(value: &str, field: &str) -> Result<B256, VerificationError> {
    value
        .parse()
        .map_err(|_| VerificationError::invalid_payload(format!("invalid descriptor {field}")))
}

/// Parse a credential descriptor into the precompile's ABI struct.
pub(super) fn wire_descriptor(d: &ChannelDescriptor) -> Result<WireDescriptor, VerificationError> {
    Ok(WireDescriptor {
        payer: parse_addr(&d.payer, "payer")?,
        payee: parse_addr(&d.payee, "payee")?,
        operator: parse_addr(&d.operator, "operator")?,
        token: parse_addr(&d.token, "token")?,
        salt: parse_b256(&d.salt, "salt")?,
        authorizedSigner: parse_addr(&d.authorized_signer, "authorizedSigner")?,
        expiringNonceHash: parse_b256(&d.expiring_nonce_hash, "expiringNonceHash")?,
    })
}

/// The address that signs the channel's vouchers.
pub(super) fn voucher_signer(d: &WireDescriptor) -> Address {
    if d.authorizedSigner == Address::ZERO {
        d.payer
    } else {
        d.authorizedSigner
    }
}

/// Require a descriptor and check that it identifies `channel_id` on this
/// escrow and chain, and pays the expected payee in the expected token
/// through the expected operator (zero when the challenge names none).
pub(super) fn validate_descriptor(
    descriptor: Option<&ChannelDescriptor>,
    channel_id: B256,
    escrow: Address,
    chain_id: u64,
    expected_payee: Address,
    expected_token: Address,
    expected_operator: Address,
) -> Result<WireDescriptor, VerificationError> {
    let descriptor = descriptor.ok_or_else(|| {
        VerificationError::invalid_payload("descriptor required for TIP-1034 session action")
    })?;
    let d = wire_descriptor(descriptor)?;
    let computed = compute_precompile_channel_id_with_escrow(
        d.payer,
        d.payee,
        d.operator,
        d.token,
        d.salt,
        d.authorizedSigner,
        d.expiringNonceHash,
        escrow,
        chain_id,
    );
    if computed != channel_id {
        return Err(VerificationError::credential_mismatch(
            "channel descriptor does not match channelId",
        ));
    }
    if d.payee != expected_payee {
        return Err(VerificationError::credential_mismatch(
            "channel descriptor payee does not match session recipient",
        ));
    }
    if d.token != expected_token {
        return Err(VerificationError::credential_mismatch(
            "channel descriptor token does not match session currency",
        ));
    }
    if d.operator != expected_operator {
        return Err(VerificationError::credential_mismatch(
            "channel descriptor operator does not match session operator",
        ));
    }
    Ok(d)
}

/// Decode a signature for `escrow`'s voucher scheme: TIP-1020 primitive bytes
/// for the precompile, canonical secp256k1 for the legacy escrow.
pub(super) fn parse_signature_for<P>(
    escrow: Address,
    signature: &str,
) -> Result<Vec<u8>, VerificationError> {
    if !is_precompile(escrow) {
        return SessionMethod::<P>::parse_signature(signature);
    }
    let s = signature.strip_prefix("0x").unwrap_or(signature);
    let bytes = hex::decode(s)
        .map_err(|e| VerificationError::invalid_payload(format!("Invalid signature hex: {e}")))?;
    if bytes.is_empty() || bytes.len() > MAX_SIGNATURE_BYTES {
        return Err(VerificationError::invalid_signature(
            "voucher signature has an invalid length",
        ));
    }
    Ok(bytes)
}

/// Verify a voucher with the scheme of `escrow`.
pub(super) fn verify_voucher_for(
    escrow: Address,
    chain_id: u64,
    channel_id: B256,
    cumulative_amount: u128,
    signature: &[u8],
    expected_signer: Address,
) -> bool {
    if !is_precompile(escrow) {
        return verify_voucher(
            escrow,
            chain_id,
            channel_id,
            cumulative_amount,
            signature,
            expected_signer,
        );
    }
    verify_precompile_voucher_signature(
        signature,
        expected_signer,
        channel_id,
        cumulative_amount,
        escrow,
        chain_id,
    )
    .unwrap_or(false)
}

/// Verify a cooperative close authorization signed by any of `signers`.
pub(super) fn verify_close_authorization(
    signature: &[u8],
    signers: &[Address],
    channel_id: B256,
    cumulative_amount: u128,
    escrow: Address,
    chain_id: u64,
) -> bool {
    let Ok(hash) = precompile_close_authorization_signing_hash_with_escrow(
        channel_id,
        cumulative_amount,
        escrow,
        chain_id,
    ) else {
        return false;
    };
    let Ok(primitive) = PrimitiveSignature::from_bytes(signature) else {
        return false;
    };
    if primitive.to_bytes().as_ref() != signature {
        return false;
    }
    TempoSignature::Primitive(primitive)
        .recover_signer(&hash)
        .is_ok_and(|signer| signers.contains(&signer))
}

alloy::sol! {
    #[sol(rpc)]
    interface IChannelReserveState {
        struct ChannelState {
            uint96 settled;
            uint96 deposit;
            uint32 closeRequestedAt;
        }
        function getChannelState(bytes32 channelId) external view returns (ChannelState memory);
    }
}

/// Read the precompile's `getChannelState` for `channel_id` as of `block`.
/// It needs no descriptor; a closed or withdrawn channel reads back unfunded.
pub(super) async fn get_precompile_channel_state<P: Provider<TempoNetwork>>(
    provider: &P,
    escrow: Address,
    channel_id: B256,
    block: alloy::eips::BlockId,
) -> Result<IChannelReserveState::ChannelState, VerificationError> {
    IChannelReserveState::new(escrow, provider)
        .getChannelState(channel_id)
        .block(block)
        .call()
        .await
        .map_err(|e| {
            VerificationError::network_error(format!("Failed to read on-chain channel: {e}"))
        })
}

/// Read channel state from the precompile. Parties come from the descriptor,
/// which the caller has validated against the channel id.
pub(super) async fn get_precompile_channel<P: Provider<TempoNetwork>>(
    provider: &P,
    escrow: Address,
    channel_id: B256,
    descriptor: &WireDescriptor,
) -> Result<OnChainChannel, VerificationError> {
    let state =
        get_precompile_channel_state(provider, escrow, channel_id, alloy::eips::BlockId::latest())
            .await?;
    Ok(OnChainChannel {
        payer: descriptor.payer,
        payee: descriptor.payee,
        token: descriptor.token,
        authorized_signer: descriptor.authorizedSigner,
        deposit: state.deposit.to::<u128>(),
        settled: state.settled.to::<u128>(),
        close_requested_at: u64::from(state.closeRequestedAt),
        // The precompile has no finalized flag: a closed or withdrawn channel is deleted and
        // reads back unfunded, which a lagging RPC can also return right after an open. Callers
        // reject zero-deposit reads for the request at hand instead of persisting them.
        finalized: false,
    })
}

/// Decode a client-signed Tempo transaction whose last call is `selector` on
/// the precompile (optionally after an approve + swap auto-swap prefix).
fn decode_management_call(
    tx_bytes: &[u8],
    escrow: Address,
    selector: [u8; 4],
    action: &str,
) -> Result<(tempo_alloy::primitives::AASigned, Bytes), VerificationError> {
    let tx_data = match tx_bytes.first() {
        Some(&tempo_alloy::primitives::transaction::TEMPO_TX_TYPE_ID) => &tx_bytes[1..],
        _ => tx_bytes,
    };
    let signed = tempo_alloy::primitives::AASigned::rlp_decode(&mut &tx_data[..]).map_err(|e| {
        VerificationError::invalid_payload(format!("failed to decode {action} transaction: {e}"))
    })?;
    let calls = &signed.tx().calls;
    if calls.len() != 1 && calls.len() != 3 {
        return Err(VerificationError::invalid_payload(format!(
            "TIP-1034 {action} transaction must contain one management call, optionally preceded by an auto-swap"
        )));
    }
    let call = calls.last().expect("non-empty");
    if call.to != TxKind::Call(escrow) || call.input.len() < 4 || call.input[..4] != selector {
        return Err(VerificationError::invalid_payload(format!(
            "TIP-1034 {action} transaction does not end with a precompile {action}() call"
        )));
    }
    let input = call.input.clone();
    Ok((signed, input))
}

/// `expiringNonceHash` the precompile derives for an open: keccak256 of the
/// transaction's signing encoding followed by the sender.
fn expiring_nonce_hash(tx: &tempo_alloy::primitives::TempoTransaction, sender: Address) -> B256 {
    let mut buf = Vec::with_capacity(tx.payload_len_for_signature() + 20);
    tx.encode_for_signing(&mut buf);
    buf.extend_from_slice(sender.as_slice());
    keccak256(buf)
}

/// Check a client-signed precompile open against its credential descriptor.
///
/// Returns the descriptor, the voucher signer and the deposit it opens with.
#[allow(clippy::too_many_arguments)]
pub(super) fn verify_open(
    tx_bytes: &[u8],
    descriptor: Option<&ChannelDescriptor>,
    channel_id: B256,
    escrow: Address,
    chain_id: u64,
    expected_payee: Address,
    expected_token: Address,
    expected_operator: Address,
) -> Result<(WireDescriptor, Address, u128), VerificationError> {
    let d = validate_descriptor(
        descriptor,
        channel_id,
        escrow,
        chain_id,
        expected_payee,
        expected_token,
        expected_operator,
    )?;
    let (signed, input) = decode_management_call(
        tx_bytes,
        escrow,
        ITIP20ChannelReserve::openCall::SELECTOR,
        "open",
    )?;
    let open = ITIP20ChannelReserve::openCall::abi_decode(&input).map_err(|e| {
        VerificationError::invalid_payload(format!("failed to decode open() calldata: {e}"))
    })?;
    let sender = signed
        .recover_signer()
        .map_err(|e| VerificationError::new(format!("failed to recover sender: {e}")))?;
    if sender != d.payer
        || open.payee != d.payee
        || open.operator != d.operator
        || open.token != d.token
        || open.salt != d.salt
        || open.authorizedSigner != d.authorizedSigner
    {
        return Err(VerificationError::credential_mismatch(
            "open transaction does not match the channel descriptor",
        ));
    }
    if expiring_nonce_hash(signed.tx(), sender) != d.expiringNonceHash {
        return Err(VerificationError::credential_mismatch(
            "credential expiringNonceHash does not match transaction",
        ));
    }
    let deposit = open.deposit.to::<u128>();
    if deposit == 0 {
        return Err(VerificationError::invalid_payload("open deposit is zero"));
    }
    let signer = voucher_signer(&d);
    Ok((d, signer, deposit))
}

/// Check a client-signed precompile topUp for `descriptor` and `additional_deposit`.
pub(super) fn verify_top_up(
    tx_bytes: &[u8],
    descriptor: &WireDescriptor,
    escrow: Address,
    additional_deposit: u128,
) -> Result<(), VerificationError> {
    let (_, input) = decode_management_call(
        tx_bytes,
        escrow,
        ITIP20ChannelReserve::topUpCall::SELECTOR,
        "topUp",
    )?;
    let top_up = ITIP20ChannelReserve::topUpCall::abi_decode(&input).map_err(|e| {
        VerificationError::invalid_payload(format!("failed to decode topUp() calldata: {e}"))
    })?;
    if top_up.descriptor != *descriptor {
        return Err(VerificationError::new(
            "topUp transaction does not match the channel descriptor",
        ));
    }
    if top_up.additionalDeposit != u96(additional_deposit, "additionalDeposit")? {
        return Err(VerificationError::new(
            "topUp transaction amount does not match additionalDeposit",
        ));
    }
    Ok(())
}

/// Check a TIP-1034 close voucher against the channel and return the amount
/// the payee captures: what was spent, never less than already settled.
pub(super) fn validate_close(
    cumulative_amount: u128,
    spent: u128,
    on_chain_settled: u128,
    on_chain_deposit: u128,
) -> Result<u128, VerificationError> {
    if on_chain_deposit == 0 {
        return Err(VerificationError::channel_closed(
            "channel is not funded on-chain",
        ));
    }
    if cumulative_amount < spent {
        return Err(VerificationError::new(format!(
            "close voucher amount must be >= {spent} (spent)"
        )));
    }
    if cumulative_amount < on_chain_settled {
        return Err(VerificationError::new(format!(
            "close voucher amount must be >= {on_chain_settled} (on-chain settled)"
        )));
    }
    if cumulative_amount > on_chain_deposit {
        return Err(VerificationError::amount_exceeds_deposit(
            "close voucher amount exceeds on-chain deposit",
        ));
    }
    Ok(spent.max(on_chain_settled))
}

/// The payee's cooperative close: settle `capture` of the voucher's
/// `cumulative_amount` and refund the rest of the deposit to the payer.
pub(super) fn close_call(
    escrow: Address,
    descriptor: WireDescriptor,
    cumulative_amount: u128,
    capture: u128,
    signature: &[u8],
) -> Result<Call, VerificationError> {
    let close = ITIP20ChannelReserve::closeCall::new((
        descriptor,
        u96(cumulative_amount, "cumulativeAmount")?,
        u96(capture, "captureAmount")?,
        Bytes::copy_from_slice(signature),
    ));
    Ok(Call {
        to: TxKind::Call(escrow),
        value: U256::ZERO,
        input: Bytes::from(close.abi_encode()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(payee: Address, token: Address) -> ChannelDescriptor {
        ChannelDescriptor {
            payer: format!("{:#x}", Address::repeat_byte(0x11)),
            payee: format!("{payee:#x}"),
            operator: format!("{:#x}", Address::ZERO),
            token: format!("{token:#x}"),
            salt: format!("{:#x}", B256::repeat_byte(0x55)),
            authorized_signer: format!("{:#x}", Address::repeat_byte(0x66)),
            expiring_nonce_hash: format!("{:#x}", B256::repeat_byte(0x77)),
        }
    }

    fn id_of(d: &ChannelDescriptor, chain_id: u64) -> B256 {
        let w = wire_descriptor(d).unwrap();
        compute_precompile_channel_id_with_escrow(
            w.payer,
            w.payee,
            w.operator,
            w.token,
            w.salt,
            w.authorizedSigner,
            w.expiringNonceHash,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            chain_id,
        )
    }

    #[test]
    fn descriptor_must_identify_the_channel_and_session() {
        let payee = Address::repeat_byte(0x22);
        let token = Address::repeat_byte(0x44);
        let d = descriptor(payee, token);
        let id = id_of(&d, 42431);
        let check = |d: Option<&ChannelDescriptor>, id, chain, payee, token, operator| {
            validate_descriptor(
                d,
                id,
                TIP20_CHANNEL_RESERVE_ADDRESS,
                chain,
                payee,
                token,
                operator,
            )
        };

        let ok = check(Some(&d), id, 42431, payee, token, Address::ZERO).unwrap();
        assert_eq!(voucher_signer(&ok), Address::repeat_byte(0x66));
        assert!(check(None, id, 42431, payee, token, Address::ZERO).is_err());
        assert!(check(Some(&d), B256::ZERO, 42431, payee, token, Address::ZERO).is_err());
        assert!(check(Some(&d), id, 4217, payee, token, Address::ZERO).is_err());
        assert!(check(Some(&d), id, 42431, token, token, Address::ZERO).is_err());
        assert!(check(Some(&d), id, 42431, payee, payee, Address::ZERO).is_err());
        assert!(check(Some(&d), id, 42431, payee, token, payee).is_err());
    }

    #[test]
    fn precompile_vouchers_accept_primitive_signatures() {
        use alloy::signers::{local::PrivateKeySigner, SignerSync};
        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0x01);
        let escrow = TIP20_CHANNEL_RESERVE_ADDRESS;
        let hash = crate::protocol::methods::tempo::precompile_voucher_signing_hash_with_escrow(
            channel_id, 5, escrow, 42431,
        )
        .unwrap();
        let sig = signer.sign_hash_sync(&hash).unwrap().as_bytes().to_vec();
        assert!(verify_voucher_for(
            escrow,
            42431,
            channel_id,
            5,
            &sig,
            signer.address()
        ));
        assert!(!verify_voucher_for(
            escrow,
            42431,
            channel_id,
            6,
            &sig,
            signer.address()
        ));
        assert!(!verify_voucher_for(
            escrow,
            4217,
            channel_id,
            5,
            &sig,
            signer.address()
        ));
        assert!(!verify_voucher_for(
            escrow,
            42431,
            channel_id,
            5,
            &sig,
            Address::ZERO
        ));
    }

    #[test]
    fn close_authorization_is_distinct_from_a_voucher() {
        use alloy::signers::{local::PrivateKeySigner, SignerSync};
        let payer = PrivateKeySigner::random();
        let escrow = TIP20_CHANNEL_RESERVE_ADDRESS;
        let channel_id = B256::repeat_byte(0x02);
        let close_hash =
            precompile_close_authorization_signing_hash_with_escrow(channel_id, 9, escrow, 42431)
                .unwrap();
        let close_sig = payer
            .sign_hash_sync(&close_hash)
            .unwrap()
            .as_bytes()
            .to_vec();
        let signers = [payer.address()];
        assert!(verify_close_authorization(
            &close_sig, &signers, channel_id, 9, escrow, 42431
        ));
        assert!(!verify_close_authorization(
            &close_sig,
            &[Address::ZERO],
            channel_id,
            9,
            escrow,
            42431
        ));
        // A close authorization is not a voucher.
        assert!(!verify_voucher_for(
            escrow,
            42431,
            channel_id,
            9,
            &close_sig,
            payer.address()
        ));
    }

    #[test]
    fn close_captures_what_was_spent() {
        assert_eq!(validate_close(50, 30, 10, 100).unwrap(), 30);
        assert_eq!(validate_close(50, 0, 20, 100).unwrap(), 20);
        assert!(validate_close(20, 30, 0, 100).is_err());
        assert!(validate_close(5, 0, 10, 100).is_err());
        assert!(validate_close(101, 0, 0, 100).is_err());
        assert!(validate_close(0, 0, 0, 0).is_err());
    }

    #[test]
    fn amounts_beyond_uint96_are_rejected() {
        assert!(u96(PRECOMPILE_MAX_CUMULATIVE_AMOUNT, "x").is_ok());
        assert!(u96(PRECOMPILE_MAX_CUMULATIVE_AMOUNT + 1, "x").is_err());
    }
}
