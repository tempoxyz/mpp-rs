//! Parsing and validation of session credential payload fields.

use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use super::{ChannelState, SessionMethod};
use crate::protocol::methods::tempo::session::TempoSessionMethodDetails;
use crate::protocol::methods::tempo::voucher::canonical_voucher_signature;
use crate::protocol::traits::VerificationError;

pub(super) fn validate_settlement_route(
    channel: &ChannelState,
    details: &TempoSessionMethodDetails,
    route: Option<&crate::protocol::methods::tempo::session::SettlementRoute>,
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

impl<P> SessionMethod<P> {
    /// Parse a hex channel ID string to B256.
    pub(super) fn parse_channel_id(channel_id: &str) -> Result<B256, VerificationError> {
        channel_id
            .parse::<B256>()
            .map_err(|e| VerificationError::invalid_payload(format!("Invalid channel ID: {}", e)))
    }

    /// Parse a hex voucher signature into its canonical 65-byte encoding.
    ///
    /// The returned bytes are what gets stored and submitted on-chain, so
    /// encodings the escrow contract cannot settle are rejected here.
    pub(super) fn parse_signature(signature: &str) -> Result<Vec<u8>, VerificationError> {
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
    pub(super) fn parse_address(addr: &str) -> Result<Address, VerificationError> {
        addr.parse::<Address>()
            .map_err(|e| VerificationError::invalid_payload(format!("Invalid address: {}", e)))
    }

    /// Parse the base-unit amount in the payload field `field`: decimal
    /// digits only, without the sign `u128::from_str` would accept.
    pub(super) fn parse_amount(amount: &str, field: &str) -> Result<u128, VerificationError> {
        crate::protocol::intents::base_unit_digits(amount)
            .and_then(|digits| digits.parse().ok())
            .ok_or_else(|| VerificationError::invalid_payload(format!("invalid {field}")))
    }
}

impl<P> SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Decode a client-signed Tempo transaction and return it together with
    /// the input of its call to `selector` on the escrow contract.
    pub(super) fn decode_escrow_call(
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
}
