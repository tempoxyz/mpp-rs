//! Fee-payer transaction encoding helpers.

/// Encode a fee-payer transaction in the wire format expected by the fee-payer
/// proxy server (viem convention).
///
/// `encoded_2718()` encodes `fee_payer_signature` as a full `[v, r, s]` RLP list,
/// but the proxy expects the `0x00` placeholder byte (same as `encode_for_signing`)
/// so it knows where to inject its own signature.
///
/// Output format: `0x76 || rlp([fields…, 0x00 placeholder, user_sig]) || sender || feefeefeefee`
#[cfg(feature = "tempo")]
pub(crate) fn encode_fee_payer_proxy_tx(
    tx: &tempo_primitives::TempoTransaction,
    user_sig: &alloy::primitives::Signature,
    sender: alloy::primitives::Address,
) -> Vec<u8> {
    use alloy::consensus::SignableTransaction;
    use tempo_primitives::transaction::TEMPO_TX_TYPE_ID;

    // encode_for_signing gives us: 0x76 || rlp([fields…, 0x00 placeholder])
    let mut signing_buf = Vec::new();
    tx.encode_for_signing(&mut signing_buf);

    // Strip type byte (0x76), decode the RLP list header to isolate the fields payload.
    let rlp_data = &signing_buf[1..];
    let fields_payload = if rlp_data[0] < 0xf8 {
        let len = (rlp_data[0] - 0xc0) as usize;
        &rlp_data[1..1 + len]
    } else {
        let len_of_len = (rlp_data[0] - 0xf7) as usize;
        let mut len = 0usize;
        for &b in &rlp_data[1..1 + len_of_len] {
            len = (len << 8) | b as usize;
        }
        &rlp_data[1 + len_of_len..1 + len_of_len + len]
    };

    // User signature as 65 bytes (r || s || v).
    let sig_bytes = user_sig.as_rsy();

    // New RLP list = fields_payload ++ RLP-encoded signature bytestring.
    let sig_rlp_len = 1 + 1 + 65; // 0xb8 prefix + length byte + 65 data bytes
    let new_payload_len = fields_payload.len() + sig_rlp_len;

    let mut out = Vec::with_capacity(1 + 4 + new_payload_len + 20 + 6);
    out.push(TEMPO_TX_TYPE_ID);

    // RLP list header.
    if new_payload_len < 56 {
        out.push(0xc0 + new_payload_len as u8);
    } else {
        let len_bytes = new_payload_len.to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_len_bytes = 8 - start;
        out.push(0xf7 + num_len_bytes as u8);
        out.extend_from_slice(&len_bytes[start..]);
    }

    out.extend_from_slice(fields_payload);

    // Signature as RLP byte string (65 bytes, uses long-string prefix).
    out.push(0xb8);
    out.push(65);
    out.extend_from_slice(&sig_bytes);

    // Viem convention suffix: sender address + fee marker.
    out.extend_from_slice(sender.as_slice());
    out.extend_from_slice(&crate::protocol::methods::tempo::FEE_PAYER_MARKER);

    out
}
