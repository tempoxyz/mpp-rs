//! Fee-payer transaction encoding helpers.

/// Build a placeholder fee payer signature when fee sponsorship is enabled.
#[cfg(feature = "tempo")]
pub(crate) fn fee_payer_placeholder(enabled: bool) -> Option<alloy::primitives::Signature> {
    if enabled {
        Some(alloy::primitives::Signature::new(
            alloy::primitives::U256::ZERO,
            alloy::primitives::U256::ZERO,
            false,
        ))
    } else {
        None
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::eips::Encodable2718;
    use alloy::primitives::{Address, Bytes, TxKind, U256};
    use alloy::signers::SignerSync;
    use tempo_alloy::rpc::TempoTransactionRequest;
    use tempo_primitives::transaction::Call;

    fn build_test_tx(fee_payer: bool) -> tempo_primitives::TempoTransaction {
        let mut request = TempoTransactionRequest::default();
        request.inner.chain_id = Some(4217);
        request.inner.nonce = Some(0);
        request.inner.gas = Some(100_000);
        request.inner.max_fee_per_gas = Some(1);
        request.inner.max_priority_fee_per_gas = Some(1);
        request.calls = vec![Call {
            to: TxKind::Call(
                "0x20c0000000000000000000000000000000000000"
                    .parse::<Address>()
                    .unwrap(),
            ),
            value: U256::ZERO,
            input: Bytes::new(),
        }];
        request.fee_payer_signature =
            fee_payer.then(|| alloy::primitives::Signature::new(U256::ZERO, U256::ZERO, false));

        request
            .build_aa()
            .expect("failed to build test TempoTransaction")
    }

    #[test]
    fn test_encode_fee_payer_proxy_tx_suffix_and_placeholder() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let tx = build_test_tx(true);

        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash).unwrap();
        let wire = encode_fee_payer_proxy_tx(&tx, &signature, signer.address());

        assert!(wire.len() > 26, "output must include suffix");
        let marker = crate::protocol::methods::tempo::FEE_PAYER_MARKER;
        assert_eq!(&wire[wire.len() - 6..], &marker);
        assert_eq!(
            Address::from_slice(&wire[wire.len() - 26..wire.len() - 6]),
            signer.address()
        );

        let placeholder = tx
            .fee_payer_signature
            .expect("placeholder signature should exist");
        assert!(placeholder.r().is_zero());
        assert!(placeholder.s().is_zero());
        assert!(!placeholder.v());
    }

    #[test]
    fn test_standard_encoding_has_no_fee_payer_suffix() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let tx = build_test_tx(false);

        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash).unwrap();
        let signed = tx.into_signed(signature.into());
        let encoded = signed.encoded_2718();

        assert!(encoded.len() > 6, "encoded tx must not be empty");
        let marker = crate::protocol::methods::tempo::FEE_PAYER_MARKER;
        assert_ne!(&encoded[encoded.len() - 6..], &marker);
    }
}
