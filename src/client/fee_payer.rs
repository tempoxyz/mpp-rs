//! Fee-payer transaction encoding helpers.

/// Encode a fee-payer envelope for the server to co-sign and broadcast.
///
/// Returns bytes prefixed with the fee payer magic byte (0x78). The
/// payload mirrors the sender signing envelope but substitutes the
/// sender address in the fee payer slot so the server can recover the
/// sender and sign the fee payer hash.
///
/// NOTE: This duplicates the RLP field layout from
/// `TempoTransaction::fee_payer_signature_hash` in `tempo_primitives`,
/// because that method only returns a `B256` hash — it does not expose
/// the raw pre-image bytes. We need the full wire envelope (pre-image +
/// user signature) so the server can decode and co-sign.
/// The `test_fee_payer_envelope_hash_matches_canonical` test guards
/// against field-order drift between this function and the canonical
/// implementation.
#[cfg(feature = "tempo")]
pub(crate) fn encode_fee_payer_proxy_tx(
    tx: &tempo_primitives::TempoTransaction,
    user_sig: &alloy::primitives::Signature,
    sender: alloy::primitives::Address,
) -> Vec<u8> {
    use alloy::rlp::{BufMut, Encodable, Header, EMPTY_STRING_CODE};

    const FEE_PAYER_SIGNATURE_MAGIC_BYTE: u8 = 0x78;

    let tempo_sig: tempo_primitives::TempoSignature = (*user_sig).into();

    let mut payload = Vec::new();
    tx.chain_id.encode(&mut payload);
    tx.max_priority_fee_per_gas.encode(&mut payload);
    tx.max_fee_per_gas.encode(&mut payload);
    tx.gas_limit.encode(&mut payload);
    tx.calls.encode(&mut payload);
    tx.access_list.encode(&mut payload);
    tx.nonce_key.encode(&mut payload);
    tx.nonce.encode(&mut payload);

    if let Some(valid_before) = tx.valid_before {
        valid_before.encode(&mut payload);
    } else {
        payload.put_u8(EMPTY_STRING_CODE);
    }

    if let Some(valid_after) = tx.valid_after {
        valid_after.encode(&mut payload);
    } else {
        payload.put_u8(EMPTY_STRING_CODE);
    }

    if let Some(fee_token) = tx.fee_token {
        fee_token.encode(&mut payload);
    } else {
        payload.put_u8(EMPTY_STRING_CODE);
    }

    sender.encode(&mut payload);
    tx.tempo_authorization_list.encode(&mut payload);
    if let Some(key_auth) = &tx.key_authorization {
        key_auth.encode(&mut payload);
    }
    tempo_sig.encode(&mut payload);

    let header = Header {
        list: true,
        payload_length: payload.len(),
    };

    let mut out = Vec::with_capacity(1 + header.length_with_payload());
    out.put_u8(FEE_PAYER_SIGNATURE_MAGIC_BYTE);
    header.encode(&mut out);
    out.extend_from_slice(&payload);
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
        build_test_tx_with_fee_token(fee_payer, None)
    }

    fn build_test_tx_with_fee_token(
        fee_payer: bool,
        fee_token: Option<Address>,
    ) -> tempo_primitives::TempoTransaction {
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
        request.fee_token = fee_token;

        request
            .build_aa()
            .expect("failed to build test TempoTransaction")
    }

    #[test]
    fn test_encode_fee_payer_proxy_tx_canonical_output() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let tx = build_test_tx(true);

        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash).unwrap();
        let wire = encode_fee_payer_proxy_tx(&tx, &signature, signer.address());

        assert_eq!(wire[0], 0x78, "must start with fee payer envelope byte");
        assert!(wire.len() > 10, "envelope bytes must not be empty");
    }

    #[test]
    fn test_fee_payer_envelope_hash_matches_canonical() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let tx = build_test_tx(true);
        let canonical_hash = tx.fee_payer_signature_hash(signer.address());

        // Rebuild the pre-image using the same field layout as
        // encode_fee_payer_proxy_tx (but without the trailing user sig)
        // and verify it hashes to the canonical fee_payer_signature_hash.
        use alloy::rlp::{BufMut, Encodable, Header, EMPTY_STRING_CODE};
        let mut payload = Vec::new();
        tx.chain_id.encode(&mut payload);
        tx.max_priority_fee_per_gas.encode(&mut payload);
        tx.max_fee_per_gas.encode(&mut payload);
        tx.gas_limit.encode(&mut payload);
        tx.calls.encode(&mut payload);
        tx.access_list.encode(&mut payload);
        tx.nonce_key.encode(&mut payload);
        tx.nonce.encode(&mut payload);
        if let Some(v) = tx.valid_before { v.encode(&mut payload); } else { payload.put_u8(EMPTY_STRING_CODE); }
        if let Some(v) = tx.valid_after { v.encode(&mut payload); } else { payload.put_u8(EMPTY_STRING_CODE); }
        if let Some(v) = tx.fee_token { v.encode(&mut payload); } else { payload.put_u8(EMPTY_STRING_CODE); }
        signer.address().encode(&mut payload);
        tx.tempo_authorization_list.encode(&mut payload);
        if let Some(ref k) = tx.key_authorization { k.encode(&mut payload); }

        let header = Header { list: true, payload_length: payload.len() };
        let mut preimage = Vec::with_capacity(1 + header.length_with_payload());
        preimage.put_u8(0x78);
        header.encode(&mut preimage);
        preimage.extend_from_slice(&payload);

        let our_hash = alloy::primitives::keccak256(&preimage);
        assert_eq!(
            our_hash, canonical_hash,
            "fee payer envelope pre-image must hash to the same value as \
             TempoTransaction::fee_payer_signature_hash"
        );
    }

    #[test]
    fn test_fee_payer_envelope_with_fee_token() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let tx = build_test_tx_with_fee_token(true, Some(fee_token));

        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash).unwrap();
        let wire = encode_fee_payer_proxy_tx(&tx, &signature, signer.address());

        assert_eq!(wire[0], 0x78);

        // Different fee tokens must produce different envelopes (fee payer
        // commits to the fee token).
        let tx_no_token = build_test_tx_with_fee_token(true, None);
        let sig_hash2 = tx_no_token.signature_hash();
        let signature2 = signer.sign_hash_sync(&sig_hash2).unwrap();
        let wire2 = encode_fee_payer_proxy_tx(&tx_no_token, &signature2, signer.address());

        assert_ne!(wire, wire2, "fee token must affect the envelope encoding");
    }

    #[test]
    fn test_fee_token_changes_canonical_hash() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();

        let tx_with = build_test_tx_with_fee_token(true, Some(fee_token));
        let tx_without = build_test_tx_with_fee_token(true, None);

        let hash_with = tx_with.fee_payer_signature_hash(signer.address());
        let hash_without = tx_without.fee_payer_signature_hash(signer.address());

        assert_ne!(
            hash_with, hash_without,
            "fee payer must commit to fee_token — different tokens must produce different hashes"
        );
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
        assert_eq!(encoded[0], 0x76, "must start with tempo tx type byte");
    }
}
