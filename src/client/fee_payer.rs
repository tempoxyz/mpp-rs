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
    fn test_fee_payer_tx_uses_standard_2718_encoding() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let tx = build_test_tx(true);

        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash).unwrap();
        let signed = tx.into_signed(signature.into());
        let wire = signed.encoded_2718();

        // Must start with type byte 0x76.
        assert_eq!(wire[0], 0x76);

        // Must NOT have the old feefee suffix.
        assert!(wire.len() > 6);
        let old_marker = [0xfe_u8, 0xef, 0xee, 0xfe, 0xef, 0xee];
        assert_ne!(&wire[wire.len() - 6..], &old_marker);
    }

    #[test]
    fn test_fee_payer_placeholder_is_zero_signature() {
        let placeholder = fee_payer_placeholder(true).expect("should be Some");
        assert!(placeholder.r().is_zero());
        assert!(placeholder.s().is_zero());
        assert!(!placeholder.v());
    }

    #[test]
    fn test_no_fee_payer_placeholder_when_disabled() {
        assert!(fee_payer_placeholder(false).is_none());
    }

    #[test]
    fn test_standard_encoding_no_fee_payer() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let tx = build_test_tx(false);

        let sig_hash = tx.signature_hash();
        let signature = signer.sign_hash_sync(&sig_hash).unwrap();
        let signed = tx.into_signed(signature.into());
        let encoded = signed.encoded_2718();

        assert!(encoded.len() > 6, "encoded tx must not be empty");
        assert_eq!(encoded[0], 0x76);
    }
}
