use super::*;

#[tokio::test]
async fn test_broadcast_rejects_unbound_memo_before_rpc() {
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let wrong_memo = attribution::encode("challenge-456", "api.example.com", None);
    let tx_bytes = encode_signed_tx(
        vec![tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(currency),
            value: U256::ZERO,
            input: make_transfer_with_memo_input(recipient, amount, wrong_memo),
        }],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let request = ChargeRequest {
        amount: amount.to_string(),
        currency: format!("{currency:#x}"),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({ "chainId": CHAIN_ID })),
        ..Default::default()
    };

    // No mock responses are queued: reaching the provider would produce a
    // different error and fail the assertion below.
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(Asserter::new());
    let method = ChargeMethod::new(provider);

    let error = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(tx_bytes),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
        )
        .await
        .expect_err("unbound memo must be rejected before broadcast");

    assert!(
        error
            .to_string()
            .contains("memo is not bound to this challenge"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn test_fee_payer_rejects_unbound_memo_before_cosign_or_rpc() {
    use alloy::providers::mock::Asserter;

    let currency = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let wrong_memo = attribution::encode("challenge-456", "api.example.com", None);
    let mut tx = make_fee_payer_tx(60);
    tx.calls = vec![tempo_alloy::primitives::transaction::Call {
        to: TxKind::Call(currency),
        value: U256::ZERO,
        input: make_transfer_with_memo_input(recipient, amount, wrong_memo),
    }];
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let tx_bytes = sign_and_encode_0x78(tx, &client_signer);
    let request = ChargeRequest {
        amount: amount.to_string(),
        currency: format!("{currency:#x}"),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({
            "chainId": CHAIN_ID,
            "feePayer": true,
        })),
        ..Default::default()
    };

    let signer_calls = Arc::new(AtomicUsize::new(0));
    let fee_payer_signer = AsyncOnlySigner {
        inner: alloy::signers::local::PrivateKeySigner::random(),
        calls: Arc::clone(&signer_calls),
    };
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(Asserter::new());
    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

    let error = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(tx_bytes),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
        )
        .await
        .expect_err("unbound memo must be rejected before sponsorship");

    assert!(
        error
            .to_string()
            .contains("memo is not bound to this challenge"),
        "unexpected error: {error}"
    );
    assert_eq!(signer_calls.load(Ordering::Relaxed), 0);
}

// ==================== Transaction credential source validation ====================

const TRANSACTION_SOURCE_INVALID: &str = "Transaction credential source is invalid.";
const TRANSACTION_SOURCE_MISMATCH: &str =
    "Transaction credential source does not match the transaction sender.";

fn challenge_bound_transfer_call(
    currency: Address,
    recipient: Address,
    amount: U256,
) -> tempo_alloy::primitives::transaction::Call {
    tempo_alloy::primitives::transaction::Call {
        to: TxKind::Call(currency),
        value: U256::ZERO,
        input: make_transfer_with_memo_input(
            recipient,
            amount,
            attribution::encode("challenge-123", "api.example.com", None),
        ),
    }
}

fn transaction_credential(
    request: &ChargeRequest,
    tx_bytes: &[u8],
    source: Option<String>,
) -> PaymentCredential {
    let mut credential = PaymentCredential::new(
        PaymentChallenge::new(
            "challenge-123",
            "api.example.com",
            "tempo",
            "charge",
            Base64UrlJson::from_typed(request).unwrap(),
        )
        .to_echo(),
        crate::protocol::core::PaymentPayload::transaction(alloy::hex::encode_prefixed(tx_bytes)),
    );
    credential.source = source;
    credential
}

#[tokio::test]
async fn test_validate_binds_transaction_credential_source_to_sender() {
    use alloy::eips::Decodable2718;
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let tx_bytes = encode_signed_tx(
        vec![challenge_bound_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let sender = tempo_alloy::primitives::AASigned::decode_2718(&mut &tx_bytes[..])
        .unwrap()
        .recover_signer()
        .unwrap();
    let request = ChargeRequest {
        amount: amount.to_string(),
        currency: format!("{currency:#x}"),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({ "chainId": CHAIN_ID })),
        ..Default::default()
    };

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(Asserter::new());
    let method = ChargeMethod::new(provider);
    method.cached_chain_id.set(CHAIN_ID).unwrap();

    let lowercase_source = format!("did:pkh:eip155:{CHAIN_ID}:{sender:#x}");
    let accepted = [
        (None, did_pkh(CHAIN_ID, sender)),
        (Some(lowercase_source.clone()), lowercase_source),
    ];
    for (source, expected) in accepted {
        let credential = transaction_credential(&request, &tx_bytes, source);
        let validation = ChargeMethodTrait::validate(&method, &credential, &request)
            .await
            .unwrap();
        assert_eq!(validation.source, Some(expected));
    }

    let rejected = [
        (
            did_pkh(CHAIN_ID, Address::repeat_byte(0x99)),
            TRANSACTION_SOURCE_MISMATCH,
        ),
        (
            did_pkh(MODERATO_CHAIN_ID, sender),
            TRANSACTION_SOURCE_INVALID,
        ),
        (format!("{sender:#x}"), TRANSACTION_SOURCE_INVALID),
    ];
    for (source, expected) in rejected {
        let credential = transaction_credential(&request, &tx_bytes, Some(source.clone()));
        let error = ChargeMethodTrait::validate(&method, &credential, &request)
            .await
            .expect_err(&source);
        assert_eq!(error.message, expected, "{source}");
    }
}

#[tokio::test]
async fn test_verify_rejects_transaction_source_mismatch_before_cosign_or_rpc() {
    use alloy::eips::Encodable2718;
    use alloy::providers::mock::Asserter;
    use alloy::signers::SignerSync;

    let currency = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let claimed_source = did_pkh(CHAIN_ID, Address::repeat_byte(0x99));

    let mut tx = make_fee_payer_tx(60);
    tx.calls = vec![challenge_bound_transfer_call(currency, recipient, amount)];
    let sponsored_tx_bytes = sign_and_encode_0x78(tx.clone(), &client_signer);
    tx.fee_payer_signature = None;
    tx.fee_token = Some(currency);
    let signature: tempo_alloy::primitives::transaction::TempoSignature = client_signer
        .sign_hash_sync(&tx.signature_hash())
        .unwrap()
        .into();
    let tx_bytes = tx.into_signed(signature).encoded_2718();

    // No mock responses are queued: reaching the provider would produce a
    // different error and fail the assertions below.
    for (fee_payer, tx_bytes) in [(false, tx_bytes), (true, sponsored_tx_bytes)] {
        let request = ChargeRequest {
            amount: amount.to_string(),
            currency: format!("{currency:#x}"),
            recipient: Some(format!("{recipient:#x}")),
            method_details: Some(serde_json::json!({
                "chainId": CHAIN_ID,
                "feePayer": fee_payer,
            })),
            ..Default::default()
        };
        let signer_calls = Arc::new(AtomicUsize::new(0));
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_mocked_client(Asserter::new());
        let method = ChargeMethod::new(provider).with_fee_payer(AsyncOnlySigner {
            inner: alloy::signers::local::PrivateKeySigner::random(),
            calls: Arc::clone(&signer_calls),
        });
        method.cached_chain_id.set(CHAIN_ID).unwrap();

        let credential = transaction_credential(&request, &tx_bytes, Some(claimed_source.clone()));
        let error = ChargeMethodTrait::verify(&method, &credential, &request)
            .await
            .expect_err("mismatched source must be rejected before broadcast");

        assert_eq!(
            error.message, TRANSACTION_SOURCE_MISMATCH,
            "fee_payer={fee_payer}"
        );
        assert_eq!(signer_calls.load(Ordering::Relaxed), 0);
    }
}
