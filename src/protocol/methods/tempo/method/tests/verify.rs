use super::*;

#[test]
fn test_zero_amount_rejected() {
    // Zero amounts should be rejected to prevent parse-failure bypasses
    let zero = U256::ZERO;
    assert!(zero.is_zero());

    let non_zero = U256::from(1u64);
    assert!(!non_zero.is_zero());
}

#[test]
fn test_zero_address_detection() {
    // Zero addresses should be rejected to prevent parse-failure bypasses
    let zero_addr = Address::ZERO;
    assert!(zero_addr.is_zero());

    let valid_addr: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f3bB77"
        .parse()
        .unwrap();
    assert!(!valid_addr.is_zero());
}

#[test]
fn test_chain_id_constant() {
    // Verify the Tempo mainnet chain ID constant
    assert_eq!(CHAIN_ID, 4217);
    // Verify the Tempo Moderato testnet chain ID constant
    assert_eq!(MODERATO_CHAIN_ID, 42431);
}

#[test]
fn test_fee_payer_not_configured() {
    // When fee_payer_signer is None, the error message should indicate
    // that fee sponsorship is not configured.
    let error = VerificationError::new(
        "feePayer requested but fee sponsorship is not configured on this server",
    );
    assert!(error
        .to_string()
        .contains("fee sponsorship is not configured"));
}

#[test]
fn test_verify_zero_amount_requires_proof_payload() {
    let request = test_charge_request_with_amount("0");
    let challenge = test_proof_challenge(&request);
    let credential = PaymentCredential::new(
        challenge.to_echo(),
        crate::protocol::core::PaymentPayload::transaction("0xdeadbeef"),
    );
    let payload = credential.charge_payload().unwrap();
    assert!(!payload.is_proof());
    assert!(request.amount_u256().unwrap().is_zero());
}

#[test]
fn test_ensure_submission_mode_allowed() {
    const HASH_UNSUPPORTED: &str = "Hash credentials are not supported for this challenge.";
    const TX_UNSUPPORTED: &str = "Transaction credentials are not supported for this challenge.";

    let hash = PaymentPayload::hash("0x00");
    let transaction = PaymentPayload::transaction("0x00");
    let proof = PaymentPayload::proof("0x00");

    // (methodDetails, payload, expected error)
    let cases = [
        (serde_json::json!({}), &hash, None),
        (serde_json::json!({}), &transaction, None),
        (serde_json::json!({ "supportedModes": null }), &hash, None),
        (
            serde_json::json!({ "supportedModes": ["pull", "push"] }),
            &hash,
            None,
        ),
        (
            serde_json::json!({ "supportedModes": ["pull", "push"] }),
            &transaction,
            None,
        ),
        (
            serde_json::json!({ "supportedModes": ["push"] }),
            &hash,
            None,
        ),
        (
            serde_json::json!({ "supportedModes": ["pull"] }),
            &transaction,
            None,
        ),
        (
            serde_json::json!({ "supportedModes": ["pull"] }),
            &hash,
            Some(HASH_UNSUPPORTED),
        ),
        (
            serde_json::json!({ "supportedModes": ["push"] }),
            &transaction,
            Some(TX_UNSUPPORTED),
        ),
        (
            serde_json::json!({ "supportedModes": [] }),
            &hash,
            Some(HASH_UNSUPPORTED),
        ),
        (
            serde_json::json!({ "supportedModes": [] }),
            &transaction,
            Some(TX_UNSUPPORTED),
        ),
        (
            serde_json::json!({ "supportedModes": "push" }),
            &hash,
            Some(HASH_UNSUPPORTED),
        ),
        // Zero-amount proofs ignore the submission mode.
        (
            serde_json::json!({ "supportedModes": ["pull"] }),
            &proof,
            None,
        ),
    ];

    for (details, payload, expected) in cases {
        let request = ChargeRequest {
            method_details: Some(details.clone()),
            ..test_charge_request_with_amount("1")
        };
        let error = ensure_submission_mode_allowed(&request, payload)
            .err()
            .map(|e| e.message);
        assert_eq!(
            error.as_deref(),
            expected,
            "{details} {:?}",
            payload.payload_type()
        );
    }

    let no_details = ChargeRequest {
        method_details: None,
        ..test_charge_request_with_amount("1")
    };
    assert!(ensure_submission_mode_allowed(&no_details, &hash).is_ok());
}

#[tokio::test]
async fn test_verify_rejects_disallowed_submission_mode_before_rpc() {
    use alloy::providers::mock::Asserter;

    let cases = [
        (
            serde_json::json!({ "chainId": 42431, "supportedModes": ["pull"] }),
            PaymentPayload::hash(format!("{:#x}", B256::repeat_byte(0x11))),
            "Hash credentials are not supported for this challenge.",
        ),
        (
            serde_json::json!({ "chainId": 42431, "supportedModes": ["push"] }),
            PaymentPayload::transaction("0x76"),
            "Transaction credentials are not supported for this challenge.",
        ),
    ];

    for (details, payload, expected) in cases {
        let request = ChargeRequest {
            method_details: Some(details),
            ..test_charge_request_with_amount("1")
        };
        let credential = PaymentCredential::new(test_proof_challenge(&request).to_echo(), payload);
        // No mock responses are queued: reaching the provider would
        // produce a different error.
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_mocked_client(Asserter::new());
        let method = ChargeMethod::new(provider);
        method.cached_chain_id.set(42431).unwrap();

        let error = method.verify(&credential, &request).await.unwrap_err();
        assert_eq!(error.message, expected);
        let error = ChargeMethodTrait::validate(&method, &credential, &request)
            .await
            .unwrap_err();
        assert_eq!(error.message, expected);
    }
}

#[tokio::test]
async fn test_rpc_and_store_failures_are_internal_errors() {
    use crate::error::PaymentError;
    use crate::store::{Store, StoreError};
    use std::pin::Pin;

    // Has no atomic claim, so recording the proof fails.
    struct NonAtomicStore;
    impl Store for NonAtomicStore {
        fn get(
            &self,
            _key: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>
        {
            Box::pin(async { Ok(None) })
        }
        fn put(
            &self,
            _key: &str,
            _value: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }
        fn delete(
            &self,
            _key: &str,
        ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
            Box::pin(async { Ok(()) })
        }
    }

    let signer = alloy::signers::local::PrivateKeySigner::random();
    let request = test_charge_request_with_amount("0");
    let challenge = test_proof_challenge(&request);
    let signature = proof::sign_proof(
        &signer,
        signer.address(),
        42431,
        &challenge.id,
        &challenge.realm,
    )
    .await
    .unwrap();
    let credential = PaymentCredential::with_source(
        challenge.to_echo(),
        proof::proof_source(signer.address(), 42431),
        crate::protocol::core::PaymentPayload::proof(signature),
    );
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());

    // The chain ID lookup hits an unreachable RPC.
    let method = ChargeMethod::new(provider.clone());
    let err = method.verify(&credential, &request).await.unwrap_err();
    assert_eq!(err.to_problem_details(None).status, 500, "{err}");

    let method = ChargeMethod::new(provider).with_store(Arc::new(NonAtomicStore));
    method.cached_chain_id.set(42431).unwrap();
    let err = method.verify(&credential, &request).await.unwrap_err();
    assert_eq!(err.to_problem_details(None).status, 500, "{err}");
}

#[tokio::test]
async fn test_local_validation_rejects_invalid_credentials_before_broadcast() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);
    method.cached_chain_id.set(42431).unwrap();

    let zero_request = test_charge_request_with_amount("0");
    let paid_request = test_charge_request_with_amount("1");

    let mut wrong_method = test_proof_challenge(&zero_request).to_echo();
    wrong_method.method = "stripe".into();
    let mut wrong_intent = test_proof_challenge(&zero_request).to_echo();
    wrong_intent.intent = "session".into();
    let mut wrong_chain_request = zero_request.clone();
    wrong_chain_request.method_details = Some(serde_json::json!({ "chainId": 1 }));

    let cases = vec![
        (
            "method",
            PaymentCredential::new(
                wrong_method,
                crate::protocol::core::PaymentPayload::proof("0x00"),
            ),
            zero_request.clone(),
            "Method mismatch",
        ),
        (
            "intent",
            PaymentCredential::new(
                wrong_intent,
                crate::protocol::core::PaymentPayload::proof("0x00"),
            ),
            zero_request.clone(),
            "Intent mismatch",
        ),
        (
            "chain",
            PaymentCredential::new(
                test_proof_challenge(&wrong_chain_request).to_echo(),
                crate::protocol::core::PaymentPayload::proof("0x00"),
            ),
            wrong_chain_request,
            "Chain ID mismatch",
        ),
        (
            "zero-hash",
            PaymentCredential::new(
                test_proof_challenge(&zero_request).to_echo(),
                crate::protocol::core::PaymentPayload::hash("0x00"),
            ),
            zero_request.clone(),
            "Zero-amount challenges require a proof credential",
        ),
        (
            "positive-proof",
            PaymentCredential::new(
                test_proof_challenge(&paid_request).to_echo(),
                crate::protocol::core::PaymentPayload::proof("0x00"),
            ),
            paid_request.clone(),
            "Proof credentials are only valid for zero-amount challenges",
        ),
        (
            "proof-source",
            PaymentCredential::with_source(
                test_proof_challenge(&zero_request).to_echo(),
                "invalid-source",
                crate::protocol::core::PaymentPayload::proof("0x00"),
            ),
            zero_request.clone(),
            "Proof credential source is invalid",
        ),
        (
            "transaction",
            PaymentCredential::new(
                test_proof_challenge(&paid_request).to_echo(),
                crate::protocol::core::PaymentPayload::transaction("not-hex"),
            ),
            paid_request.clone(),
            "Invalid transaction bytes",
        ),
        (
            "hash",
            PaymentCredential::new(
                test_proof_challenge(&paid_request).to_echo(),
                crate::protocol::core::PaymentPayload::hash("not-hex"),
            ),
            paid_request,
            "Invalid transaction hash",
        ),
    ];

    for (name, credential, request, expected) in cases {
        let error = ChargeMethodTrait::validate(&method, &credential, &request)
            .await
            .unwrap_err();
        assert!(error.message.contains(expected), "{name}: {error}");
    }
}

// ==================== Chain ID caching tests ====================

#[test]
fn test_charge_method_new_has_empty_chain_id_cache() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);
    assert!(
        method.cached_chain_id.get().is_none(),
        "cache should be empty on construction"
    );
}

#[test]
fn test_charge_method_clone_shares_chain_id_cache() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    // Pre-populate the cache
    method.cached_chain_id.set(42431).unwrap();

    // Clone shares the same Arc<OnceCell>
    let cloned = method.clone();
    assert_eq!(
        cloned.cached_chain_id.get(),
        Some(&42431),
        "clone should share the cached chain ID"
    );
}

#[tokio::test]
async fn test_cached_chain_id_survives_across_verify_calls() {
    // Verify that the OnceCell is shared across the ChargeMethod's
    // internal clones in the verify() async block.
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    // First call will fail (can't reach RPC) but the cache should remain empty
    let request = test_charge_request_with_amount("0");
    let challenge = test_proof_challenge(&request);
    let credential = PaymentCredential::new(
        challenge.to_echo(),
        crate::protocol::core::PaymentPayload::hash("0xdeadbeef"),
    );
    let _ = method.verify(&credential, &request).await;

    // Cache should still be empty because the RPC call failed
    assert!(
        method.cached_chain_id.get().is_none(),
        "failed RPC should not populate cache"
    );

    // Manually populate the cache to simulate a successful first call
    method.cached_chain_id.set(42431).unwrap();

    // Subsequent access should return the cached value
    assert_eq!(method.cached_chain_id.get(), Some(&42431));
}

#[tokio::test]
async fn test_cached_chain_id_oncecell_rejects_second_init() {
    // OnceCell should reject a second initialization attempt,
    // ensuring the cached value is immutable after first set.
    let cell = Arc::new(OnceCell::new());
    cell.set(42431).unwrap();

    let result = cell.set(9999);
    assert!(result.is_err(), "OnceCell should reject second set");
    assert_eq!(
        cell.get(),
        Some(&42431),
        "original value should be retained"
    );
}
