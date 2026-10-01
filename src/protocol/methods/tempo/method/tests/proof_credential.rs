use super::*;

#[tokio::test]
async fn test_zero_amount_proof_accepted() {
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
    let method = ChargeMethod::new(provider);

    let receipt = method.verify(&credential, &request).await.unwrap_err();
    assert!(receipt.to_string().contains("Failed to fetch chain ID") || receipt.retryable);
}

#[tokio::test]
async fn test_verify_proof_rejects_wrong_signer() {
    let signer = alloy::signers::local::PrivateKeySigner::random();
    let other = alloy::signers::local::PrivateKeySigner::random();
    let request = test_charge_request_with_amount("0");
    let challenge = test_proof_challenge(&request);
    let signature = proof::sign_proof(
        &other,
        signer.address(),
        42431,
        &challenge.id,
        &challenge.realm,
    )
    .await
    .unwrap();
    let payload = crate::protocol::core::PaymentPayload::proof(signature);
    let credential = PaymentCredential::with_source(
        challenge.to_echo(),
        proof::proof_source(signer.address(), 42431),
        payload.clone(),
    );

    let source = credential.source.as_deref().unwrap();
    let parsed = proof::parse_proof_source(source).unwrap();
    assert!(!proof::verify_proof(
        parsed.address,
        42431,
        &credential.challenge.id,
        &credential.challenge.realm,
        payload.proof_signature().unwrap(),
        parsed.address,
    ));
}

#[tokio::test]
async fn test_proof_credential_replay_rejected() {
    use crate::store::MemoryStore;

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
    let store = Arc::new(MemoryStore::new());
    let method = ChargeMethod::new(provider).with_store(store.clone());
    // Pre-cache the chain id so verify() needs no RPC; Direct-mode proof
    // verification is purely cryptographic.
    method.cached_chain_id.set(42431).unwrap();

    // First submission succeeds and records the challenge id.
    let receipt = method.verify(&credential, &request).await.unwrap();
    assert_eq!(receipt.reference, challenge.id);
    let key = format!("mpp:charge:proof:{}", challenge.id);
    assert!(store.get(&key).await.unwrap().is_some());

    // Replaying the identical credential is rejected.
    let err = method.verify(&credential, &request).await.unwrap_err();
    assert!(err.to_string().contains("already been used"));
}

#[tokio::test]
async fn test_proof_challenge_is_single_use_across_accounts() {
    use crate::store::MemoryStore;

    let request = test_charge_request_with_amount("0");
    let challenge = test_proof_challenge(&request);
    let mut credentials = Vec::new();
    for _ in 0..2 {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let signature = proof::sign_proof(
            &signer,
            signer.address(),
            42431,
            &challenge.id,
            &challenge.realm,
        )
        .await
        .unwrap();
        credentials.push(PaymentCredential::with_source(
            challenge.to_echo(),
            proof::proof_source(signer.address(), 42431),
            crate::protocol::core::PaymentPayload::proof(signature),
        ));
    }

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider).with_store(Arc::new(MemoryStore::new()));
    method.cached_chain_id.set(42431).unwrap();

    method.verify(&credentials[0], &request).await.unwrap();

    // A valid proof from another account cannot reuse the challenge.
    let err = method.verify(&credentials[1], &request).await.unwrap_err();
    assert!(err.to_string().contains("already been used"));
    let err = ChargeMethodTrait::validate(&method, &credentials[1], &request)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already been used"));
}

#[tokio::test]
async fn test_proof_validation_does_not_reserve_replay_state() {
    use crate::store::{MemoryStore, Store};

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
    let store = Arc::new(MemoryStore::new());
    let method = ChargeMethod::new(provider).with_store(store.clone());
    method.cached_chain_id.set(42431).unwrap();

    let validation = ChargeMethodTrait::validate(&method, &credential, &request)
        .await
        .unwrap();
    assert_eq!(validation.details["mode"], "proof");

    let key = format!("mpp:charge:proof:{}", challenge.id);
    assert!(store.get(&key).await.unwrap().is_none());

    let receipt = ChargeMethodTrait::broadcast(&method, &credential, &request)
        .await
        .unwrap();
    assert_eq!(receipt.reference, challenge.id);
    assert!(store.get(&key).await.unwrap().is_some());
}

#[tokio::test]
async fn test_proof_credential_replay_rejected_across_spellings() {
    use crate::store::MemoryStore;

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
        crate::protocol::core::PaymentPayload::proof(signature.clone()),
    );

    // Re-encode the same proof: uppercase signature hex + lowercased source
    // address. Semantically identical, so it must hit the same replay key.
    let upper_sig = signature.to_uppercase().replace("0X", "0x");
    let lower_source = format!("did:pkh:eip155:42431:0x{:x}", signer.address());
    assert_ne!(
        signature, upper_sig,
        "test must actually mutate the spelling"
    );
    let credential_variant = PaymentCredential::with_source(
        challenge.to_echo(),
        lower_source,
        crate::protocol::core::PaymentPayload::proof(upper_sig),
    );

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let store = Arc::new(MemoryStore::new());
    let method = ChargeMethod::new(provider).with_store(store);
    method.cached_chain_id.set(42431).unwrap();

    method.verify(&credential, &request).await.unwrap();

    // Re-encoded variant of the same proof is rejected as a replay.
    let err = method
        .verify(&credential_variant, &request)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("already been used"),
        "re-encoded proof must hit the same replay key, got: {err}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_proof_submissions_only_one_succeeds() {
    use crate::store::{MemoryStore, Store, StoreError};
    use std::future::Future;
    use std::pin::Pin;
    use std::time::Duration;

    // Delays the claim so both verifiers reach `put_if_absent` together.
    struct SlowStore {
        inner: MemoryStore,
        delay: Duration,
    }
    impl Store for SlowStore {
        fn get(
            &self,
            key: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>
        {
            self.inner.get(key)
        }
        fn put(
            &self,
            key: &str,
            value: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
            self.inner.put(key, value)
        }
        fn delete(
            &self,
            key: &str,
        ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
            self.inner.delete(key)
        }
        fn put_if_absent(
            &self,
            key: &str,
            value: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
            let key = key.to_string();
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                self.inner.put_if_absent(&key, value).await
            })
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
    let store = Arc::new(SlowStore {
        inner: MemoryStore::new(),
        delay: Duration::from_millis(50),
    });
    let method = ChargeMethod::new(provider).with_store(store);
    method.cached_chain_id.set(42431).unwrap();

    let m1 = method.clone();
    let c1 = credential.clone();
    let r1 = request.clone();
    let t1 = tokio::spawn(async move { m1.verify(&c1, &r1).await });
    let m2 = method.clone();
    let c2 = credential.clone();
    let r2 = request.clone();
    let t2 = tokio::spawn(async move { m2.verify(&c2, &r2).await });

    let res1 = t1.await.unwrap();
    let res2 = t2.await.unwrap();

    let successes = [res1.is_ok(), res2.is_ok()]
        .into_iter()
        .filter(|ok| *ok)
        .count();
    assert_eq!(
        successes, 1,
        "exactly one concurrent proof submission must succeed"
    );
    let err = res1.err().or(res2.err()).unwrap();
    assert!(err.to_string().contains("already been used"));
}
