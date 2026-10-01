use super::*;

// ==================== Fee payer co-sign unit tests ====================

/// Round-trip with a signer that intentionally does not implement
/// `SignerSync`, matching remote KMS/HSM signer capabilities.
#[tokio::test]
async fn test_fee_payer_round_trip_accepts_async_only_signer() {
    use super::super::super::{FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID};
    use alloy::signers::SignerSync;

    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let signer_calls = Arc::new(AtomicUsize::new(0));
    let fee_payer_signer = AsyncOnlySigner {
        inner: alloy::signers::local::PrivateKeySigner::random(),
        calls: Arc::clone(&signer_calls),
    };
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();

    let tx = make_fee_payer_tx(60);

    // Encode as a 0x78 fee payer envelope (sender address in the fee_payer slot).
    let sig_hash = tx.signature_hash();
    let sig = client_signer.sign_hash_sync(&sig_hash).unwrap();
    let signature: tempo_alloy::primitives::transaction::TempoSignature = sig.into();

    let encoded = FeePayerEnvelope78::from_signing_tx(tx, client_signer.address(), signature)
        .encoded_envelope();
    assert_eq!(encoded[0], TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID);

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());

    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

    let result = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await;

    let co_signed = result.expect("cosign should succeed for valid 0x78 envelope");
    assert_eq!(signer_calls.load(Ordering::Relaxed), 1);

    // Result should be a valid 0x76 transaction
    assert_eq!(
        co_signed[0],
        tempo_alloy::primitives::transaction::TEMPO_TX_TYPE_ID,
        "co-signed output should be 0x76"
    );

    // It should be decodable by AASigned
    let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut &co_signed[..])
        .expect("co-signed tx should be decodable as AASigned");

    let decoded_tx = signed.tx();
    assert_eq!(decoded_tx.chain_id, CHAIN_ID);
    assert_eq!(decoded_tx.nonce_key, U256::MAX);
    assert_eq!(decoded_tx.fee_token, Some(fee_token));
    assert!(decoded_tx.fee_payer_signature.is_some());
    assert!(decoded_tx.valid_before.is_some());
}

/// cosign_fee_payer_transaction rejects txs with wrong nonce_key.
#[tokio::test]
async fn test_cosign_rejects_wrong_nonce_key() {
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();

    let mut tx = make_fee_payer_tx(60);
    tx.nonce_key = U256::ZERO; // Wrong — should be U256::MAX

    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());

    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

    let result = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await;

    let err = result.expect_err("should reject wrong nonce_key");
    assert!(
        err.to_string().contains("expiring nonce key"),
        "error should mention expiring nonce key, got: {err}"
    );
}

/// cosign_fee_payer_transaction rejects txs without valid_before.
#[tokio::test]
async fn test_cosign_rejects_missing_valid_before() {
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();

    let mut tx = make_fee_payer_tx(60);
    tx.valid_before = None; // Missing

    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());

    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

    let result = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await;

    let err = result.expect_err("should reject missing valid_before");
    assert!(
        err.to_string().contains("must include valid_before"),
        "error should mention valid_before, got: {err}"
    );
}

/// A client that signs over a non-empty access list fails recovery
/// (sponsor strips before ecrecover → recovered ≠ envelope.sender).
#[tokio::test]
async fn test_cosign_rejects_access_list_signed_by_client() {
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();

    let mut tx = make_fee_payer_tx(60);
    tx.access_list = alloy::eips::eip2930::AccessList(vec![alloy::eips::eip2930::AccessListItem {
        address: Address::repeat_byte(0xaa),
        storage_keys: vec![],
    }]);

    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());

    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

    let result = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await;

    let err = result.expect_err("malicious access-list signature must not cosign");
    assert!(
        err.to_string().to_lowercase().contains("sender mismatch"),
        "expected sender mismatch, got: {err}"
    );
}

/// An authorization list adds intrinsic gas the sponsor would pay for
/// delegations unrelated to the charge.
#[tokio::test]
async fn test_cosign_rejects_authorization_list() {
    use alloy::signers::SignerSync;
    use tempo_alloy::primitives::transaction::TempoSignedAuthorization;

    let (method, client_signer, fee_token) = make_cosign_method(None);

    let authorization = alloy::eips::eip7702::Authorization {
        chain_id: U256::from(CHAIN_ID),
        address: Address::repeat_byte(0xde),
        nonce: 0,
    };
    let signature = client_signer
        .sign_hash_sync(&authorization.signature_hash())
        .unwrap();
    let mut tx = make_fee_payer_tx(60);
    tx.tempo_authorization_list = vec![TempoSignedAuthorization::new_unchecked(
        authorization,
        signature.into(),
    )];
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let err = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect_err("authorization list must not be sponsored");
    assert!(err.to_string().contains("authorization list"), "got: {err}");
}

/// Key authorizations are sponsored by default and rejected once the
/// server opts out.
#[tokio::test]
async fn test_cosign_key_authorization_follows_policy() {
    use alloy::signers::SignerSync;
    use tempo_alloy::primitives::transaction::{
        KeyAuthorization, PrimitiveSignature, SignatureType,
    };

    let (method, client_signer, fee_token) = make_cosign_method(None);

    let authorization = KeyAuthorization {
        chain_id: CHAIN_ID,
        key_type: SignatureType::Secp256k1,
        key_id: Address::repeat_byte(0xde),
        expiry: NonZeroU64::new(9999999999),
        limits: None,
        allowed_calls: None,
        witness: None,
        is_admin: false,
        account: None,
    };
    let signature = client_signer
        .sign_hash_sync(&authorization.signature_hash())
        .unwrap();
    let mut tx = make_fee_payer_tx(60);
    tx.key_authorization =
        Some(authorization.into_signed(PrimitiveSignature::Secp256k1(signature)));
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect("key authorization is sponsored by default");

    let method = method.with_fee_payer_allow_key_authorization(false);
    let err = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect_err("key authorization must be rejected when disallowed");
    assert!(err.to_string().contains("key authorization"), "got: {err}");
}

/// cosign_fee_payer_transaction rejects txs with expired valid_before.
#[tokio::test]
async fn test_cosign_rejects_expired_valid_before() {
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();

    // Build a tx with valid_before in the past
    let past = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 10;

    let mut tx = make_fee_payer_tx(60);
    tx.valid_before = NonZeroU64::new(past);

    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());

    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

    let result = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await;

    let err = result.expect_err("should reject expired valid_before");
    assert!(
        err.to_string().contains("expired"),
        "error should mention expiration, got: {err}"
    );
}

/// cosign_fee_payer_transaction rejects empty input.
#[tokio::test]
async fn test_cosign_rejects_empty_input() {
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());

    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

    let result = method
        .cosign_fee_payer_transaction(&[], method.fee_payer_signer.as_deref().unwrap(), fee_token)
        .await;

    let err = result.expect_err("should reject empty input");
    assert!(
        err.to_string().contains("Empty transaction bytes"),
        "error should mention empty, got: {err}"
    );
}

/// cosign_fee_payer_transaction rejects non-0x78 type byte.
#[tokio::test]
async fn test_cosign_rejects_wrong_type_byte() {
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());

    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

    let result = method
        .cosign_fee_payer_transaction(
            &[0x79, 0xc0], // wrong type byte
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await;

    let err = result.expect_err("should reject wrong type");
    assert!(
        err.to_string()
            .contains("Expected fee payer envelope (0x78)"),
        "error should mention 0x78, got: {err}"
    );
}

fn make_cosign_method(
    fee_payer_policy_override: Option<FeePayerPolicyOverride>,
) -> (
    ChargeMethod<impl alloy::providers::Provider<TempoNetwork> + Clone + 'static>,
    alloy::signers::local::PrivateKeySigner,
    Address,
) {
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let mut method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer.clone());
    if let Some(overrides) = fee_payer_policy_override {
        method = method.with_fee_payer_policy_override(overrides);
    }
    (method, fee_payer_signer, fee_token)
}

/// cosign_fee_payer_transaction rejects tx with max_fee_per_gas above policy.
#[tokio::test]
async fn test_cosign_rejects_excessive_max_fee_per_gas() {
    let overrides = FeePayerPolicyOverride {
        max_fee_per_gas: Some(500_000_000), // 0.5 gwei ceiling
        ..Default::default()
    };
    let (method, client_signer, fee_token) = make_cosign_method(Some(overrides));

    let mut tx = make_fee_payer_tx(60);
    tx.max_fee_per_gas = 600_000_000; // above 0.5 gwei ceiling
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let err = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect_err("should reject excessive max_fee_per_gas");
    assert!(err.to_string().contains("max_fee_per_gas"), "got: {err}");
}

/// cosign_fee_payer_transaction rejects tx with max_priority_fee_per_gas above policy.
#[tokio::test]
async fn test_cosign_rejects_excessive_max_priority_fee_per_gas() {
    let overrides = FeePayerPolicyOverride {
        max_priority_fee_per_gas: Some(100_000_000), // 0.1 gwei ceiling
        ..Default::default()
    };
    let (method, client_signer, fee_token) = make_cosign_method(Some(overrides));

    let mut tx = make_fee_payer_tx(60);
    tx.max_priority_fee_per_gas = 200_000_000; // above 0.1 gwei ceiling
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let err = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect_err("should reject excessive max_priority_fee_per_gas");
    assert!(
        err.to_string().contains("max_priority_fee_per_gas"),
        "got: {err}"
    );
}

/// cosign_fee_payer_transaction rejects tx whose total fee exceeds the policy cap.
#[tokio::test]
async fn test_cosign_rejects_excessive_total_fee() {
    // Set a 0.5 gwei max_fee_per_gas ceiling and default gas limit of 1M →
    // total_fee ceiling = 500_000_000_000_000. Build a tx that hits exactly
    // the total_fee limit by using a large gas_limit.
    let overrides = FeePayerPolicyOverride {
        max_total_fee: Some(500_000_000_000_000), // ceiling
        ..Default::default()
    };
    let (method, client_signer, fee_token) = make_cosign_method(Some(overrides));

    let mut tx = make_fee_payer_tx(60);
    // gas_limit=1_000_000, max_fee_per_gas=1_000_000_000 →
    // total = 1_000_000_000_000_000 > 500_000_000_000_000 ceiling
    tx.gas_limit = 1_000_000;
    tx.max_fee_per_gas = 1_000_000_000;
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let err = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect_err("should reject excessive total fee");
    assert!(err.to_string().contains("Total fee"), "got: {err}");
}

#[tokio::test]
async fn test_cosign_rejects_excessive_total_fee_under_gas_limit_and_fee_per_gas() {
    let (method, client_signer, fee_token) = make_cosign_method(None);

    let mut tx = make_fee_payer_tx(60);
    // gas_limit=1_999_999, max_fee_per_gas=99_000_000_000 →
    // total = 197_999_901_000_000_000 > 50_000_000_000_000_000 MAX_TOTAL_FEE_DEFAULT
    tx.gas_limit = 1_999_999;
    tx.max_fee_per_gas = 99_000_000_000;
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let err = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect_err("should reject excessive total fee");
    assert!(err.to_string().contains("Total fee"), "got: {err}");
}

/// cosign_fee_payer_transaction rejects tx with valid_before window beyond policy max.
#[tokio::test]
async fn test_cosign_rejects_excessive_validity_window() {
    let overrides = FeePayerPolicyOverride {
        max_validity_window_seconds: Some(30), // 30-second ceiling
        ..Default::default()
    };
    let (method, client_signer, fee_token) = make_cosign_method(Some(overrides));

    // valid_before = now + 120s → window of 120s > 30s ceiling
    let tx = make_fee_payer_tx(120);
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let err = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect_err("should reject excessive validity window");
    assert!(
        err.to_string().contains("valid_before window"),
        "got: {err}"
    );
}

/// All five limit policy override fields are respected when set together.
#[tokio::test]
async fn test_policy_override_all_fields_applied() {
    // Generous overrides — tx should pass all checks.
    let overrides = FeePayerPolicyOverride {
        max_gas: Some(2_000_000),
        max_fee_per_gas: Some(20_000_000_000),
        max_priority_fee_per_gas: Some(2_000_000_000),
        max_total_fee: Some(40_000_000_000_000_000),
        max_validity_window_seconds: Some(600),
    };
    let (method, client_signer, fee_token) = make_cosign_method(Some(overrides));

    let mut tx = make_fee_payer_tx(60);
    tx.gas_limit = 1_500_000; // within 2M override
    tx.max_fee_per_gas = 15_000_000_000; // within 20 gwei override
    tx.max_priority_fee_per_gas = 1_500_000_000; // within 2 gwei override
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect("cosign should succeed when all fields within override limits");
}

/// EIP-1559 invariant: priority fee cannot exceed max fee per gas.
#[tokio::test]
async fn test_cosign_rejects_priority_fee_above_max_fee() {
    let (method, client_signer, fee_token) = make_cosign_method(None);

    let mut tx = make_fee_payer_tx(60);
    // Both within policy ceilings, but priority > max_fee violates EIP-1559.
    tx.max_fee_per_gas = 1_000_000_000; // 1 gwei
    tx.max_priority_fee_per_gas = 2_000_000_000; // 2 gwei > max_fee_per_gas
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let err = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect_err("priority fee above max fee must be rejected");
    assert!(
        err.to_string()
            .contains("max_priority_fee_per_gas 2000000000 exceeds max_fee_per_gas"),
        "got: {err}"
    );
}

/// Moderato chain default raises `max_priority_fee_per_gas` to 50 gwei.
#[test]
fn test_policy_moderato_default_raises_priority_fee() {
    let tempo_mainnet = FeePayerPolicy::resolve(CHAIN_ID, None);
    let moderato = FeePayerPolicy::resolve(MODERATO_CHAIN_ID, None);

    assert_eq!(tempo_mainnet.max_priority_fee_per_gas, 10_000_000_000);
    assert_eq!(moderato.max_priority_fee_per_gas, 50_000_000_000);
    // All other fields should equal the mainnet default.
    assert_eq!(moderato.max_gas, tempo_mainnet.max_gas);
    assert_eq!(moderato.max_fee_per_gas, tempo_mainnet.max_fee_per_gas);
    assert_eq!(moderato.max_total_fee, tempo_mainnet.max_total_fee);
    assert_eq!(
        moderato.max_validity_window_seconds,
        tempo_mainnet.max_validity_window_seconds
    );
    assert!(FeePayerPolicy::default_allows_fee_token(
        CHAIN_ID,
        KnownTempoNetwork::Mainnet
            .default_currency()
            .parse::<Address>()
            .unwrap()
    ));
    // Mainnet also allows pathUSD, matching mppx's default fee tokens.
    assert!(FeePayerPolicy::default_allows_fee_token(
        CHAIN_ID,
        KnownTempoNetwork::Moderato
            .default_currency()
            .parse::<Address>()
            .unwrap()
    ));
    assert!(FeePayerPolicy::default_allows_fee_token(
        MODERATO_CHAIN_ID,
        KnownTempoNetwork::Moderato
            .default_currency()
            .parse::<Address>()
            .unwrap()
    ));
    assert!(!FeePayerPolicy::default_allows_fee_token(
        MODERATO_CHAIN_ID,
        KnownTempoNetwork::Mainnet
            .default_currency()
            .parse::<Address>()
            .unwrap()
    ));
    assert!(FeePayerPolicy::default_allows_fee_token(
        31337,
        DEFAULT_CURRENCY_TESTNET.parse::<Address>().unwrap()
    ));
}

#[tokio::test]
async fn test_cosign_rejects_non_allowlisted_fee_token() {
    let allowed_fee_tokens = vec![KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap()];
    let (method, client_signer, _) = make_cosign_method(None);
    let method = method.with_fee_payer_allowed_fee_tokens(allowed_fee_tokens);

    let tx = make_fee_payer_tx(60);
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    let err = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            KnownTempoNetwork::Moderato
                .default_currency()
                .parse::<Address>()
                .unwrap(),
        )
        .await
        .expect_err("cosign should reject non-allowlisted fee token");
    assert!(
        err.to_string()
            .contains("is not allowed by fee payer policy"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_cosign_uses_custom_fee_token_allowlist() {
    let allowed_fee_tokens = vec![KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap()];
    let (method, client_signer, fee_token) = make_cosign_method(None);
    let method = method.with_fee_payer_allowed_fee_tokens(allowed_fee_tokens);

    let tx = make_fee_payer_tx(60);
    let encoded = sign_and_encode_0x78(tx, &client_signer);

    method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect("cosign should accept a custom allowlisted fee token");
}

/// Sponsor MUST strip an attacker-injected wire access list: an honest
/// client signature over an empty-access-list tx is still cosigned, and
/// the broadcast 0x76 carries an empty access list.
#[tokio::test]
async fn test_cosign_strips_tampered_access_list() {
    use alloy::eips::eip2930::{AccessList, AccessListItem};
    use alloy::primitives::B256;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;

    use crate::protocol::methods::tempo::FeePayerEnvelope78;

    let client_signer = PrivateKeySigner::random();
    let fee_payer_signer = PrivateKeySigner::random();
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();

    // Honest tx with empty access list, signed by the client.
    let tx = make_fee_payer_tx(60);
    let signature: tempo_alloy::primitives::transaction::TempoSignature = client_signer
        .sign_hash_sync(&tx.signature_hash())
        .unwrap()
        .into();

    // Build envelope directly (from_signing_tx would strip) and inject
    // an attacker-controlled access list into the wire field.
    let envelope = FeePayerEnvelope78 {
        chain_id: tx.chain_id,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        max_fee_per_gas: tx.max_fee_per_gas,
        gas_limit: tx.gas_limit,
        calls: tx.calls.clone(),
        access_list: AccessList(vec![AccessListItem {
            address: Address::repeat_byte(0xaa),
            storage_keys: vec![B256::ZERO],
        }]),
        nonce_key: tx.nonce_key,
        nonce: tx.nonce,
        valid_before: tx.valid_before.map(|v| v.get()),
        valid_after: tx.valid_after.map(|v| v.get()),
        fee_token: tx.fee_token,
        sender: client_signer.address(),
        tempo_authorization_list: tx.tempo_authorization_list.clone(),
        key_authorization: tx.key_authorization.clone(),
        signature,
    };
    let envelope_bytes = envelope.encoded_envelope();

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

    let cosigned = method
        .cosign_fee_payer_transaction(
            &envelope_bytes,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect("sponsor must cosign tampered envelope");

    let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    assert!(
        signed.tx().access_list.is_empty(),
        "broadcast tx must have empty access list"
    );
    assert_eq!(signed.tx().fee_token, Some(fee_token));
}

// ==================== Sponsor fee-token selection ====================

fn fee_token_method(
    asserter: alloy::providers::mock::Asserter,
) -> ChargeMethod<impl alloy::providers::Provider<TempoNetwork> + Clone + 'static> {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);
    ChargeMethod::new(provider)
}

fn push_balance(asserter: &alloy::providers::mock::Asserter, balance: u64) {
    asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
        &U256::from(balance),
    )));
}

fn token(address: &str) -> Address {
    address.parse().unwrap()
}

#[tokio::test]
async fn test_resolve_fee_token_first_funded_allowlisted_token_wins() {
    use alloy::providers::mock::Asserter;

    let fee_payer = Address::repeat_byte(0xfe);

    // Mainnet defaults [pathUSD, USDC.e]: pathUSD empty, USDC.e funded.
    let asserter = Asserter::new();
    push_balance(&asserter, 0);
    push_balance(&asserter, 5);
    let method = fee_token_method(asserter.clone());
    let fee_token = method
        .resolve_fee_payer_fee_token(CHAIN_ID, fee_payer)
        .await
        .unwrap();
    assert_eq!(fee_token, token(USDC));
    assert!(asserter.read_q().is_empty());

    // Both funded: the first allowlisted token wins after one lookup.
    let asserter = Asserter::new();
    push_balance(&asserter, 7);
    let method = fee_token_method(asserter.clone());
    let fee_token = method
        .resolve_fee_payer_fee_token(CHAIN_ID, fee_payer)
        .await
        .unwrap();
    assert_eq!(fee_token, token(PATH_USD));
    assert!(asserter.read_q().is_empty());
}

#[tokio::test]
async fn test_resolve_fee_token_falls_back_to_first_allowed_when_none_funded() {
    use alloy::providers::mock::Asserter;

    let fee_payer = Address::repeat_byte(0xfe);

    let asserter = Asserter::new();
    push_balance(&asserter, 0);
    push_balance(&asserter, 0);
    let method = fee_token_method(asserter);
    assert_eq!(
        method
            .resolve_fee_payer_fee_token(CHAIN_ID, fee_payer)
            .await
            .unwrap(),
        token(PATH_USD)
    );

    // Failed balance lookups count as unfunded.
    let asserter = Asserter::new();
    asserter.push_failure_msg("rpc down");
    let method = fee_token_method(asserter);
    assert_eq!(
        method
            .resolve_fee_payer_fee_token(MODERATO_CHAIN_ID, fee_payer)
            .await
            .unwrap(),
        token(PATH_USD)
    );
}

#[tokio::test]
async fn test_resolve_fee_token_prefers_configured_token_without_rpc() {
    use alloy::providers::mock::Asserter;

    // No responses queued: any balance lookup would fail the call count below.
    let asserter = Asserter::new();
    let method = fee_token_method(asserter.clone()).with_fee_payer_fee_token(token(USDC));
    assert_eq!(
        method
            .resolve_fee_payer_fee_token(CHAIN_ID, Address::repeat_byte(0xfe))
            .await
            .unwrap(),
        token(USDC)
    );
}

#[tokio::test]
async fn test_resolve_fee_token_respects_explicit_allowlist() {
    use alloy::providers::mock::Asserter;

    let fee_payer = Address::repeat_byte(0xfe);
    let custom = Address::repeat_byte(0x99);

    // Only allowlisted tokens are queried, in allowlist order.
    let asserter = Asserter::new();
    push_balance(&asserter, 0);
    push_balance(&asserter, 1);
    let method = fee_token_method(asserter.clone())
        .with_fee_payer_allowed_fee_tokens(vec![token(USDC), custom]);
    assert_eq!(
        method
            .resolve_fee_payer_fee_token(CHAIN_ID, fee_payer)
            .await
            .unwrap(),
        custom
    );
    assert!(asserter.read_q().is_empty());

    let method = fee_token_method(Asserter::new()).with_fee_payer_allowed_fee_tokens(vec![]);
    let err = method
        .resolve_fee_payer_fee_token(CHAIN_ID, fee_payer)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("does not allow any fee tokens"));
}

#[tokio::test]
async fn test_configured_fee_token_outside_allowlist_is_rejected() {
    let (method, client_signer, _) = make_cosign_method(None);
    let method = method.with_fee_payer_fee_token(token(OUSD));
    let encoded = sign_and_encode_0x78(make_fee_payer_tx(60), &client_signer);

    // OUSD is never a default fee token, so co-signing refuses it...
    let err = method
        .cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_deref().unwrap(),
            token(OUSD),
        )
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("is not allowed by fee payer policy"));

    // ...and validation rejects the configured fee token before broadcast.
    let err = method
        .validate_fee_payer_transaction(&encoded, method.fee_payer_fee_token)
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("is not allowed by fee payer policy"));

    // Without a configured fee token, validation does not tie the fee token
    // to the charge currency.
    let (method, client_signer, _) = make_cosign_method(None);
    let encoded = sign_and_encode_0x78(make_fee_payer_tx(60), &client_signer);
    assert!(method
        .validate_fee_payer_transaction(&encoded, None)
        .is_ok());
}

/// Sponsored OUSD charge with default settings: the fee payer pays gas in
/// the first funded allowlisted token and the payment settles in OUSD.
async fn assert_sponsored_ousd_charge_succeeds(
    chain_id: u64,
    balances: &[u64],
    expected_fee_token: Address,
) {
    use alloy::providers::mock::Asserter;

    let ousd = token(OUSD);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(1_000_000u64);
    let challenge_id = "challenge-123";
    let realm = "api.example.com";
    let memo = attribution::encode(challenge_id, realm, None);

    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let mut tx = make_fee_payer_tx(60);
    tx.chain_id = chain_id;
    tx.calls = vec![tempo_alloy::primitives::transaction::Call {
        to: TxKind::Call(ousd),
        value: U256::ZERO,
        input: make_transfer_with_memo_input(recipient, amount, memo),
    }];
    let envelope = sign_and_encode_0x78(tx, &client_signer);
    let request = ChargeRequest {
        amount: amount.to_string(),
        currency: OUSD.to_string(),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({ "chainId": chain_id, "feePayer": true })),
        ..Default::default()
    };

    let asserter = Asserter::new();
    for &balance in balances {
        push_balance(&asserter, balance);
    }
    asserter.push_success(&serde_json::json!({
        "blocks": [{ "calls": [{ "returnData": "0x", "gasUsed": "0x5208", "status": "0x1" }] }]
    }));
    let tx_hash = B256::repeat_byte(0x11);
    let block_hash = B256::repeat_byte(0x22);
    let mut log =
        make_transfer_with_memo_log(ousd, client_signer.address(), recipient, amount, memo);
    log.as_object_mut().unwrap().extend(
        serde_json::json!({
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x1",
            "transactionHash": format!("{tx_hash:#x}"),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false,
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    asserter.push_success(&serde_json::json!({
        "type": "0x76",
        "status": "0x1",
        "cumulativeGasUsed": "0x5208",
        "logs": [log],
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "transactionHash": format!("{tx_hash:#x}"),
        "transactionIndex": "0x0",
        "blockHash": format!("{block_hash:#x}"),
        "blockNumber": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x1",
        "from": format!("{:#x}", client_signer.address()),
        "to": format!("{ousd:#x}"),
        "contractAddress": null,
        "feePayer": format!("{:#x}", fee_payer_signer.address()),
        "feeToken": format!("{expected_fee_token:#x}"),
    }));

    let store = Arc::new(crate::store::MemoryStore::new());
    let method = fee_token_method(asserter.clone())
        .with_fee_payer(fee_payer_signer.clone())
        .with_store(store.clone());

    let hash = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(&envelope),
            &request,
            None,
            chain_id,
            challenge_id,
            realm,
        )
        .await
        .expect("sponsored OUSD charge must succeed");
    assert_eq!(hash, tx_hash);
    assert!(
        asserter.read_q().is_empty(),
        "all mocked RPC calls consumed"
    );

    // The broadcast bytes are exactly the envelope co-signed with the
    // selected fee token (ECDSA signing is deterministic).
    let expected = method
        .cosign_fee_payer_transaction(&envelope, &fee_payer_signer, expected_fee_token)
        .await
        .unwrap();
    let decoded = tempo_alloy::primitives::AASigned::decode_2718(&mut &expected[..]).unwrap();
    assert_eq!(decoded.tx().fee_token, Some(expected_fee_token));
    let key = format!("mpp:charge:submission:{:#x}", keccak256(&expected));
    assert!(store.get(&key).await.unwrap().is_some());
}

#[tokio::test]
async fn test_sponsored_ousd_charge_on_mainnet_pays_gas_in_funded_allowlisted_token() {
    // pathUSD unfunded, USDC.e funded.
    assert_sponsored_ousd_charge_succeeds(CHAIN_ID, &[0, 42], token(USDC)).await;
    // pathUSD funded: first allowlisted token wins.
    assert_sponsored_ousd_charge_succeeds(CHAIN_ID, &[42], token(PATH_USD)).await;
}

#[tokio::test]
async fn test_sponsored_ousd_charge_on_moderato_pays_gas_in_path_usd() {
    assert_sponsored_ousd_charge_succeeds(MODERATO_CHAIN_ID, &[42], token(PATH_USD)).await;
    // Nothing funded: fall back to the first allowlisted token.
    assert_sponsored_ousd_charge_succeeds(MODERATO_CHAIN_ID, &[0], token(PATH_USD)).await;
}
