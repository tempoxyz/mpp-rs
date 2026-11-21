use super::*;

// ==================== Stripe tests ====================

#[cfg(feature = "stripe")]
fn test_stripe_mpp() -> Mpp<crate::protocol::methods::stripe::method::ChargeMethod> {
    use crate::server::{stripe, StripeConfig};

    Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: "sk_test_mock",
            network_id: "test-net",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .secret_key(TEST_SECRET),
    )
    .expect("failed to create stripe mpp")
}

#[cfg(feature = "stripe")]
#[tokio::test]
async fn test_stripe_verify_charge_rejects_credential_paid_for_cheaper_route() {
    let mpp = test_stripe_mpp();
    let cheap = mpp.stripe_charge("0.10").unwrap();
    let credential = PaymentCredential::new(
        cheap.to_echo(),
        serde_json::json!({ "spt": "spt_test_cheap" }),
    );

    // Rejected before the Stripe API is reached.
    let err = mpp
        .stripe_verify_charge(&credential, "1.00")
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(err.message.contains("Amount mismatch"), "{}", err.message);

    let expected = mpp
        .stripe_expected_charge_request("0.10", Default::default())
        .unwrap();
    assert_eq!(expected.amount, "10");
    assert_eq!(expected.currency, "usd");
}

#[cfg(feature = "stripe")]
#[test]
fn test_create_stripe_rejects_short_secret_key() {
    use crate::server::{stripe, StripeConfig};

    let err = Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key: "sk_test_mock",
            network_id: "test-net",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .secret_key(&"k".repeat(31)),
    )
    .err()
    .expect("31-byte key");
    assert!(err.to_string().contains("at least 32 bytes"), "{err}");
}

#[cfg(feature = "stripe")]
#[test]
fn test_stripe_challenge_has_method_details() {
    let mpp = test_stripe_mpp();
    let challenge = mpp.stripe_charge("1.00").unwrap();

    let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
    let details = &request["methodDetails"];
    assert_eq!(details["networkId"], "test-net");
    assert_eq!(details["paymentMethodTypes"], serde_json::json!(["card"]));
    assert_eq!(challenge.method.as_str(), "stripe");
    assert_eq!(challenge.intent.as_str(), "charge");
}

#[cfg(feature = "stripe")]
#[test]
fn test_stripe_charge_with_options_description() {
    use crate::server::StripeChargeOptions;

    let mpp = test_stripe_mpp();
    let challenge = mpp
        .stripe_charge_with_options(
            "0.50",
            StripeChargeOptions {
                description: Some("test desc"),
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(challenge.description, Some("test desc".to_string()));
    let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
    assert_eq!(request["description"], "test desc");
}

#[cfg(feature = "stripe")]
#[test]
fn test_stripe_charge_with_options_external_id() {
    use crate::server::StripeChargeOptions;

    let mpp = test_stripe_mpp();
    let challenge = mpp
        .stripe_charge_with_options(
            "0.50",
            StripeChargeOptions {
                external_id: Some("order-42"),
                ..Default::default()
            },
        )
        .unwrap();

    let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
    assert_eq!(request["externalId"], "order-42");
}

#[cfg(feature = "stripe")]
#[test]
fn test_stripe_charge_with_options_metadata() {
    use crate::server::StripeChargeOptions;

    let mpp = test_stripe_mpp();
    let mut metadata = std::collections::HashMap::new();
    metadata.insert("key1".to_string(), "val1".to_string());

    let challenge = mpp
        .stripe_charge_with_options(
            "0.50",
            StripeChargeOptions {
                metadata: Some(&metadata),
                ..Default::default()
            },
        )
        .unwrap();

    let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
    assert_eq!(request["methodDetails"]["metadata"]["key1"], "val1");
}

#[cfg(feature = "stripe")]
#[test]
fn test_stripe_charge_with_options_custom_expires() {
    use crate::server::StripeChargeOptions;

    let mpp = test_stripe_mpp();
    let challenge = mpp
        .stripe_charge_with_options(
            "0.50",
            StripeChargeOptions {
                expires: Some("2099-01-01T00:00:00Z"),
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(challenge.expires, Some("2099-01-01T00:00:00Z".to_string()));
}

#[cfg(feature = "stripe")]
#[test]
fn test_stripe_charge_delegates_to_with_options() {
    let mpp = test_stripe_mpp();
    let challenge = mpp.stripe_charge("0.10").unwrap();

    let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
    assert!(request["methodDetails"].is_object());
    assert!(challenge.description.is_none());
}

#[cfg(feature = "stripe")]
#[test]
fn test_stripe_charge_with_body_binds_request_body_digest() {
    let mpp = test_stripe_mpp();
    let body = br#"{"query":"paid"}"#;
    let challenge = mpp.stripe_charge_with_body("0.10", body).unwrap();

    let digest = crate::body_digest::compute(body);
    assert_eq!(challenge.digest.as_deref(), Some(digest.as_str()));
    assert!(challenge.verify(TEST_SECRET));

    let mut tampered = challenge.clone();
    tampered.digest = Some(crate::body_digest::compute(br#"{"query":"tampered"}"#));
    assert!(!tampered.verify(TEST_SECRET));
}

#[cfg(feature = "stripe")]
#[test]
fn test_stripe_charge_with_options_and_body_preserves_options() {
    use crate::server::StripeChargeOptions;

    let mpp = test_stripe_mpp();
    let body = br#"{"query":"paid"}"#;
    let challenge = mpp
        .stripe_charge_with_options_and_body(
            "0.50",
            StripeChargeOptions {
                description: Some("body-bound stripe charge"),
                external_id: Some("order-42"),
                ..Default::default()
            },
            body,
        )
        .unwrap();

    let digest = crate::body_digest::compute(body);
    assert_eq!(challenge.digest.as_deref(), Some(digest.as_str()));
    assert_eq!(
        challenge.description.as_deref(),
        Some("body-bound stripe charge")
    );
    assert!(challenge.verify(TEST_SECRET));
    let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
    assert_eq!(request["externalId"], "order-42");
}
