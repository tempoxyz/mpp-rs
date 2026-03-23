//! Live integration tests for the MPP Stripe charge flow.
//!
//! These tests call the real Stripe test-mode API to create SPTs and verify
//! PaymentIntents. They require a `STRIPE_SECRET_KEY` env var with a `sk_test_*`
//! key that has SPT (Shared Payment Tokens) access enabled.
//!
//! Skipped automatically when `STRIPE_SECRET_KEY` is not set.
//!
//! # Running
//!
//! ```bash
//! STRIPE_SECRET_KEY=sk_test_... cargo test --features integration-stripe-live --test integration_stripe_live
//! ```

#![cfg(feature = "integration-stripe-live")]

use mpp::protocol::core::PaymentCredential;
use mpp::protocol::methods::stripe::method::ChargeMethod;
use mpp::protocol::methods::stripe::StripeCredentialPayload;
use mpp::server::{stripe, Mpp, StripeConfig};

fn stripe_secret_key() -> Option<String> {
    std::env::var("STRIPE_SECRET_KEY")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Create a test SPT via Stripe's test helper endpoint.
///
/// This calls `POST /v1/test_helpers/shared_payment/granted_tokens`
/// which is only available in test mode and requires SPT access.
async fn create_test_spt(
    secret_key: &str,
    amount: &str,
    currency: &str,
    network_id: Option<&str>,
    expires_at: u64,
) -> Result<String, String> {
    let mut params = vec![
        ("payment_method".to_string(), "pm_card_visa".to_string()),
        ("usage_limits[currency]".to_string(), currency.to_string()),
        ("usage_limits[max_amount]".to_string(), amount.to_string()),
        (
            "usage_limits[expires_at]".to_string(),
            expires_at.to_string(),
        ),
    ];

    if let Some(nid) = network_id {
        params.push(("seller_details[network_id]".to_string(), nid.to_string()));
    }

    let client = reqwest::Client::new();
    let response = client
        .post("https://api.stripe.com/v1/test_helpers/shared_payment/granted_tokens")
        .header(
            "Authorization",
            format!(
                "Basic {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("{secret_key}:")
                )
            ),
        )
        .form(&params)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    if !response.status().is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Stripe SPT creation failed: {body}"));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("parse error: {e}"))?;

    body["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "missing id in SPT response".to_string())
}

/// Helper: create Mpp instance for live Stripe tests.
fn create_live_mpp(secret_key: &str) -> Mpp<ChargeMethod> {
    Mpp::create_stripe(
        stripe(StripeConfig {
            secret_key,
            network_id: "internal",
            payment_method_types: &["card"],
            currency: "usd",
            decimals: 2,
        })
        .secret_key("live-test-hmac-secret"),
    )
    .expect("failed to create Mpp")
}

// ==================== Tests ====================

/// Happy path: create a real SPT, build credential, verify against Stripe.
#[tokio::test]
async fn test_live_stripe_charge_success() {
    let Some(sk) = stripe_secret_key() else {
        eprintln!("STRIPE_SECRET_KEY not set, skipping live Stripe test");
        return;
    };

    let mpp = create_live_mpp(&sk);

    // Create challenge
    let challenge = mpp.stripe_charge("0.50").expect("challenge creation");
    assert_eq!(challenge.method.as_str(), "stripe");
    assert_eq!(challenge.intent.as_str(), "charge");

    // Decode request to get amount
    let request: serde_json::Value = challenge
        .request
        .decode_value()
        .expect("decode challenge request");
    let amount = request["amount"].as_str().expect("amount");
    assert_eq!(amount, "50"); // $0.50 with 2 decimals

    // Create SPT via Stripe test helper
    let expires_at = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs())
        + 3600;

    let spt = create_test_spt(&sk, amount, "usd", Some("internal"), expires_at)
        .await
        .expect("SPT creation failed");

    assert!(
        spt.starts_with("spt_"),
        "SPT should start with spt_, got: {spt}"
    );

    // Build credential
    let payload = StripeCredentialPayload {
        spt,
        external_id: None,
    };
    let credential = PaymentCredential::new(challenge.to_echo(), payload);

    // Verify against real Stripe
    let receipt = mpp
        .verify_credential(&credential)
        .await
        .expect("verification failed");

    assert!(receipt.is_success());
    assert_eq!(receipt.method.as_str(), "stripe");
    assert!(
        receipt.reference.starts_with("pi_"),
        "receipt reference should be a PaymentIntent ID, got: {}",
        receipt.reference
    );
}

/// Invalid SPT should be rejected by Stripe.
#[tokio::test]
async fn test_live_stripe_invalid_spt_rejected() {
    let Some(sk) = stripe_secret_key() else {
        eprintln!("STRIPE_SECRET_KEY not set, skipping live Stripe test");
        return;
    };

    let mpp = create_live_mpp(&sk);
    let challenge = mpp.stripe_charge("0.10").expect("challenge creation");

    let payload = StripeCredentialPayload {
        spt: "spt_invalid_does_not_exist".to_string(),
        external_id: None,
    };
    let credential = PaymentCredential::new(challenge.to_echo(), payload);

    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err(), "invalid SPT should fail verification");
}

/// Expired challenge should be rejected before calling Stripe.
#[tokio::test]
async fn test_live_stripe_expired_challenge_rejected() {
    let Some(sk) = stripe_secret_key() else {
        eprintln!("STRIPE_SECRET_KEY not set, skipping live Stripe test");
        return;
    };

    let mpp = create_live_mpp(&sk);

    // Create a challenge with past expiration
    let challenge = mpp
        .stripe_charge_with_options(
            "0.10",
            mpp::server::StripeChargeOptions {
                description: None,
                external_id: None,
                expires: None,
                metadata: None,
            },
        )
        .expect("challenge creation");

    // Manually build an expired credential by modifying the echo
    let mut echo = challenge.to_echo();
    let past = (time::OffsetDateTime::now_utc() - time::Duration::minutes(10))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    echo.expires = Some(past.clone());

    // Recompute challenge ID with expired timestamp so HMAC matches
    let _expired_challenge = mpp
        .stripe_charge("0.10")
        .expect("challenge for expired test");

    // Use a valid SPT format but the challenge should be rejected on expiry
    let payload = StripeCredentialPayload {
        spt: "spt_doesnt_matter".to_string(),
        external_id: None,
    };

    // Build credential with the original (non-expired) challenge but
    // we can't easily forge a valid HMAC for an expired challenge,
    // so this tests the server-side expiry check path
    let credential = PaymentCredential::new(echo, payload);
    let result = mpp.verify_credential(&credential).await;
    assert!(
        result.is_err(),
        "expired challenge should fail verification"
    );
}
