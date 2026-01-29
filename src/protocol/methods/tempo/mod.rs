//! Tempo-specific types and helpers for Web Payment Auth.
//!
//! This module provides Tempo blockchain-specific implementations.
//! Tempo uses chain_id 42431 (Moderato testnet, per IETF spec) and supports TIP-20 tokens.
//!
//! # Types
//!
//! - [`TempoMethodDetails`]: Tempo-specific method details (2D nonces, fee payer)
//! - [`TempoChargeExt`]: Extension trait for ChargeRequest with Tempo-specific accessors
//! - [`TempoTransactionRequest`]: Transaction request builder (from tempo-alloy)
//! - [`TempoTransaction`]: Full Tempo transaction type 0x76 (from tempo-primitives)
//!
//! # Constants
//!
//! - [`CHAIN_ID`]: Tempo Moderato chain ID (42431)
//! - [`METHOD_NAME`]: Payment method name ("tempo")
//!
//! # Challenge Helpers
//!
//! For server-side challenge creation, use the helper functions:
//!
//! ```
//! use mpay::protocol::methods::tempo;
//!
//! // Simple charge challenge (secret_key required for HMAC-bound ID)
//! let challenge = tempo::charge_challenge(
//!     "my-server-secret",
//!     "api.example.com",
//!     "1000000",
//!     "0x20c0000000000000000000000000000000000001",
//!     "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
//! ).unwrap();
//!
//! // With full options (fee payer, description, etc.)
//! use mpay::protocol::intents::ChargeRequest;
//! let request = ChargeRequest {
//!     amount: "1000000".into(),
//!     currency: "0x20c0000000000000000000000000000000000001".into(),
//!     recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
//!     method_details: Some(serde_json::json!({"feePayer": true})),
//!     ..Default::default()
//! };
//! let challenge = tempo::charge_challenge_with_options(
//!     "my-server-secret",
//!     "api.example.com",
//!     &request,
//!     None,
//!     Some("API access fee"),
//! ).unwrap();
//! ```
//!
//! # Transaction Format
//!
//! All Tempo payments use TempoTransaction (type 0x76) format. The client builds
//! and signs a TempoTransaction, returns it as a `transaction` credential, and the
//! server submits it via `tempo_sendTransaction`.
//!
//! # Fee Sponsorship
//!
//! When `feePayer: true` is set, the server forwards the signed transaction to a
//! fee payer service (either `feePayerUrl` or the default testnet sponsor) which
//! adds its signature and broadcasts.
//!
//! ```
//! use mpay::protocol::intents::ChargeRequest;
//! use mpay::protocol::methods::tempo::TempoChargeExt;
//!
//! # let req = ChargeRequest {
//! #     amount: "1000".into(), currency: "0x".into(), recipient: None,
//! #     expires: None, description: None, external_id: None,
//! #     method_details: Some(serde_json::json!({
//! #         "feePayer": true
//! #     })),
//! # };
//! if req.fee_payer() {
//!     // Client should build and sign a TempoTransaction (0x76),
//!     // then return it as a "transaction" credential.
//!     // The server will add fee payer signature and broadcast.
//! }
//! ```
//!
//! # Examples
//!
//! ```
//! use mpay::protocol::core::parse_www_authenticate;
//! use mpay::protocol::intents::ChargeRequest;
//! use mpay::protocol::methods::tempo::{TempoChargeExt, CHAIN_ID};
//!
//! let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QifQ""#;
//! let challenge = parse_www_authenticate(header).unwrap();
//! let req: ChargeRequest = challenge.request.decode().unwrap();
//! assert!(!req.fee_payer());
//! assert_eq!(CHAIN_ID, 42431);
//! ```

pub mod charge;
pub mod transaction;
pub mod types;

#[cfg(feature = "server")]
pub mod method;

pub use charge::TempoChargeExt;
pub use transaction::{
    Call, SignatureType, TempoTransaction, TempoTransactionRequest, TEMPO_SEND_TRANSACTION_METHOD,
    TEMPO_TX_TYPE_ID,
};
pub use types::TempoMethodDetails;

#[cfg(feature = "server")]
pub use method::ChargeMethod;

/// Tempo Moderato testnet chain ID.
pub const CHAIN_ID: u64 = 42431;

/// Payment method name for Tempo.
pub const METHOD_NAME: &str = "tempo";

/// Charge intent name.
pub const INTENT_CHARGE: &str = "charge";

/// Create a Tempo charge challenge with minimal parameters.
///
/// This is the simplest way to create a payment challenge for the Tempo network.
/// For more control over the request (fee payer, expiration, etc.), use
/// [`charge_challenge_with_options`].
///
/// # Arguments
///
/// * `secret_key` - Server secret key for HMAC-bound challenge ID
/// * `realm` - Protection space / realm (e.g., "api.example.com")
/// * `amount` - Amount in atomic units (e.g., "1000000" for 1 USDC)
/// * `currency` - Token address (e.g., alphaUSD address)
/// * `recipient` - Recipient address for the payment
///
/// # Examples
///
/// ```
/// use mpay::protocol::methods::tempo;
///
/// let challenge = tempo::charge_challenge(
///     "my-server-secret",
///     "api.example.com",
///     "1000000",
///     "0x20c0000000000000000000000000000000000001",
///     "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
/// ).unwrap();
///
/// assert_eq!(challenge.method.as_str(), "tempo");
/// assert_eq!(challenge.intent.as_str(), "charge");
/// ```
#[must_use = "this returns a new PaymentChallenge and does not have side effects"]
pub fn charge_challenge(
    secret_key: &str,
    realm: &str,
    amount: &str,
    currency: &str,
    recipient: &str,
) -> crate::error::Result<crate::protocol::core::PaymentChallenge> {
    let request = crate::protocol::intents::ChargeRequest {
        amount: amount.to_string(),
        currency: currency.to_string(),
        recipient: Some(recipient.to_string()),
        ..Default::default()
    };

    charge_challenge_with_options(secret_key, realm, &request, None, None)
}

/// Create a Tempo charge challenge with full options.
///
/// Use this when you need more control over the challenge, such as:
/// - Fee sponsorship (`feePayer: true` in method_details)
/// - Custom expiration times
/// - Descriptions or external IDs
///
/// # Arguments
///
/// * `secret_key` - Server secret key for HMAC-bound challenge ID
/// * `realm` - Protection space / realm (e.g., "api.example.com")
/// * `request` - A fully configured [`ChargeRequest`](crate::protocol::intents::ChargeRequest)
/// * `expires` - Optional challenge expiration (ISO 8601)
/// * `description` - Optional human-readable description
///
/// # Examples
///
/// ```
/// use mpay::protocol::intents::ChargeRequest;
/// use mpay::protocol::methods::tempo;
///
/// let request = ChargeRequest {
///     amount: "1000000".into(),
///     currency: "0x20c0000000000000000000000000000000000001".into(),
///     recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
///     method_details: Some(serde_json::json!({"feePayer": true})),
///     ..Default::default()
/// };
///
/// let challenge = tempo::charge_challenge_with_options(
///     "my-server-secret",
///     "api.example.com",
///     &request,
///     None,
///     Some("API access fee"),
/// ).unwrap();
///
/// assert_eq!(challenge.description, Some("API access fee".to_string()));
/// ```
pub fn charge_challenge_with_options(
    secret_key: &str,
    realm: &str,
    request: &crate::protocol::intents::ChargeRequest,
    expires: Option<&str>,
    description: Option<&str>,
) -> crate::error::Result<crate::protocol::core::PaymentChallenge> {
    use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

    let encoded_request = Base64UrlJson::from_typed(request)?;

    // Per spec: challenge ID MUST be bound to challenge parameters via HMAC-SHA256.
    let id = generate_challenge_id(
        secret_key,
        realm,
        METHOD_NAME,
        INTENT_CHARGE,
        encoded_request.raw(),
        expires,
        None,
    );

    Ok(PaymentChallenge {
        id,
        realm: realm.to_string(),
        method: METHOD_NAME.into(),
        intent: INTENT_CHARGE.into(),
        request: encoded_request,
        expires: expires.map(|s| s.to_string()),
        description: description.map(|s| s.to_string()),
        digest: None,
    })
}

/// Generate a challenge ID using HMAC-SHA256 (cross-SDK compatible).
///
/// This function generates challenge IDs that are compatible with TypeScript and Python SDKs.
/// The algorithm uses HMAC-SHA256 with a pipe-delimited input format.
///
/// # Arguments
///
/// * `secret_key` - Server secret key for HMAC
/// * `realm` - Protection space / realm
/// * `method` - Payment method name
/// * `intent` - Intent name
/// * `request` - Base64url-encoded request JSON
/// * `expires` - Optional expiration timestamp
/// * `digest` - Optional request body digest
///
/// # Returns
///
/// Base64url-encoded HMAC-SHA256 hash (no padding)
///
/// # Example
///
/// ```
/// use mpay::protocol::methods::tempo::generate_challenge_id;
///
/// let id = generate_challenge_id(
///     "my-secret-key",
///     "api.example.com",
///     "tempo",
///     "charge",
///     "eyJhbW91bnQiOiIxMDAwMDAwIn0",
///     None,
///     None,
/// );
/// ```
pub fn generate_challenge_id(
    secret_key: &str,
    realm: &str,
    method: &str,
    intent: &str,
    request: &str,
    expires: Option<&str>,
    digest: Option<&str>,
) -> String {
    use crate::protocol::core::base64url_encode;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let hmac_input = format!(
        "{}|{}|{}|{}|{}|{}",
        realm,
        method,
        intent,
        request,
        expires.unwrap_or(""),
        digest.unwrap_or("")
    );

    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(hmac_input.as_bytes());
    let result = mac.finalize();

    base64url_encode(&result.into_bytes())
}

/// Generate a challenge ID from a JSON request value using HMAC-SHA256.
///
/// This is a convenience function that serializes the request to compact JSON,
/// base64url encodes it, and generates the challenge ID.
///
/// # Arguments
///
/// * `secret_key` - Server secret key for HMAC
/// * `realm` - Protection space / realm
/// * `method` - Payment method name
/// * `intent` - Intent name
/// * `request` - Request as a serde_json::Value
/// * `expires` - Optional expiration timestamp
/// * `digest` - Optional request body digest
///
/// # Example
///
/// ```
/// use mpay::protocol::methods::tempo::generate_challenge_id_from_request;
/// use serde_json::json;
///
/// let id = generate_challenge_id_from_request(
///     "my-secret-key",
///     "api.example.com",
///     "tempo",
///     "charge",
///     &json!({
///         "amount": "1000000",
///         "currency": "0x20c0000000000000000000000000000000000001",
///         "recipient": "0x1234567890abcdef1234567890abcdef12345678"
///     }),
///     None,
///     None,
/// ).unwrap();
/// ```
pub fn generate_challenge_id_from_request(
    secret_key: &str,
    realm: &str,
    method: &str,
    intent: &str,
    request: &serde_json::Value,
    expires: Option<&str>,
    digest: Option<&str>,
) -> crate::error::Result<String> {
    use crate::protocol::core::base64url_encode;

    let request_json = serde_json::to_string(request)?;
    let request_b64 = base64url_encode(request_json.as_bytes());

    Ok(generate_challenge_id(
        secret_key,
        realm,
        method,
        intent,
        &request_b64,
        expires,
        digest,
    ))
}

/// Parse an ISO 8601 timestamp string (e.g. "2024-01-15T12:00:00Z") to Unix timestamp.
#[cfg(feature = "server")]
pub(crate) fn parse_iso8601_timestamp(s: &str) -> Option<u64> {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    OffsetDateTime::parse(s.trim(), &Iso8601::DEFAULT)
        .ok()
        .map(|dt| dt.unix_timestamp() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-secret-key";

    #[test]
    fn test_challenge_id_is_deterministic() {
        let challenge1 = charge_challenge(
            TEST_SECRET,
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        let challenge2 = charge_challenge(
            TEST_SECRET,
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        assert_eq!(
            challenge1.id, challenge2.id,
            "Same parameters should produce same challenge ID"
        );
    }

    #[test]
    fn test_challenge_id_differs_for_different_params() {
        let challenge1 = charge_challenge(
            TEST_SECRET,
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        let challenge2 = charge_challenge(
            TEST_SECRET,
            "api.example.com",
            "2000000", // Different amount
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        assert_ne!(
            challenge1.id, challenge2.id,
            "Different parameters should produce different challenge IDs"
        );
    }

    #[test]
    fn test_challenge_id_differs_for_different_realm() {
        let challenge1 = charge_challenge(
            TEST_SECRET,
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        let challenge2 = charge_challenge(
            TEST_SECRET,
            "api.other.com", // Different realm
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        assert_ne!(
            challenge1.id, challenge2.id,
            "Different realms should produce different challenge IDs"
        );
    }

    #[test]
    fn test_challenge_id_format() {
        let challenge = charge_challenge(
            TEST_SECRET,
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        // Base64url-encoded SHA256 hash is 43 characters (256 bits / 6 bits per char, no padding)
        assert_eq!(
            challenge.id.len(),
            43,
            "ID should be 43 base64url characters"
        );
        assert!(
            challenge
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "ID should only contain base64url characters"
        );
    }

    #[test]
    fn test_challenge_id_differs_for_different_secret() {
        let challenge1 = charge_challenge(
            "secret-one",
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        let challenge2 = charge_challenge(
            "secret-two", // Different secret
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        assert_ne!(
            challenge1.id, challenge2.id,
            "Different secrets should produce different challenge IDs"
        );
    }

    /// Cross-SDK compatibility tests using conformance test vectors.
    /// These test cases are from mpay-sdks/conformance/vectors/challenge-id.json
    /// and verify that Rust produces the same challenge IDs as TypeScript and Python.
    mod cross_sdk_compatibility {
        use super::*;
        use serde_json::json;

        #[test]
        fn test_basic_charge() {
            let id = generate_challenge_id_from_request(
                "test-secret-key-12345",
                "api.example.com",
                "tempo",
                "charge",
                &json!({
                    "amount": "1000000",
                    "currency": "0x20c0000000000000000000000000000000000001",
                    "recipient": "0x1234567890abcdef1234567890abcdef12345678"
                }),
                None,
                None,
            )
            .unwrap();

            assert_eq!(id, "4Y_7cCtNrnPq0ujXFLOPsk4DRMctIFYxijKxrY5uob0");
        }

        #[test]
        fn test_with_expires() {
            let id = generate_challenge_id_from_request(
                "test-secret-key-12345",
                "api.example.com",
                "tempo",
                "charge",
                &json!({
                    "amount": "5000000",
                    "currency": "0x20c0000000000000000000000000000000000001",
                    "recipient": "0xabcdef1234567890abcdef1234567890abcdef12"
                }),
                Some("2026-01-29T12:00:00Z"),
                None,
            )
            .unwrap();

            assert_eq!(id, "02h24ab0XjVsKFwbyhz8HU9FacoT-21zV4FokI2U4YI");
        }

        #[test]
        fn test_with_digest() {
            let id = generate_challenge_id_from_request(
                "my-server-secret",
                "payments.example.org",
                "tempo",
                "charge",
                &json!({
                    "amount": "250000",
                    "currency": "USD",
                    "recipient": "0x9999999999999999999999999999999999999999"
                }),
                None,
                Some("sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE="),
            )
            .unwrap();

            assert_eq!(id, "EAX2sqwdeg8Km8LIKRBFhM5xDQvEgIlbTif9FKBsOiU");
        }

        #[test]
        fn test_full_challenge() {
            let id = generate_challenge_id_from_request(
                "production-secret-abc123",
                "api.tempo.xyz",
                "tempo",
                "charge",
                &json!({
                    "amount": "10000000",
                    "currency": "0x20c0000000000000000000000000000000000001",
                    "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                    "description": "API access fee",
                    "externalId": "order-12345"
                }),
                Some("2026-02-01T00:00:00Z"),
                Some("sha-256=abc123def456"),
            )
            .unwrap();

            assert_eq!(id, "9uqa-bDFwDBiMIgJF-hytstRW_YgjpBUDCo5_SMSqG4");
        }

        #[test]
        fn test_different_secret_different_id() {
            let id = generate_challenge_id_from_request(
                "different-secret-key",
                "api.example.com",
                "tempo",
                "charge",
                &json!({
                    "amount": "1000000",
                    "currency": "0x20c0000000000000000000000000000000000001",
                    "recipient": "0x1234567890abcdef1234567890abcdef12345678"
                }),
                None,
                None,
            )
            .unwrap();

            assert_eq!(id, "GaC7Gn_Fbbq98Tw-Eb7z4FadriU7GzNrAyC7ZcY3VRI");
        }

        #[test]
        fn test_empty_request() {
            let id = generate_challenge_id_from_request(
                "test-key",
                "test.example.com",
                "tempo",
                "authorize",
                &json!({}),
                None,
                None,
            )
            .unwrap();

            assert_eq!(id, "jUTqTVe3kCv5rVizv1XBCs9qKCLg4AZLwBUnk4N3MR8");
        }

        #[test]
        fn test_unicode_in_description() {
            let id = generate_challenge_id_from_request(
                "unicode-test-key",
                "api.example.com",
                "tempo",
                "charge",
                &json!({
                    "amount": "100",
                    "currency": "EUR",
                    "recipient": "0x1111111111111111111111111111111111111111",
                    "description": "Payment for café ☕"
                }),
                None,
                None,
            )
            .unwrap();

            assert_eq!(id, "76lyru2p7i7Xw6fGTJtWzd9c7Z6mt33LIW7968Mlkz8");
        }

        #[test]
        fn test_nested_method_details() {
            let id = generate_challenge_id_from_request(
                "nested-test-key",
                "api.tempo.xyz",
                "tempo",
                "charge",
                &json!({
                    "amount": "5000000",
                    "currency": "0x20c0000000000000000000000000000000000001",
                    "recipient": "0x2222222222222222222222222222222222222222",
                    "methodDetails": {
                        "chainId": 42431,
                        "feePayer": true
                    }
                }),
                None,
                None,
            )
            .unwrap();

            assert_eq!(id, "dyItTtUU31Gp2ckWrYXoeB2wZtS1OTVpXw81D_blwuk");
        }
    }
}
