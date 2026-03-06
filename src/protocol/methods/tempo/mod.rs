//! Tempo-specific types and helpers for Web Payment Auth.
//!
//! This module provides Tempo blockchain-specific implementations.
//! Tempo mainnet uses chain_id 4217; Moderato testnet uses 42431. Both support TIP-20 tokens.
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
//! - [`CHAIN_ID`]: Tempo mainnet chain ID (4217)
//! - [`MODERATO_CHAIN_ID`]: Tempo Moderato testnet chain ID (42431)
//! - [`METHOD_NAME`]: Payment method name ("tempo")
//!
//! # Challenge Helpers
//!
//! For server-side challenge creation, use the helper functions:
//!
//! ```
//! use mpp::protocol::methods::tempo;
//!
//! // Simple charge challenge with HMAC-bound ID
//! let challenge = tempo::charge_challenge(
//!     "my-server-secret",
//!     "api.example.com",
//!     "1000000",
//!     "0x20c0000000000000000000000000000000000000",
//!     "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
//! ).unwrap();
//!
//! // With full options (fee payer, description, etc.)
//! use mpp::protocol::intents::ChargeRequest;
//! let request = ChargeRequest {
//!     amount: "1000000".into(),
//!     currency: "0x20c0000000000000000000000000000000000000".into(),
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
//! use mpp::protocol::intents::ChargeRequest;
//! use mpp::protocol::methods::tempo::TempoChargeExt;
//!
//! # let req = ChargeRequest {
//! #     amount: "1000".into(), currency: "0x".into(), recipient: None,
//! #     description: None, external_id: None,
//! #     decimals: None,
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
//! use mpp::protocol::core::parse_www_authenticate;
//! use mpp::protocol::intents::ChargeRequest;
//! use mpp::protocol::methods::tempo::{TempoChargeExt, CHAIN_ID, MODERATO_CHAIN_ID};
//!
//! let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QifQ""#;
//! let challenge = parse_www_authenticate(header).unwrap();
//! let req: ChargeRequest = challenge.request.decode().unwrap();
//! assert!(!req.fee_payer());
//! assert_eq!(CHAIN_ID, 4217);
//! assert_eq!(MODERATO_CHAIN_ID, 42431);
//! ```

pub mod charge;
pub mod fee_payer_envelope;
pub mod network;
pub mod session;
pub mod session_receipt;
pub mod transaction;
pub mod types;
pub mod voucher;

#[cfg(feature = "server")]
pub mod method;
#[cfg(feature = "server")]
pub mod session_method;

pub use charge::TempoChargeExt;
pub use fee_payer_envelope::{FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID};
pub use network::TempoNetwork;
pub use session::{SessionCredentialPayload, TempoSessionExt, TempoSessionMethodDetails};
pub use session_receipt::SessionReceipt;

/// Deprecated: use [`session_receipt`] instead. Remove in next major version.
#[deprecated(since = "0.5.0", note = "renamed to session_receipt")]
pub use session_receipt as stream_receipt;

/// Deprecated: use [`SessionReceipt`] instead. Remove in next major version.
#[deprecated(since = "0.5.0", note = "renamed to SessionReceipt")]
pub type StreamReceipt = SessionReceipt;
pub use transaction::{
    Call, SignatureType, TempoTransaction, TempoTransactionRequest, TEMPO_SEND_TRANSACTION_METHOD,
    TEMPO_TX_TYPE_ID,
};
pub use types::TempoMethodDetails;
#[cfg(feature = "evm")]
pub use voucher::{compute_channel_id, sign_voucher, DOMAIN_NAME, DOMAIN_VERSION};

#[cfg(feature = "server")]
pub use method::ChargeMethod;
#[cfg(feature = "server")]
pub use session_method::{
    ChannelState, ChannelStore, InMemoryChannelStore, SessionMethod, SessionMethodConfig,
};

/// Tempo mainnet chain ID.
pub const CHAIN_ID: u64 = 4217;

/// Tempo Moderato testnet chain ID.
pub const MODERATO_CHAIN_ID: u64 = 42431;

/// Default RPC URL for Tempo mainnet.
pub const DEFAULT_RPC_URL: &str = "https://rpc.tempo.xyz";

/// USDC currency address (USDC.e on Tempo mainnet).
pub const USDC: &str = "0x20C000000000000000000000b9537d11c60E8b50";

/// pathUSD currency address.
pub const PATH_USD: &str = "0x20c0000000000000000000000000000000000000";

/// Default currency address for Tempo mainnet (USDC).
pub const DEFAULT_CURRENCY_MAINNET: &str = USDC;

/// Default currency address for Tempo testnet (pathUSD).
pub const DEFAULT_CURRENCY_TESTNET: &str = PATH_USD;

/// Default currency address (USDC on mainnet).
#[deprecated(
    since = "0.6.0",
    note = "use DEFAULT_CURRENCY_MAINNET or DEFAULT_CURRENCY_TESTNET"
)]
pub const DEFAULT_CURRENCY: &str = USDC;

/// Default challenge expiration in minutes.
pub const DEFAULT_EXPIRES_MINUTES: u64 = 5;

/// Payment method name for Tempo.
pub const METHOD_NAME: &str = "tempo";

/// Charge intent name.
pub const INTENT_CHARGE: &str = "charge";

/// Session intent name.
pub const INTENT_SESSION: &str = "session";

/// Create a Tempo charge challenge with minimal parameters.
///
/// This is the simplest way to create a payment challenge for the Tempo network.
/// For more control over the request (fee payer, expiration, etc.), use
/// [`charge_challenge_with_options`].
///
/// # Arguments
///
/// * `secret_key` - Server secret key for HMAC-bound challenge ID.
///   Enables stateless verification of payment credentials.
/// * `realm` - Protection space / realm (e.g., "api.example.com")
/// * `amount` - Amount in atomic units (e.g., "1000000" for 1 pathUSD)
/// * `currency` - Token address (e.g., pathUSD address)
/// * `recipient` - Recipient address for the payment
///
/// # Examples
///
/// ```
/// use mpp::protocol::methods::tempo;
///
/// let challenge = tempo::charge_challenge(
///     "my-server-secret",
///     "api.example.com",
///     "1000000",
///     "0x20c0000000000000000000000000000000000000",
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
/// * `secret_key` - Server secret key for HMAC-bound challenge ID.
///   Enables stateless verification of payment credentials.
/// * `realm` - Protection space / realm (e.g., "api.example.com")
/// * `request` - A fully configured [`ChargeRequest`](crate::protocol::intents::ChargeRequest)
/// * `expires` - Optional challenge expiration (ISO 8601)
/// * `description` - Optional human-readable description
///
/// # Examples
///
/// ```
/// use mpp::protocol::intents::ChargeRequest;
/// use mpp::protocol::methods::tempo;
///
/// let request = ChargeRequest {
///     amount: "1000000".into(),
///     currency: "0x20c0000000000000000000000000000000000000".into(),
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
    use time::{Duration, OffsetDateTime};

    // Apply decimals transform if present (matches TS SDK's parseUnits behavior).
    let request = request.clone().with_base_units()?;

    let encoded_request = Base64UrlJson::from_typed(&request)?;

    let default_expires;
    let expires = match expires {
        Some(e) => Some(e),
        None => {
            let expiry_time =
                OffsetDateTime::now_utc() + Duration::minutes(DEFAULT_EXPIRES_MINUTES as i64);
            default_expires = expiry_time
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| {
                    crate::error::MppError::InvalidConfig(format!("failed to format expires: {e}"))
                })?;
            Some(default_expires.as_str())
        }
    };

    let id = generate_challenge_id(
        secret_key,
        realm,
        METHOD_NAME,
        INTENT_CHARGE,
        encoded_request.raw(),
        expires,
        None,
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
        opaque: None,
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
/// use mpp::protocol::methods::tempo::generate_challenge_id;
///
/// let id = generate_challenge_id(
///     "my-secret-key",
///     "api.example.com",
///     "tempo",
///     "charge",
///     "eyJhbW91bnQiOiIxMDAwMDAwIn0",
///     None,
///     None,
///     None,
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn generate_challenge_id(
    secret_key: &str,
    realm: &str,
    method: &str,
    intent: &str,
    request: &str,
    expires: Option<&str>,
    digest: Option<&str>,
    opaque: Option<&str>,
) -> String {
    crate::protocol::core::compute_challenge_id(
        secret_key, realm, method, intent, request, expires, digest, opaque,
    )
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
/// use mpp::protocol::methods::tempo::generate_challenge_id_from_request;
/// use serde_json::json;
///
/// let id = generate_challenge_id_from_request(
///     "my-secret-key",
///     "api.example.com",
///     "tempo",
///     "charge",
///     &json!({
///         "amount": "1000000",
///         "currency": "0x20c0000000000000000000000000000000000000",
///         "recipient": "0x1234567890abcdef1234567890abcdef12345678"
///     }),
///     None,
///     None,
///     None,
/// ).unwrap();
/// ```
#[allow(clippy::too_many_arguments)]
pub fn generate_challenge_id_from_request(
    secret_key: &str,
    realm: &str,
    method: &str,
    intent: &str,
    request: &serde_json::Value,
    expires: Option<&str>,
    digest: Option<&str>,
    opaque: Option<&str>,
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
        opaque,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-secret-key";

    #[test]
    fn test_challenge_id_is_deterministic() {
        use crate::protocol::intents::ChargeRequest;

        let request = ChargeRequest {
            amount: "1000000".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            ..Default::default()
        };

        let challenge1 = charge_challenge_with_options(
            TEST_SECRET,
            "api.example.com",
            &request,
            Some("2026-01-01T00:00:00Z"),
            None,
        )
        .unwrap();

        let challenge2 = charge_challenge_with_options(
            TEST_SECRET,
            "api.example.com",
            &request,
            Some("2026-01-01T00:00:00Z"),
            None,
        )
        .unwrap();

        assert_eq!(
            challenge1.id, challenge2.id,
            "Same parameters should produce same challenge ID"
        );
    }

    #[test]
    fn test_challenge_default_expires() {
        let challenge = charge_challenge(
            TEST_SECRET,
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        assert!(
            challenge.expires.is_some(),
            "Challenge should have default expires"
        );
    }

    #[test]
    fn test_challenge_id_differs_for_different_params() {
        let challenge1 = charge_challenge(
            TEST_SECRET,
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        let challenge2 = charge_challenge(
            TEST_SECRET,
            "api.example.com",
            "2000000", // Different amount
            "0x20c0000000000000000000000000000000000000",
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
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        let challenge2 = charge_challenge(
            TEST_SECRET,
            "api.other.com", // Different realm
            "1000000",
            "0x20c0000000000000000000000000000000000000",
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
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        // Base64url-encoded SHA256 hash is 43 characters (256 bits / 6 bits per char, no padding)
        assert_eq!(
            challenge.id.len(),
            43,
            "HMAC ID should be 43 base64url characters"
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
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        let challenge2 = charge_challenge(
            "secret-two", // Different secret
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        assert_ne!(
            challenge1.id, challenge2.id,
            "Different secrets should produce different challenge IDs"
        );
    }

    /// Cross-SDK compatibility tests using conformance test vectors.
    /// These test cases are from mpp-sdks/conformance/vectors/challenge-id.json
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
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x1234567890abcdef1234567890abcdef12345678"
                }),
                None,
                None,
                None,
            )
            .unwrap();

            assert_eq!(id, "XmJ98SdsAdzwP9Oa-8In322Uh6yweMO6rywdomWk_V4");
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
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0xabcdef1234567890abcdef1234567890abcdef12"
                }),
                Some("2026-01-29T12:00:00Z"),
                None,
                None,
            )
            .unwrap();

            assert_eq!(id, "EvqUWMPJjqhoVJVG3mhTYVqCa3Mk7bUVd_OjeJGek1A");
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
                None,
            )
            .unwrap();

            assert_eq!(id, "qcJUPoapy4bFLznQjQUutwPLyXW7FvALrWA_sMENgAY");
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
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                    "description": "API access fee",
                    "externalId": "order-12345"
                }),
                Some("2026-02-01T00:00:00Z"),
                Some("sha-256=abc123def456"),
                None,
            )
            .unwrap();

            assert_eq!(id, "JYtuAXY3wf1gGVFa4L0MsUOwQ90BQISm7wkepNiHbeM");
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
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x1234567890abcdef1234567890abcdef12345678"
                }),
                None,
                None,
                None,
            )
            .unwrap();

            assert_eq!(id, "_o55RP0duNvJYtw9PXnf44mGyY5ajV_wwGzoGdTFuNs");
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
                None,
            )
            .unwrap();

            assert_eq!(id, "MYEC2oq3_B3cHa_My1Lx3NQKn_iUiMfsns6361N0SX0");
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
                    "description": "Payment for caf\u{00e9} \u{2615}"
                }),
                None,
                None,
                None,
            )
            .unwrap();

            assert_eq!(id, "54NwtlhzrjHd2Qox2EaElEA9dl73bZ1Y-rig6Ri8Xy8");
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
                    "currency": "0x20c0000000000000000000000000000000000000",
                    "recipient": "0x2222222222222222222222222222222222222222",
                    "methodDetails": {
                        "chainId": 42431,
                        "feePayer": true
                    }
                }),
                None,
                None,
                None,
            )
            .unwrap();

            assert_eq!(id, "BdPQxVJ56pvRJnM-r7wh_ppka5hOJH_6XpRK4gM9paI");
        }
    }
}
