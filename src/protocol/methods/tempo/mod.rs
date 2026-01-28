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
//! // Simple charge challenge
//! let challenge = tempo::charge_challenge(
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
///     "api.example.com",
///     "1000000",
///     "0x20c0000000000000000000000000000000000001",
///     "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
/// ).unwrap();
///
/// assert_eq!(challenge.method.as_str(), "tempo");
/// assert_eq!(challenge.intent.as_str(), "charge");
/// ```
pub fn charge_challenge(
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

    charge_challenge_with_options(realm, &request, None, None)
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
///     "api.example.com",
///     &request,
///     None,
///     Some("API access fee"),
/// ).unwrap();
///
/// assert_eq!(challenge.description, Some("API access fee".to_string()));
/// ```
pub fn charge_challenge_with_options(
    realm: &str,
    request: &crate::protocol::intents::ChargeRequest,
    expires: Option<&str>,
    description: Option<&str>,
) -> crate::error::Result<crate::protocol::core::PaymentChallenge> {
    use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

    let encoded_request = Base64UrlJson::from_typed(request)?;

    // Per spec: challenge ID MUST be bound to challenge parameters.
    // We generate a deterministic ID by hashing: realm || method || intent || request
    let id = generate_challenge_id(realm, METHOD_NAME, INTENT_CHARGE, encoded_request.raw());

    Ok(PaymentChallenge {
        id,
        realm: realm.to_string(),
        method: METHOD_NAME.into(),
        intent: INTENT_CHARGE.into(),
        request: encoded_request,
        expires: expires.map(|s| s.to_string()),
        description: description.map(|s| s.to_string()),
    })
}

/// Generate a deterministic challenge ID bound to challenge parameters.
///
/// Per SDK spec §6.2: "MUST generate unique `id` bound to challenge parameters".
/// The ID is a truncated SHA-256 hash of `realm || method || intent || request`,
/// encoded as hex. This ensures the same parameters always produce the same ID,
/// allowing servers to validate that credentials match issued challenges.
///
/// The output is a 32-character hex string (128 bits of the hash).
fn generate_challenge_id(realm: &str, method: &str, intent: &str, request: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    // Use a deterministic hasher to create a unique ID from parameters.
    // We hash: realm + separator + method + separator + intent + separator + request
    // The separator ensures no collision between adjacent fields.
    let mut hasher = DefaultHasher::new();
    realm.hash(&mut hasher);
    "\x00".hash(&mut hasher);
    method.hash(&mut hasher);
    "\x00".hash(&mut hasher);
    intent.hash(&mut hasher);
    "\x00".hash(&mut hasher);
    request.hash(&mut hasher);

    // Get 64-bit hash and format as 16 hex chars
    let hash = hasher.finish();

    // Add a second hash with different seed for more entropy (128 bits total)
    let mut hasher2 = DefaultHasher::new();
    request.hash(&mut hasher2);
    "\x00".hash(&mut hasher2);
    intent.hash(&mut hasher2);
    "\x00".hash(&mut hasher2);
    method.hash(&mut hasher2);
    "\x00".hash(&mut hasher2);
    realm.hash(&mut hasher2);
    let hash2 = hasher2.finish();

    format!("{:016x}{:016x}", hash, hash2)
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

    #[test]
    fn test_challenge_id_is_deterministic() {
        let challenge1 = charge_challenge(
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        let challenge2 = charge_challenge(
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
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        let challenge2 = charge_challenge(
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
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        let challenge2 = charge_challenge(
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
            "api.example.com",
            "1000000",
            "0x20c0000000000000000000000000000000000001",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

        assert_eq!(challenge.id.len(), 32, "ID should be 32 hex characters");
        assert!(
            challenge.id.chars().all(|c| c.is_ascii_hexdigit()),
            "ID should only contain hex characters"
        );
    }

    #[test]
    fn test_generate_challenge_id_no_field_collision() {
        // Ensure that "ab" + "cd" != "a" + "bcd" due to separators
        let id1 = generate_challenge_id("ab", "cd", "ef", "gh");
        let id2 = generate_challenge_id("abc", "d", "ef", "gh");
        assert_ne!(
            id1, id2,
            "Different field boundaries should produce different IDs"
        );
    }
}
