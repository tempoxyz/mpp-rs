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

    Ok(PaymentChallenge {
        id: uuid::Uuid::new_v4().to_string(),
        realm: realm.to_string(),
        method: METHOD_NAME.into(),
        intent: "charge".into(),
        request: Base64UrlJson::from_typed(request)?,
        expires: expires.map(|s| s.to_string()),
        description: description.map(|s| s.to_string()),
    })
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
