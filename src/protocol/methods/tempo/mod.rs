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

/// Parse an ISO 8601 timestamp string (e.g. "2024-01-15T12:00:00Z") to Unix timestamp.
#[cfg(feature = "server")]
pub(crate) fn parse_iso8601_timestamp(s: &str) -> Option<u64> {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    OffsetDateTime::parse(s.trim(), &Iso8601::DEFAULT)
        .ok()
        .map(|dt| dt.unix_timestamp() as u64)
}
