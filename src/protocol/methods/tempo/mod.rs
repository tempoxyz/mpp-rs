//! Tempo-specific types and helpers for Web Payment Auth.
//!
//! This module provides Tempo blockchain-specific implementations.
//! Tempo uses chain_id 88153 (tempo-moderato testnet) and supports TIP-20 tokens.
//!
//! # Types
//!
//! - [`TempoMethodDetails`]: Tempo-specific method details (2D nonces, fee payer)
//! - [`TempoChargeExt`]: Extension trait for ChargeRequest with Tempo-specific accessors
//!
//! # Constants
//!
//! - [`CHAIN_ID`]: Tempo Moderato chain ID (88153)
//! - [`METHOD_NAME`]: Payment method name ("tempo")
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
//! let nonce_key = req.nonce_key();
//! assert_eq!(CHAIN_ID, 88153);
//! ```

pub mod charge;
pub mod types;

pub use charge::TempoChargeExt;
pub use types::TempoMethodDetails;

/// Tempo Moderato testnet chain ID.
pub const CHAIN_ID: u64 = 88153;

/// Payment method name for Tempo.
pub const METHOD_NAME: &str = "tempo";

/// Network name for Tempo Moderato.
pub const NETWORK_NAME: &str = "tempo-moderato";
