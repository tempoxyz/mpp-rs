//! Tempo-specific types and helpers for Web Payment Auth.
//!
//! This module provides Tempo blockchain-specific implementations.
//! Tempo uses chain_id 88153 (tempo-moderato testnet) and supports TIP-20 tokens.
//!
//! # Types
//!
//! - [`TempoMethodDetails`]: Tempo-specific method details (2D nonces, fee payer)
//! - [`TempoChargeExt`]: Extension trait for ChargeRequest with Tempo-specific accessors
//! - [`transaction::TempoTransactionParams`]: Transaction params for `tempo_sendTransaction`
//! - [`transaction::SubmissionMethod`]: Determines which RPC method to use
//!
//! # Constants
//!
//! - [`CHAIN_ID`]: Tempo Moderato chain ID (88153)
//! - [`METHOD_NAME`]: Payment method name ("tempo")
//!
//! # Fee Sponsorship
//!
//! When a ChargeRequest has `feePayer: true` in method_details, the transaction
//! should be submitted via `tempo_sendTransaction` instead of `eth_sendRawTransaction`.
//! Use [`transaction::SubmissionMethod::from_charge_request`] to determine the
//! appropriate submission method.
//!
//! ```
//! use mpay::protocol::core::parse_www_authenticate;
//! use mpay::protocol::intents::ChargeRequest;
//! use mpay::protocol::methods::tempo::{TempoChargeExt, transaction::SubmissionMethod};
//!
//! # let req = ChargeRequest {
//! #     amount: "1000".into(), currency: "0x".into(), recipient: None,
//! #     expires: None, description: None, external_id: None,
//! #     method_details: Some(serde_json::json!({"feePayer": true})),
//! # };
//! let method = SubmissionMethod::from_charge_request(&req);
//! if req.fee_payer() {
//!     assert_eq!(method.method_name(), "tempo_sendTransaction");
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
//! let nonce_key = req.nonce_key();
//! assert_eq!(CHAIN_ID, 88153);
//! ```

pub mod charge;
pub mod transaction;
pub mod types;

pub use charge::TempoChargeExt;
pub use transaction::{SubmissionMethod, TempoSendTransactionRequest, TempoTransactionParams};
pub use types::TempoMethodDetails;

/// Tempo Moderato testnet chain ID.
pub const CHAIN_ID: u64 = 88153;

/// Payment method name for Tempo.
pub const METHOD_NAME: &str = "tempo";

/// Network name for Tempo Moderato.
pub const NETWORK_NAME: &str = "tempo-moderato";
