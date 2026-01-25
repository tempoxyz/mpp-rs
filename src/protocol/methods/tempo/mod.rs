//! Tempo-specific types and helpers for Web Payment Auth.
//!
//! This module provides Tempo blockchain-specific implementations.
//! Tempo uses chain_id 88153 (tempo-moderato testnet) and supports TIP-20 tokens.
//!
//! # Types
//!
//! - [`TempoMethodDetails`]: Tempo-specific method details (2D nonces, fee payer)
//! - [`TempoChargeExt`]: Extension trait for ChargeRequest with Tempo-specific accessors
//! - [`transaction::TempoTransactionParams`]: Transaction params for building transactions
//! - [`transaction::SubmissionMethod`]: Determines which RPC method to use
//!
//! # Constants
//!
//! - [`CHAIN_ID`]: Tempo Moderato chain ID (88153)
//! - [`METHOD_NAME`]: Payment method name ("tempo")
//!
//! # Fee Sponsorship
//!
//! When a ChargeRequest has `feePayer: true` in method_details, the correct flow is:
//!
//! 1. **Server** sends a challenge with `feePayer: true` and optionally `feePayerUrl`
//! 2. **Client** builds a TempoTransaction (type 0x76) with fee payer placeholder,
//!    signs it, and returns it as a `transaction` credential (NOT broadcast)
//! 3. **Server** receives the signed transaction and forwards to the fee payer
//!    service (either `feePayerUrl` or the default testnet sponsor)
//! 4. **Fee payer** adds its signature and broadcasts the transaction
//! 5. **Server** verifies the receipt and transfer logs
//!
//! **Important**: The client does NOT submit the transaction directly. The server
//! is responsible for forwarding to the fee payer service.
//!
//! ```
//! use mpay::protocol::intents::ChargeRequest;
//! use mpay::protocol::methods::tempo::TempoChargeExt;
//!
//! # let req = ChargeRequest {
//! #     amount: "1000".into(), currency: "0x".into(), recipient: None,
//! #     expires: None, description: None, external_id: None,
//! #     method_details: Some(serde_json::json!({
//! #         "feePayer": true,
//! #         "feePayerUrl": "https://sponsor.moderato.tempo.xyz"
//! #     })),
//! # };
//! if req.fee_payer() {
//!     // Client should build and sign a TempoTransaction (0x76),
//!     // then return it as a "transaction" credential.
//!     // The server will forward to fee_payer_url for broadcasting.
//!     let fee_payer_url = req.fee_payer_url();
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
pub use types::{TempoMethodDetails, DEFAULT_FEE_PAYER_URL};

/// Tempo Moderato testnet chain ID.
pub const CHAIN_ID: u64 = 88153;

/// Payment method name for Tempo.
pub const METHOD_NAME: &str = "tempo";

/// Network name for Tempo Moderato.
pub const NETWORK_NAME: &str = "tempo-moderato";
