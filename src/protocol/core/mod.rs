//! Core Web Payment Auth protocol types and parsing.
//!
//! This module provides the foundational types and header parsing/formatting
//! functions for the Web Payment Auth protocol (IETF draft-ietf-httpauth-payment).
//!
//! **Zero heavy dependencies** - only serde, serde_json, and thiserror.
//! No alloy, no blockchain-specific types.
//!
//! # Architecture
//!
//! The protocol is organized in layers:
//!
//! - **Core** (this module): Protocol envelope types that work with any payment
//!   method or intent. Generic over method/intent names.
//! - **Intents** (`protocol::intents`): Intent-specific request types like
//!   `ChargeRequest`. Still no blockchain deps.
//! - **Methods** (`protocol::methods`): Method-specific types and helpers.
//!   Feature-gated with blockchain dependencies (e.g., `alloy` for EVM).
//!
//! # Types
//!
//! - [`MethodName`]: Payment method identifier (e.g., "tempo", "base", "stripe")
//! - [`IntentName`]: Payment intent identifier (e.g., "charge", "authorize")
//! - [`Base64UrlJson`]: JSON encoded as base64url (preserves original encoding)
//! - [`PaymentChallenge`]: Challenge from server (WWW-Authenticate header)
//! - [`PaymentCredential`]: Credential from client (Authorization header)
//! - [`Receipt`]: Receipt from server (Payment-Receipt header)
//!
//! # Parsing
//!
//! - [`parse_www_authenticate`]: Parse a single WWW-Authenticate header
//! - [`parse_www_authenticate_all`]: Parse multiple headers (multi-challenge support)
//! - [`parse_authorization`]: Parse Authorization header
//! - [`parse_receipt`]: Parse Payment-Receipt header
//!
//! # Formatting
//!
//! - [`format_www_authenticate`]: Format a single challenge
//! - [`format_www_authenticate_many`]: Format multiple challenges
//! - [`format_authorization`]: Format a credential
//! - [`format_receipt`]: Format a receipt
//!
//! # Examples
//!
//! ```
//! use mpp::protocol::core::*;
//!
//! // Parse a challenge
//! let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QifQ""#;
//! let challenge = parse_www_authenticate(header).unwrap();
//! println!("Method: {}, Intent: {}", challenge.method, challenge.intent);
//!
//! // Decode the request to a typed struct
//! use mpp::protocol::intents::ChargeRequest;
//! if challenge.intent.is_charge() {
//!     let req: ChargeRequest = challenge.request.decode().unwrap();
//!     println!("Amount: {}", req.amount);
//! }
//!
//! // Create a credential and format it
//! let credential = PaymentCredential::with_source(
//!     challenge.to_echo(),
//!     "did:pkh:eip155:42431:0x123",
//!     PaymentPayload::transaction("0xsigned_tx"),
//! );
//! let auth_header = format_authorization(&credential).unwrap();
//! ```

pub mod challenge;
pub mod headers;
pub mod types;

// Re-export all public types
#[cfg(feature = "server")]
pub(crate) use challenge::constant_time_eq;
pub use challenge::{
    compute_challenge_id, extract_tx_hash, ChallengeEcho, PaymentChallenge, PaymentCredential,
    PaymentPayload, Receipt,
};
pub use headers::{
    extract_payment_scheme, format_authorization, format_receipt, format_www_authenticate,
    format_www_authenticate_many, parse_authorization, parse_receipt, parse_www_authenticate,
    parse_www_authenticate_all, AUTHORIZATION_HEADER, PAYMENT_RECEIPT_HEADER, PAYMENT_SCHEME,
    WWW_AUTHENTICATE_HEADER,
};
pub use types::{
    base64url_decode, base64url_encode, Base64UrlJson, IntentName, MethodName, PayloadType,
    PaymentProtocol, ReceiptStatus,
};
