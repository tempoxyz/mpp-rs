//! mpp - Machine Payment Protocol for Rust
//!
//! A Rust library implementing the Web Payment Auth protocol.
//!
//! # Quick Start
//!
//! ```no_run
//! use mpp::{PaymentChallenge, PaymentCredential, Receipt, ChargeRequest};
//! use mpp::{parse_www_authenticate, format_authorization};
//! # fn main() {}
//! ```
//!
//! # Signer Integration
//!
#![cfg_attr(feature = "evm", doc = "```no_run")]
#![cfg_attr(not(feature = "evm"), doc = "```ignore")]
//! use mpp::{Signer, PrivateKeySigner};
//! # fn main() {}
//! ```
//!
//! Consumers provide their own signer. The library does not manage keystores.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ==================== Internal Modules ====================

pub mod body_digest;
pub mod error;
pub mod expires;
pub mod mcp;
pub mod protocol;
pub mod proxy;
pub mod store;

#[cfg(feature = "evm")]
pub mod evm;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "tempo")]
pub mod tempo;

// ==================== Flat Re-exports ====================

// Error types
pub use error::{MppError, Result};

// RFC 9457 Problem Details
pub use error::{
    PaymentError, PaymentErrorDetails, CORE_PROBLEM_TYPE_BASE, SESSION_PROBLEM_TYPE_BASE,
};

// Deprecated: remove in next major version.
#[allow(deprecated)]
pub use error::STREAM_PROBLEM_TYPE_BASE;

// Core protocol types
pub use protocol::core::{
    compute_challenge_id, ChallengeEcho, PaymentChallenge, PaymentCredential, PaymentPayload,
    Receipt, ReceiptStatus,
};

// Header parsing/formatting
pub use protocol::core::{
    format_authorization, format_receipt, format_www_authenticate, format_www_authenticate_many,
    parse_authorization, parse_receipt, parse_www_authenticate, parse_www_authenticate_all,
};

// Schema types
pub use protocol::core::{
    base64url_decode, base64url_encode, Base64UrlJson, IntentName, MethodName, PayloadType,
    PaymentProtocol, AUTHORIZATION_HEADER, PAYMENT_RECEIPT_HEADER, PAYMENT_SCHEME,
    WWW_AUTHENTICATE_HEADER,
};

// Store types
pub use store::{FileStore, MemoryStore, Store, StoreError};

#[cfg(all(feature = "server", feature = "tempo"))]
pub use store::ChannelStoreAdapter;

// Intent types
pub use protocol::intents::{
    deserialize_request, deserialize_request_typed, parse_units, request_from_challenge,
    request_from_challenge_typed, serialize_request, ChargeRequest, Request as PaymentRequest,
    SessionRequest,
};

// ==================== Alloy Re-exports ====================

#[cfg(feature = "evm")]
pub use alloy::signers::Signer;

#[cfg(feature = "evm")]
pub use alloy::signers::local::PrivateKeySigner;

#[cfg(feature = "evm")]
pub use alloy::primitives::{Address, U256};

#[cfg(feature = "tempo")]
pub use alloy::providers::{ProviderBuilder, RootProvider};
