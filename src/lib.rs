//! mpay - Machine Payment Protocol for Rust
//!
//! A Rust library for implementing the Web Payment Auth protocol.
//!
//! # Architecture
//!
//! mpay provides a thin protocol layer:
//!
//! - **Protocol Layer**: Core types for challenges, credentials, and receipts
//! - **Methods Layer**: Payment method implementations (tempo, evm)
//! - **Intents Layer**: Payment intent types (charge)
//!
//! # Exports
//!
//! Core types are exported as namespaced modules:
//!
//! ```no_run
//! use mpay::{Challenge, Credential, Receipt, Intent};
//! # fn main() {}
//! ```
//!
//! # Signer Integration
//!
//! mpay re-exports alloy's signer types for convenience:
//!
#![cfg_attr(feature = "evm", doc = "```no_run")]
#![cfg_attr(not(feature = "evm"), doc = "```ignore")]
//! use mpay::{Signer, PrivateKeySigner};
//! # fn main() {}
//! ```
//!
//! Consumers provide their own signer implementation. The library does not
//! manage keystore paths or password caching - those are consumer responsibilities.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ==================== Core Modules (always available) ====================

pub mod error;
pub mod protocol;
pub mod utils;

// ==================== Feature-gated Modules ====================

#[cfg(feature = "evm")]
pub mod evm;

#[cfg(feature = "client")]
pub mod client;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "tempo")]
pub mod tempo;

// ==================== Re-exports ====================

// Error types
pub use error::{MppError, Result, ResultExt, SigningContext};

// ==================== Protocol Namespace Exports (mpay style) ====================

/// Challenge types for parsing WWW-Authenticate headers
#[allow(non_snake_case)]
pub mod Challenge {
    pub use crate::protocol::core::{
        format_www_authenticate, format_www_authenticate_many, parse_www_authenticate,
        parse_www_authenticate_all, PaymentChallenge,
    };
}

/// Credential types for creating Authorization headers
#[allow(non_snake_case)]
pub mod Credential {
    pub use crate::protocol::core::{
        format_authorization, parse_authorization, ChallengeEcho, PaymentCredential, PaymentPayload,
    };
}

/// Receipt types for parsing Payment-Receipt headers
#[allow(non_snake_case)]
pub mod Receipt {
    pub use crate::protocol::core::{format_receipt, parse_receipt, Receipt, ReceiptStatus};
}

/// Intent request schemas (shared across methods)
///
/// Intents define the shared request fields for payment operations.
/// All methods implementing the same intent use the same request type.
#[allow(non_snake_case)]
pub mod Intent {
    pub use crate::protocol::intents::ChargeRequest;
}

/// Schema types for protocol encoding
#[allow(non_snake_case)]
pub mod Schema {
    pub use crate::protocol::core::{
        base64url_decode, base64url_encode, Base64UrlJson, IntentName, MethodName, PayloadType,
        PaymentProtocol, AUTHORIZATION_HEADER, PAYMENT_RECEIPT_HEADER, PAYMENT_SCHEME,
        WWW_AUTHENTICATE_HEADER,
    };
}

// ==================== Alloy Re-exports (batteries included) ====================

/// Re-export alloy's Signer trait for convenience
#[cfg(feature = "evm")]
pub use alloy::signers::Signer;

/// Re-export PrivateKeySigner for convenience
#[cfg(feature = "evm")]
pub use alloy_signer_local::PrivateKeySigner;

/// Re-export common alloy primitives
#[cfg(feature = "evm")]
pub use alloy::primitives::{Address, U256};

/// Re-export alloy provider types for server use
#[cfg(feature = "server")]
pub use alloy::providers::{ProviderBuilder, RootProvider};
