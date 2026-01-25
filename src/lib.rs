//! mpay - Micropayments Protocol for Rust
//!
//! A Rust library for implementing the Web Payment Auth protocol
//! (IETF draft-ietf-httpauth-payment).
//!
//! # Architecture
//!
//! mpay provides a thin protocol layer matching the TypeScript mpay library:
//!
//! - **Protocol Layer**: Core types for challenges, credentials, and receipts
//! - **Methods Layer**: Payment method implementations (tempo, evm, stripe)
//! - **Intents Layer**: Payment intent types (charge)
//!
//! # Feature Flags
//!
//! - `evm`: EVM blockchain support (Ethereum, Base, Polygon, etc.)
//! - `tempo`: Tempo blockchain support (includes `evm`)
//! - `stripe`: Stripe payment method support
//!
//! # Exports
//!
//! Following the mpay pattern, core types are exported as namespaced modules:
//!
//! ```no_run
//! use mpay::{Challenge, Credential, Receipt, Intent, Method};
//! # fn main() {}
//! ```
//!
//! # Signer Integration
//!
//! mpay re-exports alloy's signer types for convenience:
//!
//! ```no_run
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
pub mod crypto;

#[cfg(feature = "evm")]
pub mod evm;

// ==================== Re-exports ====================

// Error types
pub use error::{MppError, Result, ResultExt, SigningContext};

// ==================== Protocol Namespace Exports (mpay style) ====================
// Following mpay's export pattern with PascalCase module names

/// Challenge types for parsing WWW-Authenticate headers
#[allow(non_snake_case)]
pub mod Challenge {
    pub use crate::protocol::core::{
        parse_www_authenticate, parse_www_authenticate_all, PaymentChallenge,
    };
}

/// Credential types for creating Authorization headers
#[allow(non_snake_case)]
pub mod Credential {
    pub use crate::protocol::core::{
        format_authorization, ChallengeEcho, PaymentCredential, PaymentPayload,
    };
}

/// Receipt types for parsing Payment-Receipt headers
#[allow(non_snake_case)]
pub mod Receipt {
    pub use crate::protocol::core::{format_receipt, parse_receipt, PaymentReceipt, ReceiptStatus};
}

/// Intent types for payment requests
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

/// Payment method implementations
#[allow(non_snake_case)]
pub mod Method {
    #[cfg(feature = "tempo")]
    pub use crate::protocol::methods::tempo;
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
