//! mpp-rs - Micropayments Protocol for Rust
//!
//! A Rust library for implementing the Web Payment Auth protocol
//! (IETF draft-ietf-httpauth-payment).
//!
//! # Architecture
//!
//! mpp-rs provides a layered architecture similar to the TypeScript mpay library:
//!
//! - **Protocol Layer**: Core types for challenges, credentials, and receipts
//! - **Methods Layer**: Payment method implementations (tempo, evm, stripe)
//! - **Intents Layer**: Payment intent types (charge, authorize, subscription)
//!
//! # Feature Flags
//!
//! - `evm`: EVM blockchain support (Ethereum, Base, Polygon, etc.)
//! - `tempo`: Tempo blockchain support (includes `evm`)
//! - `keystore`: Keystore format encryption/decryption (no path management)
//! - `client`: High-level HTTP client with payment handling
//! - `http-client`: Low-level HTTP client support
//! - `tower-middleware`: Tower middleware for servers
//! - `reqwest-middleware`: Reqwest middleware for clients
//! - `middleware`: All middleware features
//!
//! # Exports
//!
//! Following the mpay pattern, core types are exported as namespaced modules:
//!
//! ```ignore
//! use mpp_rs::{Challenge, Credential, Receipt, Intent, Method};
//! ```
//!
//! # Signer Integration
//!
//! mpp-rs re-exports alloy's signer types for convenience:
//!
//! ```ignore
//! use mpp_rs::{Signer, PrivateKeySigner};
//! ```
//!
//! Consumers provide their own signer implementation. The library does not
//! manage keystore paths or password caching - those are consumer responsibilities.

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ==================== Core Modules (always available) ====================

pub mod currency;
pub mod error;
// Explorer moved to purl - it's UI-only, not core protocol
pub mod protocol;
pub mod utils;

// ==================== Feature-gated Modules ====================

pub mod network;

#[cfg(feature = "evm")]
pub mod crypto;

#[cfg(feature = "evm")]
pub mod money;

#[cfg(feature = "keystore")]
pub mod keystore;

// TODO: Middleware module needs redesign to accept generic Signer
// #[cfg(any(feature = "tower-middleware", feature = "reqwest-middleware"))]
// pub mod middleware;

// ==================== Re-exports ====================

// Error types
pub use error::{MppError, Result, ResultExt, SigningContext};

// Currency
pub use currency::{currencies, Currency};

// Network
pub use network::{
    evm_chain_ids, get_evm_chain_id, get_network, is_evm_network, networks, resolve_network_alias,
    ChainType, GasConfig, Network, NetworkInfo, TokenConfig,
};



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
    pub use crate::protocol::intents::{AuthorizeRequest, ChargeRequest, SubscriptionRequest};
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
    #[cfg(feature = "evm")]
    pub use crate::protocol::methods::evm;

    #[cfg(feature = "tempo")]
    pub use crate::protocol::methods::tempo;

    #[cfg(feature = "stripe")]
    pub use crate::protocol::methods::stripe;
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

// ==================== Money Module Exports ====================

#[cfg(feature = "evm")]
pub use money::{format_u256_trimmed, format_u256_with_decimals, Money, TokenId};

// ==================== Keystore Exports ====================

#[cfg(feature = "keystore")]
pub use keystore::{decrypt_keystore, encrypt_keystore, Keystore};

// ==================== Middleware Exports ====================
// TODO: Middleware exports after module redesign
// #[cfg(any(feature = "tower-middleware", feature = "reqwest-middleware"))]
// pub use middleware::{PaymentHandler, PaymentHandlerConfig};
//
// #[cfg(feature = "tower-middleware")]
// pub use middleware::{PaymentLayer, PaymentService};
//
// #[cfg(feature = "reqwest-middleware")]
// pub use middleware::PaymentMiddleware;
