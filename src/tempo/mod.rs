//! Tempo blockchain types and utilities.
//!
//! This module re-exports Tempo-specific types for both client and server use.
//!
//! # Exports
//!
//! - Intent schemas: [`ChargeRequest`]
//! - Method details: [`TempoMethodDetails`], [`TempoChargeExt`]
//! - Transaction types: [`TempoTransaction`], [`TempoTransactionRequest`]
//! - Constants: [`CHAIN_ID`], [`METHOD_NAME`]
//!
//! # Submodules
//!
//! - [`client`]: Client-side Tempo provider (requires `client` + `http`)
//! - [`server`]: Server-side Tempo verification (requires `server`)
//!
//! # Example
//!
//! ```ignore
//! use mpay::tempo::{ChargeRequest, TempoChargeExt, CHAIN_ID};
//!
//! let req: ChargeRequest = challenge.request.decode()?;
//! if req.fee_payer() {
//!     // Handle fee sponsorship
//! }
//! ```

pub use crate::protocol::intents::ChargeRequest;
pub use crate::protocol::methods::tempo::{
    Call, SignatureType, TempoChargeExt, TempoMethodDetails, TempoTransaction,
    TempoTransactionRequest, CHAIN_ID, METHOD_NAME, TEMPO_SEND_TRANSACTION_METHOD,
    TEMPO_TX_TYPE_ID,
};

#[cfg(feature = "server")]
pub use crate::protocol::methods::tempo::ChargeMethod;

/// Client-side Tempo provider.
#[cfg(all(feature = "client", feature = "http"))]
pub mod client {
    pub use crate::http::TempoProvider as Provider;
}

/// Server-side Tempo verification.
#[cfg(feature = "server")]
pub mod server {
    pub use crate::protocol::methods::tempo::ChargeMethod;
}
