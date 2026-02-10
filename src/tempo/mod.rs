//! Tempo blockchain types and utilities.
//!
//! This module re-exports Tempo-specific types for convenience.
//!
//! # Exports
//!
//! - Intent schemas: [`ChargeRequest`]
//! - Method details: [`TempoMethodDetails`], [`TempoChargeExt`]
//! - Transaction types: [`TempoTransaction`], [`TempoTransactionRequest`]
//! - Constants: [`CHAIN_ID`], [`MODERATO_CHAIN_ID`], [`METHOD_NAME`]
//!
//! For client/server specific types, use:
//! - `mpay::client::TempoProvider` (requires `client` + `http`)
//! - `mpay::server::TempoChargeMethod` (requires `server`)
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
pub use crate::protocol::intents::StreamRequest;
pub use crate::protocol::methods::tempo::{
    Call, SignatureType, TempoChargeExt, TempoMethodDetails, TempoTransaction,
    TempoTransactionRequest, CHAIN_ID, DEFAULT_EXPIRES_MINUTES, DEFAULT_RPC_URL, METHOD_NAME,
    MODERATO_CHAIN_ID, TEMPO_SEND_TRANSACTION_METHOD, TEMPO_TX_TYPE_ID,
};
pub use crate::protocol::methods::tempo::stream::{
    StreamCredentialPayload, StreamReceipt, TempoStreamExt, TempoStreamMethodDetails,
};

#[cfg(feature = "server")]
pub use crate::protocol::methods::tempo::ChargeMethod as TempoChargeMethod;

#[cfg(feature = "client")]
pub use crate::client::TempoProvider;
