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
//! - `mpp::client::TempoProvider` (requires `client` + `http`)
//! - `mpp::server::TempoChargeMethod` (requires `server`)
//!
//! # Example
//!
//! ```ignore
//! use mpp::tempo::{ChargeRequest, TempoChargeExt, CHAIN_ID};
//!
//! let req: ChargeRequest = challenge.request.decode()?;
//! if req.fee_payer() {
//!     // Handle fee sponsorship
//! }
//! ```

pub use crate::protocol::intents::{ChargeRequest, SessionRequest};
pub use crate::protocol::methods::tempo::{
    Call, SessionCredentialPayload, SignatureType, TempoChargeExt, TempoMethodDetails,
    TempoSessionExt, TempoSessionMethodDetails, TempoTransaction, TempoTransactionRequest,
    CHAIN_ID, DEFAULT_EXPIRES_MINUTES, DEFAULT_RPC_URL, METHOD_NAME, MODERATO_CHAIN_ID,
    TEMPO_SEND_TRANSACTION_METHOD, TEMPO_TX_TYPE_ID,
};

#[cfg(feature = "evm")]
pub mod attribution;

#[cfg(feature = "evm")]
pub use crate::protocol::methods::tempo::{
    compute_channel_id, sign_voucher, DOMAIN_NAME, DOMAIN_VERSION,
};

#[cfg(feature = "server")]
pub use crate::protocol::methods::tempo::ChargeMethod as TempoChargeMethod;

#[cfg(feature = "server")]
pub use crate::protocol::methods::tempo::session_method::{
    ChannelState, ChannelStore, InMemoryChannelStore as SessionChannelStore,
    SessionMethod as TempoSessionMethod, SessionMethodConfig,
};
