//! Stream payment channel infrastructure for Tempo.
//!
//! This module provides the core building blocks for streaming payments:
//!
//! - [`types`]: Core types (Voucher, SignedVoucher, StreamCredentialPayload, StreamReceipt)
//! - [`voucher`]: EIP-712 voucher signing and verification
//! - [`chain`]: On-chain escrow contract interactions
//! - [`storage`]: Channel/session storage trait and in-memory implementation
//! - [`receipt`]: Stream receipt creation and serialization
//! - [`sse`]: Server-Sent Events formatting
//! - [`errors`]: Stream-specific error types
//! - [`server`]: Server-side verification logic

pub mod chain;
pub mod errors;
pub mod receipt;
pub mod sse;
pub mod storage;
pub mod types;
pub mod voucher;

#[cfg(feature = "server")]
pub mod server;

pub use errors::StreamError;
pub use receipt::{create_stream_receipt, deserialize_stream_receipt, serialize_stream_receipt};
pub use sse::format_receipt_event;
pub use storage::{ChannelState, ChannelStorage, MemoryStorage, SessionState};
pub use types::{SignedVoucher, StreamCredential, StreamCredentialPayload, StreamReceipt, Voucher};
pub use voucher::{parse_voucher_from_payload, sign_voucher, verify_voucher};

#[cfg(feature = "server")]
pub use server::{StreamConfig, StreamServer};
