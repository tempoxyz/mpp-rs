//! Tempo-specific client implementations.
//!
//! Contains the Tempo payment providers, transaction building,
//! signing strategies, charge builder, and channel operations.

pub mod abi;
pub mod channel_ops;
pub mod charge;
mod error;
pub mod keychain;
mod provider;
mod session_provider;
pub mod signing;
pub mod tx_builder;

pub use channel_ops::ChannelEntry;
pub use charge::{SignOptions, SignedTempoCharge, TempoCharge};
pub use error::TempoClientError;
pub use provider::TempoProvider;
pub use session_provider::TempoSessionProvider;
pub use signing::TempoSigningMode;

/// Static max fee per gas: 41 gwei (`base_fee * 2 + priority_fee`).
///
/// Tempo networks use a fixed 20 gwei base fee. Using 2× base fee
/// plus priority ensures the transaction is always accepted.
pub const MAX_FEE_PER_GAS: u128 = 20_000_000_000 * 2 + 1_000_000_000; // 41 gwei

/// Static max priority fee per gas: 1 gwei.
pub const MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;
