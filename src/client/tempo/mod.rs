//! Tempo-specific client implementations.
//!
//! Contains the Tempo payment providers, transaction building,
//! signing strategies, charge builder, and channel operations.

pub mod autoswap;
pub mod charge;
mod error;
mod provider;
pub mod session;
pub mod signing;
#[cfg(feature = "sqlite")]
pub mod wallet;

pub use autoswap::AutoswapConfig;
pub use error::TempoClientError;

#[cfg(all(feature = "sqlite", not(windows)))]
fn default_wallet_directory() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|home| home.join(".tempo").join("wallet"))
}

#[cfg(all(feature = "sqlite", windows))]
fn default_wallet_directory() -> Option<std::path::PathBuf> {
    std::env::var_os("USERPROFILE")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            Some(std::path::PathBuf::from(drive).join(path))
        })
        .map(|home| home.join(".tempo").join("wallet"))
}
pub use provider::TempoProvider;

/// Static max fee per gas: 41 gwei (`base_fee * 2 + priority_fee`).
///
/// Tempo networks use a fixed 20 gwei base fee. Using 2× base fee
/// plus priority ensures the transaction is always accepted.
pub const MAX_FEE_PER_GAS: u128 = 20_000_000_000 * 2 + 1_000_000_000; // 41 gwei

/// Static max priority fee per gas: 1 gwei.
pub const MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;
