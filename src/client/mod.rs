//! Client-side payment providers.
//!
//! This module provides the client-side API for creating payment credentials.
//!
//! # Exports
//!
//! - [`PaymentProvider`]: Trait for payment providers
//! - [`Fetch`]: Extension trait for reqwest with `.send_with_payment()` method
//! - [`TempoProvider`]: Tempo blockchain provider (requires `tempo`)
//!
//! # Example
//!
//! ```ignore
//! use mpp::client::{Fetch, TempoProvider};
//!
//! let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
//! let resp = client.get(url).send_with_payment(&provider).await?;
//! ```

mod error;
mod provider;

#[cfg(feature = "tempo")]
pub mod tempo;

#[cfg(feature = "client")]
mod fetch;

#[cfg(feature = "middleware")]
mod middleware;

pub use error::HttpError;
pub use provider::{MultiProvider, PaymentProvider};

#[cfg(feature = "client")]
pub use fetch::PaymentExt as Fetch;

#[cfg(feature = "middleware")]
pub use middleware::PaymentMiddleware;

// Re-export Tempo types at client level for convenience
#[cfg(feature = "tempo")]
pub use tempo::{AutoswapConfig, TempoClientError, TempoProvider};
#[cfg(feature = "tempo")]
pub use tempo_alloy::TempoNetwork;
