//! Client-side payment providers.
//!
//! This module provides the client-side API for creating payment credentials.
//!
//! # Exports
//!
//! - [`Fetch`]: Extension trait for reqwest with `.send_with_payment()` method
//! - [`PaymentProvider`]: Trait for payment providers
//! - [`tempo`]: Tempo-specific provider (feature-gated)
//!
//! # Example
//!
//! ```ignore
//! use mpay::client::{Fetch, PaymentProvider, tempo};
//!
//! let provider = tempo::Provider::new(signer, "https://rpc.moderato.tempo.xyz")?;
//! let resp = client.get(url).send_with_payment(&provider).await?;
//! ```

pub use crate::http::{HttpError, PaymentProvider};

#[cfg(feature = "http")]
pub use crate::http::PaymentExt as Fetch;

#[cfg(feature = "middleware")]
pub use crate::http::PaymentMiddleware;

/// Tempo-specific client provider.
#[cfg(feature = "tempo")]
pub mod tempo {
    pub use crate::http::TempoProvider as Provider;
}
