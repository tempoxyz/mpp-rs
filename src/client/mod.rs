//! Client-side payment providers.
//!
//! This module provides the client-side API for creating payment credentials.
//!
//! # Exports
//!
//! - [`PaymentProvider`]: Trait for payment providers
//! - [`Fetch`]: Extension trait for reqwest with `.send_with_payment()` method (requires `http`)
//! - [`tempo`]: Tempo-specific provider (requires `tempo`)
//!
//! # Example
//!
//! ```ignore
//! use mpay::client::{Fetch, PaymentProvider, tempo};
//!
//! let provider = tempo::Provider::new(signer, "https://rpc.moderato.tempo.xyz")?;
//! let resp = client.get(url).send_with_payment(&provider).await?;
//! ```

#[cfg(feature = "http")]
pub use crate::http::{HttpError, PaymentProvider};

#[cfg(feature = "http")]
pub use crate::http::PaymentExt as Fetch;

#[cfg(feature = "middleware")]
pub use crate::http::PaymentMiddleware;

/// Tempo-specific client provider.
#[cfg(all(feature = "tempo", feature = "http"))]
pub mod tempo {
    pub use crate::http::TempoProvider as Provider;
}
