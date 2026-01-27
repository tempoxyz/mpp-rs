//! Client-side payment providers.
//!
//! This module provides the client-side API for creating payment credentials.
//!
//! # Exports
//!
//! - [`PaymentProvider`]: Trait for payment providers
//! - [`Fetch`]: Extension trait for reqwest with `.send_with_payment()` method (requires `http`)
//! - [`TempoProvider`]: Tempo blockchain provider (requires `tempo` + `http`)
//!
//! # Example
//!
//! ```ignore
//! use mpay::client::{Fetch, TempoProvider};
//!
//! let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
//! let resp = client.get(url).send_with_payment(&provider).await?;
//! ```

#[cfg(feature = "http")]
pub use crate::http::{HttpError, PaymentProvider};

#[cfg(feature = "http")]
pub use crate::http::PaymentExt as Fetch;

#[cfg(feature = "middleware")]
pub use crate::http::PaymentMiddleware;

#[cfg(all(feature = "tempo", feature = "http"))]
pub use crate::http::TempoProvider;
