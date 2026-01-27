//! HTTP client support for Web Payment Auth.
//!
//! This module provides automatic handling of HTTP 402 Payment Required responses.
//!
//! # Features
//!
//! - **`http`**: Enables reqwest and the `PaymentExt` extension trait
//! - **`middleware`**: Enables reqwest-middleware support with `PaymentMiddleware`
//!
//! # Extension Trait (recommended)
//!
//! The `PaymentExt` trait extends `reqwest::RequestBuilder` with a
//! `.send_with_payment()` method for opt-in per-request payment handling:
//!
//! ```ignore
//! use mpay::client::Fetch;
//!
//! let resp = client
//!     .get("https://api.example.com/paid")
//!     .send_with_payment(&provider)
//!     .await?;
//! ```
//!
//! # Middleware (automatic)
//!
//! With the `middleware` feature, use `PaymentMiddleware` for automatic
//! 402 handling on all requests:
//!
//! ```ignore
//! use mpay::client::PaymentMiddleware;
//! use reqwest_middleware::ClientBuilder;
//!
//! let client = ClientBuilder::new(reqwest::Client::new())
//!     .with(PaymentMiddleware::new(provider))
//!     .build();
//! ```

mod error;
mod provider;

#[cfg(feature = "http")]
mod ext;

#[cfg(feature = "middleware")]
mod middleware;

pub use error::HttpError;
pub use provider::{MultiProvider, PaymentProvider};

#[cfg(feature = "http")]
pub use ext::PaymentExt;

#[cfg(feature = "middleware")]
pub use middleware::PaymentMiddleware;

#[cfg(feature = "tempo")]
pub use provider::TempoProvider;
