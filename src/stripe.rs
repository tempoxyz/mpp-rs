//! Stripe payment method types and utilities.
//!
//! This module re-exports Stripe-specific types for convenience.
//!
//! # Exports
//!
//! - [`StripeConfig`]: Configuration for the Stripe charge method
//! - [`StripeCredentialPayload`]: Credential payload with SPT
//! - [`StripeMethodDetails`]: Method details for challenges
//! - [`StripeChargeMethod`]: Server-side charge method (requires `server` feature)
//! - [`StripeProvider`]: Client-side payment provider (requires `client` feature)
//!
//! # Server Example
//!
//! ```ignore
//! use mpp::stripe::{StripeChargeMethod, StripeConfig};
//!
//! let method = StripeChargeMethod::new(StripeConfig {
//!     secret_key: "sk_test_...".to_string(),
//!     network_id: "acct_...".to_string(),
//!     payment_method_types: vec!["card".to_string()],
//! });
//! ```
//!
//! # Client Example
//!
//! ```ignore
//! use mpp::stripe::StripeProvider;
//!
//! let provider = StripeProvider::new(|params| {
//!     Box::pin(async move {
//!         // Call your server to create an SPT
//!         Ok("spt_...".to_string())
//!     })
//! });
//! ```

pub use crate::protocol::methods::stripe::{
    StripeConfig, StripeCredentialPayload, StripeMethodDetails, METHOD_NAME,
};

#[cfg(feature = "server")]
pub use crate::protocol::methods::stripe::StripeChargeMethod;

#[cfg(feature = "client")]
pub use crate::client::stripe::StripeProvider;

#[cfg(feature = "client")]
pub use crate::client::stripe::CreateTokenParams;
