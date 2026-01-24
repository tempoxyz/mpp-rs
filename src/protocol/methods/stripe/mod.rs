//! Stripe-specific types for Web Payment Auth (stub).
//!
//! This module provides Stripe payment method support. Stripe is a non-EVM
//! payment method that demonstrates the protocol's extensibility beyond
//! blockchain payments.
//!
//! **Note**: This is a stub implementation. Full Stripe integration would
//! require the Stripe API client.
//!
//! # Types
//!
//! - [`StripeMethodDetails`]: Stripe-specific method details
//! - [`StripeChargePayload`]: Stripe payment payload (SPT token)
//!
//! # Constants
//!
//! - [`METHOD_NAME`]: Payment method name ("stripe")
//!
//! # Examples
//!
//! ```
//! use mpp_rs::protocol::methods::stripe::{StripeMethodDetails, METHOD_NAME};
//!
//! let details = StripeMethodDetails {
//!     business_network: Some("acct_123".to_string()),
//!     destination: None,
//! };
//! assert_eq!(METHOD_NAME, "stripe");
//! ```

pub mod charge;
pub mod types;

pub use charge::StripeChargePayload;
pub use types::StripeMethodDetails;

/// Payment method name for Stripe.
pub const METHOD_NAME: &str = "stripe";
