//! Stripe payment method for MPP.
//!
//! This module provides Stripe-specific types and a server-side [`ChargeMethod`]
//! implementation using Stripe's PaymentIntents API with Shared Payment Tokens (SPTs).
//!
//! # Architecture
//!
//! Stripe integration mirrors the TypeScript SDK (`mppx`). The flow:
//!
//! 1. Server creates a challenge with `method="stripe"`, `intent="charge"`
//! 2. Client obtains an SPT (via Stripe Elements + a server-side endpoint)
//! 3. Client returns credential with `{ spt: "spt_..." }` payload
//! 4. Server creates a Stripe PaymentIntent using the SPT and verifies the result
//!
//! # Feature Flag
//!
//! Requires the `stripe` feature to be enabled.
//!
//! # Example
//!
//! ```ignore
//! use mpp::stripe::{StripeChargeMethod, StripeConfig};
//!
//! // With a secret key (uses raw HTTP to Stripe API)
//! let method = StripeChargeMethod::new(StripeConfig {
//!     secret_key: "sk_test_...".to_string(),
//!     network_id: "acct_...".to_string(),
//!     payment_method_types: vec!["card".to_string()],
//! });
//! ```

#[cfg(feature = "server")]
mod method;
mod types;

#[cfg(feature = "server")]
pub use method::ChargeMethod as StripeChargeMethod;
pub use types::{StripeConfig, StripeCredentialPayload, StripeMethodDetails};

/// Payment method name for Stripe.
pub const METHOD_NAME: &str = "stripe";

/// Charge intent name.
pub const INTENT_CHARGE: &str = "charge";
