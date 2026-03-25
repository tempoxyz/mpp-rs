//! Stripe-specific types and helpers for MPP.
//!
//! This module provides the Stripe payment method implementation for one-time
//! charges using Stripe's Shared Payment Tokens (SPTs).
//!
//! # Payment Flow
//!
//! 1. Server issues a 402 challenge with `method="stripe"`, `intent="charge"`
//! 2. Client creates an SPT via a server-proxied Stripe API call
//! 3. Client sends credential containing the SPT
//! 4. Server creates a Stripe PaymentIntent with `confirm: true` and the SPT
//! 5. If PaymentIntent status is `succeeded`, payment is verified
//!
//! # Types
//!
//! - [`StripeChargeRequest`]: Stripe-specific charge request fields
//! - [`StripeCredentialPayload`]: Client credential containing the SPT
//!
//! # Constants
//!
//! - [`METHOD_NAME`]: Payment method name ("stripe")
//! - [`INTENT_CHARGE`]: Charge intent name ("charge")

pub mod types;

#[cfg(feature = "server")]
pub mod method;

pub use types::{CreateTokenResult, StripeCredentialPayload, StripeMethodDetails};

/// Payment method name for Stripe.
pub const METHOD_NAME: &str = "stripe";

/// Charge intent name (re-exported from [`crate::protocol::intents`]).
pub use crate::protocol::intents::INTENT_CHARGE;

/// Default Stripe API base URL.
pub const DEFAULT_STRIPE_API_BASE: &str = "https://api.stripe.com";
