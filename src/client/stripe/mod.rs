//! Stripe-specific client implementations.
//!
//! Provides [`StripeProvider`] which implements [`PaymentProvider`] for
//! Stripe charge challenges using Shared Payment Tokens (SPTs).

mod provider;

pub use provider::StripeProvider;
