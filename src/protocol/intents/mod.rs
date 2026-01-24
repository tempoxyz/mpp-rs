//! Intent-specific request types for Web Payment Auth.
//!
//! This module provides typed request structures for each payment intent:
//!
//! - [`ChargeRequest`]: One-time payment (charge intent)
//! - [`AuthorizeRequest`]: Pre-authorization for future payments (authorize intent)
//! - [`SubscriptionRequest`]: Recurring payment setup (subscription intent)
//!
//! **Zero heavy dependencies** - only serde and serde_json. No alloy, no blockchain types.
//!
//! All fields are strings (or primitives like u64 for interval). Typed accessors
//! like `amount_u256()` or `recipient_address()` are provided by the methods layer
//! (e.g., `protocol::methods::evm`).
//!
//! # Decoding from PaymentChallenge
//!
//! Use `PaymentChallenge.request.decode::<T>()` to decode the request to a typed struct:
//!
//! ```ignore
//! use mpp_rs::protocol::core::PaymentChallenge;
//! use mpp_rs::protocol::intents::ChargeRequest;
//!
//! let challenge = parse_www_authenticate(header)?;
//! if challenge.intent.is_charge() {
//!     let req: ChargeRequest = challenge.request.decode()?;
//!     println!("Amount: {}, Currency: {}", req.amount, req.currency);
//! }
//! ```

pub mod authorize;
pub mod charge;
pub mod subscription;

pub use authorize::AuthorizeRequest;
pub use charge::ChargeRequest;
pub use subscription::SubscriptionRequest;
