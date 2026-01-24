//! Intent-specific request types for Web Payment Auth.
//!
//! This module provides typed request structures for payment intents:
//!
//! - [`ChargeRequest`]: One-time payment (charge intent)
//!
//! **Zero heavy dependencies** - only serde and serde_json. No alloy, no blockchain types.
//!
//! All fields are strings. Typed accessors like `amount_u256()` or `recipient_address()`
//! are provided by the methods layer (e.g., `protocol::methods::evm`).
//!
//! # Decoding from PaymentChallenge
//!
//! Use `PaymentChallenge.request.decode::<T>()` to decode the request to a typed struct:
//!
//! ```ignore
//! use mpay::protocol::core::PaymentChallenge;
//! use mpay::protocol::intents::ChargeRequest;
//!
//! let challenge = parse_www_authenticate(header)?;
//! if challenge.intent.is_charge() {
//!     let req: ChargeRequest = challenge.request.decode()?;
//!     println!("Amount: {}, Currency: {}", req.amount, req.currency);
//! }
//! ```

pub mod charge;

pub use charge::ChargeRequest;
