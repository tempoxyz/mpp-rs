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
//! ```
//! use mpay::protocol::core::parse_www_authenticate;
//! use mpay::protocol::intents::ChargeRequest;
//!
//! let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QifQ""#;
//! let challenge = parse_www_authenticate(header).unwrap();
//! if challenge.intent.is_charge() {
//!     let req: ChargeRequest = challenge.request.decode().unwrap();
//!     println!("Amount: {}, Currency: {:?}", req.amount, req.currency);
//! }
//! ```

pub mod charge;
pub mod payment_request;
pub mod session;

pub use charge::ChargeRequest;
pub use payment_request::{
    deserialize as deserialize_request,
    deserialize_typed as deserialize_request_typed,
    from as from_request,
    from_challenge as request_from_challenge,
    from_challenge_typed as request_from_challenge_typed,
    serialize as serialize_request,
    Request,
};
pub use session::SessionRequest;
