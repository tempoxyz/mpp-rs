//! Intent-specific request types for Web Payment Auth.
//!
//! This module provides typed request structures for payment intents:
//!
//! - [`ChargeRequest`]: One-time payment (charge intent)
//! - [`SessionRequest`]: Pay-as-you-go session payment (session intent)
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
//! use mpp::protocol::core::parse_www_authenticate;
//! use mpp::protocol::intents::ChargeRequest;
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

/// Intent identifier for one-time payments.
pub const INTENT_CHARGE: &str = "charge";

/// Intent identifier for pay-as-you-go sessions.
pub const INTENT_SESSION: &str = "session";
pub use payment_request::{
    deserialize as deserialize_request, deserialize_typed as deserialize_request_typed,
    from_challenge as request_from_challenge, from_challenge_typed as request_from_challenge_typed,
    serialize as serialize_request, Request,
};
pub use session::SessionRequest;

/// Convert a human-readable amount to base units by scaling with `10^decimals`.
///
/// Mirrors the TypeScript SDK's `parseUnits(amount, decimals)` from viem.
///
/// # Examples
///
/// - `parse_units("1.5", 6)` → `"1500000"`
/// - `parse_units("100", 6)` → `"100000000"`
/// - `parse_units("0.001", 18)` → `"1000000000000000"`
pub fn parse_units(amount: &str, decimals: u8) -> crate::error::Result<String> {
    if amount.is_empty() {
        return Err(crate::error::MppError::InvalidAmount(
            "Amount cannot be empty".to_string(),
        ));
    }

    let parts: Vec<&str> = amount.split('.').collect();
    if parts.len() > 2 {
        return Err(crate::error::MppError::InvalidAmount(format!(
            "Invalid amount format: {}",
            amount
        )));
    }

    let integer_part = parts[0];
    let fraction_part = if parts.len() == 2 { parts[1] } else { "" };

    if fraction_part.len() > decimals as usize {
        return Err(crate::error::MppError::InvalidAmount(format!(
            "Amount {} has more than {} decimal places",
            amount, decimals
        )));
    }

    // Pad fraction to `decimals` digits
    let padded_fraction = format!("{:0<width$}", fraction_part, width = decimals as usize);

    // Combine integer + padded fraction
    let combined = format!("{}{}", integer_part, padded_fraction);

    // Strip leading zeros (but keep at least one digit)
    let result = combined.trim_start_matches('0');
    if result.is_empty() {
        Ok("0".to_string())
    } else {
        Ok(result.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_units_integer() {
        assert_eq!(parse_units("100", 6).unwrap(), "100000000");
    }

    #[test]
    fn test_parse_units_decimal() {
        assert_eq!(parse_units("1.5", 6).unwrap(), "1500000");
    }

    #[test]
    fn test_parse_units_small_decimal() {
        assert_eq!(parse_units("0.001", 18).unwrap(), "1000000000000000");
    }

    #[test]
    fn test_parse_units_zero() {
        assert_eq!(parse_units("0", 6).unwrap(), "0");
    }

    #[test]
    fn test_parse_units_zero_decimals() {
        assert_eq!(parse_units("100", 0).unwrap(), "100");
    }

    #[test]
    fn test_parse_units_too_many_decimal_places() {
        assert!(parse_units("1.1234567", 6).is_err());
    }

    #[test]
    fn test_parse_units_no_integer_part() {
        assert_eq!(parse_units("0.5", 6).unwrap(), "500000");
    }

    #[test]
    fn test_parse_units_empty_string() {
        assert!(parse_units("", 6).is_err());
    }
}
