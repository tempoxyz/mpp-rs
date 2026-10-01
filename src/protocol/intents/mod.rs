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

/// Return `amount` if it is a base-unit integer: one or more ASCII digits.
///
/// Integer parsers are more lenient than the protocol (`u128` accepts `+1`;
/// `U256` accepts `0x10`, `1_000` and the empty string), so amounts are
/// checked here before they are parsed. Leading zeros are accepted, as in mppx.
pub(crate) fn base_unit_digits(amount: &str) -> Option<&str> {
    (!amount.is_empty() && amount.bytes().all(|b| b.is_ascii_digit())).then_some(amount)
}

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

    if (integer_part.is_empty() && fraction_part.is_empty())
        || !integer_part.chars().all(|c| c.is_ascii_digit())
        || !fraction_part.chars().all(|c| c.is_ascii_digit())
    {
        return Err(crate::error::MppError::InvalidAmount(format!(
            "Invalid amount format: {}",
            amount
        )));
    }

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
        assert_eq!(parse_units(".5", 6).unwrap(), "500000");
    }

    #[test]
    fn test_parse_units_no_fractional_part() {
        assert_eq!(parse_units("1.", 6).unwrap(), "1000000");
    }

    #[test]
    fn test_parse_units_invalid_format() {
        for amount in [".", "abc", "1e3", "+1", "-1", "1.2.3"] {
            assert!(parse_units(amount, 6).is_err(), "accepted {amount}");
        }
    }

    #[test]
    fn test_parse_units_empty_string() {
        assert!(parse_units("", 6).is_err());
    }

    /// Every amount parser accepts the same grammar: ASCII digits only.
    #[test]
    fn test_amount_parsers_agree_on_grammar() {
        let charge = |amount: &str| ChargeRequest {
            amount: amount.to_string(),
            ..Default::default()
        };
        let session = |amount: &str| SessionRequest {
            amount: amount.to_string(),
            ..Default::default()
        };

        for (amount, expected) in [
            ("0", Some(0u128)),
            ("1000000", Some(1_000_000)),
            ("007", Some(7)),
            ("340282366920938463463374607431768211455", Some(u128::MAX)),
            ("", None),
            ("+100", None),
            ("-1", None),
            ("0x10", None),
            ("0X10", None),
            ("0b11", None),
            ("0o7", None),
            ("1_000", None),
            ("1.5", None),
            ("1e3", None),
            (" 1", None),
            ("1 ", None),
            ("١٢٣", None),
        ] {
            assert_eq!(
                charge(amount).parse_amount().ok(),
                expected,
                "charge {amount:?}"
            );
            assert_eq!(
                session(amount).parse_amount().ok(),
                expected,
                "session {amount:?}"
            );
            #[cfg(feature = "evm")]
            {
                let expected = expected.map(crate::evm::U256::from);
                assert_eq!(
                    crate::evm::parse_amount(amount).ok(),
                    expected,
                    "evm {amount:?}"
                );
                assert_eq!(
                    charge(amount).parse_amount_u256().ok(),
                    expected,
                    "charge u256 {amount:?}"
                );
            }
        }
    }
}
