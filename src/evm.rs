//! Shared EVM utilities for payment methods.
//!
//! This module provides common EVM types and parsing helpers used by
//! EVM-based payment methods like Tempo.
//!
//! # Re-exports
//!
//! For convenience, this module re-exports core alloy primitives:
//!
//! ```no_run
//! use mpp::evm::{Address, U256};
//! # fn main() {}
//! ```
//!
//! # Examples
//!
//! ```
//! use mpp::evm::{parse_address, parse_amount};
//!
//! let addr = parse_address("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2").unwrap();
//! let amount = parse_amount("1000000").unwrap();
//! ```

use std::str::FromStr;

use crate::error::{MppError, Result};

pub use alloy::primitives::{Address, U256};

/// Parse an Ethereum address from a string.
///
/// # Examples
///
/// ```
/// use mpp::evm::parse_address;
///
/// let addr = parse_address("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2").unwrap();
/// ```
pub fn parse_address(s: &str) -> Result<Address> {
    Address::from_str(s)
        .map_err(|e| MppError::InvalidConfig(format!("Invalid EVM address '{}': {}", s, e)))
}

/// Parse a U256 amount from a string.
///
/// # Examples
///
/// ```
/// use mpp::evm::parse_amount;
///
/// let amount = parse_amount("1000000").unwrap();
/// assert_eq!(amount.to_string(), "1000000");
/// ```
pub fn parse_amount(s: &str) -> Result<U256> {
    U256::from_str(s)
        .map_err(|e| MppError::InvalidAmount(format!("Invalid U256 amount '{}': {}", s, e)))
}

/// Format a U256 value with the given number of decimal places.
///
/// Converts atomic units to a human-readable decimal string.
/// For example, `1000000` with 6 decimals becomes `"1.000000"`.
///
/// # Examples
///
/// ```
/// use mpp::evm::format_u256_with_decimals;
/// use alloy::primitives::U256;
///
/// assert_eq!(format_u256_with_decimals(U256::from(1_500_000u64), 6), "1.500000");
/// assert_eq!(format_u256_with_decimals(U256::from(42u64), 0), "42");
/// ```
pub fn format_u256_with_decimals(value: U256, decimals: u8) -> String {
    if decimals == 0 {
        return value.to_string();
    }

    let divisor = U256::from(10u64).pow(U256::from(decimals));
    let whole = value / divisor;
    let remainder = value % divisor;

    let remainder_str = remainder.to_string();
    let padded = format!("{:0>width$}", remainder_str, width = decimals as usize);

    format!("{}.{}", whole, padded)
}

/// Format a U256 value with decimal places, trimming trailing zeros.
///
/// Like [`format_u256_with_decimals`] but removes trailing zeros for
/// cleaner display. Includes the token symbol in the output.
///
/// # Examples
///
/// ```
/// use mpp::evm::format_u256_trimmed;
/// use alloy::primitives::U256;
///
/// assert_eq!(format_u256_trimmed(U256::from(1_500_000u64), 6, "USDC"), "1.5 USDC");
/// assert_eq!(format_u256_trimmed(U256::from(1_000_000u64), 6, "USDC"), "1 USDC");
/// ```
pub fn format_u256_trimmed(value: U256, decimals: u8, symbol: &str) -> String {
    if decimals == 0 {
        return format!("{} {}", value, symbol);
    }

    let divisor = U256::from(10u64).pow(U256::from(decimals));
    let whole = value / divisor;
    let remainder = value % divisor;

    if remainder.is_zero() {
        format!("{} {}", whole, symbol)
    } else {
        let remainder_str = remainder.to_string();
        let padded = format!("{:0>width$}", remainder_str, width = decimals as usize);
        let trimmed = padded.trim_end_matches('0');
        format!("{}.{} {}", whole, trimmed, symbol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address() {
        let addr = parse_address("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2").unwrap();
        assert_eq!(
            format!("{:?}", addr).to_lowercase(),
            "0x742d35cc6634c0532925a3b844bc9e7595f1b0f2"
        );
    }

    #[test]
    fn test_parse_address_invalid() {
        assert!(parse_address("not-an-address").is_err());
        assert!(parse_address("0x123").is_err());
    }

    #[test]
    fn test_parse_amount() {
        assert_eq!(parse_amount("0").unwrap(), U256::ZERO);
        assert_eq!(parse_amount("1000000").unwrap(), U256::from(1_000_000u64));
        assert_eq!(
            parse_amount(
                "115792089237316195423570985008687907853269984665640564039457584007913129639935"
            )
            .unwrap(),
            U256::MAX
        );
    }

    #[test]
    fn test_parse_amount_invalid() {
        assert!(parse_amount("not-a-number").is_err());
        assert!(parse_amount("-1").is_err());
    }

    // --- format_u256_with_decimals ---

    #[test]
    fn test_format_u256_with_decimals_basic() {
        assert_eq!(
            format_u256_with_decimals(U256::from(1_500_000u64), 6),
            "1.500000"
        );
        assert_eq!(
            format_u256_with_decimals(U256::from(1_000_000u64), 6),
            "1.000000"
        );
        assert_eq!(format_u256_with_decimals(U256::from(1u64), 6), "0.000001");
    }

    #[test]
    fn test_format_u256_with_decimals_zero_decimals() {
        assert_eq!(format_u256_with_decimals(U256::from(42u64), 0), "42");
        assert_eq!(format_u256_with_decimals(U256::ZERO, 0), "0");
    }

    #[test]
    fn test_format_u256_with_decimals_zero_value() {
        assert_eq!(format_u256_with_decimals(U256::ZERO, 6), "0.000000");
        assert_eq!(
            format_u256_with_decimals(U256::ZERO, 18),
            "0.000000000000000000"
        );
    }

    #[test]
    fn test_format_u256_with_decimals_large_value() {
        let large = U256::from(u128::MAX) + U256::from(1u64);
        let formatted = format_u256_with_decimals(large, 18);
        assert!(!formatted.is_empty());
        assert!(formatted.contains('.'));
    }

    // --- format_u256_trimmed ---

    #[test]
    fn test_format_u256_trimmed_whole_number() {
        assert_eq!(
            format_u256_trimmed(U256::from(1_000_000u64), 6, "USDC"),
            "1 USDC"
        );
    }

    #[test]
    fn test_format_u256_trimmed_with_fraction() {
        assert_eq!(
            format_u256_trimmed(U256::from(1_500_000u64), 6, "USDC"),
            "1.5 USDC"
        );
        assert_eq!(
            format_u256_trimmed(U256::from(1_234_567u64), 6, "USDC"),
            "1.234567 USDC"
        );
    }

    #[test]
    fn test_format_u256_trimmed_zero() {
        assert_eq!(format_u256_trimmed(U256::ZERO, 6, "USDC"), "0 USDC");
    }

    #[test]
    fn test_format_u256_trimmed_zero_decimals() {
        assert_eq!(format_u256_trimmed(U256::from(42u64), 0, "ETH"), "42 ETH");
    }

    #[test]
    fn test_format_u256_trimmed_trailing_zero_trimming() {
        assert_eq!(
            format_u256_trimmed(U256::from(1_230_000u64), 6, "TOKEN"),
            "1.23 TOKEN"
        );
    }

    #[test]
    fn test_format_u256_trimmed_sub_unit_value() {
        assert_eq!(
            format_u256_trimmed(U256::from(1u64), 6, "USDC"),
            "0.000001 USDC"
        );
    }

    #[test]
    fn test_format_u256_with_decimals_padding() {
        assert_eq!(
            format_u256_with_decimals(U256::from(1000u64), 6),
            "0.001000"
        );
    }

    #[test]
    fn test_format_u256_with_decimals_18_decimals() {
        assert_eq!(
            format_u256_with_decimals(U256::from(1_500_000_000_000_000_000u64), 18),
            "1.500000000000000000"
        );
    }

    #[test]
    fn test_format_u256_trimmed_18_decimals() {
        assert_eq!(
            format_u256_trimmed(U256::from(1_500_000_000_000_000_000u64), 18, "ETH"),
            "1.5 ETH"
        );
    }

    #[test]
    fn test_format_u256_with_decimals_exact_divisor() {
        assert_eq!(
            format_u256_with_decimals(U256::from(2_000_000u64), 6),
            "2.000000"
        );
    }

    #[test]
    fn test_format_u256_trimmed_large_whole_number() {
        assert_eq!(
            format_u256_trimmed(U256::from(123_456_789_000_000u64), 6, "TOKEN"),
            "123456789 TOKEN"
        );
    }
}
