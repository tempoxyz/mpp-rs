//! EVM parsing helpers.
//!
//! Provides functions to parse EVM-specific types from strings.

use alloy::primitives::{Address, U256};
use std::str::FromStr;

use crate::error::{MppError, Result};

/// Parse an Ethereum address from a string.
///
/// # Examples
///
/// ```
/// use mpp_rs::protocol::methods::evm::parse_address;
///
/// let addr = parse_address("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2").unwrap();
/// ```
pub fn parse_address(s: &str) -> Result<Address> {
    Address::from_str(s)
        .map_err(|e| MppError::invalid_address(format!("Invalid EVM address '{}': {}", s, e)))
}

/// Parse a U256 amount from a string.
///
/// # Examples
///
/// ```
/// use mpp_rs::protocol::methods::evm::parse_amount;
///
/// let amount = parse_amount("1000000").unwrap();
/// assert_eq!(amount.to_string(), "1000000");
/// ```
pub fn parse_amount(s: &str) -> Result<U256> {
    U256::from_str(s)
        .map_err(|e| MppError::InvalidAmount(format!("Invalid U256 amount '{}': {}", s, e)))
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
        assert!(parse_address("0x123").is_err()); // too short
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
}
