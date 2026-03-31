//! Dollar amount to base unit conversion.
//!
//! Converts human-readable dollar amounts (e.g., `"0.10"`, `"1.50"`) to
//! base units (e.g., `"100000"`, `"1500000"`) using integer arithmetic only.

use std::fmt;

/// Errors from dollar amount parsing.
#[derive(Debug)]
pub enum AmountError {
    Empty,
    InvalidFormat(String),
    TooManyDecimals { given: usize, max: u32 },
    ZeroOrNegative,
    Overflow,
}

impl fmt::Display for AmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AmountError::Empty => write!(f, "amount cannot be empty"),
            AmountError::InvalidFormat(s) => write!(f, "invalid amount format: {}", s),
            AmountError::TooManyDecimals { given, max } => {
                write!(
                    f,
                    "too many decimal places: {} given, max {} for this token",
                    given, max
                )
            }
            AmountError::ZeroOrNegative => write!(f, "amount must be greater than zero"),
            AmountError::Overflow => write!(f, "amount too large"),
        }
    }
}

impl std::error::Error for AmountError {}

impl From<AmountError> for crate::error::MppError {
    fn from(e: AmountError) -> Self {
        crate::error::MppError::InvalidAmount(e.to_string())
    }
}

/// Parse a dollar amount string to base units.
///
/// Converts human-readable amounts like `"0.10"` or `"1.50"` to base unit
/// strings like `"100000"` or `"1500000"` (with 6 decimals).
///
/// Uses pure integer arithmetic — no floating point.
///
/// # Arguments
///
/// * `amount` - Dollar amount string (e.g., `"0.10"`, `"1"`, `"100.50"`)
/// * `decimals` - Number of decimal places for the token (e.g., 6 for pathUSD)
///
/// # Examples
///
/// ```
/// use mpp::server::parse_dollar_amount;
///
/// assert_eq!(parse_dollar_amount("0.10", 6).unwrap(), "100000");
/// assert_eq!(parse_dollar_amount("1", 6).unwrap(), "1000000");
/// assert_eq!(parse_dollar_amount("1.50", 6).unwrap(), "1500000");
/// assert_eq!(parse_dollar_amount("0.001", 6).unwrap(), "1000");
/// assert_eq!(parse_dollar_amount("1.000001", 6).unwrap(), "1000001");
/// ```
pub fn parse_dollar_amount(
    amount: &str,
    decimals: u32,
) -> std::result::Result<String, AmountError> {
    let amount = amount.trim();
    if amount.is_empty() {
        return Err(AmountError::Empty);
    }

    if amount.starts_with('-') {
        return Err(AmountError::ZeroOrNegative);
    }

    let (integer_part, frac_part) = match amount.split_once('.') {
        Some((int, frac)) => {
            if frac.is_empty() {
                (int, "")
            } else {
                (int, frac)
            }
        }
        None => (amount, ""),
    };

    if integer_part.is_empty() && frac_part.is_empty() {
        return Err(AmountError::InvalidFormat(amount.to_string()));
    }

    if !integer_part.is_empty() && !integer_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(AmountError::InvalidFormat(amount.to_string()));
    }
    if !frac_part.is_empty() && !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(AmountError::InvalidFormat(amount.to_string()));
    }

    let frac_len = frac_part.len();
    if frac_len > decimals as usize {
        return Err(AmountError::TooManyDecimals {
            given: frac_len,
            max: decimals,
        });
    }

    let int_val: u128 = if integer_part.is_empty() {
        0
    } else {
        integer_part
            .parse()
            .map_err(|_| AmountError::InvalidFormat(amount.to_string()))?
    };

    let frac_val: u128 = if frac_part.is_empty() {
        0
    } else {
        frac_part
            .parse()
            .map_err(|_| AmountError::InvalidFormat(amount.to_string()))?
    };

    if decimals > 38 {
        return Err(AmountError::Overflow);
    }

    let scale: u128 = 10u128.pow(decimals);
    let frac_scale: u128 = 10u128.pow(decimals - frac_len as u32);

    let base_units = int_val
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac_val.checked_mul(frac_scale)?))
        .ok_or(AmountError::Overflow)?;

    // Zero-amount charges are valid for identity/proof flows.
    // Negative amounts are caught by the leading '-' check above.

    Ok(base_units.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_whole_numbers() {
        assert_eq!(parse_dollar_amount("1", 6).unwrap(), "1000000");
        assert_eq!(parse_dollar_amount("10", 6).unwrap(), "10000000");
        assert_eq!(parse_dollar_amount("100", 6).unwrap(), "100000000");
    }

    #[test]
    fn test_decimal_amounts() {
        assert_eq!(parse_dollar_amount("0.10", 6).unwrap(), "100000");
        assert_eq!(parse_dollar_amount("0.01", 6).unwrap(), "10000");
        assert_eq!(parse_dollar_amount("1.50", 6).unwrap(), "1500000");
        assert_eq!(parse_dollar_amount("0.001", 6).unwrap(), "1000");
    }

    #[test]
    fn test_max_precision() {
        assert_eq!(parse_dollar_amount("1.000001", 6).unwrap(), "1000001");
        assert_eq!(parse_dollar_amount("0.000001", 6).unwrap(), "1");
    }

    #[test]
    fn test_too_many_decimals() {
        let err = parse_dollar_amount("0.0000001", 6).unwrap_err();
        assert!(matches!(
            err,
            AmountError::TooManyDecimals { given: 7, max: 6 }
        ));
    }

    #[test]
    fn test_zero_allowed() {
        assert_eq!(parse_dollar_amount("0", 6).unwrap(), "0");
        assert_eq!(parse_dollar_amount("0.000000", 6).unwrap(), "0");
    }

    #[test]
    fn test_negative_rejected() {
        let err = parse_dollar_amount("-1", 6).unwrap_err();
        assert!(matches!(err, AmountError::ZeroOrNegative));
    }

    #[test]
    fn test_empty_rejected() {
        let err = parse_dollar_amount("", 6).unwrap_err();
        assert!(matches!(err, AmountError::Empty));
    }

    #[test]
    fn test_invalid_format() {
        assert!(parse_dollar_amount("abc", 6).is_err());
        assert!(parse_dollar_amount("1.2.3", 6).is_err());
        assert!(parse_dollar_amount("$1.00", 6).is_err());
    }

    #[test]
    fn test_trailing_dot() {
        assert_eq!(parse_dollar_amount("1.", 6).unwrap(), "1000000");
    }

    #[test]
    fn test_18_decimals() {
        assert_eq!(parse_dollar_amount("1", 18).unwrap(), "1000000000000000000");
        assert_eq!(
            parse_dollar_amount("0.5", 18).unwrap(),
            "500000000000000000"
        );
        assert_eq!(
            parse_dollar_amount("0.000000000000000001", 18).unwrap(),
            "1"
        );
    }

    #[test]
    fn test_whitespace_trimmed() {
        assert_eq!(parse_dollar_amount("  1.50  ", 6).unwrap(), "1500000");
    }

    #[test]
    fn test_leading_zeros() {
        assert_eq!(parse_dollar_amount("01.50", 6).unwrap(), "1500000");
    }

    #[test]
    fn test_leading_dot() {
        assert_eq!(parse_dollar_amount(".5", 6).unwrap(), "500000");
        assert_eq!(parse_dollar_amount(".123456", 6).unwrap(), "123456");
        assert_eq!(parse_dollar_amount(".000001", 6).unwrap(), "1");
    }

    #[test]
    fn test_overflow_large_amount() {
        let err = parse_dollar_amount("999999999999999999999999999999999", 6).unwrap_err();
        assert!(matches!(err, AmountError::Overflow));
    }

    #[test]
    fn test_overflow_large_decimals() {
        let err = parse_dollar_amount("1", 39).unwrap_err();
        assert!(matches!(err, AmountError::Overflow));
    }

    #[test]
    fn test_decimals_boundary() {
        assert!(parse_dollar_amount("1", 38).is_ok());
        assert!(parse_dollar_amount("1", 39).is_err());
    }
}
