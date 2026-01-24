//! Utility functions for mpp-rs library

/// Format an Ethereum address with 0x prefix
pub fn format_eth_address(addr: &str) -> String {
    if addr.starts_with("0x") || addr.starts_with("0X") {
        addr.to_string()
    } else {
        format!("0x{addr}")
    }
}

/// Strip 0x prefix from hex string if present
pub fn strip_0x_prefix(s: &str) -> &str {
    s.trim()
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}

/// Truncate an address for display.
///
/// If the address is longer than `max_len`, it will be truncated to show
/// the first 6 and last 4 characters with "..." in between.
///
/// # Examples
///
/// ```
/// use mpp_rs::utils::truncate_address;
///
/// // Short addresses are unchanged
/// assert_eq!(truncate_address("0x1234", 20), "0x1234");
///
/// // Long addresses are truncated
/// let addr = "0x1234567890abcdef1234567890abcdef12345678";
/// assert_eq!(truncate_address(addr, 20), "0x1234...5678");
/// ```
pub fn truncate_address(addr: &str, max_len: usize) -> String {
    if addr.len() <= max_len {
        addr.to_string()
    } else {
        let prefix = &addr[..6];
        let suffix = &addr[addr.len() - 4..];
        format!("{prefix}...{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_eth_address() {
        assert_eq!(format_eth_address("abc123"), "0xabc123");
        assert_eq!(format_eth_address("0xabc123"), "0xabc123");
        assert_eq!(format_eth_address("0Xabc123"), "0Xabc123");
    }

    #[test]
    fn test_strip_0x_prefix() {
        assert_eq!(strip_0x_prefix("0xabc123"), "abc123");
        assert_eq!(strip_0x_prefix("0Xabc123"), "abc123");
        assert_eq!(strip_0x_prefix("abc123"), "abc123");
        // ast-grep-ignore: no-leading-whitespace-strings
        assert_eq!(strip_0x_prefix(" 0xabc123 "), "abc123"); // Intentional: testing whitespace trimming
    }

    #[test]
    fn test_truncate_short_address() {
        assert_eq!(truncate_address("0x1234", 20), "0x1234");
    }

    #[test]
    fn test_truncate_long_address() {
        let addr = "0x1234567890abcdef1234567890abcdef12345678";
        assert_eq!(truncate_address(addr, 20), "0x1234...5678");
    }

    #[test]
    fn test_truncate_exact_length() {
        let addr = "0x12345678901234567890";
        assert_eq!(truncate_address(addr, 22), addr);
    }
}
