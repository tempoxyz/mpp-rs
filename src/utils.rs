//! Utility functions for mpp library

/// Format an Ethereum address with 0x prefix
pub fn format_eth_address(addr: &str) -> String {
    if addr.starts_with("0x") || addr.starts_with("0X") {
        addr.to_string()
    } else {
        format!("0x{addr}")
    }
}

/// Truncate an address for display.
///
/// If the address is longer than `max_len`, it will be truncated to show
/// the first 6 and last 4 characters with "..." in between.
///
/// # Examples
///
/// ```
/// use mpp::utils::truncate_address;
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
