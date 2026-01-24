//! Blockchain explorer URL configuration for generating clickable links.
//!
//! This module provides flexible URL generation for blockchain explorers,
//! supporting different URL patterns (Etherscan-style, Tempo, Blockscout, etc.)
//! and allowing full customization via config.

use serde::{Deserialize, Serialize};

/// URL path patterns for different resource types.
///
/// This struct provides flexible URL generation for blockchain explorers.
/// Different explorers use different URL patterns, and this struct handles
/// those variations.
///
/// # Examples
///
/// ```
/// use mpp_rs::explorer::ExplorerConfig;
///
/// // Etherscan-style explorer
/// let etherscan = ExplorerConfig::etherscan("https://etherscan.io");
/// assert_eq!(
///     etherscan.tx_url("0xabc123"),
///     "https://etherscan.io/tx/0xabc123"
/// );
///
/// // Tempo explorer (uses /receipt/{hash} for transactions)
/// let tempo = ExplorerConfig::tempo("https://explore.tempo.xyz");
/// assert_eq!(
///     tempo.tx_url("0xabc123"),
///     "https://explore.tempo.xyz/receipt/0xabc123"
/// );
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorerConfig {
    /// Base URL (e.g., "https://etherscan.io")
    pub base_url: String,
    /// Path template for transactions (default: "/tx/{hash}")
    #[serde(default = "default_tx_path")]
    pub tx_path: String,
    /// Path template for blocks (default: "/block/{num}")
    #[serde(default = "default_block_path")]
    pub block_path: String,
    /// Path template for addresses (default: "/address/{addr}")
    #[serde(default = "default_address_path")]
    pub address_path: String,
}

fn default_tx_path() -> String {
    "/tx/{hash}".to_string()
}

fn default_block_path() -> String {
    "/block/{num}".to_string()
}

fn default_address_path() -> String {
    "/address/{addr}".to_string()
}

impl ExplorerConfig {
    /// Create an Etherscan-style explorer config.
    ///
    /// Uses standard paths: `/tx/{hash}`, `/block/{num}`, `/address/{addr}`
    pub fn etherscan(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            tx_path: default_tx_path(),
            block_path: default_block_path(),
            address_path: default_address_path(),
        }
    }

    /// Create a Tempo explorer config.
    ///
    /// Uses Tempo-specific paths: `/receipt/{hash}` for transactions.
    pub fn tempo(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            tx_path: "/receipt/{hash}".to_string(),
            block_path: default_block_path(),
            address_path: default_address_path(),
        }
    }

    /// Create a Blockscout explorer config.
    ///
    /// Uses standard Etherscan-compatible paths.
    pub fn blockscout(base_url: impl Into<String>) -> Self {
        Self::etherscan(base_url)
    }

    /// Create a custom explorer config with specified paths.
    pub fn custom(
        base_url: impl Into<String>,
        tx_path: impl Into<String>,
        block_path: impl Into<String>,
        address_path: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            tx_path: tx_path.into(),
            block_path: block_path.into(),
            address_path: address_path.into(),
        }
    }

    /// Build a transaction URL.
    ///
    /// # Example
    ///
    /// ```
    /// use mpp_rs::explorer::ExplorerConfig;
    ///
    /// let explorer = ExplorerConfig::etherscan("https://etherscan.io");
    /// let url = explorer.tx_url("0x123abc");
    /// assert_eq!(url, "https://etherscan.io/tx/0x123abc");
    /// ```
    pub fn tx_url(&self, hash: &str) -> String {
        format!("{}{}", self.base_url, self.tx_path.replace("{hash}", hash))
    }

    /// Build a block URL.
    ///
    /// # Example
    ///
    /// ```
    /// use mpp_rs::explorer::ExplorerConfig;
    ///
    /// let explorer = ExplorerConfig::etherscan("https://etherscan.io");
    /// let url = explorer.block_url("12345678");
    /// assert_eq!(url, "https://etherscan.io/block/12345678");
    /// ```
    pub fn block_url(&self, num: &str) -> String {
        format!("{}{}", self.base_url, self.block_path.replace("{num}", num))
    }

    /// Build an address URL.
    ///
    /// # Example
    ///
    /// ```
    /// use mpp_rs::explorer::ExplorerConfig;
    ///
    /// let explorer = ExplorerConfig::etherscan("https://etherscan.io");
    /// let url = explorer.address_url("0x742d35Cc6634C0532925a3b844Bc9e7595f");
    /// assert_eq!(url, "https://etherscan.io/address/0x742d35Cc6634C0532925a3b844Bc9e7595f");
    /// ```
    pub fn address_url(&self, addr: &str) -> String {
        format!(
            "{}{}",
            self.base_url,
            self.address_path.replace("{addr}", addr)
        )
    }
}

/// Well-known explorer types with predefined URL patterns.
///
/// This enum provides shortcuts for common explorer types, avoiding the need
/// to specify URL patterns manually for well-known explorers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExplorerType {
    /// Etherscan-style explorer (also used by Basescan, Arbiscan, etc.)
    #[default]
    Etherscan,
    /// Tempo blockchain explorer
    Tempo,
    /// Blockscout explorer (Etherscan-compatible paths)
    Blockscout,
}

impl ExplorerType {
    /// Get the transaction URL path for this explorer type.
    pub fn tx_path(&self) -> &'static str {
        match self {
            Self::Etherscan | Self::Blockscout => "/tx/{hash}",
            Self::Tempo => "/receipt/{hash}",
        }
    }

    /// Get the block URL path for this explorer type.
    pub fn block_path(&self) -> &'static str {
        "/block/{num}"
    }

    /// Get the address URL path for this explorer type.
    pub fn address_path(&self) -> &'static str {
        "/address/{addr}"
    }

    /// Create an ExplorerConfig from this type with the given base URL.
    pub fn with_base_url(&self, base_url: impl Into<String>) -> ExplorerConfig {
        ExplorerConfig {
            base_url: base_url.into(),
            tx_path: self.tx_path().to_string(),
            block_path: self.block_path().to_string(),
            address_path: self.address_path().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etherscan_urls() {
        let explorer = ExplorerConfig::etherscan("https://etherscan.io");

        assert_eq!(
            explorer.tx_url("0xabc123"),
            "https://etherscan.io/tx/0xabc123"
        );
        assert_eq!(
            explorer.block_url("12345678"),
            "https://etherscan.io/block/12345678"
        );
        assert_eq!(
            explorer.address_url("0x742d35Cc"),
            "https://etherscan.io/address/0x742d35Cc"
        );
    }

    #[test]
    fn test_tempo_urls() {
        let explorer = ExplorerConfig::tempo("https://explore.tempo.xyz");

        assert_eq!(
            explorer.tx_url("0xabc123"),
            "https://explore.tempo.xyz/receipt/0xabc123"
        );
        assert_eq!(
            explorer.block_url("12345678"),
            "https://explore.tempo.xyz/block/12345678"
        );
        assert_eq!(
            explorer.address_url("0x742d35Cc"),
            "https://explore.tempo.xyz/address/0x742d35Cc"
        );
    }

    #[test]
    fn test_custom_explorer() {
        let explorer = ExplorerConfig::custom(
            "https://scan.weird.com",
            "/transaction/{hash}",
            "/blocks/{num}",
            "/accounts/{addr}",
        );

        assert_eq!(
            explorer.tx_url("0xabc"),
            "https://scan.weird.com/transaction/0xabc"
        );
        assert_eq!(
            explorer.block_url("100"),
            "https://scan.weird.com/blocks/100"
        );
        assert_eq!(
            explorer.address_url("0x123"),
            "https://scan.weird.com/accounts/0x123"
        );
    }

    #[test]
    fn test_explorer_type_with_base_url() {
        let tempo = ExplorerType::Tempo.with_base_url("https://explore.tempo.xyz");
        assert_eq!(
            tempo.tx_url("0xabc"),
            "https://explore.tempo.xyz/receipt/0xabc"
        );

        let etherscan = ExplorerType::Etherscan.with_base_url("https://basescan.org");
        assert_eq!(etherscan.tx_url("0xabc"), "https://basescan.org/tx/0xabc");
    }

    #[test]
    fn test_deserialize_explorer_config() {
        let json = r#"{
            "base_url": "https://etherscan.io"
        }"#;

        let explorer: ExplorerConfig =
            serde_json::from_str(json).expect("should deserialize explorer config");
        assert_eq!(explorer.base_url, "https://etherscan.io");
        assert_eq!(explorer.tx_path, "/tx/{hash}");
        assert_eq!(explorer.block_path, "/block/{num}");
        assert_eq!(explorer.address_path, "/address/{addr}");
    }

    #[test]
    fn test_deserialize_explorer_config_with_custom_paths() {
        let json = r#"{
            "base_url": "https://custom.com",
            "tx_path": "/txn/{hash}",
            "block_path": "/blk/{num}"
        }"#;

        let explorer: ExplorerConfig = serde_json::from_str(json)
            .expect("should deserialize explorer config with custom paths");
        assert_eq!(explorer.tx_path, "/txn/{hash}");
        assert_eq!(explorer.block_path, "/blk/{num}");
        assert_eq!(explorer.address_path, "/address/{addr}");
    }

    #[test]
    fn test_deserialize_explorer_type() {
        let json = r#""tempo""#;
        let explorer_type: ExplorerType =
            serde_json::from_str(json).expect("should deserialize tempo explorer type");
        assert_eq!(explorer_type, ExplorerType::Tempo);

        let json = r#""etherscan""#;
        let explorer_type: ExplorerType =
            serde_json::from_str(json).expect("should deserialize etherscan explorer type");
        assert_eq!(explorer_type, ExplorerType::Etherscan);
    }
}
