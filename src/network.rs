//! Network registry with support for both built-in and custom networks.

use crate::currency::Currency;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

/// Network name constants for use in configuration and matching
pub mod networks {
    pub const ETHEREUM: &str = "ethereum";
    pub const ETHEREUM_SEPOLIA: &str = "ethereum-sepolia";
    pub const BASE: &str = "base";
    pub const BASE_SEPOLIA: &str = "base-sepolia";
    pub const AVALANCHE: &str = "avalanche";
    pub const AVALANCHE_FUJI: &str = "avalanche-fuji";
    pub const POLYGON: &str = "polygon";
    pub const ARBITRUM: &str = "arbitrum";
    pub const OPTIMISM: &str = "optimism";
    pub const TEMPO: &str = "tempo";
    pub const TEMPO_MODERATO: &str = "tempo-moderato";
}

/// EVM Chain ID constants.
///
/// These constants provide self-documenting, compile-time checked chain IDs
/// for use throughout the codebase instead of magic numbers.
pub mod evm_chain_ids {
    /// Ethereum Mainnet
    pub const ETHEREUM: u64 = 1;
    /// Ethereum Sepolia Testnet
    pub const ETHEREUM_SEPOLIA: u64 = 11155111;
    /// Base Mainnet
    pub const BASE: u64 = 8453;
    /// Base Sepolia Testnet
    pub const BASE_SEPOLIA: u64 = 84532;
    /// Avalanche C-Chain
    pub const AVALANCHE: u64 = 43114;
    /// Avalanche Fuji Testnet
    pub const AVALANCHE_FUJI: u64 = 43113;
    /// Polygon Mainnet
    pub const POLYGON: u64 = 137;
    /// Arbitrum One
    pub const ARBITRUM: u64 = 42161;
    /// Optimism Mainnet
    pub const OPTIMISM: u64 = 10;
    /// Tempo Mainnet
    pub const TEMPO: u64 = 4217;
    /// Tempo Moderato Testnet
    pub const TEMPO_MODERATO: u64 = 42431;
}

/// Chain type (blockchain family)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    Evm,
}

/// Built-in network definition (compile-time constant)
struct BuiltinNetwork {
    id: &'static str,
    chain_type: ChainType,
    chain_id: Option<u64>,
    mainnet: bool,
    display_name: &'static str,
    rpc_url: &'static str,
    /// Alternative network identifiers (e.g., CAIP-2 formats)
    aliases: &'static [&'static str],
}

/// Default built-in networks defined in code
const BUILTIN_NETWORKS: &[BuiltinNetwork] = &[
    BuiltinNetwork {
        id: networks::ETHEREUM,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::ETHEREUM),
        mainnet: true,
        display_name: "Ethereum",
        rpc_url: "https://eth.llamarpc.com",
        aliases: &["eip155:1"],
    },
    BuiltinNetwork {
        id: networks::ETHEREUM_SEPOLIA,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::ETHEREUM_SEPOLIA),
        mainnet: false,
        display_name: "Ethereum Sepolia",
        rpc_url: "https://ethereum-sepolia-rpc.publicnode.com",
        aliases: &["eip155:11155111"],
    },
    BuiltinNetwork {
        id: networks::BASE,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::BASE),
        mainnet: true,
        display_name: "Base",
        rpc_url: "https://mainnet.base.org",
        aliases: &["eip155:8453"],
    },
    BuiltinNetwork {
        id: networks::BASE_SEPOLIA,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::BASE_SEPOLIA),
        mainnet: false,
        display_name: "Base Sepolia",
        rpc_url: "https://sepolia.base.org",
        aliases: &["eip155:84532"],
    },
    BuiltinNetwork {
        id: networks::AVALANCHE,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::AVALANCHE),
        mainnet: true,
        display_name: "Avalanche C-Chain",
        rpc_url: "https://api.avax.network/ext/bc/C/rpc",
        aliases: &["eip155:43114"],
    },
    BuiltinNetwork {
        id: networks::AVALANCHE_FUJI,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::AVALANCHE_FUJI),
        mainnet: false,
        display_name: "Avalanche Fuji",
        rpc_url: "https://api.avax-test.network/ext/bc/C/rpc",
        aliases: &["eip155:43113"],
    },
    BuiltinNetwork {
        id: networks::POLYGON,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::POLYGON),
        mainnet: true,
        display_name: "Polygon",
        rpc_url: "https://polygon-rpc.com",
        aliases: &["eip155:137"],
    },
    BuiltinNetwork {
        id: networks::ARBITRUM,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::ARBITRUM),
        mainnet: true,
        display_name: "Arbitrum One",
        rpc_url: "https://arb1.arbitrum.io/rpc",
        aliases: &["eip155:42161"],
    },
    BuiltinNetwork {
        id: networks::OPTIMISM,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::OPTIMISM),
        mainnet: true,
        display_name: "Optimism",
        rpc_url: "https://mainnet.optimism.io",
        aliases: &["eip155:10"],
    },
    BuiltinNetwork {
        id: networks::TEMPO,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::TEMPO),
        mainnet: true,
        display_name: "Tempo",
        rpc_url: "https://rpc.tempo.xyz",
        aliases: &["eip155:4217"],
    },
    BuiltinNetwork {
        id: networks::TEMPO_MODERATO,
        chain_type: ChainType::Evm,
        chain_id: Some(evm_chain_ids::TEMPO_MODERATO),
        mainnet: false,
        display_name: "Tempo Moderato (Testnet)",
        rpc_url: "https://rpc.moderato.tempo.xyz",
        aliases: &["eip155:42431"],
    },
];

/// Runtime network information
///
/// Contains metadata about a blockchain network including its type,
/// chain ID, mainnet/testnet status, display name,
/// and RPC endpoint URL.
///
/// # Examples
///
/// ```
/// use mpp_rs::network::get_network;
///
/// let tempo = get_network("tempo").expect("tempo network exists");
/// assert!(tempo.mainnet);
/// assert!(!tempo.is_testnet());
/// ```
#[derive(Debug, Clone)]
pub struct NetworkInfo {
    /// The blockchain family
    pub chain_type: ChainType,
    /// Chain ID for EVM networks
    pub chain_id: Option<u64>,
    /// True if this is a mainnet, false for testnets
    pub mainnet: bool,
    /// Human-readable display name
    pub display_name: String,
    /// RPC endpoint URL for blockchain interactions
    pub rpc_url: String,
}

impl NetworkInfo {
    pub fn is_testnet(&self) -> bool {
        !self.mainnet
    }
}

/// Registry for managing network configurations
///
/// Loads network definitions from built-in defaults.
/// Consumers can extend this with custom networks through their own configuration layer.
///
/// The registry provides lookup and filtering capabilities for all configured networks.
///
/// # Structure
///
/// Maps network ID (e.g., "tempo", "ethereum") to [`NetworkInfo`]
///

pub struct NetworkRegistry {
    networks: HashMap<String, NetworkInfo>,
    /// Maps network aliases (e.g., CAIP-2 formats) to canonical network IDs
    aliases: HashMap<String, String>,
}

impl NetworkRegistry {
    /// Load network registry from built-in defaults and config.toml overrides.
    ///
    /// The loading order is:
    /// 1. Start with built-in network definitions (defined in code)
    /// 2. Apply RPC URL overrides from config.toml `[rpc]` section
    /// 3. Merge custom networks from config.toml `[[networks]]` section
    fn load() -> Self {
        // Start with built-in defaults from code
        let mut networks = HashMap::new();
        let mut aliases = HashMap::new();

        for builtin in BUILTIN_NETWORKS {
            let info = NetworkInfo {
                chain_type: builtin.chain_type,
                chain_id: builtin.chain_id,
                mainnet: builtin.mainnet,
                display_name: builtin.display_name.to_string(),
                rpc_url: builtin.rpc_url.to_string(),
            };
            networks.insert(builtin.id.to_string(), info);

            // Register all aliases for this network
            for alias in builtin.aliases {
                aliases.insert(alias.to_string(), builtin.id.to_string());
            }
        }

        // mpp-rs: No config file loading - only built-in networks
        // Consumers (like purl) can add custom networks via their own config layer

        Self { networks, aliases }
    }

    /// Get network info by ID
    pub fn get(&self, id: &str) -> Option<&NetworkInfo> {
        self.networks.get(id)
    }

    /// Resolve a network alias to its canonical ID
    ///
    /// Supports both v1 names (returned as-is) and v2 CAIP-2 formats (resolved to v1 names).
    /// Returns the input unchanged if it's already a canonical ID or if no alias exists.
    pub fn resolve_alias<'a>(&'a self, network: &'a str) -> &'a str {
        self.aliases
            .get(network)
            .map(|s| s.as_str())
            .unwrap_or(network)
    }

    /// Get all network IDs
    pub fn all_ids(&self) -> impl Iterator<Item = &String> {
        self.networks.keys()
    }

    /// Get all networks of a specific chain type
    pub fn by_chain_type(
        &self,
        chain_type: ChainType,
    ) -> impl Iterator<Item = (&String, &NetworkInfo)> {
        self.networks
            .iter()
            .filter(move |(_, info)| info.chain_type == chain_type)
    }

    /// Check if a network ID is an EVM network
    pub fn is_evm(&self, id: &str) -> bool {
        self.get(id)
            .map(|n| n.chain_type == ChainType::Evm)
            .unwrap_or(false)
    }

    /// Get the number of registered networks
    pub fn len(&self) -> usize {
        self.networks.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }
}

/// Global network registry
pub static NETWORK_REGISTRY: LazyLock<NetworkRegistry> = LazyLock::new(NetworkRegistry::load);

/// Type-safe network identifier with FromStr parsing.
///
/// This enum provides compile-time guarantees for well-known network names.
/// For dynamic/custom networks, use the NetworkRegistry directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Ethereum,
    EthereumSepolia,
    Base,
    BaseSepolia,
    Avalanche,
    AvalancheFuji,
    Polygon,
    Arbitrum,
    Optimism,
    TempoModerato,
}

impl Network {
    /// Get the string identifier for this network.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Network::Ethereum => networks::ETHEREUM,
            Network::EthereumSepolia => networks::ETHEREUM_SEPOLIA,
            Network::Base => networks::BASE,
            Network::BaseSepolia => networks::BASE_SEPOLIA,
            Network::Avalanche => networks::AVALANCHE,
            Network::AvalancheFuji => networks::AVALANCHE_FUJI,
            Network::Polygon => networks::POLYGON,
            Network::Arbitrum => networks::ARBITRUM,
            Network::Optimism => networks::OPTIMISM,
            Network::TempoModerato => networks::TEMPO_MODERATO,
        }
    }

    /// Get the NetworkInfo for this network from the registry.
    pub fn info(&self) -> NetworkInfo {
        // These should always exist since they're built-in
        NETWORK_REGISTRY
            .get(self.as_str())
            .cloned()
            .expect("Built-in network missing from registry")
    }

    /// Get all network variants as a const array.
    pub const fn all() -> [Network; 10] {
        [
            Network::Ethereum,
            Network::EthereumSepolia,
            Network::Base,
            Network::BaseSepolia,
            Network::Avalanche,
            Network::AvalancheFuji,
            Network::Polygon,
            Network::Arbitrum,
            Network::Optimism,
            Network::TempoModerato,
        ]
    }

    /// Get the chain type for this network.
    pub fn chain_type(&self) -> ChainType {
        self.info().chain_type
    }

    /// Check if this is a mainnet network.
    pub fn is_mainnet(&self) -> bool {
        self.info().mainnet
    }

    /// Check if this is a testnet network.
    pub fn is_testnet(&self) -> bool {
        !self.is_mainnet()
    }

    /// Get all networks of a specific chain type, optionally filtered by name.
    /// Only returns networks that have USDC support configured.
    pub fn by_chain_type(chain_type: ChainType, name_filter: Option<&str>) -> Vec<Network> {
        Network::all()
            .into_iter()
            .filter(|n| n.chain_type() == chain_type)
            .filter(|n| n.usdc_config().is_some())
            .filter(|n| name_filter.is_none_or(|f| n.as_str() == f))
            .collect()
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            networks::ETHEREUM => Ok(Network::Ethereum),
            networks::ETHEREUM_SEPOLIA => Ok(Network::EthereumSepolia),
            networks::BASE => Ok(Network::Base),
            networks::BASE_SEPOLIA => Ok(Network::BaseSepolia),
            networks::AVALANCHE => Ok(Network::Avalanche),
            networks::AVALANCHE_FUJI => Ok(Network::AvalancheFuji),
            networks::POLYGON => Ok(Network::Polygon),
            networks::ARBITRUM => Ok(Network::Arbitrum),
            networks::OPTIMISM => Ok(Network::Optimism),
            networks::TEMPO_MODERATO => Ok(Network::TempoModerato),
            _ => Err(format!("Unknown network: {s}")),
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Token configuration for a specific token on a network
///
/// Contains the currency metadata (symbol, decimals) and the token's
/// on-chain address (contract address for EVM).
///
/// # Examples
///
/// ```
/// use mpp_rs::network::Network;
///
/// let tempo = Network::TempoModerato;
/// let token_config = tempo.usdc_config().expect("Tempo has token support");
/// assert_eq!(token_config.currency.decimals, 6);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct TokenConfig {
    /// Currency information (symbol, decimals, etc.)
    pub currency: Currency,
    /// Token address - contract address for EVM chains (ERC20)
    pub address: &'static str,
}

/// Gas configuration for EVM networks.
///
/// Different networks may have different gas requirements and fee structures.
/// This struct provides network-specific defaults that can be overridden.
///
/// # Examples
///
/// ```
/// use mpp_rs::network::Network;
///
/// let tempo = Network::TempoModerato;
/// let gas_config = tempo.gas_config().expect("Tempo has gas config");
/// assert_eq!(gas_config.gas_limit, 100_000);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct GasConfig {
    /// Default gas limit for token transfers.
    ///
    /// 100,000 gas is a conservative estimate that covers:
    /// - Standard ERC-20 transfer: ~65,000 gas
    /// - Buffer for contract variations and potential state changes
    pub gas_limit: u64,

    /// Maximum priority fee per gas in wei (the "tip" to validators).
    ///
    /// 1 gwei (1,000,000,000 wei) is a reasonable default for most networks.
    pub max_priority_fee_per_gas: u64,

    /// Maximum total fee per gas in wei (base fee + priority fee).
    ///
    /// 10 gwei is set higher than typical base fees to ensure transactions
    /// are included even during moderate congestion. Unused gas is refunded.
    pub max_fee_per_gas: u64,
}

impl GasConfig {
    /// Default gas configuration suitable for most EVM networks.
    pub const DEFAULT: Self = Self {
        gas_limit: 100_000,
        max_priority_fee_per_gas: 1_000_000_000, // 1 gwei
        max_fee_per_gas: 10_000_000_000,         // 10 gwei
    };

    /// Get max_fee_per_gas as u128 (for alloy compatibility).
    pub const fn max_fee_per_gas_u128(&self) -> u128 {
        self.max_fee_per_gas as u128
    }

    /// Get max_priority_fee_per_gas as u128 (for alloy compatibility).
    pub const fn max_priority_fee_per_gas_u128(&self) -> u128 {
        self.max_priority_fee_per_gas as u128
    }
}

impl Network {
    /// Get token configuration for a specific currency on this network
    /// Currently only supports USDC
    pub const fn token_config(&self, _currency: &str) -> Option<TokenConfig> {
        // For now, only USDC is supported
        self.usdc_config()
    }

    /// Get USDC configuration for this network
    pub const fn usdc_config(&self) -> Option<TokenConfig> {
        use crate::currency::currencies;

        match self {
            Network::Ethereum => Some(TokenConfig {
                currency: currencies::USDC,
                address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
            }),
            Network::EthereumSepolia => Some(TokenConfig {
                currency: currencies::USDC,
                address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238",
            }),
            Network::Base => Some(TokenConfig {
                currency: currencies::USDC,
                address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
            }),
            Network::BaseSepolia => Some(TokenConfig {
                currency: currencies::USDC,
                address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            }),
            Network::TempoModerato => Some(TokenConfig {
                currency: currencies::ALPHA_USD,
                address: "0x20c0000000000000000000000000000000000001",
            }),
            // Other networks don't have token support yet
            _ => None,
        }
    }

    /// Get USDC configuration for this network, or error if not configured.
    ///
    /// Use this when token configuration is required (e.g., for displaying
    /// formatted payment amounts to users).
    ///
    /// # Errors
    ///
    /// Returns `UnsupportedToken` if the network doesn't have token configuration.
    pub fn require_usdc_config(&self) -> crate::error::Result<TokenConfig> {
        self.usdc_config().ok_or_else(|| {
            crate::error::MppError::UnsupportedToken(format!(
                "No token configuration for network '{}'. \
                 Use --dry-run to see raw payment details.",
                self
            ))
        })
    }

    /// Get gas configuration for EVM networks.
    ///
    /// Networks can have custom gas settings; if not specified, defaults are used.
    ///
    /// # Examples
    ///
    /// ```
    /// use mpp_rs::network::Network;
    ///
    /// // EVM networks have gas config
    /// assert!(Network::Base.gas_config().is_some());
    /// assert!(Network::TempoModerato.gas_config().is_some());
    /// ```
    pub const fn gas_config(&self) -> Option<GasConfig> {
        match self {
            // EVM networks use default gas configuration
            // Individual networks can override if needed (e.g., L2s with different fee structures)
            Network::Ethereum
            | Network::EthereumSepolia
            | Network::Base
            | Network::BaseSepolia
            | Network::Avalanche
            | Network::AvalancheFuji
            | Network::Polygon
            | Network::Arbitrum
            | Network::Optimism
            | Network::TempoModerato => Some(GasConfig::DEFAULT),
        }
    }
}

// ==================== Convenience Functions ====================

/// Look up network info by name.
///
/// Supports both v1 names and v2 CAIP-2 formats (e.g., "eip155:8453").
#[must_use]
pub fn get_network(name: &str) -> Option<NetworkInfo> {
    let canonical = NETWORK_REGISTRY.resolve_alias(name);
    NETWORK_REGISTRY.get(canonical).cloned()
}

/// Check if a network name refers to an EVM network.
///
/// Supports both v1 names and v2 CAIP-2 formats (e.g., "eip155:8453").
#[must_use]
pub fn is_evm_network(name: &str) -> bool {
    let canonical = NETWORK_REGISTRY.resolve_alias(name);
    NETWORK_REGISTRY.is_evm(canonical)
}

/// Get the EVM chain ID for a network by name.
///
/// Supports both v1 names and v2 CAIP-2 formats (e.g., "eip155:8453").
#[must_use]
pub fn get_evm_chain_id(name: &str) -> Option<u64> {
    let canonical = NETWORK_REGISTRY.resolve_alias(name);
    NETWORK_REGISTRY.get(canonical).and_then(|n| n.chain_id)
}

/// Resolve network alias to canonical network name
///
/// Supports both v1 names (returned as-is) and v2 CAIP-2 formats (resolved to v1 names).
/// Uses the network registry's alias mappings defined in built-in network definitions.
///
/// # Examples
///
/// ```
/// use mpp_rs::network::resolve_network_alias;
///
/// assert_eq!(resolve_network_alias("base"), "base");
/// assert_eq!(resolve_network_alias("eip155:8453"), "base");
/// ```
pub fn resolve_network_alias(network: &str) -> &str {
    NETWORK_REGISTRY.resolve_alias(network)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_lookup() {
        let tempo = get_network("tempo").expect("tempo network should exist");
        assert_eq!(tempo.chain_type, ChainType::Evm);
        assert_eq!(tempo.chain_id, Some(4217));
        assert!(tempo.mainnet);
    }

    #[test]
    fn test_is_evm_network() {
        assert!(is_evm_network("tempo"));
        assert!(is_evm_network("ethereum"));
        assert!(!is_evm_network("unknown"));
    }

    #[test]
    fn test_get_evm_chain_id() {
        assert_eq!(get_evm_chain_id("tempo"), Some(4217));
        assert_eq!(get_evm_chain_id("ethereum"), Some(1));
        assert_eq!(get_evm_chain_id("tempo-moderato"), Some(42431));
        assert_eq!(get_evm_chain_id("unknown"), None);
    }

    #[test]
    fn test_network_enum_from_str() {
        assert_eq!(
            "tempo-moderato"
                .parse::<Network>()
                .expect("Failed to parse tempo-moderato"),
            Network::TempoModerato
        );
        assert_eq!(
            "base".parse::<Network>().expect("Failed to parse base"),
            Network::Base
        );
        assert_eq!(
            "ethereum-sepolia"
                .parse::<Network>()
                .expect("Failed to parse ethereum-sepolia"),
            Network::EthereumSepolia
        );
        assert!("unknown-network".parse::<Network>().is_err());
    }

    #[test]
    fn test_network_enum_to_str() {
        assert_eq!(Network::TempoModerato.as_str(), "tempo-moderato");
        assert_eq!(Network::EthereumSepolia.as_str(), "ethereum-sepolia");
        assert_eq!(Network::Base.to_string(), "base");
    }

    #[test]
    fn test_network_enum_info() {
        let tempo = Network::TempoModerato;
        assert_eq!(tempo.chain_type(), ChainType::Evm);
        assert!(!tempo.is_mainnet()); // tempo-moderato is testnet
        assert!(tempo.is_testnet());

        let sepolia = Network::EthereumSepolia;
        assert_eq!(sepolia.chain_type(), ChainType::Evm);
        assert!(!sepolia.is_mainnet());
        assert!(sepolia.is_testnet());
    }

    #[test]
    fn test_network_enum_roundtrip() {
        for network_str in &[
            "ethereum",
            "ethereum-sepolia",
            "base",
            "base-sepolia",
            "avalanche",
            "avalanche-fuji",
            "polygon",
            "arbitrum",
            "optimism",
            "tempo-moderato",
        ] {
            let network: Network = network_str.parse().expect("should parse");
            assert_eq!(network.as_str(), *network_str);
            assert_eq!(network.to_string(), *network_str);
        }
    }

    #[test]
    fn test_registry_has_all_networks() {
        for network in Network::all() {
            assert!(
                NETWORK_REGISTRY.get(network.as_str()).is_some(),
                "Registry missing network: {}",
                network.as_str()
            );
        }
    }

    #[test]
    fn test_resolve_network_alias() {
        // EVM networks - v2 CAIP-2 format should resolve to v1 names
        assert_eq!(resolve_network_alias("eip155:4217"), "tempo");
        assert_eq!(resolve_network_alias("eip155:42431"), "tempo-moderato");
        assert_eq!(resolve_network_alias("eip155:1"), "ethereum");

        // Already v1 format - should return unchanged
        assert_eq!(resolve_network_alias("tempo"), "tempo");

        // Unknown network - should return unchanged
        assert_eq!(resolve_network_alias("eip155:999999"), "eip155:999999");
    }

    #[test]
    fn test_v2_format_with_convenience_functions() {
        // Test that convenience functions work with v2 CAIP-2 formats

        // get_network
        let tempo_v1 = get_network("tempo").expect("tempo should exist");
        let tempo_v2 = get_network("eip155:4217").expect("eip155:4217 should resolve to tempo");
        assert_eq!(tempo_v1.chain_id, tempo_v2.chain_id);
        assert_eq!(tempo_v1.chain_id, Some(4217));

        // is_evm_network
        assert!(is_evm_network("tempo"));
        assert!(is_evm_network("eip155:4217"));

        // get_evm_chain_id
        assert_eq!(get_evm_chain_id("tempo"), Some(4217));
        assert_eq!(get_evm_chain_id("eip155:4217"), Some(4217));
        assert_eq!(get_evm_chain_id("eip155:42431"), Some(42431));
    }
}
