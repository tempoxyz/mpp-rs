use core::fmt;

/// Known Tempo blockchain networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TempoNetwork {
    /// Tempo mainnet (chain ID 4217)
    Mainnet,
    /// Tempo Moderato testnet (chain ID 42431)
    Moderato,
}

impl TempoNetwork {
    /// Returns the chain ID for this network.
    pub const fn chain_id(self) -> u64 {
        match self {
            Self::Mainnet => super::CHAIN_ID,
            Self::Moderato => super::MODERATO_CHAIN_ID,
        }
    }

    /// Returns the default RPC URL for this network.
    pub const fn default_rpc_url(self) -> &'static str {
        match self {
            Self::Mainnet => super::DEFAULT_RPC_URL,
            Self::Moderato => "https://rpc.moderato.tempo.xyz",
        }
    }

    /// Returns the default currency address for this network.
    pub const fn default_currency(self) -> &'static str {
        super::DEFAULT_CURRENCY
    }

    /// Returns the network for a given chain ID, if known.
    pub fn from_chain_id(chain_id: u64) -> Option<Self> {
        match chain_id {
            super::CHAIN_ID => Some(Self::Mainnet),
            super::MODERATO_CHAIN_ID => Some(Self::Moderato),
            _ => None,
        }
    }

    /// Returns a string identifier for this network.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "tempo",
            Self::Moderato => "tempo-moderato",
        }
    }
}

impl fmt::Display for TempoNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_chain_id_roundtrip() {
        for network in [TempoNetwork::Mainnet, TempoNetwork::Moderato] {
            let id = network.chain_id();
            let recovered = TempoNetwork::from_chain_id(id).unwrap();
            assert_eq!(recovered, network);
        }
    }

    #[test]
    fn unknown_chain_id_returns_none() {
        assert_eq!(TempoNetwork::from_chain_id(0), None);
        assert_eq!(TempoNetwork::from_chain_id(1), None);
        assert_eq!(TempoNetwork::from_chain_id(999999), None);
    }

    #[test]
    fn as_str_matches_expected() {
        assert_eq!(TempoNetwork::Mainnet.as_str(), "tempo");
        assert_eq!(TempoNetwork::Moderato.as_str(), "tempo-moderato");
    }

    #[test]
    fn display_output() {
        assert_eq!(format!("{}", TempoNetwork::Mainnet), "tempo");
        assert_eq!(format!("{}", TempoNetwork::Moderato), "tempo-moderato");
    }
}
