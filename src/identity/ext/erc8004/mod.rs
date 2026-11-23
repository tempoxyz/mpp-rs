//! ERC-8004 agents as an identity method, as mppx's
//! `mppx/extensions/identity/erc8004`.
//!
//! An agent is its token in an [ERC-8004](https://eips.ethereum.org/EIPS/eip-8004)
//! Identity Registry (by default the one on Tempo mainnet), and proves who it
//! is with the wallet the registry names (`getAgentWallet`). It signs each
//! request with that wallet and pays from it.
//!
//! - **Headers:** `Agent-Id: eip155:<chainId>:<registry>:<agentId>` and
//!   `Agent-Signature: <created>.<nonce>.<signature>`, an EIP-191 signature
//!   over the method, URL, created time and nonce ([`message`]).
//! - **Server:** [`server::create`] returns a
//!   [`verifier`](server::Erc8004::verifier), which reads the agent's wallet
//!   from the registry and checks the signature by EOA recovery or ERC-1271,
//!   and a [`payment_check`](server::Erc8004::payment_check), which accepts a
//!   `tempo` charge (a transaction or a proof) whose source is the agent's
//!   wallet and otherwise falls back to the signature. A signature is valid
//!   for five minutes and, with a store, once.
//! - **Client:** [`client::prover`] signs each request with the agent's wallet.
//!
//! ```no_run
//! # #[cfg(all(feature = "server", feature = "axum"))]
//! # fn example() {
//! use std::sync::Arc;
//! use mpp::identity::ext::erc8004::server::{self, Config};
//! use mpp::identity::RouteIdentity;
//! use mpp::store::MemoryStore;
//!
//! let agents = server::create(
//!     Config::new("https://api.example").store(Arc::new(MemoryStore::new())),
//! )
//! .unwrap();
//! let identity = RouteIdentity::new()
//!     .verifier(&agents.verifier)
//!     .payment(&agents.payment_check);
//! // Router::new().route("/haiku", get(handler)).layer(axum::Extension(identity))
//! # }
//! ```

use alloy::primitives::{Address, U256};

pub mod server;

#[cfg(feature = "client")]
pub mod client;

#[cfg(test)]
mod tests;

/// ERC-8004 values.
pub mod constants {
    use alloy::primitives::{address, Address};

    /// Identity type advertised in a 402's `Identity-Required` header.
    pub const TYPE: &str = "erc8004";
    /// Chain the default registry is on: Tempo mainnet.
    pub const CHAIN_ID: u64 = 4217;
    /// The ERC-8004 Identity Registry, at the same address on every chain that deploys it.
    pub const IDENTITY_REGISTRY: Address = address!("0x8004A169FB4a3325136EB29fA0ceB6D2e539a432");
    /// Default RPC for Tempo mainnet.
    pub const RPC_URL: &str = "https://rpc.tempo.xyz";
    /// Header that carries the agent's ID: `eip155:<chainId>:<registry>:<agentId>`.
    pub const ID_HEADER: &str = "Agent-Id";
    /// Header that carries `<created>.<nonce>.<signature>`: the agent wallet's signature of the request.
    pub const SIGNATURE_HEADER: &str = "Agent-Signature";
    /// How long, in seconds, a request signature stays valid.
    pub const MAX_AGE: u64 = 300;
    /// Allowed clock skew, in seconds.
    pub const CLOCK_TOLERANCE: u64 = 60;
}

/// An ERC-8004 agent whose wallet signed the request or paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    /// The agent's global ID: `eip155:<chainId>:<registry>:<agentId>`.
    pub id: String,
    /// The agent's token ID in the Identity Registry.
    pub agent_id: U256,
    /// The agent's wallet, from the registry's `getAgentWallet`.
    pub wallet: Address,
}

/// An agent's place in a registry: its chain, registry and token ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRef {
    /// The registry's chain.
    pub chain_id: u64,
    /// The Identity Registry.
    pub registry: Address,
    /// The agent's token ID.
    pub agent_id: U256,
}

impl AgentRef {
    /// Formats the agent's global ID: `eip155:<chainId>:<registry>:<agentId>`,
    /// with the registry checksummed.
    pub fn format(&self) -> String {
        format!(
            "eip155:{}:{}:{}",
            self.chain_id,
            self.registry.to_checksum(None),
            self.agent_id
        )
    }

    /// Parses an agent's global ID, or returns `None` when it is malformed.
    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split(':');
        let (Some("eip155"), Some(chain_id), Some(registry), Some(agent_id), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return None;
        };
        let digits = |value: &str, max: usize| {
            !value.is_empty() && value.len() <= max && value.bytes().all(|b| b.is_ascii_digit())
        };
        let hex = registry.strip_prefix("0x")?;
        if !digits(chain_id, 15)
            || !digits(agent_id, 78)
            || hex.len() != 40
            || !hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        Some(Self {
            chain_id: chain_id.parse().ok()?,
            registry: registry.parse().ok()?,
            agent_id: U256::from_str_radix(agent_id, 10).ok()?,
        })
    }
}

/// The message an agent's wallet signs (EIP-191) for one request attempt:
/// `mppx:erc8004`, the agent ID, `<METHOD> <origin><path><query>`, the
/// created time and the nonce, joined by newlines.
///
/// `target` is the request's origin, path and query, such as
/// `https://api.example/haiku?q=1`.
pub fn message(id: &str, method: &str, target: &str, created: u64, nonce: &str) -> String {
    format!("mppx:erc8004\n{id}\n{method} {target}\n{created}\n{nonce}")
}
