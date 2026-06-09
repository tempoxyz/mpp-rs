//! Tempo payment method configuration and builder.

use alloy::primitives::Address;

use super::mpp::detect_realm;

pub use crate::protocol::methods::tempo::session_method::{
    InMemoryChannelStore as SessionChannelStore, SessionMethod as TempoSessionMethod,
    SessionMethodConfig,
};
pub use crate::protocol::methods::tempo::ChargeMethod as TempoChargeMethod;
pub use crate::protocol::methods::tempo::{
    TempoChargeExt, TempoMethodDetails, CHAIN_ID, METHOD_NAME,
};

/// Configuration for the Tempo payment method.
///
/// Only `recipient` is required. Everything else has smart defaults.
pub struct TempoConfig<'a> {
    /// Recipient address for payments.
    pub recipient: &'a str,
}

/// Builder returned by [`tempo()`] for configuring a Tempo payment method.
///
/// Has smart defaults for everything; use builder methods to override.
pub struct TempoBuilder {
    pub(crate) currency: String,
    pub(crate) currency_explicit: bool,
    pub(crate) recipient: String,
    pub(crate) rpc_url: String,
    pub(crate) realm: String,
    pub(crate) secret_key: Option<String>,
    pub(crate) decimals: u32,
    pub(crate) fee_payer: bool,
    pub(crate) chain_id: Option<u64>,
    pub(crate) fee_payer_signer: Option<alloy::signers::local::PrivateKeySigner>,
    pub(crate) fee_payer_allowed_fee_tokens: Option<Vec<Address>>,
    pub(crate) store: Option<std::sync::Arc<dyn crate::store::Store>>,
}

impl TempoBuilder {
    /// Override the RPC URL (default: `https://rpc.tempo.xyz`).
    ///
    /// Also auto-detects the chain ID from the URL if not explicitly set:
    /// - URLs containing "moderato" → chain ID 42431 (Tempo Moderato testnet)
    /// - Otherwise → chain ID 4217 (Tempo mainnet)
    pub fn rpc_url(mut self, url: &str) -> Self {
        self.rpc_url = url.to_string();
        if self.chain_id.is_none() {
            self.chain_id = Some(chain_id_from_rpc_url(url));
        }
        self
    }

    /// Explicitly set the chain ID for challenges.
    pub fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = Some(id);
        self
    }

    /// Override the token currency (default: USDC on mainnet, pathUSD on testnet).
    pub fn currency(mut self, addr: &str) -> Self {
        self.currency = addr.to_string();
        self.currency_explicit = true;
        self
    }

    /// Override the realm (default: auto-detected from environment variables).
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = realm.to_string();
        self
    }

    /// Override the secret key (default: reads `MPP_SECRET_KEY` env var).
    pub fn secret_key(mut self, key: &str) -> Self {
        self.secret_key = Some(key.to_string());
        self
    }

    /// Override the token decimals (default: `6`).
    pub fn decimals(mut self, d: u32) -> Self {
        self.decimals = d;
        self
    }

    /// Enable fee sponsorship for all challenges (default: `false`).
    ///
    /// When enabled, all charge and session challenges will include
    /// `feePayer: true` in their `methodDetails`. You should also call
    /// [`fee_payer_signer`](Self::fee_payer_signer) to provide the signer
    /// that will sponsor transaction fees.
    pub fn fee_payer(mut self, enabled: bool) -> Self {
        self.fee_payer = enabled;
        self
    }

    /// Set the signer used for fee sponsorship.
    ///
    /// When clients send transactions with `feePayer: true`, the server
    /// uses this signer to co-sign and sponsor the transaction gas fees.
    /// The signer's account must have sufficient balance for gas.
    pub fn fee_payer_signer(mut self, signer: alloy::signers::local::PrivateKeySigner) -> Self {
        self.fee_payer_signer = Some(signer);
        self
    }

    /// Replace the fee-sponsor token allowlist used when co-signing fee-payer
    /// transactions.
    ///
    /// By default, sponsored transactions accept the known default currency for
    /// the transaction chain ID. Use this when `.currency(...)` points at a
    /// custom token that the fee payer should sponsor.
    pub fn fee_payer_allowed_fee_tokens(mut self, allowed_fee_tokens: Vec<Address>) -> Self {
        self.fee_payer_allowed_fee_tokens = Some(allowed_fee_tokens);
        self
    }

    /// Set the replay-protection store (default: in-memory).
    ///
    /// Provide a shared backend (Redis, SQL, etc.) for multi-instance deployments.
    pub fn store(mut self, store: std::sync::Arc<dyn crate::store::Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Disable replay-protection storage (removes the default in-memory store).
    pub fn without_store(mut self) -> Self {
        self.store = None;
        self
    }
}

/// Create a Tempo payment method configuration with smart defaults.
///
/// Only `recipient` is required. Returns a [`TempoBuilder`]
/// that can be passed to [`Mpp::create()`](super::Mpp::create).
///
/// # Defaults
///
/// - **rpc_url**: `https://rpc.tempo.xyz`
/// - **realm**: auto-detected from `MPP_REALM`, `FLY_APP_NAME`, `HEROKU_APP_NAME`,
///   `HOST`, `HOSTNAME`, `RAILWAY_PUBLIC_DOMAIN`, `RENDER_EXTERNAL_HOSTNAME`,
///   `VERCEL_URL`, `WEBSITE_HOSTNAME` — falling back to `"MPP Payment"`
/// - **secret_key**: reads `MPP_SECRET_KEY` env var; required if not explicitly set
/// - **currency**: pathUSD by default, mainnet USDC with `.chain_id(4217)`,
///   or pathUSD with `.chain_id(42431)` / a Moderato RPC URL
/// - **decimals**: `6` (for pathUSD / USDC / standard stablecoins)
/// - **expires**: `now + 5 minutes`
///
/// # Example
///
/// ```ignore
/// use mpp::server::{Mpp, tempo, TempoConfig};
///
/// // Minimal — currency defaults to pathUSD
/// let mpp = Mpp::create(tempo(TempoConfig {
///     recipient: "0xabc...123",
/// }))?;
///
/// // With overrides
/// let mpp = Mpp::create(
///     tempo(TempoConfig {
///         recipient: "0xabc...123",
///     })
///     .currency("0xcustom_token_address")
///     .rpc_url("https://rpc.moderato.tempo.xyz")
///     .realm("my-api.com")
///     .secret_key("my-secret")
///     .decimals(18),
/// )?;
/// ```
pub fn tempo(config: TempoConfig<'_>) -> TempoBuilder {
    TempoBuilder {
        currency: crate::protocol::methods::tempo::DEFAULT_CURRENCY_MAINNET.to_string(),
        currency_explicit: false,
        recipient: config.recipient.to_string(),
        rpc_url: crate::protocol::methods::tempo::DEFAULT_RPC_URL.to_string(),
        realm: detect_realm(),
        secret_key: None,
        decimals: 6,
        fee_payer: false,
        chain_id: None,
        fee_payer_signer: None,
        fee_payer_allowed_fee_tokens: None,
        // Default in-memory store; replay protection on by default.
        store: Some(std::sync::Arc::new(crate::store::MemoryStore::new())),
    }
}

/// Derive a chain ID from an RPC URL.
///
/// Returns `MODERATO_CHAIN_ID` (42431) for URLs containing "moderato",
/// otherwise returns `CHAIN_ID` (4217).
fn chain_id_from_rpc_url(url: &str) -> u64 {
    if url.contains("moderato") {
        crate::protocol::methods::tempo::MODERATO_CHAIN_ID
    } else {
        crate::protocol::methods::tempo::CHAIN_ID
    }
}

/// Create a Tempo-compatible provider for server-side verification.
///
/// This provider uses `TempoNetwork` which properly handles Tempo's
/// custom transaction type (0x76) and receipt format.
pub fn tempo_provider(rpc_url: &str) -> crate::error::Result<TempoProvider> {
    use alloy::providers::ProviderBuilder;
    use tempo_alloy::TempoNetwork;

    let url = rpc_url
        .parse()
        .map_err(|e| crate::error::MppError::InvalidConfig(format!("invalid RPC URL: {}", e)))?;
    Ok(ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(url))
}

/// Type alias for the Tempo provider returned by [`tempo_provider`].
pub type TempoProvider = alloy::providers::fillers::FillProvider<
    alloy::providers::fillers::JoinFill<
        alloy::providers::Identity,
        alloy::providers::fillers::JoinFill<
            alloy::providers::fillers::NonceFiller,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::ChainIdFiller,
            >,
        >,
    >,
    alloy::providers::RootProvider<tempo_alloy::TempoNetwork>,
    tempo_alloy::TempoNetwork,
>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tempo_builder_defaults_to_a_store() {
        // Replay protection must be active on the default server path.
        let builder = tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        });
        assert!(
            builder.store.is_some(),
            "default builder should configure a replay-protection store"
        );
    }

    #[test]
    fn tempo_builder_store_override_and_opt_out() {
        let custom: std::sync::Arc<dyn crate::store::Store> =
            std::sync::Arc::new(crate::store::MemoryStore::new());
        let builder = tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .store(custom.clone());
        assert!(builder.store.is_some());

        let builder = builder.without_store();
        assert!(
            builder.store.is_none(),
            "without_store() should clear the configured store"
        );
    }
}
