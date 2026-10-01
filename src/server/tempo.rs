//! Tempo payment method configuration and builder.

use alloy::primitives::Address;

use super::mpp::detect_realm;
use crate::error::MppError;
use crate::protocol::methods::tempo::network::TempoNetwork as KnownTempoNetwork;
use crate::protocol::methods::tempo::PATH_USD;

pub use crate::protocol::methods::tempo::session_method::{
    deduct_from_channel, InMemoryChannelStore as SessionChannelStore,
    SessionMethod as TempoSessionMethod, SessionMethodConfig,
};
pub use crate::protocol::methods::tempo::ChargeMethod as TempoChargeMethod;
pub use crate::protocol::methods::tempo::{
    RelayConfig as TempoRelayConfig, RelayErrorCode as TempoRelayErrorCode, TempoChargeExt,
    TempoMethodDetails, CHAIN_ID, METHOD_NAME,
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
    pub(crate) currencies: Option<Vec<String>>,
    pub(crate) recipient: String,
    pub(crate) rpc_url: String,
    pub(crate) realm: String,
    pub(crate) secret_key: Option<String>,
    pub(crate) decimals: u32,
    pub(crate) fee_payer: bool,
    pub(crate) machine_token_enabled: bool,
    pub(crate) chain_id: Option<u64>,
    pub(crate) fee_payer_signer: Option<std::sync::Arc<crate::protocol::methods::tempo::DynSigner>>,
    pub(crate) fee_payer_allowed_fee_tokens: Option<Vec<Address>>,
    pub(crate) fee_payer_fee_token: Option<Address>,
    pub(crate) store: Option<std::sync::Arc<dyn crate::store::Store>>,
    pub(crate) relay: Option<TempoRelayConfig>,
    pub(crate) requires_auth: bool,
}

impl TempoBuilder {
    /// Override the RPC URL (default: `https://rpc.tempo.xyz`).
    ///
    /// Also auto-detects the chain ID from the URL if not explicitly set:
    /// - URLs containing "moderato" → chain ID 42431 (Tempo Moderato testnet)
    /// - Otherwise → chain ID 4217 (Tempo mainnet)
    pub fn rpc_url(mut self, url: &str) -> Self {
        self.rpc_url = url.to_string();
        self
    }

    /// Explicitly set the chain ID for challenges.
    pub fn chain_id(mut self, id: u64) -> Self {
        self.chain_id = Some(id);
        self
    }

    /// Accept exactly one token currency.
    ///
    /// **Deprecated:** use [`currencies`](Self::currencies) with a one-element
    /// list instead. Setting both `currency` and `currencies` is rejected by
    /// [`Mpp::create()`](super::Mpp::create).
    pub fn currency(mut self, addr: &str) -> Self {
        self.currency = addr.to_string();
        self.currency_explicit = true;
        self
    }

    /// Set the ordered list of accepted token currencies.
    ///
    /// The server issues one charge challenge per currency, in this order.
    /// An explicit list replaces the defaults (see [`tempo()`]). Addresses
    /// must be valid; duplicates are removed case-insensitively, keeping the
    /// first occurrence. An empty list is rejected by
    /// [`Mpp::create()`](super::Mpp::create).
    pub fn currencies<I, T>(mut self, currencies: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.currencies = Some(currencies.into_iter().map(Into::into).collect());
        self
    }

    /// Override the realm (default: auto-detected from environment variables).
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = realm.to_string();
        self
    }

    /// Override the secret key (default: reads `MPP_SECRET_KEY` env var).
    ///
    /// Must be at least 32 bytes; [`Mpp::create()`](super::Mpp::create)
    /// rejects shorter keys.
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
    /// When enabled, all charge challenges will include `feePayer: true` in
    /// their `methodDetails`, and so will session challenges if the session
    /// method sponsors client transactions (Tempo's `SessionMethod` does
    /// not). You should also call
    /// [`fee_payer_signer`](Self::fee_payer_signer) to provide the signer
    /// that will sponsor transaction fees.
    pub fn fee_payer(mut self, enabled: bool) -> Self {
        self.fee_payer = enabled;
        self
    }

    /// Advertise canonical first-party machine-token funding for charges.
    ///
    /// Clients that support this hint prefer machineUSD and atomically settle
    /// the configured challenge currency through the canonical swapper.
    pub fn machine_token_enabled(mut self, enabled: bool) -> Self {
        self.machine_token_enabled = enabled;
        self
    }

    /// Set the signer used for fee sponsorship.
    ///
    /// When clients send transactions with `feePayer: true`, the server
    /// uses this signer to co-sign and sponsor the transaction gas fees.
    /// The signer's account must have sufficient balance for gas.
    pub fn fee_payer_signer<S>(mut self, signer: S) -> Self
    where
        S: alloy::signers::Signer + Send + Sync + 'static,
    {
        self.fee_payer_signer = Some(std::sync::Arc::new(signer));
        self
    }

    /// Replace the fee-sponsor token allowlist used when co-signing fee-payer
    /// transactions.
    ///
    /// By default, the fee payer may pay gas in pathUSD or the known default
    /// currency for the transaction chain ID (mainnet: pathUSD and USDC.e;
    /// Moderato: pathUSD). The fee token is independent of the charge
    /// currency, so charges in any accepted currency (including OUSD) are
    /// sponsored with one of these tokens.
    pub fn fee_payer_allowed_fee_tokens(mut self, allowed_fee_tokens: Vec<Address>) -> Self {
        self.fee_payer_allowed_fee_tokens = Some(allowed_fee_tokens);
        self
    }

    /// Set the token the local fee payer uses to pay gas.
    ///
    /// When unset, the fee payer uses the first allowlisted fee token it holds
    /// a nonzero balance of, falling back to the first allowlisted token. An
    /// explicit token must also be in the allowlist (see
    /// [`fee_payer_allowed_fee_tokens`](Self::fee_payer_allowed_fee_tokens)).
    pub fn fee_payer_fee_token(mut self, fee_token: Address) -> Self {
        self.fee_payer_fee_token = Some(fee_token);
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

    /// Delegate Tempo charge validation and finalization to an MPP relay.
    pub fn relay(mut self, config: TempoRelayConfig) -> Self {
        self.relay = Some(config);
        self
    }

    /// Use `Payment-Authorization` for Payment credentials so `Authorization`
    /// remains available for application authentication.
    pub fn requires_auth(mut self, enabled: bool) -> Self {
        self.requires_auth = enabled;
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
/// - **currencies**: one charge challenge per accepted currency, in order:
///   - Tempo mainnet (`.chain_id(4217)` or a non-Moderato `.rpc_url(...)`):
///     OUSD, then USDC.e
///   - Moderato (`.chain_id(42431)` or a Moderato `.rpc_url(...)`): OUSD, then
///     pathUSD
///   - omitted chain ID: inferred from the RPC URL (mainnet by default)
///   - an unknown chain ID: pathUSD only
///
///   An explicit `.chain_id(...)` takes precedence over the RPC-inferred chain.
///   Use `.currencies([...])` to replace the defaults. Sponsored charges pay
///   gas in an allowlisted fee token independent of the charge currency (see
///   [`fee_payer_fee_token`](TempoBuilder::fee_payer_fee_token)).
/// - **decimals**: `6` (for pathUSD / USDC / OUSD / standard stablecoins)
/// - **expires**: `now + 5 minutes`
///
/// # Example
///
/// ```ignore
/// use mpp::server::{Mpp, tempo, TempoConfig};
///
/// // Minimal — mainnet, offering OUSD then USDC.e
/// let mpp = Mpp::create(tempo(TempoConfig {
///     recipient: "0xabc...123",
/// }))?;
///
/// // Mainnet — offers OUSD first, then USDC.e
/// let mpp = Mpp::create(
///     tempo(TempoConfig {
///         recipient: "0xabc...123",
///     })
///     .chain_id(4217),
/// )?;
/// let offers = mpp.charge("0.10")?;
///
/// // With overrides
/// let mpp = Mpp::create(
///     tempo(TempoConfig {
///         recipient: "0xabc...123",
///     })
///     .currencies(["0xcustom_token_address"])
///     .rpc_url("https://rpc.moderato.tempo.xyz")
///     .realm("my-api.com")
///     .secret_key("my-hmac-secret-of-at-least-32-bytes")
///     .decimals(18),
/// )?;
/// ```
pub fn tempo(config: TempoConfig<'_>) -> TempoBuilder {
    TempoBuilder {
        currency: crate::protocol::methods::tempo::DEFAULT_CURRENCY_MAINNET.to_string(),
        currency_explicit: false,
        currencies: None,
        recipient: config.recipient.to_string(),
        rpc_url: crate::protocol::methods::tempo::DEFAULT_RPC_URL.to_string(),
        realm: detect_realm(),
        secret_key: None,
        decimals: 6,
        fee_payer: false,
        machine_token_enabled: false,
        chain_id: None,
        fee_payer_signer: None,
        fee_payer_allowed_fee_tokens: None,
        fee_payer_fee_token: None,
        // Default in-memory store; replay protection on by default.
        store: Some(std::sync::Arc::new(crate::store::MemoryStore::new())),
        relay: None,
        requires_auth: false,
    }
}

/// Derive a chain ID from an RPC URL.
///
/// Returns `MODERATO_CHAIN_ID` (42431) for URLs containing "moderato",
/// otherwise returns `CHAIN_ID` (4217).
pub(crate) fn chain_id_from_rpc_url(url: &str) -> u64 {
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
                tempo_alloy::fillers::TempoGasFiller,
                alloy::providers::fillers::ChainIdFiller,
            >,
        >,
    >,
    alloy::providers::RootProvider<tempo_alloy::TempoNetwork>,
    tempo_alloy::TempoNetwork,
>;

/// Resolve the ordered, deduplicated currencies a builder accepts.
///
/// An explicit `currencies` list replaces the defaults, and the legacy
/// `currency` option restricts acceptance to that one token. Otherwise the
/// chain's defaults apply (OUSD first on known Tempo networks, pathUSD on
/// unknown chains).
pub(crate) fn resolve_currencies(builder: &TempoBuilder) -> crate::error::Result<Vec<String>> {
    let candidates = match (&builder.currencies, builder.currency_explicit) {
        (Some(_), true) => {
            return Err(MppError::InvalidConfig(
                "Specify either `currency` or `currencies`, not both.".into(),
            ));
        }
        (Some(currencies), false) => currencies.clone(),
        (None, true) => vec![builder.currency.clone()],
        (None, false) => builder
            .chain_id
            .and_then(KnownTempoNetwork::from_chain_id)
            .map_or(&[PATH_USD][..], KnownTempoNetwork::default_currencies)
            .iter()
            .map(|currency| currency.to_string())
            .collect(),
    };

    let mut resolved = Vec::<String>::with_capacity(candidates.len());
    for currency in candidates {
        if currency.parse::<Address>().is_err() {
            return Err(MppError::InvalidConfig(format!(
                "Invalid Tempo currency address: {currency}."
            )));
        }
        if !resolved
            .iter()
            .any(|seen| seen.eq_ignore_ascii_case(&currency))
        {
            resolved.push(currency);
        }
    }
    if resolved.is_empty() {
        return Err(MppError::InvalidConfig(
            "No accepted currencies configured; `currencies` must not be empty.".into(),
        ));
    }
    Ok(resolved)
}

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
