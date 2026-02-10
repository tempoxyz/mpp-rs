//! Server-side payment verification.
//!
//! # Simple API
//!
//! ```ignore
//! use mpay::server::{Mpay, tempo, TempoConfig};
//!
//! let mpay = Mpay::create(tempo(TempoConfig {
//!     currency: "0x20c0000000000000000000000000000000000000",
//!     recipient: "0xabc...123",
//! }))?;
//!
//! // Charge $0.10 — everything else has smart defaults
//! let challenge = mpay.charge("0.10")?;
//! ```
//!
//! # Advanced API
//!
//! ```ignore
//! use mpay::server::{Mpay, tempo_provider, TempoChargeMethod};
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
//! let method = TempoChargeMethod::new(provider);
//! let payment = Mpay::new(method, "api.example.com", "my-server-secret");
//!
//! let challenge = payment.charge_challenge("1000000", "0x...", "0x...")?;
//! let receipt = payment.verify(&credential, &request).await?;
//! ```

mod amount;
mod mpay;

pub use crate::protocol::traits::{ChargeMethod, ErrorCode, StreamMethod, VerificationError};
pub use amount::{parse_dollar_amount, AmountError};
pub use mpay::Mpay;

#[cfg(feature = "tempo")]
pub use crate::protocol::methods::tempo::ChargeMethod as TempoChargeMethod;

#[cfg(feature = "tempo")]
pub use crate::protocol::methods::tempo::StreamMethod as TempoStreamMethod;

#[cfg(feature = "tempo")]
pub use crate::protocol::methods::tempo::{
    TempoChargeExt, TempoMethodDetails, CHAIN_ID, METHOD_NAME,
};

#[cfg(feature = "tempo")]
pub use crate::protocol::methods::tempo::stream::{
    StreamCredentialPayload, StreamReceipt, TempoStreamExt, TempoStreamMethodDetails,
};

// ==================== Simple API ====================

/// Configuration for the Tempo payment method.
///
/// Only `currency` and `recipient` are required. Everything else has smart defaults.
#[cfg(feature = "tempo")]
pub struct TempoConfig<'a> {
    /// Token address (e.g., pathUSD).
    pub currency: &'a str,
    /// Recipient address for payments.
    pub recipient: &'a str,
}

/// Builder returned by [`tempo()`] for configuring a Tempo payment method.
///
/// Has smart defaults for everything; use builder methods to override.
#[cfg(feature = "tempo")]
pub struct TempoBuilder {
    pub(crate) currency: String,
    pub(crate) recipient: String,
    pub(crate) rpc_url: String,
    pub(crate) realm: String,
    pub(crate) secret_key: Option<String>,
    pub(crate) decimals: u32,
}

#[cfg(feature = "tempo")]
impl TempoBuilder {
    /// Override the RPC URL (default: `https://rpc.tempo.xyz`).
    pub fn rpc_url(mut self, url: &str) -> Self {
        self.rpc_url = url.to_string();
        self
    }

    /// Override the realm (default: `"MPP Payment"`).
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = realm.to_string();
        self
    }

    /// Override the secret key (default: reads `MPAY_SECRET_KEY` env var or generates UUID).
    pub fn secret_key(mut self, key: &str) -> Self {
        self.secret_key = Some(key.to_string());
        self
    }

    /// Override the token decimals (default: `6`).
    pub fn decimals(mut self, d: u32) -> Self {
        self.decimals = d;
        self
    }
}

/// Options for [`Mpay::charge_with_options()`].
#[derive(Debug, Default)]
pub struct ChargeOptions<'a> {
    /// Human-readable description.
    pub description: Option<&'a str>,
    /// Merchant reference ID.
    pub external_id: Option<&'a str>,
    /// Custom expiration (ISO 8601). Default: now + 5 minutes.
    pub expires: Option<&'a str>,
    /// Enable fee sponsorship.
    pub fee_payer: bool,
}

/// Create a Tempo payment method configuration with smart defaults.
///
/// Only `currency` and `recipient` are required. Returns a [`TempoBuilder`]
/// that can be passed to [`Mpay::create()`].
///
/// # Defaults
///
/// - **rpc_url**: `https://rpc.tempo.xyz`
/// - **realm**: `"MPP Payment"`
/// - **secret_key**: reads `MPAY_SECRET_KEY` env var, or generates a random UUID
/// - **decimals**: `6` (for pathUSD / standard stablecoins)
/// - **expires**: `now + 5 minutes`
///
/// # Example
///
/// ```ignore
/// use mpay::server::{Mpay, tempo, TempoConfig};
///
/// // Minimal
/// let mpay = Mpay::create(tempo(TempoConfig {
///     currency: "0x20c0000000000000000000000000000000000000",
///     recipient: "0xabc...123",
/// }))?;
///
/// // With overrides
/// let mpay = Mpay::create(
///     tempo(TempoConfig {
///         currency: "0x20c0000000000000000000000000000000000000",
///         recipient: "0xabc...123",
///     })
///     .rpc_url("https://rpc.moderato.tempo.xyz")
///     .realm("my-api.com")
///     .secret_key("my-secret")
///     .decimals(18),
/// )?;
/// ```
#[cfg(feature = "tempo")]
pub fn tempo(config: TempoConfig<'_>) -> TempoBuilder {
    TempoBuilder {
        currency: config.currency.to_string(),
        recipient: config.recipient.to_string(),
        rpc_url: crate::protocol::methods::tempo::DEFAULT_RPC_URL.to_string(),
        realm: "MPP Payment".to_string(),
        secret_key: None,
        decimals: 6,
    }
}

// ==================== Advanced API ====================

/// Create a Tempo-compatible provider for server-side verification.
///
/// This provider uses `TempoNetwork` which properly handles Tempo's
/// custom transaction type (0x76) and receipt format.
#[cfg(feature = "tempo")]
pub fn tempo_provider(rpc_url: &str) -> crate::error::Result<TempoProvider> {
    use alloy::providers::ProviderBuilder;
    use tempo_alloy::TempoNetwork;

    let url = rpc_url
        .parse()
        .map_err(|e| crate::error::MppError::InvalidConfig(format!("invalid RPC URL: {}", e)))?;
    Ok(ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(url))
}

/// Type alias for the Tempo provider returned by [`tempo_provider`].
#[cfg(feature = "tempo")]
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
