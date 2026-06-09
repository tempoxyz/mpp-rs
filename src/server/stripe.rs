//! Stripe payment method configuration and builder.

use super::mpp::detect_realm;

pub use crate::protocol::methods::stripe::method::ChargeMethod as StripeChargeMethod;
pub use crate::protocol::methods::stripe::{StripeCredentialPayload, StripeMethodDetails};

/// Configuration for the Stripe payment method.
///
/// All fields are required for Stripe payment verification.
pub struct StripeConfig<'a> {
    /// Stripe secret API key (e.g., `sk_test_...`).
    pub secret_key: &'a str,
    /// Stripe Business Network profile ID.
    pub network_id: &'a str,
    /// Accepted payment method types (e.g., `&["card"]`).
    pub payment_method_types: &'a [&'a str],
    /// Three-letter ISO currency code (e.g., "usd").
    pub currency: &'a str,
    /// Token decimals for amount conversion (e.g., 2 for USD cents).
    pub decimals: u8,
}

/// Options for [`Mpp::stripe_charge_with_options()`](super::Mpp::stripe_charge_with_options).
#[derive(Debug, Default)]
pub struct StripeChargeOptions<'a> {
    /// Human-readable description.
    pub description: Option<&'a str>,
    /// Merchant reference ID.
    pub external_id: Option<&'a str>,
    /// Custom expiration (ISO 8601). Default: now + 5 minutes.
    pub expires: Option<&'a str>,
    /// Optional metadata key-value pairs.
    pub metadata: Option<&'a std::collections::HashMap<String, String>>,
}

/// Builder returned by [`stripe()`] for configuring a Stripe payment method.
pub struct StripeBuilder {
    pub(crate) secret_key: String,
    pub(crate) network_id: String,
    pub(crate) payment_method_types: Vec<String>,
    pub(crate) currency: String,
    pub(crate) decimals: u8,
    pub(crate) realm: String,
    pub(crate) hmac_secret_key: Option<String>,
    pub(crate) stripe_api_base: Option<String>,
}

impl StripeBuilder {
    /// Override the realm (default: auto-detected from environment variables).
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = realm.to_string();
        self
    }

    /// Override the HMAC secret key (default: reads `MPP_SECRET_KEY` env var).
    pub fn secret_key(mut self, key: &str) -> Self {
        self.hmac_secret_key = Some(key.to_string());
        self
    }

    /// Override the Stripe API base URL (for testing with a mock server).
    pub fn stripe_api_base(mut self, url: &str) -> Self {
        self.stripe_api_base = Some(url.to_string());
        self
    }
}

/// Create a Stripe payment method configuration.
///
/// Returns a [`StripeBuilder`] that can be passed to [`Mpp::create()`](super::Mpp::create).
///
/// # Example
///
/// ```ignore
/// use mpp::server::{Mpp, stripe, StripeConfig};
///
/// let mpp = Mpp::create(
///     stripe(StripeConfig {
///         secret_key: "sk_test_...",
///         network_id: "internal",
///         payment_method_types: &["card"],
///         currency: "usd",
///         decimals: 2,
///     })
///     .secret_key("my-hmac-secret"),
/// )?;
/// ```
pub fn stripe(config: StripeConfig<'_>) -> StripeBuilder {
    StripeBuilder {
        secret_key: config.secret_key.to_string(),
        network_id: config.network_id.to_string(),
        payment_method_types: config
            .payment_method_types
            .iter()
            .map(|s| s.to_string())
            .collect(),
        currency: config.currency.to_string(),
        decimals: config.decimals,
        realm: detect_realm(),
        hmac_secret_key: None,
        stripe_api_base: None,
    }
}
