//! Payment handler that binds method, realm, and secret_key.
//!
//! This module provides the [`Mpp`] struct which wraps a payment method
//! with server configuration for stateless challenge verification.
//!
//! # Example (simple API)
//!
//! ```ignore
//! use mpp::server::{Mpp, tempo};
//!
//! let mpp = Mpp::create(tempo(mpp::server::TempoConfig {
//!     recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
//! }))?;
//!
//! let challenges = mpp.charge("0.10")?;
//! ```

use std::sync::Arc;

#[cfg(any(feature = "tempo", feature = "stripe"))]
use crate::error::Result;
use crate::protocol::core::Base64UrlJson;
use crate::protocol::traits::ChargeMethod;
use crate::server::events::{
    PaymentSuccessContext, ServerEvent, ServerEventKind, ServerEventSubscription, ServerEvents,
};

#[cfg(any(feature = "tempo", feature = "stripe"))]
mod issue;
mod session;
mod verify;

pub use session::SessionVerifyResult;

const SECRET_KEY_ENV_VAR: &str = "MPP_SECRET_KEY";
const DEFAULT_DECIMALS: u32 = 6;

/// Environment variables checked (in order) to auto-detect the server realm.
///
/// `HOST` and `HOSTNAME` are deliberately absent: container runtimes set them
/// per replica, and the realm is part of the challenge HMAC, so a credential
/// for a challenge issued by one replica would be rejected by the others.
const REALM_ENV_VARS: &[&str] = &[
    "MPP_REALM",
    "FLY_APP_NAME",
    "HEROKU_APP_NAME",
    "RAILWAY_PUBLIC_DOMAIN",
    "RENDER_EXTERNAL_HOSTNAME",
    "VERCEL_URL",
    "WEBSITE_HOSTNAME",
];

const DEFAULT_REALM: &str = "MPP Payment";

#[cfg(any(feature = "tempo", feature = "stripe"))]
fn advertised_builder_credential_header(requires_auth: bool) -> Option<String> {
    requires_auth.then(|| crate::protocol::core::PAYMENT_AUTHORIZATION_HEADER.to_string())
}

/// Detect the server realm from environment variables.
///
/// Checks platform-specific env vars in order (see [`REALM_ENV_VARS`]),
/// falling back to `"MPP Payment"`.
pub(crate) fn detect_realm() -> String {
    realm_from_env(|name| std::env::var(name).ok())
}

fn realm_from_env(lookup: impl Fn(&str) -> Option<String>) -> String {
    REALM_ENV_VARS
        .iter()
        .find_map(|name| lookup(name).filter(|value| !value.is_empty()))
        .unwrap_or_else(|| DEFAULT_REALM.to_string())
}

/// Server-side payment handler.
///
/// Binds a payment method with realm, secret_key, and optionally
/// a default currency and recipient for simplified `charge()` calls.
///
/// Cloning is cheap: clones share the payment method and the configuration.
///
/// # Simple API
///
/// ```ignore
/// use mpp::server::{Mpp, tempo, TempoConfig};
///
/// let mpp = Mpp::create(tempo(TempoConfig {
///     recipient: "0xabc...123",
/// }))?;
///
/// // Charge $0.10 — currency, recipient, realm, secret, expires all handled
/// let challenges = mpp.charge("0.10")?;
///
/// // Accept a credential only if it paid this route's $0.10
/// let receipt = mpp.verify_charge(&credential, "0.10").await?;
/// ```
///
/// # Advanced API
///
/// ```ignore
/// use std::sync::Arc;
/// use mpp::server::{Mpp, tempo_provider, TempoChargeMethod};
/// use mpp::store::MemoryStore;
///
/// let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
/// // The store makes credentials single-use; `TempoChargeMethod::new` has none.
/// let method = TempoChargeMethod::new(provider).with_store(Arc::new(MemoryStore::new()));
/// let payment = Mpp::new(method, "api.example.com", "my-server-secret-of-at-least-32-bytes");
///
/// let challenge = payment.charge_challenge("1000000", "0x...", "0x...")?;
/// ```
#[derive(Clone)]
pub struct Mpp<M, S = ()> {
    method: Arc<M>,
    session_method: Option<Arc<S>>,
    config: Arc<Config>,
    events: ServerEvents,
}

/// Handler settings, shared by every clone of an [`Mpp`].
#[derive(Clone)]
struct Config {
    realm: String,
    secret_key: String,
    currencies: Vec<String>,
    recipient: Option<String>,
    decimals: u32,
    fee_payer: bool,
    machine_token_enabled: bool,
    chain_id: Option<u64>,
    opaque: Option<Base64UrlJson>,
    credential_header: Option<String>,
}

impl Config {
    fn new(realm: String, secret_key: String) -> Self {
        Self {
            realm,
            secret_key,
            currencies: Vec::new(),
            recipient: None,
            decimals: DEFAULT_DECIMALS,
            fee_payer: false,
            machine_token_enabled: false,
            chain_id: None,
            opaque: None,
            credential_header: None,
        }
    }
}

impl<M> Mpp<M, ()>
where
    M: ChargeMethod,
{
    /// Create a new payment handler (advanced API).
    ///
    /// For a simpler API, use [`Mpp::create()`] with [`tempo()`](super::tempo).
    ///
    /// `secret_key` should be at least 32 bytes. This constructor cannot fail
    /// and does not check the length; [`Mpp::create()`] does.
    pub fn new(method: M, realm: impl Into<String>, secret_key: impl Into<String>) -> Mpp<M, ()> {
        Self::from_config(method, Config::new(realm.into(), secret_key.into()))
    }

    /// Create a new payment handler with pre-configured currency and recipient (advanced API).
    ///
    /// `secret_key` must be at least 32 bytes; see [`Mpp::new()`].
    pub fn new_with_config(
        method: M,
        realm: impl Into<String>,
        secret_key: impl Into<String>,
        currency: impl Into<String>,
        recipient: impl Into<String>,
    ) -> Self {
        Self::from_config(
            method,
            Config {
                currencies: vec![currency.into()],
                recipient: Some(recipient.into()),
                ..Config::new(realm.into(), secret_key.into())
            },
        )
    }

    fn from_config(method: M, config: Config) -> Self {
        Mpp {
            method: Arc::new(method),
            session_method: None,
            config: Arc::new(config),
            events: ServerEvents::default(),
        }
    }
}

impl<M, S> Mpp<M, S>
where
    M: ChargeMethod,
{
    /// Add a session method to this payment handler.
    pub fn with_session_method<S2>(self, session_method: S2) -> Mpp<M, S2> {
        Mpp {
            method: self.method,
            session_method: Some(Arc::new(session_method)),
            config: self.config,
            events: self.events,
        }
    }

    /// Use an existing event registry for payment callbacks.
    pub fn with_events(mut self, events: ServerEvents) -> Self {
        self.events = events;
        self
    }

    /// Pin the route `opaque` for issuance and verification: challenge helpers
    /// emit it, and verification rejects any credential that doesn't match.
    pub fn with_opaque(mut self, opaque: Base64UrlJson) -> Self {
        Arc::make_mut(&mut self.config).opaque = Some(opaque);
        self
    }

    /// Use `Payment-Authorization` for Payment credentials so `Authorization`
    /// remains available for application authentication.
    ///
    /// Challenges advertise `header="Payment-Authorization"`, and clients send
    /// the credential in that field instead of `Authorization`.
    pub fn with_requires_auth(mut self, enabled: bool) -> Self {
        Arc::make_mut(&mut self.config).credential_header =
            enabled.then(|| crate::protocol::core::PAYMENT_AUTHORIZATION_HEADER.to_string());
        self
    }

    /// Whether this handler requires ordinary application authentication.
    ///
    /// When true, Payment credentials use `Payment-Authorization`.
    pub fn requires_auth(&self) -> bool {
        self.config.credential_header.is_some()
    }

    /// HTTP field a client must use for Payment credentials issued by this handler.
    pub fn credential_header(&self) -> &str {
        self.config
            .credential_header
            .as_deref()
            .unwrap_or("Authorization")
    }

    /// Get the event registry used by this payment handler.
    pub fn events(&self) -> ServerEvents {
        self.events.clone()
    }

    /// Register a server event observer.
    pub fn on<F, Fut>(&self, kind: ServerEventKind, handler: F) -> ServerEventSubscription
    where
        F: Fn(ServerEvent) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.events.on(kind, handler)
    }

    /// Register an observer for every server event.
    pub fn on_any<F, Fut>(&self, handler: F) -> ServerEventSubscription
    where
        F: Fn(ServerEvent) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.events.on_any(handler)
    }

    /// Register a `payment.success` observer.
    pub fn on_payment_success<F, Fut>(&self, handler: F) -> ServerEventSubscription
    where
        F: Fn(PaymentSuccessContext) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        self.events.on_payment_success(handler)
    }

    /// Get the realm.
    pub fn realm(&self) -> &str {
        &self.config.realm
    }

    /// Get the method name.
    pub fn method_name(&self) -> &str {
        self.method.method()
    }

    /// Get the bound currency, if configured.
    ///
    /// When several currencies are accepted, this is the first (preferred)
    /// one. See [`currencies()`](Self::currencies) for the full list.
    pub fn currency(&self) -> Option<&str> {
        self.config.currencies.first().map(String::as_str)
    }

    /// Get the ordered list of accepted currencies (empty when unbound).
    pub fn currencies(&self) -> &[String] {
        &self.config.currencies
    }

    /// Get the bound recipient, if configured.
    pub fn recipient(&self) -> Option<&str> {
        self.config.recipient.as_deref()
    }

    /// Get the configured decimals.
    pub fn decimals(&self) -> u32 {
        self.config.decimals
    }

    /// Get whether fee sponsorship is enabled.
    pub fn fee_payer(&self) -> bool {
        self.config.fee_payer
    }

    /// Get whether canonical first-party machine-token funding is advertised.
    pub fn machine_token_enabled(&self) -> bool {
        self.config.machine_token_enabled
    }

    /// Get the configured chain ID, if set.
    pub fn chain_id(&self) -> Option<u64> {
        self.config.chain_id
    }

    /// Replace the bound currencies (test-only helper for sibling modules).
    #[cfg(test)]
    pub(crate) fn with_currencies(mut self, currencies: Vec<String>) -> Self {
        Arc::make_mut(&mut self.config).currencies = currencies;
        self
    }
}

/// Tempo-specific `create` constructor for [`Mpp`].
#[cfg(feature = "tempo")]
impl Mpp<super::TempoChargeMethod<super::TempoProvider>> {
    /// Create a payment handler from a [`TempoBuilder`](super::TempoBuilder).
    ///
    /// This is the simplest way to set up server-side payments.
    /// Currency and recipient are bound at creation time, so
    /// [`charge()`](Mpp::charge) only needs the dollar amount.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use mpp::server::{Mpp, tempo, TempoConfig};
    ///
    /// let mpp = Mpp::create(tempo(TempoConfig {
    ///     currency: "0x20c0000000000000000000000000000000000000",
    ///     recipient: "0xabc...123",
    /// }))?;
    ///
    /// let challenges = mpp.charge("1.00")?;
    /// ```
    pub fn create(mut builder: super::TempoBuilder) -> Result<Self> {
        builder
            .chain_id
            .get_or_insert_with(|| super::tempo::chain_id_from_rpc_url(&builder.rpc_url));
        if builder.fee_payer_fee_token.is_some() && builder.fee_payer_signer.is_none() {
            return Err(crate::error::MppError::InvalidConfig(
                "fee_payer_fee_token requires a local fee payer signer".into(),
            ));
        }
        // Without a sponsor every challenge would advertise `feePayer: true`
        // and every credential built for it would then be rejected.
        if builder.fee_payer && builder.fee_payer_signer.is_none() && builder.relay.is_none() {
            return Err(crate::error::MppError::InvalidConfig(
                "fee_payer(true) requires fee_payer_signer(...) or relay(...)".into(),
            ));
        }
        if builder
            .fee_payer_allowed_fee_tokens
            .as_ref()
            .is_some_and(Vec::is_empty)
        {
            return Err(crate::error::MppError::InvalidConfig(
                "fee_payer_allowed_fee_tokens must contain at least one token".into(),
            ));
        }
        if builder.machine_token_enabled {
            let chain_id = builder
                .chain_id
                .unwrap_or(crate::protocol::methods::tempo::CHAIN_ID);
            if !crate::protocol::methods::tempo::machine_token::is_supported(chain_id) {
                return Err(crate::error::MppError::InvalidConfig(format!(
                    "machine tokens are not supported on chain ID {chain_id}"
                )));
            }
        }
        // Resolve accepted currencies (explicit list, legacy single currency,
        // or chain defaults) before moving fields out of the builder.
        let currencies = super::tempo::resolve_currencies(&builder)?;
        let secret_key = builder
            .secret_key
            .or_else(|| std::env::var(SECRET_KEY_ENV_VAR).ok())
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                crate::error::MppError::InvalidConfig(format!(
                    "Missing secret key. Set {} environment variable or pass .secret_key(...).",
                    SECRET_KEY_ENV_VAR
                ))
            })?;
        crate::protocol::core::validate_secret_key(&secret_key)?;

        let provider = super::tempo_provider(&builder.rpc_url)?;
        let mut method = crate::protocol::methods::tempo::ChargeMethod::new(provider);
        if let Some(signer) = builder.fee_payer_signer {
            method = method.with_fee_payer_arc(signer);
        }
        if let Some(allowed_fee_tokens) = builder.fee_payer_allowed_fee_tokens {
            method = method.with_fee_payer_allowed_fee_tokens(allowed_fee_tokens);
        }
        if let Some(fee_token) = builder.fee_payer_fee_token {
            method = method.with_fee_payer_fee_token(fee_token);
        }
        if let Some(store) = builder.store {
            method = method.with_store(store);
        }
        if let Some(relay) = builder.relay {
            method = method.with_relay(relay)?;
        }

        Ok(Self::from_config(
            method,
            Config {
                currencies,
                recipient: Some(builder.recipient),
                decimals: builder.decimals,
                fee_payer: builder.fee_payer,
                machine_token_enabled: builder.machine_token_enabled,
                chain_id: builder.chain_id,
                credential_header: advertised_builder_credential_header(builder.requires_auth),
                ..Config::new(builder.realm, secret_key)
            },
        ))
    }
}

#[cfg(feature = "stripe")]
impl Mpp<crate::protocol::methods::stripe::method::ChargeMethod> {
    /// Create a Stripe payment handler from a [`StripeBuilder`](super::StripeBuilder).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use mpp::server::{Mpp, stripe, StripeConfig};
    ///
    /// let mpp = Mpp::create_stripe(stripe(StripeConfig {
    ///     secret_key: "sk_test_...",
    ///     network_id: "internal",
    ///     payment_method_types: &["card"],
    ///     currency: "usd",
    ///     decimals: 2,
    /// })
    /// .secret_key("my-hmac-secret-of-at-least-32-bytes"))?;
    /// ```
    pub fn create_stripe(builder: super::StripeBuilder) -> Result<Self> {
        let secret_key = builder
            .hmac_secret_key
            .or_else(|| std::env::var(SECRET_KEY_ENV_VAR).ok())
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                crate::error::MppError::InvalidConfig(format!(
                    "Missing secret key. Set {} environment variable or pass .secret_key(...).",
                    SECRET_KEY_ENV_VAR
                ))
            })?;
        crate::protocol::core::validate_secret_key(&secret_key)?;

        let mut method = crate::protocol::methods::stripe::method::ChargeMethod::new(
            &builder.secret_key,
            &builder.network_id,
            builder.payment_method_types.clone(),
        );
        if let Some(api_base) = builder.stripe_api_base {
            method = method.with_api_base(api_base);
        }

        Ok(Self::from_config(
            method,
            Config {
                currencies: vec![builder.currency],
                decimals: builder.decimals as u32,
                credential_header: advertised_builder_credential_header(builder.requires_auth),
                ..Config::new(builder.realm, secret_key)
            },
        ))
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests;
