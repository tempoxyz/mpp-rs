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

#[cfg(any(feature = "tempo", feature = "stripe"))]
use crate::error::Result;
#[cfg(any(feature = "tempo", feature = "stripe"))]
use crate::protocol::core::PaymentChallenge;
use crate::protocol::core::{Base64UrlJson, PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod, ChargeValidation, VerificationError};
use crate::server::events::{
    PaymentSuccessContext, ServerEvent, ServerEventKind, ServerEventSubscription, ServerEvents,
};

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

/// Validate the `supportedModes` a charge challenge advertises.
///
/// The verifier rejects credentials whose mode is not listed, so an empty or
/// misspelled list would make the challenge unpayable.
#[cfg(feature = "tempo")]
fn validate_charge_modes(modes: &[&str]) -> Result<()> {
    if modes.is_empty() || modes.iter().any(|mode| !matches!(*mode, "pull" | "push")) {
        return Err(crate::error::MppError::InvalidConfig(
            "supported_modes must be a non-empty list of \"pull\" and/or \"push\"".into(),
        ));
    }
    Ok(())
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

/// Result of session verification, including optional management response.
#[derive(Debug)]
pub struct SessionVerifyResult {
    /// The payment receipt.
    pub receipt: Receipt,
    /// Optional management response body (for channel open/close/topUp).
    /// When `Some`, the caller should return this as the response body
    /// instead of proceeding with normal request handling.
    pub management_response: Option<serde_json::Value>,
}

/// Server-side payment handler.
///
/// Binds a payment method with realm, secret_key, and optionally
/// a default currency and recipient for simplified `charge()` calls.
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
    method: M,
    session_method: Option<S>,
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
    events: ServerEvents,
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
        Mpp {
            method,
            session_method: None,
            realm: realm.into(),
            secret_key: secret_key.into(),
            currencies: Vec::new(),
            recipient: None,
            decimals: DEFAULT_DECIMALS,
            fee_payer: false,
            machine_token_enabled: false,
            chain_id: None,
            opaque: None,
            credential_header: None,
            events: ServerEvents::default(),
        }
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
        Mpp {
            method,
            session_method: None,
            realm: realm.into(),
            secret_key: secret_key.into(),
            currencies: vec![currency.into()],
            recipient: Some(recipient.into()),
            decimals: DEFAULT_DECIMALS,
            fee_payer: false,
            machine_token_enabled: false,
            chain_id: None,
            opaque: None,
            credential_header: None,
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
            session_method: Some(session_method),
            realm: self.realm,
            secret_key: self.secret_key,
            currencies: self.currencies,
            recipient: self.recipient,
            decimals: self.decimals,
            fee_payer: self.fee_payer,
            machine_token_enabled: self.machine_token_enabled,
            chain_id: self.chain_id,
            opaque: self.opaque,
            credential_header: self.credential_header,
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
        self.opaque = Some(opaque);
        self
    }

    /// Use `Payment-Authorization` for Payment credentials so `Authorization`
    /// remains available for application authentication.
    ///
    /// Challenges advertise `header="Payment-Authorization"`, and clients send
    /// the credential in that field instead of `Authorization`.
    pub fn with_requires_auth(mut self, enabled: bool) -> Self {
        self.credential_header =
            enabled.then(|| crate::protocol::core::PAYMENT_AUTHORIZATION_HEADER.to_string());
        self
    }

    /// Whether this handler requires ordinary application authentication.
    ///
    /// When true, Payment credentials use `Payment-Authorization`.
    pub fn requires_auth(&self) -> bool {
        self.credential_header.is_some()
    }

    /// HTTP field a client must use for Payment credentials issued by this handler.
    pub fn credential_header(&self) -> &str {
        self.credential_header.as_deref().unwrap_or("Authorization")
    }

    /// Stamp configured `opaque` and credential `header` onto an issued
    /// challenge and recompute its HMAC id. No-op when neither is configured.
    #[cfg(any(feature = "tempo", feature = "stripe"))]
    fn apply_pinned_opaque(&self, mut challenge: PaymentChallenge) -> PaymentChallenge {
        if self.opaque.is_none() && self.credential_header.is_none() {
            return challenge;
        }
        if let Some(opaque) = &self.opaque {
            challenge.opaque = Some(opaque.clone());
        }
        challenge.header = self.credential_header.clone();
        challenge.id = crate::protocol::core::compute_challenge_id_with_header(
            &self.secret_key,
            &challenge.realm,
            challenge.method.as_str(),
            challenge.intent.as_str(),
            challenge.request.raw(),
            challenge.expires.as_deref(),
            challenge.digest.as_deref(),
            challenge.opaque.as_ref().map(|o| o.raw()),
            challenge.header.as_deref(),
        );
        challenge
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
        &self.realm
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
        self.currencies.first().map(String::as_str)
    }

    /// Get the ordered list of accepted currencies (empty when unbound).
    pub fn currencies(&self) -> &[String] {
        &self.currencies
    }

    /// Get the bound recipient, if configured.
    pub fn recipient(&self) -> Option<&str> {
        self.recipient.as_deref()
    }

    /// Get the configured decimals.
    pub fn decimals(&self) -> u32 {
        self.decimals
    }

    /// Get whether fee sponsorship is enabled.
    pub fn fee_payer(&self) -> bool {
        self.fee_payer
    }

    /// Get whether canonical first-party machine-token funding is advertised.
    pub fn machine_token_enabled(&self) -> bool {
        self.machine_token_enabled
    }

    /// Get the configured chain ID, if set.
    pub fn chain_id(&self) -> Option<u64> {
        self.chain_id
    }

    /// Reject unless the credential's echoed `opaque` equals the configured one.
    fn verify_opaque(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<(), VerificationError> {
        let configured_opaque = self.opaque.as_ref().map(|o| o.raw());
        let echoed_opaque = credential.challenge.opaque.as_ref().map(|o| o.raw());
        if echoed_opaque != configured_opaque {
            return Err(VerificationError::with_code(
                "credential opaque data does not match this route's requirements",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }
        Ok(())
    }

    /// Tier-2 pinned field verification.
    ///
    /// After the HMAC check (Tier 1) confirms the echoed challenge was issued
    /// by this server, this check compares economically-significant fields
    /// from the credential against the server's current configuration to
    /// prevent cross-route credential replay attacks.
    fn verify_pinned_fields(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<(), VerificationError> {
        // Challenge-level fields: method, intent, realm
        if credential.challenge.method.as_str() != self.method.method() {
            return Err(VerificationError::with_code(
                format!(
                    "credential method '{}' does not match this route's requirements (expected '{}')",
                    credential.challenge.method, self.method.method()
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if !credential.challenge.intent.is_charge() {
            return Err(VerificationError::with_code(
                format!(
                    "credential intent '{}' does not match this route's requirements (expected 'charge')",
                    credential.challenge.intent
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if credential.challenge.realm != self.realm {
            return Err(VerificationError::with_code(
                format!(
                    "credential realm '{}' does not match this route's requirements (expected '{}')",
                    credential.challenge.realm, self.realm
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        self.verify_opaque(credential)?;

        // Request-level core fields: currency, recipient
        if !self.currencies.is_empty() && !self.offers_currency(&request.currency) {
            return Err(VerificationError::with_code(
                format!(
                    "credential currency '{}' does not match this route's requirements",
                    request.currency
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if let Some(ref expected_recipient) = self.recipient {
            if request.recipient.as_deref() != Some(expected_recipient.as_str()) {
                return Err(VerificationError::with_code(
                    "credential recipient does not match this route's requirements",
                    crate::protocol::traits::ErrorCode::InvalidChallenge,
                ));
            }
        }

        // Request-level method fields: chainId (fail-closed when expected but missing)
        if let Some(expected_chain_id) = self.chain_id {
            let actual_chain_id = request
                .method_details
                .as_ref()
                .and_then(|md| md.get("chainId"))
                .and_then(|v| match v {
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    serde_json::Value::String(s) => Some(s.clone()),
                    _ => None,
                });

            if actual_chain_id.as_deref() != Some(&*expected_chain_id.to_string()) {
                return Err(VerificationError::with_code(
                    format!(
                        "credential chainId {:?} does not match this route's requirements (expected '{}')",
                        actual_chain_id, expected_chain_id
                    ),
                    crate::protocol::traits::ErrorCode::InvalidChallenge,
                ));
            }
        }

        Ok(())
    }

    /// Verify the challenge HMAC and reject expired challenges.
    ///
    /// Shared validation used by both charge and session verification paths.
    fn verify_hmac_and_expiry(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<(), VerificationError> {
        let expected_id = crate::protocol::core::compute_challenge_id_with_header(
            &self.secret_key,
            &self.realm,
            credential.challenge.method.as_str(),
            credential.challenge.intent.as_str(),
            credential.challenge.request.raw(),
            credential.challenge.expires.as_deref(),
            credential.challenge.digest.as_deref(),
            credential.challenge.opaque.as_ref().map(|o| o.raw()),
            credential.challenge.header.as_deref(),
        );

        if !crate::protocol::core::constant_time_eq(&credential.challenge.id, &expected_id) {
            return Err(VerificationError::with_code(
                "Challenge ID mismatch - not issued by this server",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        let expires = credential.challenge.expires.as_deref().ok_or_else(|| {
            VerificationError::with_code(
                "Challenge missing required expires field",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            )
        })?;

        let expires_at =
            time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
                .map_err(|_| {
                    VerificationError::invalid_challenge("Invalid expires timestamp in challenge")
                })?;

        if expires_at <= time::OffsetDateTime::now_utc() {
            return Err(VerificationError::expired(format!(
                "Challenge expired at {}",
                expires
            )));
        }

        Ok(())
    }

    #[cfg(feature = "tempo")]
    fn require_bound_config(&self) -> Result<(&str, &str)> {
        let currency = self.currency().ok_or_else(|| {
            crate::error::MppError::InvalidConfig(
                "currency not configured — use Mpp::create() or set currency".into(),
            )
        })?;
        let recipient = self.recipient.as_deref().ok_or_else(|| {
            crate::error::MppError::InvalidConfig(
                "recipient not configured — use Mpp::create() or set recipient".into(),
            )
        })?;
        Ok((currency, recipient))
    }

    /// Generate one charge challenge per accepted currency, in order.
    ///
    /// Servers created with [`Mpp::create()`] on Tempo mainnet or Moderato
    /// accept OUSD first by default (see [`tempo()`](super::tempo)). Return
    /// every challenge in the 402 response (for example with
    /// [`format_www_authenticate_many()`](crate::protocol::core::format_www_authenticate_many))
    /// so clients can pay with any accepted currency. A credential for any of
    /// these challenges verifies against this handler.
    ///
    /// `amount` is in dollars (e.g., `"0.10"` for 10 cents), converted using
    /// the configured decimals (default: 6). Even a single accepted currency
    /// returns a one-element vector.
    ///
    /// Requires currency and recipient to be bound (via [`Mpp::create()`]).
    #[cfg(feature = "tempo")]
    pub fn charge(&self, amount: &str) -> Result<Vec<PaymentChallenge>> {
        self.charge_with_options(amount, super::ChargeOptions::default())
    }

    /// Generate one body-bound charge challenge per accepted currency.
    ///
    /// See [`charge()`](Self::charge).
    #[cfg(feature = "tempo")]
    pub fn charge_with_body(&self, amount: &str, body: &[u8]) -> Result<Vec<PaymentChallenge>> {
        self.charge_with_options_and_body(amount, super::ChargeOptions::default(), body)
    }

    /// Generate one charge challenge per accepted currency with additional options.
    ///
    /// See [`charge()`](Self::charge).
    #[cfg(feature = "tempo")]
    pub fn charge_with_options(
        &self,
        amount: &str,
        options: super::ChargeOptions<'_>,
    ) -> Result<Vec<PaymentChallenge>> {
        self.require_bound_config()?;
        self.currencies
            .iter()
            .map(|currency| self.charge_for_currency(amount, currency, &options))
            .collect()
    }

    /// Generate one body-bound charge challenge per accepted currency.
    ///
    /// See [`charge()`](Self::charge).
    #[cfg(feature = "tempo")]
    pub fn charge_with_options_and_body(
        &self,
        amount: &str,
        options: super::ChargeOptions<'_>,
        body: &[u8],
    ) -> Result<Vec<PaymentChallenge>> {
        Ok(self
            .charge_with_options(amount, options)?
            .into_iter()
            .map(|challenge| self.with_body_digest(challenge, body))
            .collect())
    }

    /// Generate a charge challenge for one bound currency.
    #[cfg(feature = "tempo")]
    fn charge_for_currency(
        &self,
        amount: &str,
        currency: &str,
        options: &super::ChargeOptions<'_>,
    ) -> Result<PaymentChallenge> {
        let (_, recipient) = self.require_bound_config()?;
        let base_units = super::parse_dollar_amount(amount, self.decimals)?;
        let mut request = ChargeRequest {
            amount: base_units,
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            description: options.description.map(|s| s.to_string()),
            external_id: options.external_id.map(|s| s.to_string()),
            mppx_scope: options.mppx_scope.cloned(),
            ..Default::default()
        };
        {
            let mut details = serde_json::Map::new();
            if options.fee_payer || self.fee_payer {
                details.insert("feePayer".into(), serde_json::json!(true));
            }
            if self.machine_token_enabled {
                details.insert("machineTokenEnabled".into(), serde_json::json!(true));
            }
            if let Some(chain_id) = self.chain_id {
                details.insert("chainId".into(), serde_json::json!(chain_id));
            }
            if let Some(supported_modes) = options.supported_modes {
                validate_charge_modes(supported_modes)?;
                details.insert("supportedModes".into(), serde_json::json!(supported_modes));
            }
            if !details.is_empty() {
                request.method_details = Some(serde_json::Value::Object(details));
            }
        }
        let challenge = crate::protocol::methods::tempo::charge_challenge_with_options(
            &self.secret_key,
            &self.realm,
            &request,
            options.expires,
            options.description,
        )?;
        Ok(self.apply_pinned_opaque(challenge))
    }

    /// Generate a charge challenge with explicit parameters (base units).
    ///
    /// Use this when you want to specify amount, currency, and recipient
    /// per-call instead of using bound defaults. Amount is in base units
    /// (e.g., `"1000000"` for 1 pathUSD).
    #[cfg(feature = "tempo")]
    pub fn charge_challenge(
        &self,
        amount: &str,
        currency: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        let request = ChargeRequest {
            amount: amount.to_string(),
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            ..Default::default()
        };
        self.charge_challenge_with_options(&request, None, None)
    }

    /// Generate a charge challenge with full options (base units).
    #[cfg(feature = "tempo")]
    pub fn charge_challenge_with_options(
        &self,
        request: &ChargeRequest,
        expires: Option<&str>,
        description: Option<&str>,
    ) -> Result<PaymentChallenge> {
        // Verification fails closed on a missing `chainId` when one is pinned,
        // so a caller-built request must carry it like `charge()` requests do.
        let mut request = request.clone();
        if let Some(chain_id) = self.chain_id {
            let details = request
                .method_details
                .get_or_insert_with(|| serde_json::json!({}));
            if let Some(details) = details.as_object_mut() {
                details
                    .entry("chainId")
                    .or_insert_with(|| serde_json::json!(chain_id));
            }
        }
        let challenge = crate::protocol::methods::tempo::charge_challenge_with_options(
            &self.secret_key,
            &self.realm,
            &request,
            expires,
            description,
        )?;
        Ok(self.apply_pinned_opaque(challenge))
    }

    fn decode_credential_request(
        credential: &PaymentCredential,
    ) -> std::result::Result<ChargeRequest, VerificationError> {
        credential.challenge.request.decode().map_err(|e| {
            VerificationError::invalid_challenge(format!("Failed to decode request: {e}"))
        })
    }

    /// Validate a payment credential without consuming or broadcasting it.
    ///
    /// Not bound to a route: see [`Self::broadcast_credential`].
    pub async fn validate_credential(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.validate(credential, &request).await
    }

    /// Validate a credential against the actual request body without accepting payment.
    ///
    /// Not bound to a route: see [`Self::broadcast_credential`].
    pub async fn validate_credential_with_body(
        &self,
        credential: &PaymentCredential,
        body: &[u8],
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.validate_with_body(credential, &request, Some(body))
            .await
    }

    /// Validate a credential against expected route values without accepting payment.
    pub async fn validate_credential_with_expected_request(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.verify_expected_request_matches(credential, &request, expected)?;
        self.validate(credential, &request).await
    }

    /// Validate a credential against expected route values and body bytes.
    pub async fn validate_credential_with_expected_request_and_body(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
        body: &[u8],
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.verify_expected_request_matches(credential, &request, expected)?;
        self.validate_with_body(credential, &request, Some(body))
            .await
    }

    /// Re-validate and accept a payment credential.
    ///
    /// Not bound to a route: this accepts any unexpired charge challenge this
    /// handler issued, whatever its amount. A handler that serves routes with
    /// different prices must compare the credential with the route's request,
    /// using [`Self::broadcast_credential_with_expected_request`] or
    /// [`Self::verify_charge`]. Otherwise a credential paid for the cheapest
    /// route unlocks every other one.
    pub async fn broadcast_credential(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<Receipt, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.broadcast(credential, &request).await
    }

    /// Re-validate and accept a credential bound to the actual request body.
    ///
    /// Not bound to a route: see [`Self::broadcast_credential`].
    pub async fn broadcast_credential_with_body(
        &self,
        credential: &PaymentCredential,
        body: &[u8],
    ) -> std::result::Result<Receipt, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.broadcast_with_body(credential, &request, Some(body))
            .await
    }

    /// Re-validate and accept a credential matching expected route values.
    pub async fn broadcast_credential_with_expected_request(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.verify_expected_request_matches(credential, &request, expected)?;
        self.broadcast(credential, &request).await
    }

    /// Re-validate and accept a credential matching expected route values and body bytes.
    pub async fn broadcast_credential_with_expected_request_and_body(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
        body: &[u8],
    ) -> std::result::Result<Receipt, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.verify_expected_request_matches(credential, &request, expected)?;
        self.broadcast_with_body(credential, &request, Some(body))
            .await
    }

    /// The charge request [`charge_with_options()`](Self::charge_with_options)
    /// issues for `amount` and `options`: what a route with that price expects
    /// a credential to have paid.
    ///
    /// Pass it to the `*_with_expected_request` verification methods, for
    /// example to validate without accepting payment or to verify a
    /// body-bound challenge. It names the first accepted currency; credentials
    /// for the other accepted currencies match it too.
    #[cfg(feature = "tempo")]
    pub fn expected_charge_request(
        &self,
        amount: &str,
        options: super::ChargeOptions<'_>,
    ) -> Result<ChargeRequest> {
        let (currency, _) = self.require_bound_config()?;
        self.charge_for_currency(amount, currency, &options)?
            .request
            .decode()
    }

    /// Accept a credential for a route that charges `amount` with
    /// [`charge()`](Self::charge).
    ///
    /// Rejects a credential whose challenge was issued for another amount,
    /// currency or recipient, so a payment for a cheaper route cannot be
    /// replayed here. `amount` is in dollars, as for `charge()`.
    #[cfg(feature = "tempo")]
    pub async fn verify_charge(
        &self,
        credential: &PaymentCredential,
        amount: &str,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.verify_charge_with_options(credential, amount, super::ChargeOptions::default())
            .await
    }

    /// Accept a credential for a route that charges `amount` with
    /// [`charge_with_options()`](Self::charge_with_options).
    ///
    /// Pass the options the route issues its challenges with. See
    /// [`verify_charge()`](Self::verify_charge).
    #[cfg(feature = "tempo")]
    pub async fn verify_charge_with_options(
        &self,
        credential: &PaymentCredential,
        amount: &str,
        options: super::ChargeOptions<'_>,
    ) -> std::result::Result<Receipt, VerificationError> {
        let expected = self.expected_charge_request(amount, options).map_err(|e| {
            VerificationError::new(format!("Failed to build expected charge request: {e}"))
        })?;
        self.broadcast_credential_with_expected_request(credential, &expected)
            .await
    }

    /// Backwards-compatible alias for [`Self::broadcast_credential`].
    #[deprecated(
        since = "0.15.0",
        note = "accepts a credential paid for any route of this handler, whatever its price; use `verify_charge` (Tempo), `stripe_verify_charge` (Stripe) or `verify_credential_with_expected_request`. `broadcast_credential` keeps the unbound behavior"
    )]
    pub async fn verify_credential(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast_credential(credential).await
    }

    /// Backwards-compatible alias for [`Self::broadcast_credential_with_body`].
    #[deprecated(
        since = "0.15.0",
        note = "accepts a credential paid for any route of this handler, whatever its price; use `verify_credential_with_expected_request_and_body`. `broadcast_credential_with_body` keeps the unbound behavior"
    )]
    pub async fn verify_credential_with_body(
        &self,
        credential: &PaymentCredential,
        body: &[u8],
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast_credential_with_body(credential, body).await
    }

    /// Backwards-compatible alias for [`Self::broadcast_credential_with_expected_request`].
    pub async fn verify_credential_with_expected_request(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast_credential_with_expected_request(credential, expected)
            .await
    }

    /// Backwards-compatible alias for
    /// [`Self::broadcast_credential_with_expected_request_and_body`].
    pub async fn verify_credential_with_expected_request_and_body(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
        body: &[u8],
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast_credential_with_expected_request_and_body(credential, expected, body)
            .await
    }

    fn verify_expected_request_matches(
        &self,
        _credential: &PaymentCredential,
        request: &ChargeRequest,
        expected: &ChargeRequest,
    ) -> std::result::Result<(), VerificationError> {
        if request.amount != expected.amount {
            return Err(VerificationError::with_code(
                format!(
                    "Amount mismatch: credential has {} but endpoint expects {}",
                    request.amount, expected.amount
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        // A route built from this handler's bound currencies accepts any of
        // them, since each was offered as an equivalent challenge.
        if request.currency != expected.currency
            && !(self.offers_currency(&expected.currency)
                && self.offers_currency(&request.currency))
        {
            return Err(VerificationError::with_code(
                format!(
                    "Currency mismatch: credential has {} but endpoint expects {}",
                    request.currency, expected.currency
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if request.recipient != expected.recipient {
            return Err(VerificationError::with_code(
                "Recipient mismatch: credential was issued for a different recipient",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if request.mppx_scope != expected.mppx_scope {
            return Err(VerificationError::with_code(
                "Framework scope mismatch: credential was issued for a different route",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if request.external_id != expected.external_id {
            return Err(VerificationError::with_code(
                "External ID mismatch: credential was issued for a different order",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        #[cfg(feature = "tempo")]
        if _credential.challenge.method.as_str() == crate::protocol::methods::tempo::METHOD_NAME {
            let req_transfers =
                crate::protocol::methods::tempo::transfers::get_request_transfers(request)
                    .map_err(|e| {
                        VerificationError::with_code(
                            format!("Invalid Tempo request in credential: {e}"),
                            crate::protocol::traits::ErrorCode::InvalidCredential,
                        )
                    })?;
            let expected_transfers =
                crate::protocol::methods::tempo::transfers::get_request_transfers(expected)
                    .map_err(|e| {
                        VerificationError::with_code(
                            format!("Invalid expected Tempo request: {e}"),
                            crate::protocol::traits::ErrorCode::Internal,
                        )
                    })?;

            let mut unmatched = req_transfers;
            let same_transfers = unmatched.len() == expected_transfers.len()
                && expected_transfers.into_iter().all(|expected| {
                    unmatched
                        .iter()
                        .position(|actual| *actual == expected)
                        .map(|index| unmatched.swap_remove(index))
                        .is_some()
                });
            if !same_transfers {
                return Err(VerificationError::with_code(
                    "Tempo transfer routing mismatch: credential was issued with different memo or splits",
                    crate::protocol::traits::ErrorCode::InvalidChallenge,
                ));
            }
        }

        Ok(())
    }

    /// Validate a charge credential with an explicit request without accepting payment.
    pub async fn validate(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        self.validate_with_body(credential, request, None).await
    }

    async fn validate_with_body(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
        body: Option<&[u8]>,
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        self.verify_hmac_and_expiry(credential)?;
        self.verify_body_digest(credential, body)?;
        self.verify_pinned_fields(credential, request)?;
        self.method.validate(credential, request).await
    }

    async fn validate_before_broadcast(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<(), VerificationError> {
        if self.method.supports_validation() {
            self.method.validate(credential, request).await?;
        }
        Ok(())
    }

    /// Re-validate and perform the terminal payment operation.
    pub async fn broadcast(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast_with_body(credential, request, None).await
    }

    async fn broadcast_with_body(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
        body: Option<&[u8]>,
    ) -> std::result::Result<Receipt, VerificationError> {
        // Tier 1: HMAC provenance + expiry
        self.verify_hmac_and_expiry(credential)?;
        self.verify_body_digest(credential, body)?;
        // Tier 2: Pinned field safety net
        self.verify_pinned_fields(credential, request)?;
        self.validate_before_broadcast(credential, request).await?;
        let receipt = self.method.broadcast(credential, request).await?;
        self.events
            .emit_payment_success(PaymentSuccessContext {
                credential: credential.clone(),
                receipt: receipt.clone(),
                request: serde_json::to_value(request).unwrap_or(serde_json::Value::Null),
                method: credential.challenge.method.as_str().to_string(),
                intent: credential.challenge.intent.as_str().to_string(),
                management_response: false,
            })
            .await;
        Ok(receipt)
    }

    /// Backwards-compatible alias for [`Self::broadcast`].
    pub async fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast(credential, request).await
    }

    fn verify_body_digest(
        &self,
        credential: &PaymentCredential,
        body: Option<&[u8]>,
    ) -> std::result::Result<(), VerificationError> {
        match (credential.challenge.digest.as_deref(), body) {
            (Some(_), None) => Err(VerificationError::with_code(
                "body digest present but request body was not provided",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            )),
            (None, Some(_)) => Err(VerificationError::with_code(
                "missing body digest",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            )),
            (Some(digest), Some(body)) if !crate::body_digest::verify(digest, body) => {
                Err(VerificationError::with_code(
                    "body digest mismatch",
                    crate::protocol::traits::ErrorCode::InvalidChallenge,
                ))
            }
            _ => Ok(()),
        }
    }

    #[cfg(any(feature = "tempo", feature = "stripe"))]
    fn with_body_digest(&self, mut challenge: PaymentChallenge, body: &[u8]) -> PaymentChallenge {
        let digest = crate::body_digest::compute(body);
        challenge.id = crate::protocol::core::compute_challenge_id_with_header(
            &self.secret_key,
            &challenge.realm,
            challenge.method.as_str(),
            challenge.intent.as_str(),
            challenge.request.raw(),
            challenge.expires.as_deref(),
            Some(&digest),
            challenge.opaque.as_ref().map(|o| o.raw()),
            challenge.header.as_deref(),
        );
        challenge.digest = Some(digest);
        challenge
    }

    /// Whether `currency` is one of this handler's bound currencies.
    fn offers_currency(&self, currency: &str) -> bool {
        self.currencies.iter().any(|offered| offered == currency)
    }

    /// Replace the bound currencies (test-only helper for sibling modules).
    #[cfg(test)]
    pub(crate) fn with_currencies(mut self, currencies: Vec<String>) -> Self {
        self.currencies = currencies;
        self
    }
}

impl<M, S> Mpp<M, S>
where
    M: ChargeMethod,
    S: crate::protocol::traits::SessionMethod,
{
    /// Generate a session challenge.
    #[cfg(feature = "tempo")]
    pub fn session_challenge(
        &self,
        amount: &str,
        currency: &str,
        recipient: &str,
    ) -> crate::error::Result<PaymentChallenge> {
        use crate::protocol::intents::SessionRequest;
        use time::{Duration, OffsetDateTime};

        let request = SessionRequest {
            amount: amount.to_string(),
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            ..Default::default()
        };
        let encoded = Base64UrlJson::from_typed(&request)?;

        let expires = {
            let expiry_time = OffsetDateTime::now_utc()
                + Duration::minutes(
                    crate::protocol::methods::tempo::DEFAULT_EXPIRES_MINUTES as i64,
                );
            expiry_time
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| {
                    crate::error::MppError::InvalidConfig(format!("failed to format expires: {e}"))
                })?
        };

        let id = crate::protocol::methods::tempo::generate_challenge_id(
            &self.secret_key,
            &self.realm,
            "tempo",
            "session",
            encoded.raw(),
            Some(&expires),
            None,
            None,
        );

        Ok(self.apply_pinned_opaque(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: "tempo".into(),
            intent: "session".into(),
            request: encoded,
            expires: Some(expires),
            description: None,
            digest: None,
            opaque: None,
            header: None,
        }))
    }

    /// Generate a session challenge with method details populated from the session method.
    ///
    /// When a session method is configured (e.g., Tempo's `SessionMethod`), this
    /// automatically populates `methodDetails` with fields like `escrowContract`,
    /// `chainId`, and `minVoucherDelta`. Additional options like `suggestedDeposit`,
    /// `feePayer`, `description`, and `expires` can be set via [`SessionChallengeOptions`](super::SessionChallengeOptions).
    ///
    /// `feePayer` and the machine-token settlement route are only advertised
    /// when the session method reports that it supports them (see
    /// [`SessionMethod::supports_fee_payer`](crate::protocol::traits::SessionMethod::supports_fee_payer)
    /// and
    /// [`SessionMethod::supports_machine_tokens`](crate::protocol::traits::SessionMethod::supports_machine_tokens)).
    /// Tempo's `SessionMethod` supports neither.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let challenge = mpp.session_challenge_with_details(
    ///     "1000",
    ///     "0x20c0...",
    ///     "0x742d...",
    ///     SessionChallengeOptions {
    ///         unit_type: Some("second"),
    ///         suggested_deposit: Some("60000"),
    ///         ..Default::default()
    ///     },
    /// )?;
    /// ```
    #[cfg(feature = "tempo")]
    pub fn session_challenge_with_details(
        &self,
        amount: &str,
        currency: &str,
        recipient: &str,
        options: super::SessionChallengeOptions<'_>,
    ) -> crate::error::Result<PaymentChallenge> {
        use crate::protocol::intents::SessionRequest;
        use time::{Duration, OffsetDateTime};

        let session = self.session_method.as_ref();

        let mut method_details = session.and_then(|s| s.challenge_method_details());

        // Fee sponsorship and machine tokens are configured on the handler for
        // charges; only advertise them when the session method can honour them.
        let sponsors_fees = session.is_some_and(|s| s.supports_fee_payer());
        let settles_machine_tokens = session.is_some_and(|s| s.supports_machine_tokens());

        if (options.fee_payer || self.fee_payer) && sponsors_fees {
            let details = method_details.get_or_insert_with(|| serde_json::json!({}));
            if let Some(obj) = details.as_object_mut() {
                obj.insert("feePayer".to_string(), serde_json::json!(true));
            }
        }

        if self.machine_token_enabled && settles_machine_tokens {
            let chain_id = self
                .chain_id
                .unwrap_or(crate::protocol::methods::tempo::CHAIN_ID);
            let (_, adapter) =
                crate::protocol::methods::tempo::machine_token::session_addresses(chain_id)
                    .ok_or_else(|| {
                        crate::error::MppError::InvalidConfig(format!(
                            "machine tokens are not supported on chain ID {chain_id}"
                        ))
                    })?;
            let details = method_details.get_or_insert_with(|| serde_json::json!({}));
            if let Some(obj) = details.as_object_mut() {
                obj.insert("machineTokenEnabled".to_string(), serde_json::json!(true));
                obj.insert("settlementAdapter".to_string(), serde_json::json!(adapter));
                obj.insert(
                    "settlementRecipient".to_string(),
                    serde_json::json!(recipient),
                );
                obj.insert("settlementToken".to_string(), serde_json::json!(currency));
            }
        }

        let request = SessionRequest {
            amount: amount.to_string(),
            unit_type: options.unit_type.map(|s| s.to_string()),
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            suggested_deposit: options.suggested_deposit.map(|s| s.to_string()),
            method_details,
            ..Default::default()
        };
        let encoded = Base64UrlJson::from_typed(&request)?;

        let default_expires;
        let expires = match options.expires {
            Some(e) => Some(e),
            None => {
                let expiry_time = OffsetDateTime::now_utc()
                    + Duration::minutes(
                        crate::protocol::methods::tempo::DEFAULT_EXPIRES_MINUTES as i64,
                    );
                default_expires = expiry_time
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|e| {
                        crate::error::MppError::InvalidConfig(format!(
                            "failed to format expires: {e}"
                        ))
                    })?;
                Some(default_expires.as_str())
            }
        };

        let id = crate::protocol::methods::tempo::generate_challenge_id(
            &self.secret_key,
            &self.realm,
            "tempo",
            "session",
            encoded.raw(),
            expires,
            None,
            None,
        );

        Ok(self.apply_pinned_opaque(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: "tempo".into(),
            intent: "session".into(),
            request: encoded,
            expires: expires.map(|s| s.to_string()),
            description: options.description.map(|s| s.to_string()),
            digest: None,
            opaque: None,
            header: None,
        }))
    }

    /// Verify a session credential.
    pub async fn verify_session(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<SessionVerifyResult, crate::protocol::traits::VerificationError> {
        let session = self.session_method.as_ref().ok_or_else(|| {
            crate::protocol::traits::VerificationError::new("No session method configured")
        })?;

        self.verify_hmac_and_expiry(credential)?;
        self.verify_opaque(credential)?;

        let request: crate::protocol::intents::SessionRequest =
            credential.challenge.request.decode().map_err(|e| {
                crate::protocol::traits::VerificationError::invalid_challenge(format!(
                    "Failed to decode session request: {}",
                    e
                ))
            })?;

        // Channels opened in any accepted currency keep verifying, including
        // channels opened before OUSD became the preferred default.
        if !self.currencies.is_empty()
            && !self
                .currencies
                .iter()
                .any(|bound| request.currency.eq_ignore_ascii_case(bound))
        {
            return Err(VerificationError::with_code(
                format!(
                    "Currency mismatch: credential has {} but server expects {}",
                    request.currency,
                    self.currencies.join(" or ")
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if let Some(bound) = &self.recipient {
            let echoed = request.recipient.as_deref().unwrap_or("");
            if !echoed.eq_ignore_ascii_case(bound) {
                return Err(VerificationError::with_code(
                    format!(
                        "Recipient mismatch: credential has {} but server expects {}",
                        echoed, bound
                    ),
                    crate::protocol::traits::ErrorCode::InvalidChallenge,
                ));
            }
        }

        let receipt = session.verify_session(credential, &request).await?;

        // Call respond hook — management actions (open, topUp, close) may
        // return a response body that short-circuits normal request handling.
        let management_response = session.respond(credential, &receipt);
        let has_management_response = management_response.is_some();

        self.events
            .emit_payment_success(PaymentSuccessContext {
                credential: credential.clone(),
                receipt: receipt.clone(),
                request: serde_json::to_value(&request).unwrap_or(serde_json::Value::Null),
                method: credential.challenge.method.as_str().to_string(),
                intent: credential.challenge.intent.as_str().to_string(),
                management_response: has_management_response,
            })
            .await;

        Ok(SessionVerifyResult {
            receipt,
            management_response,
        })
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

        Ok(Self {
            method,
            session_method: None,
            realm: builder.realm,
            secret_key,
            currencies,
            recipient: Some(builder.recipient),
            decimals: builder.decimals,
            fee_payer: builder.fee_payer,
            machine_token_enabled: builder.machine_token_enabled,
            chain_id: builder.chain_id,
            opaque: None,
            credential_header: advertised_builder_credential_header(builder.requires_auth),
            events: ServerEvents::default(),
        })
    }
}

// ==================== Stripe charge helpers ====================

#[cfg(feature = "stripe")]
impl<S> Mpp<crate::protocol::methods::stripe::method::ChargeMethod, S> {
    /// Generate a Stripe charge challenge for a dollar amount.
    ///
    /// Creates a `method=stripe`, `intent=charge` challenge with HMAC-bound ID.
    pub fn stripe_charge(&self, amount: &str) -> Result<PaymentChallenge> {
        self.stripe_charge_with_options(amount, super::StripeChargeOptions::default())
    }

    /// Generate a Stripe charge challenge and bind it to the actual request body bytes.
    pub fn stripe_charge_with_body(&self, amount: &str, body: &[u8]) -> Result<PaymentChallenge> {
        self.stripe_charge_with_options_and_body(
            amount,
            super::StripeChargeOptions::default(),
            body,
        )
    }

    /// Generate a Stripe charge challenge with additional options.
    ///
    /// Accepts [`StripeChargeOptions`](super::StripeChargeOptions) for description,
    /// external ID, expiration, and metadata.
    pub fn stripe_charge_with_options(
        &self,
        amount: &str,
        options: super::StripeChargeOptions<'_>,
    ) -> Result<PaymentChallenge> {
        use time::{Duration, OffsetDateTime};

        use crate::protocol::methods::stripe::StripeMethodDetails;

        let base_units = super::parse_dollar_amount(amount, self.decimals)?;
        let currency = self.currency().unwrap_or("usd");

        let details = StripeMethodDetails {
            network_id: self.method.network_id().to_string(),
            payment_method_types: self.method.payment_method_types().to_vec(),
            metadata: options.metadata.cloned(),
        };

        let request = ChargeRequest {
            amount: base_units,
            currency: currency.to_string(),
            description: options.description.map(|s| s.to_string()),
            external_id: options.external_id.map(|s| s.to_string()),
            method_details: Some(serde_json::to_value(&details).map_err(|e| {
                crate::error::MppError::InvalidConfig(format!(
                    "failed to serialize methodDetails: {e}"
                ))
            })?),
            mppx_scope: options.mppx_scope.cloned(),
            ..Default::default()
        };

        let encoded_request = Base64UrlJson::from_typed(&request)?;

        let expires = if let Some(exp) = options.expires {
            exp.to_string()
        } else {
            let expiry_time = OffsetDateTime::now_utc() + Duration::minutes(5);
            expiry_time
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| {
                    crate::error::MppError::InvalidConfig(format!("failed to format expires: {e}"))
                })?
        };

        let id = crate::protocol::core::compute_challenge_id(
            &self.secret_key,
            &self.realm,
            crate::protocol::methods::stripe::METHOD_NAME,
            crate::protocol::methods::stripe::INTENT_CHARGE,
            encoded_request.raw(),
            Some(&expires),
            None,
            None,
        );

        Ok(self.apply_pinned_opaque(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: crate::protocol::methods::stripe::METHOD_NAME.into(),
            intent: crate::protocol::methods::stripe::INTENT_CHARGE.into(),
            request: encoded_request,
            expires: Some(expires),
            description: options.description.map(|s| s.to_string()),
            digest: None,
            opaque: None,
            header: None,
        }))
    }

    /// Generate a Stripe charge challenge with options and bind it to the actual request body bytes.
    pub fn stripe_charge_with_options_and_body(
        &self,
        amount: &str,
        options: super::StripeChargeOptions<'_>,
        body: &[u8],
    ) -> Result<PaymentChallenge> {
        let challenge = self.stripe_charge_with_options(amount, options)?;
        Ok(self.with_body_digest(challenge, body))
    }

    /// The charge request
    /// [`stripe_charge_with_options()`](Self::stripe_charge_with_options)
    /// issues for `amount` and `options`: what a route with that price expects
    /// a credential to have paid.
    ///
    /// Pass it to the `*_with_expected_request` verification methods, for
    /// example to validate without accepting payment or to verify a
    /// body-bound challenge.
    pub fn stripe_expected_charge_request(
        &self,
        amount: &str,
        options: super::StripeChargeOptions<'_>,
    ) -> Result<ChargeRequest> {
        self.stripe_charge_with_options(amount, options)?
            .request
            .decode()
    }

    /// Accept a credential for a route that charges `amount` with
    /// [`stripe_charge()`](Self::stripe_charge).
    ///
    /// Rejects a credential whose challenge was issued for another amount or
    /// currency, so a payment for a cheaper route cannot be replayed here.
    pub async fn stripe_verify_charge(
        &self,
        credential: &PaymentCredential,
        amount: &str,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.stripe_verify_charge_with_options(
            credential,
            amount,
            super::StripeChargeOptions::default(),
        )
        .await
    }

    /// Accept a credential for a route that charges `amount` with
    /// [`stripe_charge_with_options()`](Self::stripe_charge_with_options).
    ///
    /// Pass the options the route issues its challenges with. See
    /// [`stripe_verify_charge()`](Self::stripe_verify_charge).
    pub async fn stripe_verify_charge_with_options(
        &self,
        credential: &PaymentCredential,
        amount: &str,
        options: super::StripeChargeOptions<'_>,
    ) -> std::result::Result<Receipt, VerificationError> {
        let expected = self
            .stripe_expected_charge_request(amount, options)
            .map_err(|e| {
                VerificationError::new(format!("Failed to build expected charge request: {e}"))
            })?;
        self.broadcast_credential_with_expected_request(credential, &expected)
            .await
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

        Ok(Self {
            method,
            session_method: None,
            realm: builder.realm,
            secret_key,
            currencies: vec![builder.currency],
            recipient: None,
            decimals: builder.decimals as u32,
            fee_payer: false,
            machine_token_enabled: false,
            chain_id: None,
            opaque: None,
            credential_header: advertised_builder_credential_header(builder.requires_auth),
            events: ServerEvents::default(),
        })
    }
}

#[cfg(test)]
#[allow(deprecated)]
mod tests;
