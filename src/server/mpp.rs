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
//! let challenge = mpp.charge("0.10")?;
//! ```

#[cfg(any(feature = "tempo", feature = "stripe"))]
use crate::error::Result;
#[cfg(any(feature = "tempo", feature = "stripe"))]
use crate::protocol::core::PaymentChallenge;
use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod, VerificationError};

const SECRET_KEY_ENV_VAR: &str = "MPP_SECRET_KEY";
const DEFAULT_DECIMALS: u32 = 6;

/// Environment variables checked (in order) to auto-detect the server realm.
const REALM_ENV_VARS: &[&str] = &[
    "MPP_REALM",
    "FLY_APP_NAME",
    "HEROKU_APP_NAME",
    "HOST",
    "HOSTNAME",
    "RAILWAY_PUBLIC_DOMAIN",
    "RENDER_EXTERNAL_HOSTNAME",
    "VERCEL_URL",
    "WEBSITE_HOSTNAME",
];

const DEFAULT_REALM: &str = "MPP Payment";

/// Detect the server realm from environment variables.
///
/// Checks platform-specific env vars in order (see [`REALM_ENV_VARS`]),
/// falling back to `"MPP Payment"`.
pub(crate) fn detect_realm() -> String {
    for name in REALM_ENV_VARS {
        if let Ok(value) = std::env::var(name) {
            if !value.is_empty() {
                return value;
            }
        }
    }
    DEFAULT_REALM.to_string()
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
/// let challenge = mpp.charge("0.10")?;
/// ```
///
/// # Advanced API
///
/// ```ignore
/// use mpp::server::{Mpp, tempo_provider, TempoChargeMethod};
///
/// let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
/// let method = TempoChargeMethod::new(provider);
/// let payment = Mpp::new(method, "api.example.com", "my-server-secret");
///
/// let challenge = payment.charge_challenge("1000000", "0x...", "0x...")?;
/// ```
#[derive(Clone)]
pub struct Mpp<M, S = ()> {
    method: M,
    session_method: Option<S>,
    realm: String,
    secret_key: String,
    currency: Option<String>,
    recipient: Option<String>,
    decimals: u32,
    fee_payer: bool,
    chain_id: Option<u64>,
}

impl<M> Mpp<M, ()>
where
    M: ChargeMethod,
{
    /// Create a new payment handler (advanced API).
    ///
    /// For a simpler API, use [`Mpp::create()`] with [`tempo()`](super::tempo).
    pub fn new(method: M, realm: impl Into<String>, secret_key: impl Into<String>) -> Mpp<M, ()> {
        Mpp {
            method,
            session_method: None,
            realm: realm.into(),
            secret_key: secret_key.into(),
            currency: None,
            recipient: None,
            decimals: DEFAULT_DECIMALS,
            fee_payer: false,
            chain_id: None,
        }
    }
}

impl<M> Mpp<M, ()>
where
    M: ChargeMethod,
{
    /// Create a payment handler with bound currency/recipient for testing.
    #[cfg(test)]
    pub(crate) fn new_with_config(
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
            currency: Some(currency.into()),
            recipient: Some(recipient.into()),
            decimals: DEFAULT_DECIMALS,
            fee_payer: false,
            chain_id: None,
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
            currency: self.currency,
            recipient: self.recipient,
            decimals: self.decimals,
            fee_payer: self.fee_payer,
            chain_id: self.chain_id,
        }
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
    pub fn currency(&self) -> Option<&str> {
        self.currency.as_deref()
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

    /// Get the configured chain ID, if set.
    pub fn chain_id(&self) -> Option<u64> {
        self.chain_id
    }

    /// Verify the challenge HMAC and reject expired challenges.
    ///
    /// Shared validation used by both charge and session verification paths.
    fn verify_hmac_and_expiry(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<(), VerificationError> {
        let expected_id = crate::protocol::core::compute_challenge_id(
            &self.secret_key,
            &self.realm,
            credential.challenge.method.as_str(),
            credential.challenge.intent.as_str(),
            credential.challenge.request.raw(),
            credential.challenge.expires.as_deref(),
            credential.challenge.digest.as_deref(),
            credential.challenge.opaque.as_ref().map(|o| o.raw()),
        );

        if !crate::protocol::core::constant_time_eq(&credential.challenge.id, &expected_id) {
            return Err(VerificationError::with_code(
                "Challenge ID mismatch - not issued by this server",
                crate::protocol::traits::ErrorCode::CredentialMismatch,
            ));
        }

        let expires = credential.challenge.expires.as_deref().ok_or_else(|| {
            VerificationError::with_code(
                "Challenge missing required expires field",
                crate::protocol::traits::ErrorCode::CredentialMismatch,
            )
        })?;

        let expires_at =
            time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
                .map_err(|_| VerificationError::new("Invalid expires timestamp in challenge"))?;

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
        let currency = self.currency.as_deref().ok_or_else(|| {
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

    /// Generate a charge challenge for a dollar amount.
    ///
    /// Requires currency and recipient to be bound (via [`Mpp::create()`]).
    /// The amount is automatically converted from dollars to base units
    /// using the configured decimals (default: 6).
    ///
    /// # Arguments
    ///
    /// * `amount` - Amount in dollars (e.g., `"0.10"` for 10 cents)
    ///
    /// # Example
    ///
    /// ```ignore
    /// let challenge = mpp.charge("0.10")?;
    /// ```
    #[cfg(feature = "tempo")]
    pub fn charge(&self, amount: &str) -> Result<PaymentChallenge> {
        self.charge_with_options(amount, super::ChargeOptions::default())
    }

    /// Generate a charge challenge with a dollar amount and additional options.
    ///
    /// Requires currency and recipient to be bound (via [`Mpp::create()`]).
    #[cfg(feature = "tempo")]
    pub fn charge_with_options(
        &self,
        amount: &str,
        options: super::ChargeOptions<'_>,
    ) -> Result<PaymentChallenge> {
        let (currency, recipient) = self.require_bound_config()?;
        let base_units = super::parse_dollar_amount(amount, self.decimals)?;
        let mut request = ChargeRequest {
            amount: base_units,
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            description: options.description.map(|s| s.to_string()),
            external_id: options.external_id.map(|s| s.to_string()),
            ..Default::default()
        };
        {
            let mut details = serde_json::Map::new();
            if options.fee_payer || self.fee_payer {
                details.insert("feePayer".into(), serde_json::json!(true));
            }
            if let Some(chain_id) = self.chain_id {
                details.insert("chainId".into(), serde_json::json!(chain_id));
            }
            if !details.is_empty() {
                request.method_details = Some(serde_json::Value::Object(details));
            }
        }
        crate::protocol::methods::tempo::charge_challenge_with_options(
            &self.secret_key,
            &self.realm,
            &request,
            options.expires,
            options.description,
        )
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
        crate::protocol::methods::tempo::charge_challenge(
            &self.secret_key,
            &self.realm,
            amount,
            currency,
            recipient,
        )
    }

    /// Generate a charge challenge with full options (base units).
    #[cfg(feature = "tempo")]
    pub fn charge_challenge_with_options(
        &self,
        request: &ChargeRequest,
        expires: Option<&str>,
        description: Option<&str>,
    ) -> Result<PaymentChallenge> {
        crate::protocol::methods::tempo::charge_challenge_with_options(
            &self.secret_key,
            &self.realm,
            request,
            expires,
            description,
        )
    }

    /// Verify a payment credential (simple API).
    ///
    /// Decodes the charge request from the echoed challenge automatically.
    /// No need to reconstruct the request manually.
    pub async fn verify_credential(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<Receipt, VerificationError> {
        let request: ChargeRequest = credential
            .challenge
            .request
            .decode()
            .map_err(|e| VerificationError::new(format!("Failed to decode request: {}", e)))?;
        self.verify(credential, &request).await
    }

    /// Verify a payment credential, ensuring the charge request matches the server's expected values.
    ///
    /// This prevents cross-route credential replay attacks where a credential
    /// obtained from a cheaper endpoint (or different recipient/currency) is
    /// replayed on another.
    pub async fn verify_credential_with_expected_request(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        let request: ChargeRequest = credential
            .challenge
            .request
            .decode()
            .map_err(|e| VerificationError::new(format!("Failed to decode request: {}", e)))?;

        if request.amount != expected.amount {
            return Err(VerificationError::with_code(
                format!(
                    "Amount mismatch: credential has {} but endpoint expects {}",
                    request.amount, expected.amount
                ),
                crate::protocol::traits::ErrorCode::CredentialMismatch,
            ));
        }

        if request.currency != expected.currency {
            return Err(VerificationError::with_code(
                format!(
                    "Currency mismatch: credential has {} but endpoint expects {}",
                    request.currency, expected.currency
                ),
                crate::protocol::traits::ErrorCode::CredentialMismatch,
            ));
        }

        if request.recipient != expected.recipient {
            return Err(VerificationError::with_code(
                "Recipient mismatch: credential was issued for a different recipient",
                crate::protocol::traits::ErrorCode::CredentialMismatch,
            ));
        }

        #[cfg(feature = "tempo")]
        if credential.challenge.method.as_str() == crate::protocol::methods::tempo::METHOD_NAME {
            let req_transfers =
                crate::protocol::methods::tempo::transfers::get_request_transfers(&request)
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
                            crate::protocol::traits::ErrorCode::InvalidCredential,
                        )
                    })?;

            if req_transfers != expected_transfers {
                return Err(VerificationError::with_code(
                    "Tempo transfer routing mismatch: credential was issued with different memo or splits",
                    crate::protocol::traits::ErrorCode::CredentialMismatch,
                ));
            }
        }

        self.verify(credential, &request).await
    }

    /// Verify a charge credential with an explicit request.
    pub async fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.verify_hmac_and_expiry(credential)?;
        let receipt = self.method.verify(credential, request).await?;
        Ok(receipt)
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
        let encoded = crate::protocol::core::Base64UrlJson::from_typed(&request)?;

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

        Ok(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: "tempo".into(),
            intent: "session".into(),
            request: encoded,
            expires: Some(expires),
            description: None,
            digest: None,
            opaque: None,
        })
    }

    /// Generate a session challenge with method details populated from the session method.
    ///
    /// When a session method is configured (e.g., Tempo's `SessionMethod`), this
    /// automatically populates `methodDetails` with fields like `escrowContract`,
    /// `chainId`, and `minVoucherDelta`. Additional options like `suggestedDeposit`,
    /// `feePayer`, `description`, and `expires` can be set via [`SessionChallengeOptions`](super::SessionChallengeOptions).
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
    ///         fee_payer: true,
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

        if options.fee_payer || self.fee_payer {
            let details = method_details.get_or_insert_with(|| serde_json::json!({}));
            if let Some(obj) = details.as_object_mut() {
                obj.insert("feePayer".to_string(), serde_json::json!(true));
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
        let encoded = crate::protocol::core::Base64UrlJson::from_typed(&request)?;

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

        Ok(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: "tempo".into(),
            intent: "session".into(),
            request: encoded,
            expires: expires.map(|s| s.to_string()),
            description: options.description.map(|s| s.to_string()),
            digest: None,
            opaque: None,
        })
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

        let request: crate::protocol::intents::SessionRequest =
            credential.challenge.request.decode().map_err(|e| {
                crate::protocol::traits::VerificationError::new(format!(
                    "Failed to decode session request: {}",
                    e
                ))
            })?;

        if let Some(bound) = &self.currency {
            if !request.currency.eq_ignore_ascii_case(bound) {
                return Err(VerificationError::with_code(
                    format!(
                        "Currency mismatch: credential has {} but server expects {}",
                        request.currency, bound
                    ),
                    crate::protocol::traits::ErrorCode::CredentialMismatch,
                ));
            }
        }

        if let Some(bound) = &self.recipient {
            let echoed = request.recipient.as_deref().unwrap_or("");
            if !echoed.eq_ignore_ascii_case(bound) {
                return Err(VerificationError::with_code(
                    format!(
                        "Recipient mismatch: credential has {} but server expects {}",
                        echoed, bound
                    ),
                    crate::protocol::traits::ErrorCode::CredentialMismatch,
                ));
            }
        }

        let receipt = session.verify_session(credential, &request).await?;

        // Call respond hook — management actions (open, topUp, close) may
        // return a response body that short-circuits normal request handling.
        let management_response = session.respond(credential, &receipt);

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
    /// let challenge = mpp.charge("1.00")?;
    /// ```
    pub fn create(builder: super::TempoBuilder) -> Result<Self> {
        let secret_key = builder
            .secret_key
            .or_else(|| std::env::var(SECRET_KEY_ENV_VAR).ok())
            .and_then(|value| {
                if value.trim().is_empty() {
                    None
                } else {
                    Some(value)
                }
            })
            .ok_or_else(|| {
                crate::error::MppError::InvalidConfig(format!(
                    "Missing secret key. Set {} environment variable or pass .secret_key(...).",
                    SECRET_KEY_ENV_VAR
                ))
            })?;

        let provider = super::tempo_provider(&builder.rpc_url)?;
        let mut method = crate::protocol::methods::tempo::ChargeMethod::new(provider);
        if let Some(signer) = builder.fee_payer_signer {
            method = method.with_fee_payer(signer);
        }

        // Resolve currency from chain_id when not explicitly set
        let currency = if builder.currency_explicit {
            builder.currency
        } else {
            use crate::protocol::methods::tempo::network::TempoNetwork;
            builder
                .chain_id
                .and_then(TempoNetwork::from_chain_id)
                .map(|n| n.default_currency().to_string())
                .unwrap_or_else(|| crate::protocol::methods::tempo::PATH_USD.to_string())
        };

        Ok(Self {
            method,
            session_method: None,
            realm: builder.realm,
            secret_key,
            currency: Some(currency),
            recipient: Some(builder.recipient),
            decimals: builder.decimals,
            fee_payer: builder.fee_payer,
            chain_id: builder.chain_id,
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

    /// Generate a Stripe charge challenge with additional options.
    ///
    /// Accepts [`StripeChargeOptions`](super::StripeChargeOptions) for description,
    /// external ID, expiration, and metadata.
    pub fn stripe_charge_with_options(
        &self,
        amount: &str,
        options: super::StripeChargeOptions<'_>,
    ) -> Result<PaymentChallenge> {
        use crate::protocol::core::Base64UrlJson;
        use time::{Duration, OffsetDateTime};

        use crate::protocol::methods::stripe::StripeMethodDetails;

        let base_units = super::parse_dollar_amount(amount, self.decimals)?;
        let currency = self.currency.as_deref().unwrap_or("usd");

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

        Ok(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: crate::protocol::methods::stripe::METHOD_NAME.into(),
            intent: crate::protocol::methods::stripe::INTENT_CHARGE.into(),
            request: encoded_request,
            expires: Some(expires),
            description: options.description.map(|s| s.to_string()),
            digest: None,
            opaque: None,
        })
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
    /// .secret_key("my-hmac-secret"))?;
    /// ```
    pub fn create_stripe(builder: super::StripeBuilder) -> Result<Self> {
        let secret_key = builder
            .hmac_secret_key
            .or_else(|| std::env::var(SECRET_KEY_ENV_VAR).ok())
            .and_then(|value| {
                if value.trim().is_empty() {
                    None
                } else {
                    Some(value)
                }
            })
            .ok_or_else(|| {
                crate::error::MppError::InvalidConfig(format!(
                    "Missing secret key. Set {} environment variable or pass .secret_key(...).",
                    SECRET_KEY_ENV_VAR
                ))
            })?;

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
            currency: Some(builder.currency),
            recipient: None,
            decimals: builder.decimals as u32,
            fee_payer: false,
            chain_id: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{ChallengeEcho, PaymentPayload};
    use crate::protocol::traits::ErrorCode;
    #[cfg(feature = "tempo")]
    use crate::server::{tempo, ChargeOptions, TempoConfig};
    use std::future::Future;

    #[derive(Clone)]
    struct MockMethod;

    #[allow(clippy::manual_async_fn)]
    impl ChargeMethod for MockMethod {
        fn method(&self) -> &str {
            "mock"
        }

        fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &ChargeRequest,
        ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
            async { Ok(Receipt::success("mock", "mock_ref")) }
        }
    }

    #[derive(Clone)]
    struct SuccessReceiptMethod;

    #[allow(clippy::manual_async_fn)]
    impl ChargeMethod for SuccessReceiptMethod {
        fn method(&self) -> &str {
            "mock"
        }

        fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &ChargeRequest,
        ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
            async { Ok(Receipt::success("mock", "0xabc123")) }
        }
    }

    #[derive(Clone)]
    struct FailedTransactionMethod;

    #[allow(clippy::manual_async_fn)]
    impl ChargeMethod for FailedTransactionMethod {
        fn method(&self) -> &str {
            "mock"
        }

        fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &ChargeRequest,
        ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
            async {
                Err(VerificationError::transaction_failed(
                    "Transaction reverted on-chain",
                ))
            }
        }
    }

    fn test_credential(secret_key: &str) -> PaymentCredential {
        let request = "eyJ0ZXN0IjoidmFsdWUifQ";
        let expires = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let id = {
            #[cfg(feature = "tempo")]
            {
                crate::protocol::methods::tempo::generate_challenge_id(
                    secret_key,
                    "api.example.com",
                    "mock",
                    "charge",
                    request,
                    Some(&expires),
                    None,
                    None,
                )
            }
            #[cfg(not(feature = "tempo"))]
            {
                "test-id".to_string()
            }
        };

        let echo = ChallengeEcho {
            id,
            realm: "api.example.com".into(),
            method: "mock".into(),
            intent: "charge".into(),
            request: crate::protocol::core::Base64UrlJson::from_raw(request),
            expires: Some(expires),
            digest: None,
            opaque: None,
        };
        PaymentCredential::new(echo, PaymentPayload::hash("0x123"))
    }

    fn test_request() -> ChargeRequest {
        ChargeRequest {
            amount: "1000".into(),
            currency: "0x123".into(),
            recipient: Some("0x456".into()),
            ..Default::default()
        }
    }

    #[test]
    fn test_mpp_creation() {
        let payment = Mpp::new(MockMethod, "api.example.com", "secret");
        assert_eq!(payment.realm(), "api.example.com");
        assert_eq!(payment.method_name(), "mock");
        assert!(payment.currency().is_none());
        assert!(payment.recipient().is_none());
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_challenge_generation() {
        let payment = Mpp::new(MockMethod, "api.example.com", "test-secret");
        let challenge = payment
            .charge_challenge(
                "1000000",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            )
            .unwrap();

        assert_eq!(challenge.realm, "api.example.com");
        assert_eq!(challenge.method.as_str(), "tempo");
        assert_eq!(challenge.intent.as_str(), "charge");
        assert_eq!(challenge.id.len(), 43);
    }

    #[tokio::test]
    async fn test_verify_returns_receipt_for_success() {
        let payment = Mpp::new(SuccessReceiptMethod, "api.example.com", "secret");
        let credential = test_credential("secret");
        let request = test_request();

        let result = payment.verify(&credential, &request).await;

        assert!(result.is_ok());
        let receipt = result.unwrap();
        assert!(receipt.is_success());
        assert_eq!(receipt.reference, "0xabc123");
    }

    #[tokio::test]
    async fn test_verify_returns_error_for_failed_transaction() {
        use crate::error::{MppError, PaymentError};
        use crate::protocol::traits::ErrorCode;

        let payment = Mpp::new(FailedTransactionMethod, "api.example.com", "secret");
        let credential = test_credential("secret");
        let request = test_request();

        let result = payment.verify(&credential, &request).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::TransactionFailed));
        assert!(err.message.contains("reverted"));

        let mpp_err: MppError = err.into();
        let problem = mpp_err.to_problem_details(None);
        assert_eq!(problem.status, 402);
    }

    #[cfg(feature = "tempo")]
    fn create_test_mpp() -> Mpp<crate::server::TempoChargeMethod<crate::server::TempoProvider>> {
        Mpp::create(
            tempo(TempoConfig {
                recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            })
            .secret_key("test-secret"),
        )
        .unwrap()
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_mpp_create() {
        let mpp = create_test_mpp();
        assert_eq!(mpp.realm(), "MPP Payment");
        // No chain_id set → unknown chain → defaults to pathUSD
        assert_eq!(
            mpp.currency(),
            Some("0x20c0000000000000000000000000000000000000")
        );
        assert_eq!(
            mpp.recipient(),
            Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2")
        );
        assert_eq!(mpp.decimals(), 6);
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_mpp_create_requires_secret_key() {
        struct EnvGuard(Option<String>);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                if let Some(value) = &self.0 {
                    unsafe { std::env::set_var(SECRET_KEY_ENV_VAR, value) };
                } else {
                    unsafe { std::env::remove_var(SECRET_KEY_ENV_VAR) };
                }
            }
        }

        let _guard = EnvGuard(std::env::var(SECRET_KEY_ENV_VAR).ok());
        unsafe { std::env::remove_var(SECRET_KEY_ENV_VAR) };

        let result = Mpp::create(tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        }));
        match result {
            Ok(_) => panic!("missing secret key should fail creation"),
            Err(err) => assert!(err.to_string().contains("Missing secret key")),
        }

        unsafe { std::env::set_var(SECRET_KEY_ENV_VAR, "   ") };
        let whitespace_env = Mpp::create(tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        }));
        match whitespace_env {
            Ok(_) => panic!("whitespace-only env secret key should fail creation"),
            Err(err) => assert!(err.to_string().contains("Missing secret key")),
        }

        let whitespace_builder = Mpp::create(
            tempo(TempoConfig {
                recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            })
            .secret_key(""),
        );
        match whitespace_builder {
            Ok(_) => panic!("empty builder secret key should fail creation"),
            Err(err) => assert!(err.to_string().contains("Missing secret key")),
        }
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_dollar_amount() {
        let mpp = create_test_mpp();

        let challenge = mpp.charge("0.10").unwrap();
        assert_eq!(challenge.method.as_str(), "tempo");
        assert_eq!(challenge.intent.as_str(), "charge");
        assert_eq!(challenge.realm, "MPP Payment");

        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(request.amount, "100000");
        assert_eq!(
            request.currency,
            "0x20c0000000000000000000000000000000000000"
        );
        assert_eq!(
            request.recipient,
            Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string())
        );
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_one_dollar() {
        let mpp = create_test_mpp();
        let challenge = mpp.charge("1").unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(request.amount, "1000000");
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_default_expires() {
        let mpp = create_test_mpp();
        let challenge = mpp.charge("1").unwrap();
        assert!(challenge.expires.is_some());
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_requires_bound_currency() {
        let payment = Mpp::new(MockMethod, "api.example.com", "secret");
        let result = payment.charge("1.00");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_credential_decodes_request() {
        let request = ChargeRequest {
            amount: "500000".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            ..Default::default()
        };
        let encoded = crate::protocol::core::Base64UrlJson::from_typed(&request).unwrap();
        let raw = encoded.raw().to_string();

        let secret = "test-secret";
        let expires = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let id = {
            #[cfg(feature = "tempo")]
            {
                crate::protocol::methods::tempo::generate_challenge_id(
                    secret,
                    "api.example.com",
                    "mock",
                    "charge",
                    &raw,
                    Some(&expires),
                    None,
                    None,
                )
            }
            #[cfg(not(feature = "tempo"))]
            {
                "test-id".to_string()
            }
        };

        let echo = ChallengeEcho {
            id,
            realm: "api.example.com".into(),
            method: "mock".into(),
            intent: "charge".into(),
            request: crate::protocol::core::Base64UrlJson::from_raw(raw),
            expires: Some(expires),
            digest: None,
            opaque: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));

        let payment = Mpp::new(SuccessReceiptMethod, "api.example.com", secret);
        let receipt = payment.verify_credential(&credential).await.unwrap();
        assert!(receipt.is_success());
        assert_eq!(receipt.reference, "0xabc123");
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_with_options() {
        let mpp = create_test_mpp();
        let challenge = mpp
            .charge_with_options(
                "5.50",
                ChargeOptions {
                    description: Some("API access fee"),
                    ..Default::default()
                },
            )
            .unwrap();

        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(request.amount, "5500000");
        assert_eq!(challenge.description, Some("API access fee".to_string()));
    }

    // ── Real HMAC challenge verification tests ─────────────────────────

    /// A mock ChargeMethod that always returns a success receipt, using
    /// the "tempo" method name so it matches challenges from create_test_mpp().
    #[derive(Clone)]
    struct TempoSuccessMethod;

    #[allow(clippy::manual_async_fn)]
    impl ChargeMethod for TempoSuccessMethod {
        fn method(&self) -> &str {
            "tempo"
        }

        fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &ChargeRequest,
        ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
            async { Ok(Receipt::success("tempo", "0xtxhash")) }
        }
    }

    /// Helper: build an Mpp with TempoSuccessMethod whose realm, secret_key,
    /// currency, recipient, and decimals match create_test_mpp().
    #[cfg(feature = "tempo")]
    fn create_hmac_test_mpp() -> Mpp<TempoSuccessMethod> {
        Mpp {
            method: TempoSuccessMethod,
            session_method: None,
            realm: "MPP Payment".into(),
            secret_key: "test-secret".into(),
            currency: Some("0x20c0000000000000000000000000000000000000".into()),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            decimals: DEFAULT_DECIMALS,
            fee_payer: false,
            chain_id: None,
        }
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_hmac_verify_happy_path() {
        let mpp = create_hmac_test_mpp();
        let challenge = mpp.charge("0.10").unwrap();

        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

        let receipt = mpp.verify_credential(&credential).await.unwrap();
        assert!(receipt.is_success());
        assert_eq!(receipt.reference, "0xtxhash");
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_hmac_tampered_request_rejected() {
        let mpp = create_hmac_test_mpp();
        let challenge = mpp.charge("0.10").unwrap();

        let mut echo = challenge.to_echo();
        // Tamper: replace the request with a different amount
        let tampered_request = ChargeRequest {
            amount: "999999".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            ..Default::default()
        };
        let encoded = crate::protocol::core::Base64UrlJson::from_typed(&tampered_request).unwrap();
        echo.request = encoded;

        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
        let result = mpp.verify_credential(&credential).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().message.contains("mismatch"),
            "expected HMAC mismatch error"
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_hmac_tampered_realm_ignored() {
        // The server recomputes the HMAC using its own realm (self.realm),
        // not the echoed realm from the credential. So tampering the echoed
        // realm has no effect on HMAC verification — the server is the
        // authority on its own realm. This is correct security behavior.
        let mpp = create_hmac_test_mpp();
        let challenge = mpp.charge("0.10").unwrap();

        let mut echo = challenge.to_echo();
        echo.realm = "evil.example.com".into();

        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
        let result = mpp.verify_credential(&credential).await;
        // Verification succeeds because the server uses its own realm for
        // HMAC recomputation, not the echoed one.
        assert!(
            result.is_ok(),
            "echoed realm is ignored by server HMAC check"
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_hmac_tampered_method_rejected() {
        let mpp = create_hmac_test_mpp();
        let challenge = mpp.charge("0.10").unwrap();

        let mut echo = challenge.to_echo();
        echo.method = "evil-method".into();

        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
        let result = mpp.verify_credential(&credential).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().message.contains("mismatch"),
            "expected HMAC mismatch error"
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_hmac_tampered_intent_rejected() {
        let mpp = create_hmac_test_mpp();
        let challenge = mpp.charge("0.10").unwrap();

        let mut echo = challenge.to_echo();
        echo.intent = "session".into();

        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
        let result = mpp.verify_credential(&credential).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().message.contains("mismatch"),
            "expected HMAC mismatch error"
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_hmac_charge_with_options_roundtrip() {
        let mpp = create_hmac_test_mpp();
        let challenge = mpp
            .charge_with_options(
                "2.50",
                ChargeOptions {
                    description: Some("Premium access"),
                    fee_payer: true,
                    ..Default::default()
                },
            )
            .unwrap();

        // Verify challenge fields
        assert_eq!(challenge.description, Some("Premium access".to_string()));
        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(request.amount, "2500000");
        let details = request.method_details.unwrap();
        assert_eq!(details["feePayer"], serde_json::json!(true));

        // Roundtrip: credential built from this challenge verifies
        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
        let receipt = mpp.verify_credential(&credential).await.unwrap();
        assert!(receipt.is_success());
    }

    // ── Mock SessionMethod for session verification tests ─────────────

    #[derive(Clone)]
    struct MockSessionMethod {
        receipt: Receipt,
        management_response: Option<serde_json::Value>,
    }

    impl MockSessionMethod {
        fn success() -> Self {
            Self {
                receipt: Receipt::success("tempo", "0xsession_ref"),
                management_response: None,
            }
        }

        fn with_management_response(mut self, resp: serde_json::Value) -> Self {
            self.management_response = Some(resp);
            self
        }
    }

    impl crate::protocol::traits::SessionMethod for MockSessionMethod {
        fn method(&self) -> &str {
            "tempo"
        }

        fn verify_session(
            &self,
            _credential: &PaymentCredential,
            _request: &crate::protocol::intents::SessionRequest,
        ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
            let receipt = self.receipt.clone();
            async move { Ok(receipt) }
        }

        fn respond(
            &self,
            _credential: &PaymentCredential,
            _receipt: &Receipt,
        ) -> Option<serde_json::Value> {
            self.management_response.clone()
        }
    }

    // ── Mock SessionMethod that always returns an error ─────────────────

    #[derive(Clone)]
    struct MockFailingSessionMethod {
        error: VerificationError,
    }

    impl MockFailingSessionMethod {
        fn with_error(code: ErrorCode, message: &str) -> Self {
            Self {
                error: VerificationError::with_code(message, code),
            }
        }
    }

    impl crate::protocol::traits::SessionMethod for MockFailingSessionMethod {
        fn method(&self) -> &str {
            "tempo"
        }

        fn verify_session(
            &self,
            _credential: &PaymentCredential,
            _request: &crate::protocol::intents::SessionRequest,
        ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
            let error = self.error.clone();
            async move { Err(error) }
        }

        fn respond(
            &self,
            _credential: &PaymentCredential,
            _receipt: &Receipt,
        ) -> Option<serde_json::Value> {
            None
        }
    }

    #[cfg(feature = "tempo")]
    fn create_session_test_mpp() -> Mpp<TempoSuccessMethod, MockSessionMethod> {
        Mpp {
            method: TempoSuccessMethod,
            session_method: Some(MockSessionMethod::success()),
            realm: "MPP Payment".into(),
            secret_key: "test-secret".into(),
            currency: Some("0x20c0000000000000000000000000000000000000".into()),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            decimals: DEFAULT_DECIMALS,
            fee_payer: false,
            chain_id: None,
        }
    }

    #[cfg(feature = "tempo")]
    fn make_session_credential(
        mpp: &Mpp<TempoSuccessMethod, MockSessionMethod>,
        payload: serde_json::Value,
    ) -> PaymentCredential {
        let challenge = mpp
            .session_challenge(
                "1000",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            )
            .unwrap();
        PaymentCredential::new(challenge.to_echo(), payload)
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_session_challenge_roundtrip() {
        let mpp = create_session_test_mpp();
        let challenge = mpp
            .session_challenge(
                "1000",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            )
            .unwrap();
        assert_eq!(challenge.method.as_str(), "tempo");
        assert_eq!(challenge.intent.as_str(), "session");
        assert!(!challenge.id.is_empty());
        assert!(
            challenge.expires.is_some(),
            "session challenge should have default expires"
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_session_happy_path() {
        let mpp = create_session_test_mpp();
        let credential = make_session_credential(
            &mpp,
            serde_json::json!({
                "action": "voucher",
                "channelId": "0xabc",
                "cumulativeAmount": "5000",
                "signature": "0xdef"
            }),
        );

        let result = mpp.verify_session(&credential).await;
        assert!(result.is_ok());
        let session_result = result.unwrap();
        assert!(session_result.receipt.is_success());
        assert_eq!(session_result.receipt.reference, "0xsession_ref");
        assert!(session_result.management_response.is_none());
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_session_management_response() {
        let mock_session = MockSessionMethod::success()
            .with_management_response(serde_json::json!({"status": "ok", "channelId": "0xabc"}));
        let mpp: Mpp<TempoSuccessMethod, MockSessionMethod> = Mpp {
            method: TempoSuccessMethod,
            session_method: Some(mock_session),
            realm: "MPP Payment".into(),
            secret_key: "test-secret".into(),
            currency: Some("0x20c0000000000000000000000000000000000000".into()),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            decimals: DEFAULT_DECIMALS,
            fee_payer: false,
            chain_id: None,
        };

        let challenge = mpp
            .session_challenge(
                "1000",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            )
            .unwrap();

        let echo = challenge.to_echo();
        let payload_json = serde_json::json!({
            "action": "open",
            "type": "transaction",
            "channelId": "0xabc",
            "transaction": "0x1234",
            "cumulativeAmount": "5000",
            "signature": "0xdef"
        });
        let credential = PaymentCredential::new(echo, payload_json);

        let result = mpp.verify_session(&credential).await;
        assert!(result.is_ok());
        let session_result = result.unwrap();
        assert!(session_result.management_response.is_some());
        let mgmt = session_result.management_response.unwrap();
        assert_eq!(mgmt["channelId"], "0xabc");
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_session_no_session_method() {
        let mpp: Mpp<TempoSuccessMethod, MockSessionMethod> = Mpp {
            method: TempoSuccessMethod,
            session_method: None,
            realm: "MPP Payment".into(),
            secret_key: "test-secret".into(),
            currency: Some("0x20c0000000000000000000000000000000000000".into()),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            decimals: DEFAULT_DECIMALS,
            fee_payer: false,
            chain_id: None,
        };

        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "MPP Payment".into(),
            method: "tempo".into(),
            intent: "session".into(),
            request: crate::protocol::core::Base64UrlJson::from_raw("eyJ0ZXN0IjoidmFsdWUifQ"),
            expires: None,
            digest: None,
            opaque: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));

        let result = mpp.verify_session(&credential).await;
        let err = result.unwrap_err();
        assert!(err.message.contains("No session method"));
        assert!(
            err.code.is_none(),
            "no-session-method should not have an error code"
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_session_hmac_mismatch() {
        let mpp = create_session_test_mpp();
        let challenge = mpp
            .session_challenge(
                "1000",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            )
            .unwrap();

        let mut echo = challenge.to_echo();
        let tampered = crate::protocol::intents::SessionRequest {
            amount: "999999".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            ..Default::default()
        };
        let encoded = crate::protocol::core::Base64UrlJson::from_typed(&tampered).unwrap();
        echo.request = encoded;

        let payload_json = serde_json::json!({
            "action": "voucher",
            "channelId": "0xabc",
            "cumulativeAmount": "5000",
            "signature": "0xdef"
        });
        let credential = PaymentCredential::new(echo, payload_json);

        let result = mpp.verify_session(&credential).await;
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_session_challenge_with_details() {
        let mpp = create_session_test_mpp();
        let challenge = mpp
            .session_challenge_with_details(
                "1000",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                super::super::SessionChallengeOptions {
                    unit_type: Some("second"),
                    suggested_deposit: Some("60000"),
                    fee_payer: true,
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(challenge.method.as_str(), "tempo");
        assert_eq!(challenge.intent.as_str(), "session");
        let request: crate::protocol::intents::SessionRequest = challenge.request.decode().unwrap();
        assert_eq!(request.amount, "1000");
        assert_eq!(request.unit_type.as_deref(), Some("second"));
        assert_eq!(request.suggested_deposit.as_deref(), Some("60000"));
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_session_method_returns_error() {
        let mock_session = MockFailingSessionMethod::with_error(
            ErrorCode::InsufficientBalance,
            "channel balance exhausted",
        );
        let mpp: Mpp<TempoSuccessMethod, MockFailingSessionMethod> = Mpp {
            method: TempoSuccessMethod,
            session_method: Some(mock_session),
            realm: "MPP Payment".into(),
            secret_key: "test-secret".into(),
            currency: Some("0x20c0000000000000000000000000000000000000".into()),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            decimals: DEFAULT_DECIMALS,
            fee_payer: false,
            chain_id: None,
        };

        let challenge = mpp
            .session_challenge(
                "1000",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            )
            .unwrap();

        let echo = challenge.to_echo();
        let payload_json = serde_json::json!({
            "action": "voucher",
            "channelId": "0xabc",
            "cumulativeAmount": "5000",
            "signature": "0xdef"
        });
        let credential = PaymentCredential::new(echo, payload_json);

        let result = mpp.verify_session(&credential).await;
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::InsufficientBalance));
        assert!(err.message.contains("channel balance exhausted"));
    }

    #[test]
    fn test_session_verify_result_debug() {
        let result = SessionVerifyResult {
            receipt: Receipt::success("tempo", "0xref"),
            management_response: Some(serde_json::json!({"status": "ok"})),
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("0xref"));
        assert!(debug.contains("status"));
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_expired_challenge_rejected() {
        let mpp = create_hmac_test_mpp();

        // Create a credential with an expired timestamp so the HMAC matches
        let past = (time::OffsetDateTime::now_utc() - time::Duration::minutes(10))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();

        let challenge = mpp
            .charge_with_options(
                "0.10",
                crate::server::ChargeOptions {
                    expires: Some(&past),
                    ..Default::default()
                },
            )
            .unwrap();
        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

        let result = mpp.verify_credential(&credential).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::Expired));
        assert!(
            err.message.contains("expired"),
            "expected expiry error, got: {}",
            err.message
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_non_expired_challenge_accepted() {
        let mpp = create_hmac_test_mpp();
        // Default charge generates an expires 5 minutes in the future
        let challenge = mpp.charge("0.10").unwrap();
        assert!(
            challenge.expires.is_some(),
            "charge should have default expires"
        );

        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

        let result = mpp.verify_credential(&credential).await;
        assert!(result.is_ok(), "non-expired challenge should be accepted");
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_malformed_expires_rejected() {
        let mpp = create_hmac_test_mpp();

        // Manually create a credential with a malformed expires that has a valid HMAC
        let challenge = mpp
            .charge_with_options(
                "0.10",
                crate::server::ChargeOptions {
                    expires: Some("not-a-timestamp"),
                    ..Default::default()
                },
            )
            .unwrap();
        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

        let result = mpp.verify_credential(&credential).await;
        assert!(result.is_err());
        assert!(
            result.unwrap_err().message.contains("Invalid expires"),
            "expected invalid expires error"
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_missing_expires_rejected() {
        let mpp = create_hmac_test_mpp();

        // Manually create a credential without expires — HMAC computed without expires
        let request = ChargeRequest {
            amount: "100000".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            ..Default::default()
        };
        let encoded = crate::protocol::core::Base64UrlJson::from_typed(&request).unwrap();
        let id = crate::protocol::methods::tempo::generate_challenge_id(
            "test-secret",
            "MPP Payment",
            "tempo",
            "charge",
            encoded.raw(),
            None,
            None,
            None,
        );

        let echo = ChallengeEcho {
            id,
            realm: "MPP Payment".into(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: encoded,
            expires: None,
            digest: None,
            opaque: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

        let result = mpp.verify_credential(&credential).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
        assert!(
            err.message.contains("missing required expires"),
            "expected missing expires error, got: {}",
            err.message
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_credential_with_wrong_amount_rejected() {
        let mpp = create_hmac_test_mpp();
        let challenge = mpp.charge("0.10").unwrap(); // 100000 base units

        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

        let wrong_request = ChargeRequest {
            amount: "999999999".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            ..Default::default()
        };
        let result = mpp
            .verify_credential_with_expected_request(&credential, &wrong_request)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
        assert!(
            err.message.contains("Amount mismatch"),
            "expected amount mismatch error, got: {}",
            err.message
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_credential_with_correct_request_accepted() {
        let mpp = create_hmac_test_mpp();
        let challenge = mpp.charge("0.10").unwrap(); // 100000 base units

        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

        let expected_request = ChargeRequest {
            amount: "100000".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            ..Default::default()
        };
        let result = mpp
            .verify_credential_with_expected_request(&credential, &expected_request)
            .await;
        assert!(result.is_ok(), "correct request should be accepted");
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_credential_with_wrong_recipient_rejected() {
        let mpp = create_hmac_test_mpp();
        let challenge = mpp.charge("0.10").unwrap();

        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

        let wrong_recipient = ChargeRequest {
            amount: "100000".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            recipient: Some("0x0000000000000000000000000000000000000001".into()),
            ..Default::default()
        };
        let result = mpp
            .verify_credential_with_expected_request(&credential, &wrong_recipient)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
        assert!(
            err.message.contains("Recipient mismatch"),
            "expected recipient mismatch error, got: {}",
            err.message
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_credential_with_split_routing_mismatch_rejected() {
        let mpp = create_hmac_test_mpp();

        let challenge = mpp
            .charge_challenge_with_options(
                &ChargeRequest {
                    amount: "100000".into(),
                    currency: "0x20c0000000000000000000000000000000000000".into(),
                    recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
                    method_details: Some(serde_json::json!({
                        "splits": [{
                            "amount": "10000",
                            "recipient": "0x0000000000000000000000000000000000000003"
                        }]
                    })),
                    ..Default::default()
                },
                None,
                None,
            )
            .unwrap();

        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

        let no_splits_request = ChargeRequest {
            amount: "100000".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            ..Default::default()
        };

        let result = mpp
            .verify_credential_with_expected_request(&credential, &no_splits_request)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
        assert!(
            err.message.contains("Tempo transfer routing mismatch"),
            "expected split routing mismatch error, got: {}",
            err.message
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_credential_with_memo_routing_mismatch_rejected() {
        let mpp = create_hmac_test_mpp();

        let challenge = mpp
            .charge_challenge_with_options(
                &ChargeRequest {
                    amount: "100000".into(),
                    currency: "0x20c0000000000000000000000000000000000000".into(),
                    recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
                    method_details: Some(serde_json::json!({
                        "memo": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                    })),
                    ..Default::default()
                },
                None,
                None,
            )
            .unwrap();

        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

        let request_without_memo = ChargeRequest {
            amount: "100000".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            ..Default::default()
        };

        let result = mpp
            .verify_credential_with_expected_request(&credential, &request_without_memo)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
        assert!(
            err.message.contains("Tempo transfer routing mismatch"),
            "expected memo routing mismatch error, got: {}",
            err.message
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_verify_session_expired_challenge_rejected() {
        let mpp = create_session_test_mpp();

        let past = (time::OffsetDateTime::now_utc() - time::Duration::minutes(10))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();

        let challenge = mpp
            .session_challenge_with_details(
                "1000",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                crate::server::SessionChallengeOptions {
                    expires: Some(&past),
                    ..Default::default()
                },
            )
            .unwrap();

        let echo = challenge.to_echo();
        let payload_json = serde_json::json!({
            "action": "voucher",
            "channelId": "0xabc",
            "cumulativeAmount": "5000",
            "signature": "0xdef"
        });
        let credential = PaymentCredential::new(echo, payload_json);

        let result = mpp.verify_session(&credential).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::Expired));
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_session_missing_expires_rejected() {
        let mpp = create_session_test_mpp();

        let request = crate::protocol::intents::SessionRequest {
            amount: "1000".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
            ..Default::default()
        };
        let encoded = crate::protocol::core::Base64UrlJson::from_typed(&request).unwrap();
        let id = crate::protocol::methods::tempo::generate_challenge_id(
            "test-secret",
            "MPP Payment",
            "tempo",
            "session",
            encoded.raw(),
            None,
            None,
            None,
        );

        let echo = ChallengeEcho {
            id,
            realm: "MPP Payment".into(),
            method: "tempo".into(),
            intent: "session".into(),
            request: encoded,
            expires: None,
            digest: None,
            opaque: None,
        };
        let credential = PaymentCredential::new(
            echo,
            serde_json::json!({
                "action": "voucher",
                "channelId": "0xabc",
                "cumulativeAmount": "5000",
                "signature": "0xdef"
            }),
        );

        let result = mpp.verify_session(&credential).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
        assert!(
            err.message.contains("missing required expires"),
            "expected missing expires error, got: {}",
            err.message
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_session_default_expires_accepted() {
        let mpp = create_session_test_mpp();

        let challenge = mpp
            .session_challenge(
                "1000",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            )
            .unwrap();
        assert!(
            challenge.expires.is_some(),
            "session_challenge should set default expires"
        );

        let echo = challenge.to_echo();
        let credential = PaymentCredential::new(
            echo,
            serde_json::json!({
                "action": "voucher",
                "channelId": "0xabc",
                "cumulativeAmount": "5000",
                "signature": "0xdef"
            }),
        );

        let result = mpp.verify_session(&credential).await;
        assert!(
            result.is_ok(),
            "session with default expires should be accepted"
        );
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_session_challenge_with_details_default_expires() {
        let mpp = create_session_test_mpp();

        let challenge = mpp
            .session_challenge_with_details(
                "1000",
                "0x20c0000000000000000000000000000000000000",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                Default::default(),
            )
            .unwrap();
        assert!(
            challenge.expires.is_some(),
            "session_challenge_with_details with default options should set default expires"
        );
    }

    // ==================== Stripe tests ====================

    #[cfg(feature = "stripe")]
    fn test_stripe_mpp() -> Mpp<crate::protocol::methods::stripe::method::ChargeMethod> {
        use crate::server::{stripe, StripeConfig};

        Mpp::create_stripe(
            stripe(StripeConfig {
                secret_key: "sk_test_mock",
                network_id: "test-net",
                payment_method_types: &["card"],
                currency: "usd",
                decimals: 2,
            })
            .secret_key("test-hmac-secret"),
        )
        .expect("failed to create stripe mpp")
    }

    #[cfg(feature = "stripe")]
    #[test]
    fn test_stripe_challenge_has_method_details() {
        let mpp = test_stripe_mpp();
        let challenge = mpp.stripe_charge("1.00").unwrap();

        let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
        let details = &request["methodDetails"];
        assert_eq!(details["networkId"], "test-net");
        assert_eq!(details["paymentMethodTypes"], serde_json::json!(["card"]));
        assert_eq!(challenge.method.as_str(), "stripe");
        assert_eq!(challenge.intent.as_str(), "charge");
    }

    #[cfg(feature = "stripe")]
    #[test]
    fn test_stripe_charge_with_options_description() {
        use crate::server::StripeChargeOptions;

        let mpp = test_stripe_mpp();
        let challenge = mpp
            .stripe_charge_with_options(
                "0.50",
                StripeChargeOptions {
                    description: Some("test desc"),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(challenge.description, Some("test desc".to_string()));
        let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
        assert_eq!(request["description"], "test desc");
    }

    #[cfg(feature = "stripe")]
    #[test]
    fn test_stripe_charge_with_options_external_id() {
        use crate::server::StripeChargeOptions;

        let mpp = test_stripe_mpp();
        let challenge = mpp
            .stripe_charge_with_options(
                "0.50",
                StripeChargeOptions {
                    external_id: Some("order-42"),
                    ..Default::default()
                },
            )
            .unwrap();

        let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
        assert_eq!(request["externalId"], "order-42");
    }

    #[cfg(feature = "stripe")]
    #[test]
    fn test_stripe_charge_with_options_metadata() {
        use crate::server::StripeChargeOptions;

        let mpp = test_stripe_mpp();
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("key1".to_string(), "val1".to_string());

        let challenge = mpp
            .stripe_charge_with_options(
                "0.50",
                StripeChargeOptions {
                    metadata: Some(&metadata),
                    ..Default::default()
                },
            )
            .unwrap();

        let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
        assert_eq!(request["methodDetails"]["metadata"]["key1"], "val1");
    }

    #[cfg(feature = "stripe")]
    #[test]
    fn test_stripe_charge_with_options_custom_expires() {
        use crate::server::StripeChargeOptions;

        let mpp = test_stripe_mpp();
        let challenge = mpp
            .stripe_charge_with_options(
                "0.50",
                StripeChargeOptions {
                    expires: Some("2099-01-01T00:00:00Z"),
                    ..Default::default()
                },
            )
            .unwrap();

        assert_eq!(challenge.expires, Some("2099-01-01T00:00:00Z".to_string()));
    }

    #[cfg(feature = "stripe")]
    #[test]
    fn test_stripe_charge_delegates_to_with_options() {
        let mpp = test_stripe_mpp();
        let challenge = mpp.stripe_charge("0.10").unwrap();

        let request: serde_json::Value = challenge.request.decode_value().expect("decode request");
        assert!(request["methodDetails"].is_object());
        assert!(challenge.description.is_none());
    }
}
