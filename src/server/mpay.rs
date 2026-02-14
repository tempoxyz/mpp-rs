//! Payment handler that binds method, realm, and secret_key.
//!
//! This module provides the [`Mpay`] struct which wraps a payment method
//! with server configuration for stateless challenge verification.
//!
//! # Example (simple API)
//!
//! ```ignore
//! use mpay::server::{Mpay, tempo};
//!
//! let mpay = Mpay::create(tempo(mpay::server::TempoConfig {
//!     currency: "0x20c0000000000000000000000000000000000000",
//!     recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
//! }))?;
//!
//! let challenge = mpay.charge("0.10")?;
//! ```

#[cfg(feature = "tempo")]
use crate::error::Result;
#[cfg(feature = "tempo")]
use crate::protocol::core::PaymentChallenge;
use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod, VerificationError};

const SECRET_KEY_ENV_VAR: &str = "MPAY_SECRET_KEY";
const DEFAULT_DECIMALS: u32 = 6;

/// Result of session verification, including optional management response.
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
/// use mpay::server::{Mpay, tempo, TempoConfig};
///
/// let mpay = Mpay::create(tempo(TempoConfig {
///     currency: "0x20c0000000000000000000000000000000000000",
///     recipient: "0xabc...123",
/// }))?;
///
/// // Charge $0.10 — currency, recipient, realm, secret, expires all handled
/// let challenge = mpay.charge("0.10")?;
/// ```
///
/// # Advanced API
///
/// ```ignore
/// use mpay::server::{Mpay, tempo_provider, TempoChargeMethod};
///
/// let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
/// let method = TempoChargeMethod::new(provider);
/// let payment = Mpay::new(method, "api.example.com", "my-server-secret");
///
/// let challenge = payment.charge_challenge("1000000", "0x...", "0x...")?;
/// ```
#[derive(Clone)]
pub struct Mpay<M, S = ()> {
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

impl<M> Mpay<M, ()>
where
    M: ChargeMethod,
{
    /// Create a new payment handler (advanced API).
    ///
    /// For a simpler API, use [`Mpay::create()`] with [`tempo()`](super::tempo).
    pub fn new(method: M, realm: impl Into<String>, secret_key: impl Into<String>) -> Mpay<M, ()> {
        Mpay {
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

impl<M, S> Mpay<M, S>
where
    M: ChargeMethod,
{
    /// Add a session method to this payment handler.
    pub fn with_session_method<S2>(self, session_method: S2) -> Mpay<M, S2> {
        Mpay {
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

    #[cfg(feature = "tempo")]
    fn require_bound_config(&self) -> Result<(&str, &str)> {
        let currency = self.currency.as_deref().ok_or_else(|| {
            crate::error::MppError::InvalidConfig(
                "currency not configured — use Mpay::create() or set currency".into(),
            )
        })?;
        let recipient = self.recipient.as_deref().ok_or_else(|| {
            crate::error::MppError::InvalidConfig(
                "recipient not configured — use Mpay::create() or set recipient".into(),
            )
        })?;
        Ok((currency, recipient))
    }

    /// Generate a charge challenge for a dollar amount.
    ///
    /// Requires currency and recipient to be bound (via [`Mpay::create()`]).
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
    /// let challenge = mpay.charge("0.10")?;
    /// ```
    #[cfg(feature = "tempo")]
    pub fn charge(&self, amount: &str) -> Result<PaymentChallenge> {
        self.charge_with_options(amount, super::ChargeOptions::default())
    }

    /// Generate a charge challenge with a dollar amount and additional options.
    ///
    /// Requires currency and recipient to be bound (via [`Mpay::create()`]).
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
        let request: ChargeRequest =
            crate::protocol::core::Base64UrlJson::from_raw(credential.challenge.request.clone())
                .decode()
                .map_err(|e| VerificationError::new(format!("Failed to decode request: {}", e)))?;
        self.verify(credential, &request).await
    }

    /// Verify a charge credential with an explicit request.
    pub async fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        #[cfg(feature = "tempo")]
        {
            let expected_id = crate::protocol::methods::tempo::generate_challenge_id(
                &self.secret_key,
                &self.realm,
                credential.challenge.method.as_str(),
                credential.challenge.intent.as_str(),
                &credential.challenge.request,
                credential.challenge.expires.as_deref(),
                credential.challenge.digest.as_deref(),
            );

            if credential.challenge.id != expected_id {
                return Err(VerificationError::new(
                    "Challenge ID mismatch - not issued by this server",
                ));
            }
        }

        let receipt = self.method.verify(credential, request).await?;

        Ok(receipt)
    }
}

impl<M, S> Mpay<M, S>
where
    M: ChargeMethod,
    S: crate::protocol::traits::SessionMethod,
{
    /// Generate a session challenge.
    #[cfg(feature = "tempo")]
    pub fn session_challenge(
        &self,
        amount: &str,
        unit_type: &str,
        currency: &str,
        recipient: &str,
    ) -> crate::error::Result<PaymentChallenge> {
        use crate::protocol::intents::SessionRequest;

        let request = SessionRequest {
            amount: amount.to_string(),
            unit_type: unit_type.to_string(),
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            ..Default::default()
        };
        let encoded = crate::protocol::core::Base64UrlJson::from_typed(&request)?;

        let id = crate::protocol::methods::tempo::generate_challenge_id(
            &self.secret_key,
            &self.realm,
            "tempo",
            "session",
            encoded.raw(),
            None,
            None,
        );

        Ok(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: "tempo".into(),
            intent: "session".into(),
            request: encoded,
            expires: None,
            description: None,
            digest: None,
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
    /// let challenge = mpay.session_challenge_with_details(
    ///     "1000",
    ///     "second",
    ///     "0x20c0...",
    ///     "0x742d...",
    ///     SessionChallengeOptions {
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
        unit_type: &str,
        currency: &str,
        recipient: &str,
        options: super::SessionChallengeOptions<'_>,
    ) -> crate::error::Result<PaymentChallenge> {
        use crate::protocol::intents::SessionRequest;

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
            unit_type: unit_type.to_string(),
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            suggested_deposit: options.suggested_deposit.map(|s| s.to_string()),
            method_details,
        };
        let encoded = crate::protocol::core::Base64UrlJson::from_typed(&request)?;

        let id = crate::protocol::methods::tempo::generate_challenge_id(
            &self.secret_key,
            &self.realm,
            "tempo",
            "session",
            encoded.raw(),
            options.expires,
            None,
        );

        Ok(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: "tempo".into(),
            intent: "session".into(),
            request: encoded,
            expires: options.expires.map(|s| s.to_string()),
            description: options.description.map(|s| s.to_string()),
            digest: None,
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

        // Verify HMAC
        #[cfg(feature = "tempo")]
        {
            let expected_id = crate::protocol::methods::tempo::generate_challenge_id(
                &self.secret_key,
                &self.realm,
                credential.challenge.method.as_str(),
                credential.challenge.intent.as_str(),
                &credential.challenge.request,
                credential.challenge.expires.as_deref(),
                credential.challenge.digest.as_deref(),
            );
            if credential.challenge.id != expected_id {
                return Err(crate::protocol::traits::VerificationError::with_code(
                    "Challenge ID mismatch",
                    crate::protocol::traits::ErrorCode::CredentialMismatch,
                ));
            }
        }

        let request: crate::protocol::intents::SessionRequest =
            crate::protocol::core::Base64UrlJson::from_raw(credential.challenge.request.clone())
                .decode()
                .map_err(|e| {
                    crate::protocol::traits::VerificationError::new(format!(
                        "Failed to decode session request: {}",
                        e
                    ))
                })?;

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

/// Tempo-specific `create` constructor for [`Mpay`].
#[cfg(feature = "tempo")]
impl Mpay<super::TempoChargeMethod<super::TempoProvider>> {
    /// Create a payment handler from a [`TempoBuilder`](super::TempoBuilder).
    ///
    /// This is the simplest way to set up server-side payments.
    /// Currency and recipient are bound at creation time, so
    /// [`charge()`](Mpay::charge) only needs the dollar amount.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use mpay::server::{Mpay, tempo, TempoConfig};
    ///
    /// let mpay = Mpay::create(tempo(TempoConfig {
    ///     currency: "0x20c0000000000000000000000000000000000000",
    ///     recipient: "0xabc...123",
    /// }))?;
    ///
    /// let challenge = mpay.charge("1.00")?;
    /// ```
    pub fn create(builder: super::TempoBuilder) -> Result<Self> {
        let secret_key = builder.secret_key.unwrap_or_else(|| {
            std::env::var(SECRET_KEY_ENV_VAR).unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())
        });

        let provider = super::tempo_provider(&builder.rpc_url)?;
        let mut method = crate::protocol::methods::tempo::ChargeMethod::new(provider);
        if let Some(signer) = builder.fee_payer_signer {
            method = method.with_fee_payer(signer);
        }

        Ok(Self {
            method,
            session_method: None,
            realm: builder.realm,
            secret_key,
            currency: Some(builder.currency),
            recipient: Some(builder.recipient),
            decimals: builder.decimals,
            fee_payer: builder.fee_payer,
            chain_id: builder.chain_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{ChallengeEcho, PaymentPayload};
    #[cfg(feature = "tempo")]
    use crate::server::{tempo, ChargeOptions, TempoConfig};
    use std::future::Future;

    #[derive(Clone)]
    struct MockMethod;

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
        let id = {
            #[cfg(feature = "tempo")]
            {
                crate::protocol::methods::tempo::generate_challenge_id(
                    secret_key,
                    "api.example.com",
                    "mock",
                    "charge",
                    request,
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
            request: request.into(),
            expires: None,
            digest: None,
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
    fn test_mpay_creation() {
        let payment = Mpay::new(MockMethod, "api.example.com", "secret");
        assert_eq!(payment.realm(), "api.example.com");
        assert_eq!(payment.method_name(), "mock");
        assert!(payment.currency().is_none());
        assert!(payment.recipient().is_none());
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_challenge_generation() {
        let payment = Mpay::new(MockMethod, "api.example.com", "test-secret");
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
        let payment = Mpay::new(SuccessReceiptMethod, "api.example.com", "secret");
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

        let payment = Mpay::new(FailedTransactionMethod, "api.example.com", "secret");
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
    fn create_test_mpay() -> Mpay<crate::server::TempoChargeMethod<crate::server::TempoProvider>> {
        Mpay::create(
            tempo(TempoConfig {
                currency: "0x20c0000000000000000000000000000000000000",
                recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            })
            .secret_key("test-secret"),
        )
        .unwrap()
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_mpay_create() {
        let mpay = create_test_mpay();
        assert_eq!(mpay.realm(), "MPP Payment");
        assert_eq!(
            mpay.currency(),
            Some("0x20c0000000000000000000000000000000000000")
        );
        assert_eq!(
            mpay.recipient(),
            Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2")
        );
        assert_eq!(mpay.decimals(), 6);
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_dollar_amount() {
        let mpay = create_test_mpay();

        let challenge = mpay.charge("0.10").unwrap();
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
        let mpay = create_test_mpay();
        let challenge = mpay.charge("1").unwrap();
        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(request.amount, "1000000");
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_default_expires() {
        let mpay = create_test_mpay();
        let challenge = mpay.charge("1").unwrap();
        assert!(challenge.expires.is_some());
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_requires_bound_currency() {
        let payment = Mpay::new(MockMethod, "api.example.com", "secret");
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
        let id = {
            #[cfg(feature = "tempo")]
            {
                crate::protocol::methods::tempo::generate_challenge_id(
                    secret,
                    "api.example.com",
                    "mock",
                    "charge",
                    &raw,
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
            request: raw,
            expires: None,
            digest: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));

        let payment = Mpay::new(SuccessReceiptMethod, "api.example.com", secret);
        let receipt = payment.verify_credential(&credential).await.unwrap();
        assert!(receipt.is_success());
        assert_eq!(receipt.reference, "0xabc123");
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_with_options() {
        let mpay = create_test_mpay();
        let challenge = mpay
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
}
