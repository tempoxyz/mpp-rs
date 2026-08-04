//! ChargeMethod trait for server-side one-time payment verification.
//!
//! Implementations verify payment credentials against a typed [`ChargeRequest`],
//! ensuring consistent field names (amount, currency, recipient) across all
//! payment methods.

use crate::protocol::core::{ChallengeEcho, IntentName, MethodName, PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::VerificationError;
use std::future::Future;

/// Result of non-mutating charge credential validation.
///
/// Validation proves that the credential is structurally and method-specifically
/// acceptable without consuming replay state or performing the terminal payment
/// operation. Use the server acceptance APIs to re-validate and accept payment.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChargeValidation {
    /// Challenge echoed by the credential.
    pub challenge: ChallengeEcho,
    /// Validated credential.
    pub credential: PaymentCredential,
    /// Method-specific validation details.
    pub details: serde_json::Value,
    /// Validated payment intent.
    pub intent: IntentName,
    /// Validated payment method.
    pub method: MethodName,
    /// Parsed charge request.
    pub request: ChargeRequest,
    /// Optional payer identity.
    pub source: Option<String>,
}

impl ChargeValidation {
    /// Build a validation result from a credential and parsed request.
    pub fn new(
        credential: &PaymentCredential,
        request: &ChargeRequest,
        details: serde_json::Value,
    ) -> Self {
        Self {
            challenge: credential.challenge.clone(),
            credential: credential.clone(),
            details,
            intent: credential.challenge.intent.clone(),
            method: credential.challenge.method.clone(),
            request: request.clone(),
            source: credential.source.clone(),
        }
    }
}

/// Trait for payment methods that implement the "charge" intent.
///
/// ChargeMethod verifies one-time payment credentials on the server side.
/// All implementations use the same [`ChargeRequest`] schema, enforcing
/// consistent field names per the IETF spec.
///
/// # Intent = Schema, Method = Implementation
///
/// - **Intent** ("charge"): Defines the shared schema (`ChargeRequest`)
/// - **Method** (e.g., "tempo"): Implements verification for that schema
///
/// This design allows clients to parse any charge request consistently
/// while servers use method-specific verification logic.
///
/// # Examples
///
/// ## Implementing for a custom payment network
///
/// ```
/// use mpp::protocol::traits::{ChargeMethod, VerificationError};
/// use mpp::protocol::core::{PaymentCredential, Receipt};
/// use mpp::protocol::intents::ChargeRequest;
/// use std::future::Future;
///
/// #[derive(Clone)]
/// struct StripeChargeMethod {
///     api_key: String,
/// }
///
/// impl ChargeMethod for StripeChargeMethod {
///     fn method(&self) -> &str {
///         "stripe"
///     }
///
///     fn verify(
///         &self,
///         credential: &PaymentCredential,
///         request: &ChargeRequest,
///     ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
///         let credential = credential.clone();
///         let request = request.clone();
///         async move {
///             // Verify with Stripe API using request.amount, request.currency, etc.
///             Ok(Receipt::success("stripe", "pi_xxx"))
///         }
///     }
/// }
/// ```
///
/// ## Using with Axum
///
/// ```ignore
/// use axum::{extract::State, response::IntoResponse};
/// use mpp::protocol::traits::ChargeMethod;
///
/// async fn verify_payment<M: ChargeMethod>(
///     State(method): State<M>,
///     credential: PaymentCredential,
///     request: ChargeRequest,
/// ) -> impl IntoResponse {
///     match method.verify(&credential, &request).await {
///         Ok(receipt) => (StatusCode::OK, receipt.to_header()),
///         Err(e) => (StatusCode::PAYMENT_REQUIRED, e.to_string()),
///     }
/// }
/// ```
pub trait ChargeMethod: Clone + Send + Sync {
    /// Payment method identifier (e.g., "tempo", "stripe", "base").
    ///
    /// This should match the `method` field in payment challenges.
    fn method(&self) -> &str;

    /// Transform a charge request before challenge creation.
    ///
    /// This hook is called during **challenge creation only** (when `credential` is `None`).
    /// It allows methods to apply defaults and normalize the request before it gets
    /// encoded into the challenge. The credential parameter is provided for future
    /// extensibility but should typically be `None` at call sites.
    ///
    /// **Important**: This must be a fast, synchronous, deterministic operation.
    /// Do not perform network I/O here. Any async operations should happen in
    /// the method constructor or in validation/broadcast hooks.
    ///
    /// # Arguments
    ///
    /// * `request` - The charge request to transform
    /// * `credential` - Always `None` during challenge creation
    ///
    /// # Returns
    ///
    /// The transformed request. Default implementation returns the request unchanged.
    ///
    /// # Example
    ///
    /// ```ignore
    /// fn prepare_request(
    ///     &self,
    ///     request: ChargeRequest,
    ///     _credential: Option<&PaymentCredential>,
    /// ) -> ChargeRequest {
    ///     let mut req = request;
    ///     if req.currency.is_empty() {
    ///         req.currency = self.default_currency.clone();
    ///     }
    ///     if req.recipient.is_none() {
    ///         req.recipient = Some(self.default_recipient.clone());
    ///     }
    ///     req
    /// }
    /// ```
    fn prepare_request(
        &self,
        request: ChargeRequest,
        _credential: Option<&PaymentCredential>,
    ) -> ChargeRequest {
        request
    }

    /// Whether this method supports non-mutating validation.
    ///
    /// Existing implementations default to the legacy combined verification
    /// lifecycle. Methods overriding [`Self::validate`] must return `true` so
    /// server acceptance paths validate before broadcasting.
    fn supports_validation(&self) -> bool {
        false
    }

    /// Validate a credential without consuming or broadcasting it.
    ///
    /// This is an advisory pre-check. Implementations must not reserve replay
    /// keys, sign fee-payer transactions, broadcast, or otherwise mutate payment
    /// state. The default reports that validation is unsupported.
    fn validate(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> impl Future<Output = Result<ChargeValidation, VerificationError>> + Send {
        let method = self.method().to_string();
        async move {
            Err(VerificationError::new(format!(
                "{method}/charge does not support non-mutating credential validation"
            )))
        }
    }

    /// Perform the terminal payment operation.
    ///
    /// [`crate::server::Mpp`] calls [`Self::validate`] first for split-lifecycle
    /// methods. New methods should override this hook. The compatibility default
    /// invokes the legacy combined [`Self::verify`] hook.
    fn broadcast(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        self.verify(credential, request)
    }

    /// Legacy combined verification hook.
    ///
    /// Existing methods may implement only this hook. Split-lifecycle methods
    /// should preserve it for direct consumers by calling validation followed
    /// by broadcast, while server acceptance paths use those hooks directly.
    ///
    /// # Arguments
    ///
    /// * `credential` - The payment credential from the client
    /// * `request` - The typed charge request (parsed from challenge)
    ///
    /// # Returns
    ///
    /// * `Ok(Receipt)` - Payment was verified successfully
    /// * `Err(VerificationError)` - Verification failed
    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{ChallengeEcho, PaymentPayload};

    #[derive(Clone)]
    struct TestChargeMethod;

    #[allow(clippy::manual_async_fn)]
    impl ChargeMethod for TestChargeMethod {
        fn method(&self) -> &str {
            "test"
        }

        fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &ChargeRequest,
        ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
            async { Ok(Receipt::success("test", "test_ref")) }
        }
    }

    #[test]
    fn test_charge_method_name() {
        let method = TestChargeMethod;
        assert_eq!(method.method(), "test");
    }

    #[test]
    fn test_charge_method_prepare_request_defaults_to_identity() {
        let method = TestChargeMethod;
        let request = ChargeRequest {
            amount: "100".into(),
            currency: "USD".into(),
            ..Default::default()
        };

        let prepared = method.prepare_request(request.clone(), None);

        assert_eq!(prepared.amount, request.amount);
        assert_eq!(prepared.currency, request.currency);
    }

    #[tokio::test]
    async fn test_charge_method_verify() {
        let method = TestChargeMethod;
        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "test.com".into(),
            method: "test".into(),
            intent: "charge".into(),
            request: crate::protocol::core::Base64UrlJson::from_raw("eyJ0ZXN0IjoidmFsdWUifQ"),
            expires: None,
            digest: None,
            opaque: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));
        let request = ChargeRequest {
            amount: "1000".into(),
            currency: "usd".into(),
            ..Default::default()
        };

        let result = method.verify(&credential, &request).await;
        assert!(result.is_ok());
        let receipt = result.unwrap();
        assert_eq!(receipt.reference, "test_ref");
    }

    #[tokio::test]
    async fn test_charge_method_broadcast_falls_back_to_legacy_verify() {
        let method = TestChargeMethod;
        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "test.com".into(),
            method: "test".into(),
            intent: "charge".into(),
            request: crate::protocol::core::Base64UrlJson::from_raw("e30"),
            expires: None,
            digest: None,
            opaque: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));

        let receipt = method
            .broadcast(&credential, &ChargeRequest::default())
            .await
            .unwrap();

        assert_eq!(receipt.reference, "test_ref");
    }

    #[tokio::test]
    async fn test_legacy_charge_method_reports_validation_unsupported() {
        let method = TestChargeMethod;
        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "test.com".into(),
            method: "test".into(),
            intent: "charge".into(),
            request: crate::protocol::core::Base64UrlJson::from_raw("e30"),
            expires: None,
            digest: None,
            opaque: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));

        let error = method
            .validate(&credential, &ChargeRequest::default())
            .await
            .unwrap_err();

        assert!(error.message.contains("test/charge"));
        assert!(error.message.contains("does not support non-mutating"));
    }

    #[test]
    fn test_charge_validation_serializes_public_contract() {
        let request = ChargeRequest {
            amount: "100".into(),
            currency: "USD".into(),
            ..Default::default()
        };
        let credential = PaymentCredential::with_source(
            ChallengeEcho {
                id: "challenge".into(),
                realm: "test.com".into(),
                method: "test".into(),
                intent: "charge".into(),
                request: crate::protocol::core::Base64UrlJson::from_typed(&request).unwrap(),
                expires: None,
                digest: None,
                opaque: None,
            },
            "did:example:payer",
            PaymentPayload::hash("0x123"),
        );

        let value = serde_json::to_value(ChargeValidation::new(
            &credential,
            &request,
            serde_json::json!({ "mode": "test" }),
        ))
        .unwrap();

        assert_eq!(value["challenge"]["id"], "challenge");
        assert_eq!(value["credential"]["source"], "did:example:payer");
        assert_eq!(value["details"]["mode"], "test");
        assert_eq!(value["intent"], "charge");
        assert_eq!(value["method"], "test");
        assert_eq!(value["request"]["amount"], "100");
        assert_eq!(value["source"], "did:example:payer");
    }
}
