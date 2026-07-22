//! ChargeMethod trait for server-side one-time payment verification.
//!
//! Implementations verify payment credentials against a typed [`ChargeRequest`],
//! ensuring consistent field names (amount, currency, recipient) across all
//! payment methods.

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::VerificationError;
use std::future::Future;

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
    /// the method constructor or in `verify()`.
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

    /// Verify a charge credential against the typed request.
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
}
