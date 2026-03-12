//! SessionMethod trait for server-side session payment verification.
//!
//! Implementations verify session payment credentials against a typed [`SessionRequest`],
//! ensuring consistent field names (amount, unit_type, currency, recipient) across all
//! payment methods.

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::SessionRequest;
use crate::protocol::traits::VerificationError;
use std::future::Future;

/// Trait for payment methods that implement the "session" intent.
///
/// SessionMethod verifies session (pay-as-you-go) payment credentials
/// on the server side. All implementations use the same [`SessionRequest`] schema,
/// enforcing consistent field names per the IETF spec.
///
/// # Intent = Schema, Method = Implementation
///
/// - **Intent** ("session"): Defines the shared schema (`SessionRequest`)
/// - **Method** (e.g., "tempo"): Implements verification for that schema
///
/// # Examples
///
/// ## Implementing for a custom payment network
///
/// ```
/// use mpp::protocol::traits::{SessionMethod, VerificationError};
/// use mpp::protocol::core::{PaymentCredential, Receipt};
/// use mpp::protocol::intents::SessionRequest;
/// use std::future::Future;
///
/// #[derive(Clone)]
/// struct StubSessionMethod;
///
/// impl SessionMethod for StubSessionMethod {
///     fn method(&self) -> &str {
///         "stub"
///     }
///
///     fn verify_session(
///         &self,
///         credential: &PaymentCredential,
///         request: &SessionRequest,
///     ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
///         let credential = credential.clone();
///         let request = request.clone();
///         async move {
///             Err(VerificationError::new("not implemented"))
///         }
///     }
/// }
/// ```
pub trait SessionMethod: Clone + Send + Sync {
    /// Payment method identifier (e.g., "tempo", "stripe", "base").
    ///
    /// This should match the `method` field in payment challenges.
    fn method(&self) -> &str;

    /// Verify a session credential against the typed request.
    ///
    /// # Arguments
    ///
    /// * `credential` - The payment credential from the client
    /// * `request` - The typed session request (parsed from challenge)
    ///
    /// # Returns
    ///
    /// * `Ok(Receipt)` - Payment was verified successfully
    /// * `Err(VerificationError)` - Verification failed
    fn verify_session(
        &self,
        credential: &PaymentCredential,
        request: &SessionRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send;

    /// Return method-specific details to populate in session challenges.
    ///
    /// The default implementation returns `None`. Implementations like
    /// Tempo's `SessionMethod` override this to provide `escrowContract`,
    /// `chainId`, `minVoucherDelta`, etc.
    fn challenge_method_details(&self) -> Option<serde_json::Value> {
        None
    }

    /// Optional respond hook called after successful verification.
    ///
    /// If this returns `Some(response_body)`, the request is treated as a
    /// management action (e.g., channel open, top-up, close) and the caller
    /// should return the response directly with the receipt attached.
    /// If `None`, the caller proceeds with its normal response handling.
    ///
    /// This mirrors the TypeScript SDK's `RespondFn` pattern where management
    /// responses short-circuit the normal request flow.
    ///
    /// # Arguments
    ///
    /// * `credential` - The verified payment credential
    /// * `receipt` - The receipt from successful verification
    ///
    /// # Returns
    ///
    /// * `Some(serde_json::Value)` - Management response body (caller should return 200/204)
    /// * `None` - No management response; caller handles response normally
    fn respond(
        &self,
        _credential: &PaymentCredential,
        _receipt: &Receipt,
    ) -> Option<serde_json::Value> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{ChallengeEcho, PaymentPayload};

    #[derive(Clone)]
    struct TestSessionMethod;

    #[allow(clippy::manual_async_fn)]
    impl SessionMethod for TestSessionMethod {
        fn method(&self) -> &str {
            "test"
        }

        fn verify_session(
            &self,
            _credential: &PaymentCredential,
            _request: &SessionRequest,
        ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
            async { Ok(Receipt::success("test", "test_ref")) }
        }
    }

    #[test]
    fn test_session_method_name() {
        let method = TestSessionMethod;
        assert_eq!(method.method(), "test");
    }

    #[tokio::test]
    async fn test_session_method_verify() {
        let method = TestSessionMethod;
        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "test.com".into(),
            method: "test".into(),
            intent: "session".into(),
            request: crate::protocol::core::Base64UrlJson::from_raw("eyJ0ZXN0IjoidmFsdWUifQ"),
            expires: None,
            digest: None,
            opaque: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));
        let request = SessionRequest {
            amount: "1000".into(),
            unit_type: Some("second".into()),
            currency: "usd".into(),
            ..Default::default()
        };

        let result = method.verify_session(&credential, &request).await;
        assert!(result.is_ok());
        let receipt = result.unwrap();
        assert_eq!(receipt.reference, "test_ref");
    }
}
