//! StreamMethod trait for server-side streaming payment verification.
//!
//! Implementations verify stream payment credentials against a typed [`StreamRequest`],
//! ensuring consistent field names (amount, currency, recipient, unitType) across all
//! payment methods.

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::StreamRequest;
use crate::protocol::traits::VerificationError;
use std::future::Future;

/// Trait for payment methods that implement the "stream" intent.
///
/// StreamMethod verifies streaming payment credentials on the server side.
/// Stream credentials use a discriminated union on `action` (open, topUp, voucher, close)
/// to manage payment channels.
///
/// # Intent = Schema, Method = Implementation
///
/// - **Intent** ("stream"): Defines the shared schema (`StreamRequest`)
/// - **Method** (e.g., "tempo"): Implements verification for that schema
pub trait StreamMethod: Clone + Send + Sync {
    /// Payment method identifier (e.g., "tempo").
    fn method(&self) -> &str;

    /// Transform a stream request before challenge creation.
    ///
    /// Default implementation returns the request unchanged.
    fn prepare_request(
        &self,
        request: StreamRequest,
        _credential: Option<&PaymentCredential>,
    ) -> StreamRequest {
        request
    }

    /// Verify a stream credential against the typed request.
    ///
    /// The credential's `raw_payload` contains the full JSON payload
    /// which should be parsed as a `StreamCredentialPayload` (or equivalent).
    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &StreamRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{ChallengeEcho, PaymentPayload};

    #[derive(Clone)]
    struct TestStreamMethod;

    impl StreamMethod for TestStreamMethod {
        fn method(&self) -> &str {
            "test"
        }

        fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &StreamRequest,
        ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
            async { Ok(Receipt::success("test", "test_ref")) }
        }
    }

    #[test]
    fn test_stream_method_name() {
        let method = TestStreamMethod;
        assert_eq!(method.method(), "test");
    }

    #[tokio::test]
    async fn test_stream_method_verify() {
        let method = TestStreamMethod;
        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "test.com".into(),
            method: "test".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjoidmFsdWUifQ".into(),
            expires: None,
            digest: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));
        let request = StreamRequest {
            amount: "1000".into(),
            unit_type: "llm_token".into(),
            currency: "usd".into(),
            ..Default::default()
        };

        let result = method.verify(&credential, &request).await;
        assert!(result.is_ok());
        let receipt = result.unwrap();
        assert_eq!(receipt.reference, "test_ref");
    }
}
