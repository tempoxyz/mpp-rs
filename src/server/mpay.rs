//! Payment handler that binds method, realm, and secret_key.
//!
//! This module provides the [`Mpay`] struct which wraps a payment method
//! with server configuration for stateless challenge verification.
//!
//! # Example
//!
//! ```ignore
//! use mpay::server::{Mpay, tempo_provider, TempoChargeMethod};
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
//! let method = TempoChargeMethod::new(provider);
//!
//! let payment = Mpay::new(method, "api.example.com", "my-server-secret");
//!
//! // Generate a challenge (no credential provided)
//! let challenge = payment.charge_challenge("1000000", "0x...", "0x...")?;
//!
//! // Verify a credential
//! let receipt = payment.verify(&credential, &request).await?;
//! ```

#[cfg(feature = "tempo")]
use crate::error::Result;
#[cfg(feature = "tempo")]
use crate::protocol::core::PaymentChallenge;
use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod, VerificationError};

/// Server-side payment handler.
///
/// Binds a payment method with realm and secret_key for stateless
/// challenge verification.
///
/// # Type Parameters
///
/// * `M` - The payment method type (must implement [`ChargeMethod`])
///
/// # Example
///
/// ```ignore
/// use mpay::server::{Mpay, tempo_provider, TempoChargeMethod};
///
/// let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
/// let method = TempoChargeMethod::new(provider);
///
/// let payment = Mpay::new(method, "api.example.com", "my-server-secret");
///
/// // In your request handler:
/// let challenge = payment.charge_challenge("1000000", "0x...", "0x...")?;
///
/// // Return 402 with WWW-Authenticate header
/// let header = challenge.to_www_authenticate()?;
/// ```
#[derive(Clone)]
pub struct Mpay<M> {
    method: M,
    realm: String,
    secret_key: String,
}

impl<M> Mpay<M>
where
    M: ChargeMethod,
{
    /// Create a new payment handler.
    ///
    /// # Arguments
    ///
    /// * `method` - Payment method (e.g., `TempoChargeMethod`)
    /// * `realm` - Server realm for WWW-Authenticate header
    /// * `secret_key` - Server secret for HMAC-bound challenge IDs.
    ///   Enables stateless challenge verification.
    pub fn new(method: M, realm: impl Into<String>, secret_key: impl Into<String>) -> Self {
        Self {
            method,
            realm: realm.into(),
            secret_key: secret_key.into(),
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

    /// Generate a charge challenge with minimal parameters.
    ///
    /// Creates a payment challenge with an HMAC-bound ID for stateless
    /// verification. The client will echo this challenge back with their
    /// credential, and the server can verify it without storing state.
    ///
    /// # Arguments
    ///
    /// * `amount` - Amount in atomic units (e.g., "1000000" for 1 USDC)
    /// * `currency` - Token address
    /// * `recipient` - Recipient address
    ///
    /// # Example
    ///
    /// ```ignore
    /// let challenge = payment.charge_challenge(
    ///     "1000000",
    ///     "0x20c0000000000000000000000000000000000001",
    ///     "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
    /// )?;
    /// ```
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

    /// Generate a charge challenge with full options.
    ///
    /// Use this when you need more control over the challenge, such as:
    /// - Fee sponsorship (`feePayer: true` in method_details)
    /// - Custom expiration times
    /// - Descriptions or external IDs
    ///
    /// # Arguments
    ///
    /// * `request` - A fully configured [`ChargeRequest`]
    /// * `expires` - Optional challenge expiration (ISO 8601)
    /// * `description` - Optional human-readable description
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

    /// Verify a charge credential.
    ///
    /// Validates the credential against the request and returns a receipt
    /// on success.
    ///
    /// # Arguments
    ///
    /// * `credential` - The payment credential from the client
    /// * `request` - The charge request parameters
    ///
    /// # Returns
    ///
    /// * `Ok(Receipt)` - Payment was verified successfully
    /// * `Err(VerificationError)` - Verification failed
    ///
    /// # Note
    ///
    /// Per the IETF Payment Auth spec, synchronous flows MUST NOT return
    /// a successful response with a failed receipt. If the underlying method
    /// returns a receipt with `status: "failed"`, this function converts it
    /// to a `VerificationError` with the transaction reference.
    pub async fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        // Verify the challenge ID matches our HMAC
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{ChallengeEcho, PaymentPayload};
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

    /// Mock method that returns a successful receipt
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
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_charge_challenge_generation() {
        let payment = Mpay::new(MockMethod, "api.example.com", "test-secret");
        let challenge = payment
            .charge_challenge(
                "1000000",
                "0x20c0000000000000000000000000000000000001",
                "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            )
            .unwrap();

        assert_eq!(challenge.realm, "api.example.com");
        assert_eq!(challenge.method.as_str(), "tempo");
        assert_eq!(challenge.intent.as_str(), "charge");
        // ID should be 43 chars (base64url SHA256)
        assert_eq!(challenge.id.len(), 43);
    }

    /// Verify that successful receipts are returned normally.
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
}
