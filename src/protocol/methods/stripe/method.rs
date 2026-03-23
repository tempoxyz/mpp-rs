//! Stripe charge method for server-side payment verification.
//!
//! Verifies payments by creating a Stripe PaymentIntent with the client's
//! Shared Payment Token (SPT). Supports both a pre-configured Stripe SDK
//! client and raw secret key modes.
//!
//! # Example
//!
//! ```ignore
//! use mpp::protocol::methods::stripe::method::ChargeMethod;
//!
//! let method = ChargeMethod::new("sk_test_...", "internal", vec!["card"]);
//! let receipt = method.verify(&credential, &request).await?;
//! ```

use std::future::Future;

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod as ChargeMethodTrait, VerificationError};

use super::types::StripeCredentialPayload;
use super::{DEFAULT_STRIPE_API_BASE, METHOD_NAME};

/// Stripe charge method for one-time payment verification via SPTs.
#[derive(Clone)]
pub struct ChargeMethod {
    secret_key: String,
    network_id: String,
    payment_method_types: Vec<String>,
    api_base: String,
}

impl ChargeMethod {
    /// Create a new Stripe charge method.
    ///
    /// # Arguments
    ///
    /// * `secret_key` - Stripe secret API key (e.g., `sk_test_...` or `sk_live_...`)
    /// * `network_id` - Stripe Business Network profile ID
    /// * `payment_method_types` - Accepted payment method types (e.g., `["card"]`)
    pub fn new(
        secret_key: impl Into<String>,
        network_id: impl Into<String>,
        payment_method_types: Vec<String>,
    ) -> Self {
        Self {
            secret_key: secret_key.into(),
            network_id: network_id.into(),
            payment_method_types,
            api_base: DEFAULT_STRIPE_API_BASE.to_string(),
        }
    }

    /// Override the Stripe API base URL (for testing with a mock server).
    pub fn with_api_base(mut self, url: impl Into<String>) -> Self {
        self.api_base = url.into();
        self
    }

    /// Get the configured network ID.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// Get the configured payment method types.
    pub fn payment_method_types(&self) -> &[String] {
        &self.payment_method_types
    }

    /// Create a Stripe PaymentIntent with the given SPT.
    async fn create_payment_intent(
        &self,
        spt: &str,
        amount: &str,
        currency: &str,
        idempotency_key: &str,
        metadata: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<(String, String), VerificationError> {
        let url = format!("{}/v1/payment_intents", self.api_base);

        let mut params = vec![
            ("amount".to_string(), amount.to_string()),
            (
                "automatic_payment_methods[allow_redirects]".to_string(),
                "never".to_string(),
            ),
            (
                "automatic_payment_methods[enabled]".to_string(),
                "true".to_string(),
            ),
            ("confirm".to_string(), "true".to_string()),
            ("currency".to_string(), currency.to_string()),
            ("shared_payment_granted_token".to_string(), spt.to_string()),
        ];

        if let Some(meta) = metadata {
            for (key, value) in meta {
                params.push((format!("metadata[{key}]"), value.clone()));
            }
        }

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header(
                "Authorization",
                format!(
                    "Basic {}",
                    base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD,
                        format!("{}:", self.secret_key)
                    )
                ),
            )
            .header("Idempotency-Key", idempotency_key)
            .form(&params)
            .send()
            .await
            .map_err(|e| {
                VerificationError::network_error(format!("Stripe API request failed: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            let message = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["error"]["message"].as_str().map(String::from))
                .unwrap_or_else(|| format!("HTTP {status}"));
            return Err(VerificationError::new(format!(
                "Stripe PaymentIntent creation failed: {message}"
            )));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| VerificationError::new(format!("Failed to parse Stripe response: {e}")))?;

        let id = body["id"]
            .as_str()
            .ok_or_else(|| VerificationError::new("Missing id in Stripe response"))?
            .to_string();
        let status = body["status"]
            .as_str()
            .ok_or_else(|| VerificationError::new("Missing status in Stripe response"))?
            .to_string();

        Ok((id, status))
    }
}

impl ChargeMethodTrait for ChargeMethod {
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let credential = credential.clone();
        let this = self.clone();

        async move {
            // Parse the SPT from the credential payload
            let payload: StripeCredentialPayload =
                serde_json::from_value(credential.payload.clone()).map_err(|e| {
                    VerificationError::new(format!(
                        "Invalid credential payload: missing or malformed spt: {e}"
                    ))
                })?;

            let challenge = &credential.challenge;

            // Check expiry
            if let Some(ref expires) = challenge.expires {
                if let Ok(expires_at) = time::OffsetDateTime::parse(
                    expires,
                    &time::format_description::well_known::Rfc3339,
                ) {
                    if expires_at <= time::OffsetDateTime::now_utc() {
                        return Err(VerificationError::expired(format!(
                            "Challenge expired at {expires}"
                        )));
                    }
                }
            }

            // Decode the challenge request to get amount/currency
            let charge_request: ChargeRequest = challenge.request.decode().map_err(|e| {
                VerificationError::new(format!("Failed to decode challenge request: {e}"))
            })?;

            let idempotency_key = format!("mppx_{}_{}", challenge.id, payload.spt);

            let (pi_id, status) = this
                .create_payment_intent(
                    &payload.spt,
                    &charge_request.amount,
                    &charge_request.currency,
                    &idempotency_key,
                    None,
                )
                .await?;

            match status.as_str() {
                "succeeded" => Ok(Receipt::success(METHOD_NAME, &pi_id)),
                "requires_action" => Err(VerificationError::new(
                    "Stripe PaymentIntent requires action (e.g., 3DS)",
                )),
                other => Err(VerificationError::new(format!(
                    "Stripe PaymentIntent status: {other}"
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_charge_method_name() {
        let method = ChargeMethod::new("sk_test", "internal", vec!["card".into()]);
        assert_eq!(ChargeMethodTrait::method(&method), "stripe");
    }

    #[test]
    fn test_with_api_base() {
        let method = ChargeMethod::new("sk_test", "internal", vec!["card".into()])
            .with_api_base("http://localhost:9999");
        assert_eq!(method.api_base, "http://localhost:9999");
    }

    #[test]
    fn test_accessors() {
        let method = ChargeMethod::new(
            "sk_test",
            "my-network",
            vec!["card".into(), "us_bank_account".into()],
        );
        assert_eq!(method.network_id(), "my-network");
        assert_eq!(method.payment_method_types(), &["card", "us_bank_account"]);
    }
}
