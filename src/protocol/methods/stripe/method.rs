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

use std::collections::HashMap;
use std::future::Future;

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod as ChargeMethodTrait, VerificationError};

use super::types::{StripeCredentialPayload, StripeMethodDetails};
use super::{DEFAULT_STRIPE_API_BASE, METHOD_NAME};

/// Stripe's limit for a metadata value, in characters.
const MAX_METADATA_VALUE_CHARS: usize = 500;

/// Minimal Stripe PaymentIntent response fields.
#[derive(serde::Deserialize)]
struct PaymentIntentResponse {
    id: String,
    status: String,
}

/// Stripe charge method for one-time payment verification via SPTs.
#[derive(Clone)]
pub struct ChargeMethod {
    secret_key: String,
    network_id: String,
    payment_method_types: Vec<String>,
    api_base: String,
    client: reqwest::Client,
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
            client: reqwest::Client::new(),
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

    fn idempotency_key(challenge_id: &str, spt: &str) -> String {
        format!("mpp_{challenge_id}_{spt}")
    }

    /// Create a Stripe PaymentIntent with the given SPT.
    async fn create_payment_intent(
        &self,
        spt: &str,
        amount: &str,
        currency: &str,
        idempotency_key: &str,
        metadata: &HashMap<String, String>,
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

        for (key, value) in metadata {
            params.push((format!("metadata[{key}]"), value.clone()));
        }

        let response = self
            .client
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
            let message = format!("Stripe PaymentIntent creation failed: {message}");
            return Err(if status.is_server_error() {
                VerificationError::internal(message)
            } else {
                VerificationError::new(message)
            });
        }

        // https://docs.stripe.com/error-low-level#idempotency
        let replayed = response
            .headers()
            .get("idempotent-replayed")
            .and_then(|v| v.to_str().ok())
            == Some("true");
        if replayed {
            return Err(VerificationError::new(
                "Payment has already been processed.",
            ));
        }

        let pi: PaymentIntentResponse = response.json().await.map_err(|e| {
            VerificationError::internal(format!("Failed to parse Stripe response: {e}"))
        })?;

        Ok((pi.id, pi.status))
    }

    /// Build analytics metadata for the PaymentIntent. Values are truncated
    /// to Stripe's metadata value limit so a long client-supplied `source`
    /// cannot make the request fail.
    fn build_analytics(credential: &PaymentCredential) -> HashMap<String, String> {
        let challenge = &credential.challenge;
        let mut meta: HashMap<String, String> = [
            ("mpp_version", "1"),
            ("mpp_is_mpp", "true"),
            ("mpp_intent", challenge.intent.as_str()),
            ("mpp_challenge_id", challenge.id.as_str()),
            ("mpp_server_id", challenge.realm.as_str()),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
        if let Some(ref source) = credential.source {
            meta.insert("mpp_client_id".into(), source.clone());
        }
        for value in meta.values_mut() {
            if let Some((end, _)) = value.char_indices().nth(MAX_METADATA_VALUE_CHARS) {
                value.truncate(end);
            }
        }
        meta
    }
}

impl ChargeMethodTrait for ChargeMethod {
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let credential = credential.clone();
        let charge_request = request.clone();
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

            // Note: expiry is already checked by Mpp::verify_hmac_and_expiry()
            // before this method is called.

            // A request-bound externalId must be echoed by the credential.
            if let Some(expected) = charge_request.external_id.as_deref() {
                if payload.external_id.as_deref() != Some(expected) {
                    return Err(VerificationError::credential_mismatch(
                        "credential externalId does not match this route request",
                    ));
                }
            }

            // Build metadata: analytics + user metadata from methodDetails
            let mut metadata = Self::build_analytics(&credential);
            let details: StripeMethodDetails = charge_request
                .method_details
                .as_ref()
                .map(|v| serde_json::from_value(v.clone()))
                .transpose()
                .map_err(|e| VerificationError::new(format!("Invalid methodDetails: {e}")))?
                .unwrap_or_default();
            if let Some(user_meta) = details.metadata {
                metadata.extend(user_meta);
            }
            metadata.insert("machine_payment".into(), "true".into());

            let idempotency_key = Self::idempotency_key(&challenge.id, &payload.spt);

            let (pi_id, status) = this
                .create_payment_intent(
                    &payload.spt,
                    &charge_request.amount,
                    &charge_request.currency,
                    &idempotency_key,
                    &metadata,
                )
                .await?;

            match status.as_str() {
                "succeeded" => {
                    let receipt = Receipt::success(METHOD_NAME, &pi_id);
                    Ok(match charge_request.external_id {
                        Some(external_id) => receipt.with_external_id(external_id),
                        None => receipt,
                    })
                }
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

    #[tokio::test]
    async fn test_unreachable_api_is_an_internal_error() {
        use crate::error::PaymentError;

        let method = ChargeMethod::new("sk_test", "internal", vec!["card".into()])
            .with_api_base("http://127.0.0.1:1");
        let err = method
            .create_payment_intent("spt_test", "100", "usd", "key", &HashMap::new())
            .await
            .unwrap_err();
        assert_eq!(err.to_problem_details(None).status, 500, "{err}");
    }

    #[test]
    fn test_build_analytics_truncates_values() {
        let challenge = crate::protocol::core::ChallengeEcho {
            id: "i".repeat(501),
            realm: "test".into(),
            method: METHOD_NAME.into(),
            intent: "é".repeat(501).into(),
            request: Default::default(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
            header: None,
        };
        let credential = PaymentCredential::with_source(
            challenge,
            "s".repeat(501),
            StripeCredentialPayload {
                spt: "spt".into(),
                external_id: None,
            },
        );
        let metadata = ChargeMethod::build_analytics(&credential);
        assert_eq!(metadata["mpp_challenge_id"], "i".repeat(500));
        assert_eq!(metadata["mpp_intent"], "é".repeat(500));
        assert_eq!(metadata["mpp_client_id"], "s".repeat(500));
    }

    #[test]
    fn test_idempotency_key_uses_mpp_prefix() {
        assert_eq!(
            ChargeMethod::idempotency_key("challenge-id", "spt_test"),
            "mpp_challenge-id_spt_test"
        );
    }
}
