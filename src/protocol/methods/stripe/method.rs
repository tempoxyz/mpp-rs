//! Stripe charge method for server-side payment verification.
//!
//! Verifies payment credentials by creating a Stripe PaymentIntent with the
//! provided Shared Payment Token (SPT). Mirrors the TypeScript SDK's
//! `stripe.charge()` server method from mppx.
//!
//! # Example
//!
//! ```ignore
//! use mpp::stripe::{StripeChargeMethod, StripeConfig};
//! use mpp::protocol::traits::ChargeMethod;
//!
//! let method = StripeChargeMethod::new(StripeConfig {
//!     secret_key: "sk_test_...".to_string(),
//!     network_id: "acct_...".to_string(),
//!     payment_method_types: vec!["card".to_string()],
//! });
//!
//! let receipt = method.verify(&credential, &request).await?;
//! ```

use std::future::Future;

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod as ChargeMethodTrait, ErrorCode, VerificationError};

use super::types::{StripeConfig, StripeCredentialPayload, StripeMethodDetails};
use super::METHOD_NAME;

/// Stripe charge method for one-time payment verification via PaymentIntents.
#[derive(Clone)]
pub struct ChargeMethod {
    secret_key: String,
    network_id: String,
    payment_method_types: Vec<String>,
}

impl ChargeMethod {
    /// Create a new Stripe charge method.
    pub fn new(config: StripeConfig) -> Self {
        Self {
            secret_key: config.secret_key,
            network_id: config.network_id,
            payment_method_types: config.payment_method_types,
        }
    }
}

impl ChargeMethodTrait for ChargeMethod {
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn prepare_request(
        &self,
        mut request: ChargeRequest,
        _credential: Option<&PaymentCredential>,
    ) -> ChargeRequest {
        let mut details = match &request.method_details {
            Some(v) => serde_json::from_value::<StripeMethodDetails>(v.clone()).unwrap_or_default(),
            None => StripeMethodDetails::default(),
        };

        if details.network_id.is_none() {
            details.network_id = Some(self.network_id.clone());
        }
        if details.payment_method_types.is_none() {
            details.payment_method_types = Some(self.payment_method_types.clone());
        }

        request.method_details = Some(serde_json::to_value(&details).unwrap_or_default());
        request
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let credential = credential.clone();
        let request = request.clone();
        let secret_key = self.secret_key.clone();

        async move {
            // Check expiry
            if let Some(ref expires) = credential.challenge.expires {
                if let Ok(expires_at) = time::OffsetDateTime::parse(
                    expires,
                    &time::format_description::well_known::Rfc3339,
                ) {
                    if expires_at <= time::OffsetDateTime::now_utc() {
                        return Err(VerificationError::expired(format!(
                            "Challenge expired at {}",
                            expires
                        )));
                    }
                }
            }

            // Parse credential payload
            let payload: StripeCredentialPayload =
                serde_json::from_value(credential.payload.clone()).map_err(|e| {
                    VerificationError::with_code(
                        format!("Invalid credential payload: {}", e),
                        ErrorCode::InvalidPayload,
                    )
                })?;

            // Build analytics metadata
            let mut metadata = std::collections::HashMap::new();
            metadata.insert("mpp_version".into(), "1".into());
            metadata.insert("mpp_is_mpp".into(), "true".into());
            metadata.insert("mpp_intent".into(), credential.challenge.intent.to_string());
            metadata.insert("mpp_challenge_id".into(), credential.challenge.id.clone());
            metadata.insert("mpp_server_id".into(), credential.challenge.realm.clone());

            // Merge user-provided metadata from method_details
            if let Some(ref details) = request.method_details {
                if let Some(user_meta) = details.get("metadata").and_then(|v| v.as_object()) {
                    for (k, v) in user_meta {
                        if let Some(s) = v.as_str() {
                            metadata.insert(k.clone(), s.to_string());
                        }
                    }
                }
            }

            // Create PaymentIntent via Stripe API
            let pi = create_payment_intent(
                &secret_key,
                &credential.challenge.id,
                &request.amount,
                &request.currency,
                &payload.spt,
                &metadata,
            )
            .await?;

            if pi.status == "requires_action" {
                return Err(VerificationError::with_code(
                    "Stripe PaymentIntent requires action",
                    ErrorCode::InvalidCredential,
                ));
            }

            if pi.status != "succeeded" {
                return Err(VerificationError::transaction_failed(format!(
                    "Stripe PaymentIntent status: {}",
                    pi.status
                )));
            }

            Ok(Receipt::success(METHOD_NAME, &pi.id))
        }
    }
}

/// Minimal PaymentIntent response from Stripe API.
struct PaymentIntentResponse {
    id: String,
    status: String,
}

/// Create a Stripe PaymentIntent using the raw HTTP API.
async fn create_payment_intent(
    secret_key: &str,
    challenge_id: &str,
    amount: &str,
    currency: &str,
    spt: &str,
    metadata: &std::collections::HashMap<String, String>,
) -> Result<PaymentIntentResponse, VerificationError> {
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
        params.push((format!("metadata[{}]", key), value.clone()));
    }

    let body = params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    let idempotency_key = format!("mpp_{challenge_id}_{spt}");

    let client = reqwest::Client::new();
    let response = client
        .post("https://api.stripe.com/v1/payment_intents")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Idempotency-Key", &idempotency_key)
        .basic_auth(secret_key, Option::<&str>::None)
        .body(body)
        .send()
        .await
        .map_err(|e| {
            VerificationError::network_error(format!("Stripe API request failed: {}", e))
        })?;

    if !response.status().is_success() {
        return Err(VerificationError::transaction_failed(
            "Stripe PaymentIntent failed",
        ));
    }

    let json: serde_json::Value = response.json().await.map_err(|e| {
        VerificationError::network_error(format!("Failed to parse Stripe response: {}", e))
    })?;

    let id = json["id"]
        .as_str()
        .ok_or_else(|| VerificationError::new("Missing id in Stripe response"))?
        .to_string();

    let status = json["status"]
        .as_str()
        .ok_or_else(|| VerificationError::new("Missing status in Stripe response"))?
        .to_string();

    Ok(PaymentIntentResponse { id, status })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{ChallengeEcho, PaymentPayload};
    use crate::protocol::intents::ChargeRequest;

    #[test]
    fn test_stripe_method_name() {
        let method = ChargeMethod::new(StripeConfig {
            secret_key: "sk_test_123".into(),
            network_id: "acct_123".into(),
            payment_method_types: vec!["card".into()],
        });
        assert_eq!(ChargeMethodTrait::method(&method), "stripe");
    }

    #[test]
    fn test_prepare_request_injects_defaults() {
        let method = ChargeMethod::new(StripeConfig {
            secret_key: "sk_test_123".into(),
            network_id: "acct_abc".into(),
            payment_method_types: vec!["card".into(), "us_bank_account".into()],
        });

        let request = ChargeRequest {
            amount: "100".into(),
            currency: "usd".into(),
            ..Default::default()
        };

        let prepared = method.prepare_request(request, None);
        let details = prepared.method_details.unwrap();
        assert_eq!(details["networkId"], "acct_abc");
        assert_eq!(
            details["paymentMethodTypes"],
            serde_json::json!(["card", "us_bank_account"])
        );
    }

    #[test]
    fn test_prepare_request_preserves_existing_details() {
        let method = ChargeMethod::new(StripeConfig {
            secret_key: "sk_test_123".into(),
            network_id: "acct_abc".into(),
            payment_method_types: vec!["card".into()],
        });

        let request = ChargeRequest {
            amount: "100".into(),
            currency: "usd".into(),
            method_details: Some(serde_json::json!({
                "networkId": "acct_custom",
            })),
            ..Default::default()
        };

        let prepared = method.prepare_request(request, None);
        let details = prepared.method_details.unwrap();
        // Existing networkId should be preserved
        assert_eq!(details["networkId"], "acct_custom");
        // payment_method_types should be injected since it was missing
        assert_eq!(details["paymentMethodTypes"], serde_json::json!(["card"]));
    }

    #[tokio::test]
    async fn test_verify_rejects_invalid_payload() {
        let method = ChargeMethod::new(StripeConfig {
            secret_key: "sk_test_123".into(),
            network_id: "acct_123".into(),
            payment_method_types: vec!["card".into()],
        });

        let echo = ChallengeEcho {
            id: "test-id".into(),
            realm: "test.com".into(),
            method: "stripe".into(),
            intent: "charge".into(),
            request: "eyJ0ZXN0IjoidmFsdWUifQ".into(),
            expires: None,
            digest: None,
            opaque: None,
        };

        // Payload without required "spt" field
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xno_spt"));
        let request = ChargeRequest {
            amount: "100".into(),
            currency: "usd".into(),
            ..Default::default()
        };

        let result = ChargeMethodTrait::verify(&method, &credential, &request).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::InvalidPayload));
    }

    #[tokio::test]
    async fn test_verify_rejects_expired_challenge() {
        let method = ChargeMethod::new(StripeConfig {
            secret_key: "sk_test_123".into(),
            network_id: "acct_123".into(),
            payment_method_types: vec!["card".into()],
        });

        let past = (time::OffsetDateTime::now_utc() - time::Duration::minutes(10))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();

        let echo = ChallengeEcho {
            id: "test-id".into(),
            realm: "test.com".into(),
            method: "stripe".into(),
            intent: "charge".into(),
            request: "eyJ0ZXN0IjoidmFsdWUifQ".into(),
            expires: Some(past),
            digest: None,
            opaque: None,
        };

        let credential = PaymentCredential::new(echo, serde_json::json!({"spt": "spt_test_123"}));
        let request = ChargeRequest {
            amount: "100".into(),
            currency: "usd".into(),
            ..Default::default()
        };

        let result = ChargeMethodTrait::verify(&method, &credential, &request).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::Expired));
    }
}
