//! Client-side Stripe payment provider.
//!
//! Provides a [`StripeProvider`] that implements [`PaymentProvider`] for Stripe
//! challenges. When a `method="stripe"` challenge is received, the provider calls
//! a user-supplied `create_token` callback to obtain a Shared Payment Token (SPT),
//! then returns a credential with `{ spt: "..." }` payload.
//!
//! # Example
//!
//! ```ignore
//! use mpp::client::stripe::StripeProvider;
//!
//! let provider = StripeProvider::new(|params| async move {
//!     // Call your backend to create an SPT
//!     let resp = reqwest::Client::new()
//!         .post("https://your-api.com/create-spt")
//!         .json(&serde_json::json!({
//!             "amount": params.amount,
//!             "currency": params.currency,
//!             "payment_method": "pm_card_visa",
//!         }))
//!         .send()
//!         .await?;
//!     let body: serde_json::Value = resp.json().await?;
//!     Ok(body["spt"].as_str().unwrap().to_string())
//! });
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::client::PaymentProvider;
use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use crate::protocol::methods::stripe::{INTENT_CHARGE, METHOD_NAME};

/// Parameters passed to the `create_token` callback.
#[derive(Debug, Clone)]
pub struct CreateTokenParams {
    /// Payment amount in base units.
    pub amount: String,
    /// Currency code (e.g., "usd").
    pub currency: String,
    /// Stripe Business Network profile ID from the challenge.
    pub network_id: Option<String>,
    /// Challenge expiration as a Unix timestamp (seconds), if present.
    pub expires_at: Option<i64>,
    /// Optional metadata from the challenge's method details.
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// Trait alias for the create_token callback.
pub trait CreateTokenFn:
    Fn(CreateTokenParams) -> Pin<Box<dyn Future<Output = Result<String, MppError>> + Send>>
    + Send
    + Sync
{
}

impl<F> CreateTokenFn for F where
    F: Fn(CreateTokenParams) -> Pin<Box<dyn Future<Output = Result<String, MppError>> + Send>>
        + Send
        + Sync
{
}

/// Client-side Stripe payment provider.
///
/// Handles `method="stripe"` + `intent="charge"` challenges by calling
/// a user-provided callback to obtain an SPT, then constructing the credential.
#[derive(Clone)]
pub struct StripeProvider {
    create_token: Arc<dyn CreateTokenFn>,
    external_id: Option<String>,
}

impl StripeProvider {
    /// Create a new Stripe provider with a token creation callback.
    pub fn new<F>(create_token: F) -> Self
    where
        F: Fn(CreateTokenParams) -> Pin<Box<dyn Future<Output = Result<String, MppError>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        Self {
            create_token: Arc::new(create_token),
            external_id: None,
        }
    }

    /// Set an external reference ID to include in credential payloads.
    pub fn with_external_id(mut self, id: impl Into<String>) -> Self {
        self.external_id = Some(id.into());
        self
    }
}

impl PaymentProvider for StripeProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == METHOD_NAME && intent == INTENT_CHARGE
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        let request: crate::protocol::intents::ChargeRequest = challenge.request.decode()?;

        let network_id = request
            .method_details
            .as_ref()
            .and_then(|d| d.get("networkId"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let metadata = request
            .method_details
            .as_ref()
            .and_then(|d| d.get("metadata"))
            .and_then(|v| v.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            });

        let expires_at = challenge.expires.as_ref().and_then(|e| {
            time::OffsetDateTime::parse(e, &time::format_description::well_known::Rfc3339)
                .ok()
                .map(|dt| dt.unix_timestamp())
        });

        let params = CreateTokenParams {
            amount: request.amount.clone(),
            currency: request.currency.clone(),
            network_id,
            expires_at,
            metadata,
        };

        let spt = (self.create_token)(params).await?;

        let mut payload = serde_json::json!({ "spt": spt });
        if let Some(ref ext_id) = self.external_id {
            payload["externalId"] = serde_json::json!(ext_id);
        }

        let echo = challenge.to_echo();
        Ok(PaymentCredential {
            challenge: echo,
            source: None,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

    fn test_challenge() -> PaymentChallenge {
        let request = crate::protocol::intents::ChargeRequest {
            amount: "100".into(),
            currency: "usd".into(),
            method_details: Some(serde_json::json!({
                "networkId": "acct_123",
                "paymentMethodTypes": ["card"],
            })),
            ..Default::default()
        };

        let request_json = serde_json::to_value(&request).unwrap();
        let request_b64 = Base64UrlJson::from_value(&request_json).unwrap();
        PaymentChallenge::new(
            "test-id",
            "test.com",
            METHOD_NAME,
            INTENT_CHARGE,
            request_b64,
        )
    }

    #[test]
    fn test_supports() {
        let provider = StripeProvider::new(|_| Box::pin(async { Ok("spt_test".to_string()) }));
        assert!(provider.supports("stripe", "charge"));
        assert!(!provider.supports("tempo", "charge"));
        assert!(!provider.supports("stripe", "session"));
    }

    #[tokio::test]
    async fn test_pay_creates_credential() {
        let provider = StripeProvider::new(|params| {
            Box::pin(async move {
                assert_eq!(params.amount, "100");
                assert_eq!(params.currency, "usd");
                assert_eq!(params.network_id.as_deref(), Some("acct_123"));
                Ok("spt_test_token".to_string())
            })
        });

        let challenge = test_challenge();
        let credential = provider.pay(&challenge).await.unwrap();

        assert_eq!(credential.challenge.method.as_str(), "stripe");
        let payload = &credential.payload;
        assert_eq!(payload["spt"], "spt_test_token");
    }

    #[tokio::test]
    async fn test_pay_with_external_id() {
        let provider =
            StripeProvider::new(|_| Box::pin(async { Ok("spt_test_token".to_string()) }))
                .with_external_id("order-42");

        let challenge = test_challenge();
        let credential = provider.pay(&challenge).await.unwrap();

        let payload = &credential.payload;
        assert_eq!(payload["externalId"], "order-42");
    }
}
