//! Stripe payment provider for client-side credential creation.
//!
//! The provider handles the `method="stripe"`, `intent="charge"` flow by
//! delegating SPT creation to a user-provided async callback.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::client::PaymentProvider;
use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use crate::protocol::methods::stripe::{StripeCredentialPayload, METHOD_NAME};

/// Parameters passed to the `create_token` callback.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CreateTokenParams {
    /// Payment amount in smallest currency unit.
    pub amount: String,
    /// Three-letter ISO currency code.
    pub currency: String,
    /// Stripe Business Network profile ID.
    pub network_id: String,
    /// SPT expiration as Unix timestamp (seconds).
    pub expires_at: u64,
    /// Optional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// Trait alias for the SPT creation callback.
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
/// Handles 402 challenges with `method="stripe"` by creating an SPT via
/// the user-provided `create_token` callback and returning a credential.
///
/// # Example
///
/// ```ignore
/// use mpp::client::stripe::StripeProvider;
///
/// let provider = StripeProvider::new(|params| {
///     Box::pin(async move {
///         let resp = reqwest::Client::new()
///             .post("https://my-server.com/api/create-spt")
///             .json(&params)
///             .send().await?
///             .json::<serde_json::Value>().await?;
///         Ok(resp["spt"].as_str().unwrap().to_string())
///     })
/// });
/// ```
#[derive(Clone)]
pub struct StripeProvider {
    create_token: Arc<dyn CreateTokenFn>,
    external_id: Option<String>,
}

impl StripeProvider {
    /// Create a new Stripe provider with the given SPT creation callback.
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
        method == METHOD_NAME && intent == "charge"
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        let request: serde_json::Value =
            challenge
                .request
                .decode_value()
                .map_err(|e| MppError::InvalidChallenge {
                    id: None,
                    reason: Some(format!("Failed to decode challenge request: {e}")),
                })?;

        let amount = request["amount"]
            .as_str()
            .ok_or_else(|| MppError::InvalidChallenge {
                id: None,
                reason: Some("Missing amount in challenge".into()),
            })?
            .to_string();
        let currency = request["currency"]
            .as_str()
            .ok_or_else(|| MppError::InvalidChallenge {
                id: None,
                reason: Some("Missing currency in challenge".into()),
            })?
            .to_string();

        let network_id = request
            .get("methodDetails")
            .and_then(|md| md.get("networkId"))
            .or_else(|| request.get("networkId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let expires_at = challenge
            .expires
            .as_ref()
            .and_then(|e| {
                time::OffsetDateTime::parse(e, &time::format_description::well_known::Rfc3339).ok()
            })
            .map(|dt| dt.unix_timestamp() as u64)
            .unwrap_or_else(|| {
                (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs())
                    + 3600
            });

        let params = CreateTokenParams {
            amount,
            currency,
            network_id,
            expires_at,
            metadata: None,
        };

        let spt = (self.create_token)(params).await?;

        let payload = StripeCredentialPayload {
            spt,
            external_id: self.external_id.clone(),
        };

        let echo = challenge.to_echo();
        Ok(PaymentCredential::new(echo, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supports() {
        let provider = StripeProvider::new(|_| Box::pin(async { Ok("spt_test".to_string()) }));

        assert!(provider.supports("stripe", "charge"));
        assert!(!provider.supports("tempo", "charge"));
        assert!(!provider.supports("stripe", "session"));
    }
}
