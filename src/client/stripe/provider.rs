//! Stripe payment provider for client-side credential creation.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::client::PaymentProvider;
use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use crate::protocol::methods::stripe::types::CreateTokenResult;
use crate::protocol::methods::stripe::{StripeCredentialPayload, METHOD_NAME};

/// Parameters passed to the `create_token` callback.
///
/// Matches the mppx `OnChallengeParameters` shape.
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
    /// Optional metadata from the challenge's methodDetails.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::HashMap<String, String>>,
    /// The full challenge as JSON, for advanced use cases.
    #[serde(skip)]
    pub challenge: serde_json::Value,
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
/// use mpp::protocol::methods::stripe::CreateTokenResult;
///
/// let provider = StripeProvider::new(|params| {
///     Box::pin(async move {
///         let resp = reqwest::Client::new()
///             .post("https://my-server.com/api/create-spt")
///             .json(&params)
///             .send().await.map_err(|e| mpp::MppError::Http(e.to_string()))?
///             .json::<serde_json::Value>().await
///             .map_err(|e| mpp::MppError::Http(e.to_string()))?;
///         Ok(CreateTokenResult {
///             spt: resp["spt"].as_str().unwrap().to_string(),
///             external_id: None,
///         })
///     })
/// });
/// ```
#[derive(Clone)]
pub struct StripeProvider {
    create_token: Arc<
        dyn Fn(
                CreateTokenParams,
            )
                -> Pin<Box<dyn Future<Output = Result<CreateTokenResult, MppError>> + Send>>
            + Send
            + Sync,
    >,
}

impl StripeProvider {
    /// Create a new Stripe provider with the given SPT creation callback.
    ///
    /// The callback receives [`CreateTokenParams`] and should return a
    /// [`CreateTokenResult`] containing the SPT and optional external ID.
    pub fn new<F>(create_token: F) -> Self
    where
        F: Fn(
                CreateTokenParams,
            )
                -> Pin<Box<dyn Future<Output = Result<CreateTokenResult, MppError>> + Send>>
            + Send
            + Sync
            + 'static,
    {
        Self {
            create_token: Arc::new(create_token),
        }
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

        let method_details = request.get("methodDetails");

        let network_id = method_details
            .and_then(|md| md.get("networkId"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let metadata: Option<std::collections::HashMap<String, String>> = method_details
            .and_then(|md| md.get("metadata"))
            .and_then(|m| serde_json::from_value(m.clone()).ok());

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

        let challenge_json = serde_json::to_value(challenge).unwrap_or_default();

        let params = CreateTokenParams {
            amount,
            currency,
            network_id,
            expires_at,
            metadata,
            challenge: challenge_json,
        };

        let result = (self.create_token)(params).await?;

        let payload = StripeCredentialPayload {
            spt: result.spt,
            external_id: result.external_id,
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
        let provider = StripeProvider::new(|_| {
            Box::pin(async { Ok(CreateTokenResult::from("spt_test".to_string())) })
        });

        assert!(provider.supports("stripe", "charge"));
        assert!(!provider.supports("tempo", "charge"));
        assert!(!provider.supports("stripe", "session"));
    }
}
