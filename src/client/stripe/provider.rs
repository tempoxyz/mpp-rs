//! Stripe payment provider for client-side credential creation.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::client::PaymentProvider;
use crate::error::{MppError, ResultExt};
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::methods::stripe::types::CreateTokenResult;
use crate::protocol::methods::stripe::{
    StripeCredentialPayload, StripeMethodDetails, INTENT_CHARGE, METHOD_NAME,
};

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
type CreateTokenFn = dyn Fn(
        CreateTokenParams,
    ) -> Pin<Box<dyn Future<Output = Result<CreateTokenResult, MppError>> + Send>>
    + Send
    + Sync;

#[derive(Clone)]
pub struct StripeProvider {
    create_token: Arc<CreateTokenFn>,
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
        method == METHOD_NAME && intent == INTENT_CHARGE
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        let request: ChargeRequest = challenge
            .request
            .decode()
            .mpp_config("failed to decode challenge request")?;

        let details: StripeMethodDetails = request
            .method_details
            .as_ref()
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .mpp_config("invalid methodDetails")?
            .unwrap_or_default();

        let expires_at = challenge
            .expires
            .as_ref()
            .and_then(|e| {
                time::OffsetDateTime::parse(e, &time::format_description::well_known::Rfc3339).ok()
            })
            .map(|dt| dt.unix_timestamp() as u64)
            .unwrap_or_else(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600
            });

        let params = CreateTokenParams {
            amount: request.amount,
            currency: request.currency,
            network_id: details.network_id,
            expires_at,
            metadata: details.metadata,
            challenge: serde_json::to_value(challenge).unwrap_or_default(),
        };

        let result = (self.create_token)(params).await?;

        let payload = StripeCredentialPayload {
            spt: result.spt,
            external_id: result.external_id,
        };

        Ok(PaymentCredential::new(challenge.to_echo(), payload))
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
