//! Stripe-specific types for MPP.

use serde::{Deserialize, Serialize};

/// Stripe-specific method details nested under `methodDetails` in the challenge request.
///
/// Matches the mppx wire format where `networkId`, `paymentMethodTypes`, and `metadata`
/// are nested inside the `methodDetails` field of the `ChargeRequest`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StripeMethodDetails {
    /// Stripe Business Network profile ID.
    #[serde(rename = "networkId")]
    pub network_id: String,

    /// Accepted Stripe payment method types (e.g., ["card"]).
    #[serde(rename = "paymentMethodTypes")]
    pub payment_method_types: Vec<String>,

    /// Optional metadata key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// Client credential payload for Stripe charge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeCredentialPayload {
    /// Shared Payment Token from Stripe.
    pub spt: String,

    /// Optional external reference ID.
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// Result returned by the `create_token` callback.
#[derive(Debug, Clone)]
pub struct CreateTokenResult {
    /// Shared Payment Token from Stripe.
    pub spt: String,
    /// Optional per-payment external reference ID.
    pub external_id: Option<String>,
}

impl From<String> for CreateTokenResult {
    fn from(spt: String) -> Self {
        Self {
            spt,
            external_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stripe_credential_payload_serde() {
        let payload = StripeCredentialPayload {
            spt: "spt_test_abc123".to_string(),
            external_id: Some("order-42".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"spt\":\"spt_test_abc123\""));
        assert!(json.contains("\"externalId\":\"order-42\""));
        let parsed: StripeCredentialPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.spt, "spt_test_abc123");
        assert_eq!(parsed.external_id.as_deref(), Some("order-42"));
    }

    #[test]
    fn test_stripe_credential_payload_without_external_id() {
        let payload = StripeCredentialPayload {
            spt: "spt_test_xyz".to_string(),
            external_id: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("externalId"));
    }

    #[test]
    fn test_stripe_method_details_serde() {
        let details = StripeMethodDetails {
            network_id: "internal".to_string(),
            payment_method_types: vec!["card".to_string()],
            metadata: None,
        };
        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"networkId\":\"internal\""));
        assert!(json.contains("\"paymentMethodTypes\":[\"card\"]"));
        let parsed: StripeMethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.network_id, "internal");
    }

    #[test]
    fn test_stripe_method_details_with_metadata() {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert("order_id".to_string(), "12345".to_string());
        let details = StripeMethodDetails {
            network_id: "internal".to_string(),
            payment_method_types: vec!["card".to_string()],
            metadata: Some(metadata),
        };
        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"order_id\":\"12345\""));
    }

    #[test]
    fn test_create_token_result_from_string() {
        let result: CreateTokenResult = "spt_123".to_string().into();
        assert_eq!(result.spt, "spt_123");
        assert!(result.external_id.is_none());
    }
}
