//! Stripe-specific types for MPP.

use serde::{Deserialize, Serialize};

/// Configuration for the Stripe payment method.
#[derive(Debug, Clone)]
pub struct StripeConfig {
    /// Stripe secret API key (e.g., `sk_test_...` or `sk_live_...`).
    pub secret_key: String,
    /// Stripe Business Network profile ID.
    pub network_id: String,
    /// Accepted payment method types (e.g., `["card"]`).
    pub payment_method_types: Vec<String>,
}

/// Stripe-specific method details included in the challenge request.
///
/// These are placed in `ChargeRequest.method_details.networkId` and
/// `ChargeRequest.method_details.paymentMethodTypes`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StripeMethodDetails {
    /// Stripe Business Network profile ID.
    #[serde(rename = "networkId", skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
    /// Accepted payment method types.
    #[serde(rename = "paymentMethodTypes", skip_serializing_if = "Option::is_none")]
    pub payment_method_types: Option<Vec<String>>,
    /// Optional metadata key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// Credential payload for Stripe charge verification.
///
/// The client sends this as the credential payload after obtaining an SPT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeCredentialPayload {
    /// Shared Payment Token from Stripe.
    pub spt: String,
    /// Optional external reference ID.
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_payload_deserialization() {
        let json = r#"{"spt":"spt_test_abc123"}"#;
        let payload: StripeCredentialPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.spt, "spt_test_abc123");
        assert!(payload.external_id.is_none());
    }

    #[test]
    fn test_credential_payload_with_external_id() {
        let json = r#"{"spt":"spt_test_abc123","externalId":"order-42"}"#;
        let payload: StripeCredentialPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.spt, "spt_test_abc123");
        assert_eq!(payload.external_id.as_deref(), Some("order-42"));
    }

    #[test]
    fn test_method_details_serialization() {
        let details = StripeMethodDetails {
            network_id: Some("acct_123".into()),
            payment_method_types: Some(vec!["card".into()]),
            metadata: None,
        };
        let json = serde_json::to_value(&details).unwrap();
        assert_eq!(json["networkId"], "acct_123");
        assert_eq!(json["paymentMethodTypes"], serde_json::json!(["card"]));
    }
}
