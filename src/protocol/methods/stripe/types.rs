//! Stripe-specific types for MPP.

use serde::{Deserialize, Serialize};

/// Stripe-specific charge request fields.
///
/// These fields are included in the challenge's `request` object
/// alongside the standard `amount`, `currency`, and `recipient` fields
/// from [`ChargeRequest`](crate::protocol::intents::ChargeRequest).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeChargeRequest {
    /// Payment amount in smallest currency unit.
    pub amount: String,

    /// Three-letter ISO currency code (e.g., "usd").
    pub currency: String,

    /// Token decimals for amount conversion.
    pub decimals: u8,

    /// Stripe Business Network profile ID.
    #[serde(rename = "networkId")]
    pub network_id: String,

    /// Accepted Stripe payment method types (e.g., ["card"]).
    #[serde(rename = "paymentMethodTypes")]
    pub payment_method_types: Vec<String>,

    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Merchant reference ID.
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Optional metadata key-value pairs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::HashMap<String, String>>,

    /// Recipient address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
}

/// Client credential payload for Stripe charge.
///
/// The client sends this after creating an SPT via the server-proxied
/// Stripe API endpoint.
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
    fn test_stripe_charge_request_serde() {
        let req = StripeChargeRequest {
            amount: "1000".to_string(),
            currency: "usd".to_string(),
            decimals: 2,
            network_id: "internal".to_string(),
            payment_method_types: vec!["card".to_string()],
            description: Some("Test charge".to_string()),
            external_id: None,
            metadata: None,
            recipient: None,
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"networkId\":\"internal\""));
        assert!(json.contains("\"paymentMethodTypes\":[\"card\"]"));

        let parsed: StripeChargeRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.network_id, "internal");
        assert_eq!(parsed.payment_method_types, vec!["card"]);
    }
}
