//! Stripe-specific types for Web Payment Auth.
//!
//! These types have ZERO blockchain dependencies - only serde.

use serde::{Deserialize, Serialize};

/// Stripe method-specific details in payment requests.
///
/// Stripe payments use traditional payment rails with Stripe's infrastructure.
///
/// # Examples
///
/// ```
/// use mpp_rs::protocol::methods::stripe::StripeMethodDetails;
///
/// let details = StripeMethodDetails {
///     business_network: Some("acct_123abc".to_string()),
///     destination: Some("ba_456def".to_string()),
/// };
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StripeMethodDetails {
    /// Stripe connected account ID (e.g., "acct_...")
    #[serde(rename = "businessNetwork", skip_serializing_if = "Option::is_none")]
    pub business_network: Option<String>,

    /// Destination for the payment (bank account, card, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stripe_method_details_serialization() {
        let details = StripeMethodDetails {
            business_network: Some("acct_123".to_string()),
            destination: Some("ba_456".to_string()),
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"businessNetwork\":\"acct_123\""));
        assert!(json.contains("\"destination\":\"ba_456\""));

        let parsed: StripeMethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.business_network, Some("acct_123".to_string()));
    }

    #[test]
    fn test_stripe_method_details_minimal() {
        let details = StripeMethodDetails::default();
        let json = serde_json::to_string(&details).unwrap();
        assert_eq!(json, "{}");
    }
}
