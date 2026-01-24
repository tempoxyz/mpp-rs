//! Stripe charge payload types.
//!
//! These types have ZERO blockchain dependencies - only serde.

use serde::{Deserialize, Serialize};

/// Stripe charge payload.
///
/// For Stripe payments, the payload contains a Stripe Payment Token (SPT)
/// that authorizes the payment.
///
/// # Examples
///
/// ```
/// use mpp_rs::protocol::methods::stripe::StripeChargePayload;
///
/// let payload = StripeChargePayload {
///     spt: "spt_abc123def456".to_string(),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeChargePayload {
    /// Stripe Payment Token
    pub spt: String,
}

impl StripeChargePayload {
    /// Create a new Stripe charge payload.
    pub fn new(spt: impl Into<String>) -> Self {
        Self { spt: spt.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stripe_charge_payload_serialization() {
        let payload = StripeChargePayload::new("spt_test123");

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"spt\":\"spt_test123\""));

        let parsed: StripeChargePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.spt, "spt_test123");
    }
}
