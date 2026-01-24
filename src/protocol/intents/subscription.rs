//! Subscription intent request type.
//!
//! The subscription intent represents a recurring payment setup.

use serde::{Deserialize, Serialize};

/// Subscription request (for subscription intent).
///
/// Represents a recurring payment request with a specified interval.
/// All fields are strings except for interval which is numeric.
///
/// # Examples
///
/// ```
/// use mpp_rs::protocol::intents::SubscriptionRequest;
///
/// let req = SubscriptionRequest {
///     asset: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
///     destination: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string(),
///     amount: "1000000".to_string(),
///     interval: 86400, // daily
///     expires: "2025-12-31T23:59:59Z".to_string(),
///     fee_payer: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SubscriptionRequest {
    /// Token/asset contract address or identifier
    pub asset: String,

    /// Subscription recipient
    pub destination: String,

    /// Amount per interval in base units
    pub amount: String,

    /// Interval in seconds
    pub interval: u64,

    /// Subscription expiration (ISO 8601)
    pub expires: String,

    /// Whether server pays transaction fees
    #[serde(rename = "feePayer", skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,
}

impl SubscriptionRequest {
    /// Get the interval as a human-readable duration.
    pub fn interval_description(&self) -> String {
        let seconds = self.interval;
        if seconds.is_multiple_of(86400) {
            let days = seconds / 86400;
            if days == 1 {
                "daily".to_string()
            } else {
                format!("every {} days", days)
            }
        } else if seconds.is_multiple_of(3600) {
            let hours = seconds / 3600;
            format!("every {} hours", hours)
        } else if seconds.is_multiple_of(60) {
            let minutes = seconds / 60;
            format!("every {} minutes", minutes)
        } else {
            format!("every {} seconds", seconds)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_request_serialization() {
        let req = SubscriptionRequest {
            asset: "0x123".to_string(),
            destination: "0x456".to_string(),
            amount: "1000000".to_string(),
            interval: 86400,
            expires: "2025-12-31T23:59:59Z".to_string(),
            fee_payer: Some(false),
        };

        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"interval\":86400"));
        assert!(json.contains("\"feePayer\":false"));

        let parsed: SubscriptionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.interval, 86400);
    }

    #[test]
    fn test_interval_description() {
        let daily = SubscriptionRequest {
            interval: 86400,
            ..Default::default()
        };
        assert_eq!(daily.interval_description(), "daily");

        let weekly = SubscriptionRequest {
            interval: 86400 * 7,
            ..Default::default()
        };
        assert_eq!(weekly.interval_description(), "every 7 days");

        let hourly = SubscriptionRequest {
            interval: 3600,
            ..Default::default()
        };
        assert_eq!(hourly.interval_description(), "every 1 hours");
    }
}
