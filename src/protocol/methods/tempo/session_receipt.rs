//! Session receipt type for Tempo session payments.

use serde::{Deserialize, Serialize};

use crate::protocol::core::{MethodName, Receipt, ReceiptStatus};

/// Session receipt for Tempo session/pay-as-you-go payments.
///
/// Extends the base [`Receipt`] with session-specific fields like channel ID,
/// cumulative amounts, and units consumed. The `reference` field mirrors
/// `channel_id` for compatibility with the base receipt contract.
///
/// # Examples
///
/// ```
/// use mpp::protocol::methods::tempo::SessionReceipt;
///
/// let receipt = SessionReceipt::new(
///     "2026-01-01T00:00:00Z",
///     "challenge-123",
///     "0xabc",
///     "5000",
///     "1000",
/// );
/// assert_eq!(receipt.method, "tempo");
/// assert_eq!(receipt.intent, "session");
/// assert_eq!(receipt.status, "success");
/// assert_eq!(receipt.reference, "0xabc");
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionReceipt {
    /// Payment method (always "tempo").
    pub method: String,

    /// Payment intent (always "session").
    pub intent: String,

    /// Receipt status (always "success").
    pub status: String,

    /// Timestamp (ISO 8601).
    pub timestamp: String,

    /// Payment reference (channelId). Satisfies the base Receipt contract.
    pub reference: String,

    /// Challenge identifier.
    #[serde(rename = "challengeId")]
    pub challenge_id: String,

    /// Channel identifier (hex).
    #[serde(rename = "channelId")]
    pub channel_id: String,

    /// Highest accepted cumulative voucher amount.
    #[serde(rename = "acceptedCumulative")]
    pub accepted_cumulative: String,

    /// Amount spent in this session.
    pub spent: String,

    /// Number of units consumed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub units: Option<u64>,

    /// Settlement transaction hash (hex).
    #[serde(rename = "txHash", skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
}

impl SessionReceipt {
    /// Create a new session receipt with default method/intent/status.
    ///
    /// Sets `reference` to `channel_id` for base receipt compatibility.
    #[must_use]
    pub fn new(
        timestamp: impl Into<String>,
        challenge_id: impl Into<String>,
        channel_id: impl Into<String>,
        accepted_cumulative: impl Into<String>,
        spent: impl Into<String>,
    ) -> Self {
        let channel_id = channel_id.into();
        Self {
            method: "tempo".to_string(),
            intent: "session".to_string(),
            status: "success".to_string(),
            timestamp: timestamp.into(),
            reference: channel_id.clone(),
            challenge_id: challenge_id.into(),
            channel_id,
            accepted_cumulative: accepted_cumulative.into(),
            spent: spent.into(),
            units: None,
            tx_hash: None,
        }
    }

    /// Convert to a base [`Receipt`] for protocol-level compatibility.
    #[must_use]
    pub fn to_base_receipt(&self) -> Receipt {
        Receipt {
            status: ReceiptStatus::Success,
            method: MethodName::new(&self.method),
            timestamp: self.timestamp.clone(),
            reference: self.reference.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_sets_defaults() {
        let receipt = SessionReceipt::new(
            "2026-01-01T00:00:00Z",
            "challenge-123",
            "0xabc",
            "5000",
            "1000",
        );

        assert_eq!(receipt.method, "tempo");
        assert_eq!(receipt.intent, "session");
        assert_eq!(receipt.status, "success");
        assert_eq!(receipt.timestamp, "2026-01-01T00:00:00Z");
        assert_eq!(receipt.reference, "0xabc");
        assert_eq!(receipt.challenge_id, "challenge-123");
        assert_eq!(receipt.channel_id, "0xabc");
        assert_eq!(receipt.accepted_cumulative, "5000");
        assert_eq!(receipt.spent, "1000");
        assert!(receipt.units.is_none());
        assert!(receipt.tx_hash.is_none());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut receipt = SessionReceipt::new(
            "2026-01-01T00:00:00Z",
            "challenge-123",
            "0xabc",
            "5000",
            "1000",
        );
        receipt.units = Some(42);
        receipt.tx_hash = Some("0xdef".to_string());

        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: SessionReceipt = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.method, receipt.method);
        assert_eq!(parsed.intent, receipt.intent);
        assert_eq!(parsed.status, receipt.status);
        assert_eq!(parsed.timestamp, receipt.timestamp);
        assert_eq!(parsed.reference, receipt.reference);
        assert_eq!(parsed.challenge_id, receipt.challenge_id);
        assert_eq!(parsed.channel_id, receipt.channel_id);
        assert_eq!(parsed.accepted_cumulative, receipt.accepted_cumulative);
        assert_eq!(parsed.spent, receipt.spent);
        assert_eq!(parsed.units, Some(42));
        assert_eq!(parsed.tx_hash, Some("0xdef".to_string()));
    }

    #[test]
    fn test_serialization_camel_case_keys() {
        let receipt = SessionReceipt::new(
            "2026-01-01T00:00:00Z",
            "challenge-123",
            "0xabc",
            "5000",
            "1000",
        );

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"challengeId\""));
        assert!(json.contains("\"channelId\""));
        assert!(json.contains("\"acceptedCumulative\""));
        // Optional None fields should be omitted
        assert!(!json.contains("\"units\""));
        assert!(!json.contains("\"txHash\""));
    }

    #[test]
    fn test_serialization_optional_fields_present() {
        let mut receipt = SessionReceipt::new(
            "2026-01-01T00:00:00Z",
            "challenge-123",
            "0xabc",
            "5000",
            "1000",
        );
        receipt.units = Some(10);
        receipt.tx_hash = Some("0x123".to_string());

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"units\":10"));
        assert!(json.contains("\"txHash\":\"0x123\""));
    }

    #[test]
    fn test_to_base_receipt() {
        let receipt = SessionReceipt::new(
            "2026-01-01T00:00:00Z",
            "challenge-123",
            "0xabc",
            "5000",
            "1000",
        );

        let base = receipt.to_base_receipt();
        assert!(base.is_success());
        assert_eq!(base.method.as_str(), "tempo");
        assert_eq!(base.timestamp, "2026-01-01T00:00:00Z");
        assert_eq!(base.reference, "0xabc");
    }
}
