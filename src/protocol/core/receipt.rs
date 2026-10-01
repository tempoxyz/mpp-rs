//! Payment receipt.

use serde::{Deserialize, Serialize};

use super::types::{MethodName, ReceiptStatus};

/// Payment receipt from server (parsed from Payment-Receipt header).
///
/// Per IETF spec, contains: status, method, timestamp, reference. Payment
/// methods MAY add fields; the Tempo subscription method adds `subscriptionId`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Receipt status (always "success")
    pub status: ReceiptStatus,

    /// Payment method used
    pub method: MethodName,

    /// Timestamp (ISO 8601)
    pub timestamp: String,

    /// Transaction hash or reference
    pub reference: String,

    /// Merchant correlation reference, echoed from the credential payload.
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,

    /// Server-issued subscription identifier, present on receipts for the
    /// subscription intent (activation and renewal).
    #[serde(rename = "subscriptionId", skip_serializing_if = "Option::is_none")]
    pub subscription_id: Option<String>,

    /// Method-specific receipt fields not defined by the core protocol.
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

impl Receipt {
    /// Create a successful payment receipt.
    #[must_use]
    pub fn success(method: impl Into<MethodName>, reference: impl Into<String>) -> Self {
        Self {
            status: ReceiptStatus::Success,
            method: method.into(),
            timestamp: now_iso8601(),
            reference: reference.into(),
            external_id: None,
            subscription_id: None,
            extensions: serde_json::Map::new(),
        }
    }

    /// Set the merchant correlation reference.
    #[must_use]
    pub fn with_external_id(mut self, external_id: impl Into<String>) -> Self {
        self.external_id = Some(external_id.into());
        self
    }

    /// Set the server-issued subscription identifier.
    #[must_use]
    pub fn with_subscription_id(mut self, subscription_id: impl Into<String>) -> Self {
        self.subscription_id = Some(subscription_id.into());
        self
    }

    /// Check if the payment was successful.
    pub fn is_success(&self) -> bool {
        self.status == ReceiptStatus::Success
    }

    /// Format as Payment-Receipt header value.
    pub fn to_header(&self) -> crate::error::Result<String> {
        super::format_receipt(self)
    }

    /// Parse a Receipt from a Payment-Receipt header value.
    ///
    /// This is a convenience method equivalent to [`parse_receipt`](super::parse_receipt).
    pub fn from_header(header: &str) -> crate::error::Result<Self> {
        super::parse_receipt(header)
    }

    /// Parse a Receipt from a response's Payment-Receipt header.
    ///
    /// Extracts the `Payment-Receipt` header value and parses it.
    ///
    /// # Arguments
    /// * `receipt_header` - The value of the Payment-Receipt header
    pub fn from_response(receipt_header: &str) -> crate::error::Result<Self> {
        Self::from_header(receipt_header)
    }
}

fn now_iso8601() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Extract the `txHash` field from a base64url-encoded receipt JSON.
///
/// The receipt is base64url-encoded JSON that may contain a `txHash` field
/// with the on-chain transaction hash.
pub fn extract_tx_hash(receipt_b64: &str) -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let decoded = URL_SAFE_NO_PAD.decode(receipt_b64.trim()).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json.get("txHash")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_receipt_status() {
        let success = Receipt {
            status: ReceiptStatus::Success,
            method: "tempo".into(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            reference: "0xabc".to_string(),
            external_id: None,
            subscription_id: None,
            extensions: serde_json::Map::new(),
        };
        assert!(success.is_success());
        assert!(success.external_id.is_none());
    }

    #[test]
    fn test_receipt_with_external_id() {
        let receipt = Receipt::success("tempo", "0xabc").with_external_id("order-123");
        assert_eq!(receipt.external_id.as_deref(), Some("order-123"));

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"externalId\":\"order-123\""));

        let parsed: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.external_id.as_deref(), Some("order-123"));

        let bare = Receipt::success("tempo", "0xabc");
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("externalId"));
    }

    #[test]
    fn test_receipt_with_subscription_id() {
        let receipt = Receipt::success("tempo", "0xabc").with_subscription_id("sub_123");
        assert_eq!(receipt.subscription_id.as_deref(), Some("sub_123"));

        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"subscriptionId\":\"sub_123\""));

        let parsed: Receipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.subscription_id.as_deref(), Some("sub_123"));

        let bare = Receipt::success("tempo", "0xabc");
        let bare_json = serde_json::to_string(&bare).unwrap();
        assert!(!bare_json.contains("subscriptionId"));
    }

    #[test]
    fn test_receipt_from_header() {
        let receipt = Receipt::success("tempo", "0xabc123");
        let header = receipt.to_header().unwrap();
        let parsed = Receipt::from_header(&header).unwrap();
        assert!(parsed.is_success());
        assert_eq!(parsed.reference, "0xabc123");
    }

    #[test]
    fn test_extract_tx_hash_valid() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let json = serde_json::json!({"txHash": "0xabc123", "status": "success"});
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        assert_eq!(extract_tx_hash(&encoded), Some("0xabc123".to_string()));
    }

    #[test]
    fn test_extract_tx_hash_missing() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let json = serde_json::json!({"status": "success"});
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        assert_eq!(extract_tx_hash(&encoded), None);
    }

    #[test]
    fn test_extract_tx_hash_empty() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let json = serde_json::json!({"txHash": ""});
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        assert_eq!(extract_tx_hash(&encoded), None);
    }

    #[test]
    fn test_extract_tx_hash_invalid_base64() {
        assert_eq!(extract_tx_hash("not-valid-base64!!!"), None);
    }

    #[test]
    fn test_extract_tx_hash_invalid_json() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let encoded = URL_SAFE_NO_PAD.encode(b"not json");
        assert_eq!(extract_tx_hash(&encoded), None);
    }
}
