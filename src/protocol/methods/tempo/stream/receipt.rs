//! Stream receipt creation and serialization.

use crate::protocol::core::base64url_encode;
use alloy::primitives::FixedBytes;

use super::types::StreamReceipt;

/// Create a stream receipt.
pub fn create_stream_receipt(params: CreateStreamReceiptParams) -> StreamReceipt {
    StreamReceipt {
        method: "tempo".to_string(),
        intent: "stream".to_string(),
        status: "success".to_string(),
        timestamp: time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
        reference: params.channel_id.to_string(),
        challenge_id: params.challenge_id,
        channel_id: params.channel_id.to_string(),
        accepted_cumulative: params.accepted_cumulative.to_string(),
        spent: params.spent.to_string(),
        units: params.units,
        tx_hash: params.tx_hash,
    }
}

/// Parameters for creating a stream receipt.
pub struct CreateStreamReceiptParams {
    pub challenge_id: String,
    pub channel_id: FixedBytes<32>,
    pub accepted_cumulative: u128,
    pub spent: u128,
    pub units: Option<u64>,
    pub tx_hash: Option<String>,
}

/// Serialize a stream receipt to the Payment-Receipt header format (base64url JSON).
pub fn serialize_stream_receipt(receipt: &StreamReceipt) -> String {
    let json = serde_json::to_string(receipt).unwrap_or_default();
    base64url_encode(json.as_bytes())
}

/// Deserialize a Payment-Receipt header value to a stream receipt.
pub fn deserialize_stream_receipt(
    encoded: &str,
) -> Result<StreamReceipt, crate::error::MppError> {
    let bytes = crate::protocol::core::base64url_decode(encoded)?;
    let json = String::from_utf8(bytes)?;
    let receipt: StreamReceipt = serde_json::from_str(&json)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_channel_id() -> FixedBytes<32> {
        FixedBytes::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1,
        ])
    }

    #[test]
    fn test_create_stream_receipt() {
        let receipt = create_stream_receipt(CreateStreamReceiptParams {
            challenge_id: "c1".to_string(),
            channel_id: test_channel_id(),
            accepted_cumulative: 5_000_000,
            spent: 1_000_000,
            units: Some(3),
            tx_hash: None,
        });

        assert_eq!(receipt.method, "tempo");
        assert_eq!(receipt.intent, "stream");
        assert_eq!(receipt.status, "success");
        assert_eq!(receipt.challenge_id, "c1");
        assert_eq!(receipt.accepted_cumulative, "5000000");
        assert_eq!(receipt.spent, "1000000");
        assert_eq!(receipt.units, Some(3));
        assert!(receipt.tx_hash.is_none());
    }

    #[test]
    fn test_serialize_deserialize_round_trip() {
        let receipt = create_stream_receipt(CreateStreamReceiptParams {
            challenge_id: "c1".to_string(),
            channel_id: test_channel_id(),
            accepted_cumulative: 5_000_000,
            spent: 1_000_000,
            units: Some(3),
            tx_hash: Some("0xdeadbeef".to_string()),
        });

        let encoded = serialize_stream_receipt(&receipt);
        let decoded = deserialize_stream_receipt(&encoded).unwrap();

        assert_eq!(decoded.method, "tempo");
        assert_eq!(decoded.challenge_id, "c1");
        assert_eq!(decoded.accepted_cumulative, "5000000");
        assert_eq!(decoded.spent, "1000000");
        assert_eq!(decoded.units, Some(3));
        assert_eq!(decoded.tx_hash, Some("0xdeadbeef".to_string()));
    }
}
