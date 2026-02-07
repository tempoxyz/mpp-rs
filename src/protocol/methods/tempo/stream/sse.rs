//! Server-Sent Events formatting for stream receipts.

use super::types::StreamReceipt;

/// Format a stream receipt as a Server-Sent Event.
///
/// Produces a valid SSE event string with `event: payment-receipt`
/// and the receipt JSON as the `data` field.
///
/// # Example
///
/// ```ignore
/// let sse_event = format_receipt_event(&receipt);
/// // Returns: "event: payment-receipt\ndata: {\"method\":\"tempo\",...}\n\n"
/// ```
pub fn format_receipt_event(receipt: &StreamReceipt) -> String {
    format!(
        "event: payment-receipt\ndata: {}\n\n",
        serde_json::to_string(receipt).unwrap_or_default()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_receipt_event() {
        let receipt = StreamReceipt {
            method: "tempo".to_string(),
            intent: "stream".to_string(),
            status: "success".to_string(),
            timestamp: "2026-02-07T12:00:00Z".to_string(),
            reference: "0xchannel".to_string(),
            challenge_id: "c1".to_string(),
            channel_id: "0xchannel".to_string(),
            accepted_cumulative: "5000000".to_string(),
            spent: "1000000".to_string(),
            units: Some(3),
            tx_hash: None,
        };

        let event = format_receipt_event(&receipt);
        assert!(event.starts_with("event: payment-receipt\n"));
        assert!(event.contains("data: "));
        assert!(event.ends_with("\n\n"));
        assert!(event.contains("\"method\":\"tempo\""));
        assert!(event.contains("\"intent\":\"stream\""));
    }
}
