//! SSE (Server-Sent Events) utilities for metered streaming payments.
//!
//! Provides event formatting/parsing and helpers for building HTTP responses
//! from SSE streams.
//!
//! # Event types
//!
//! Three SSE event types are used by mpp streaming:
//! - `message` — application data
//! - `payment-need-voucher` — balance exhausted, client should send voucher
//! - `payment-receipt` — final receipt

use serde::{Deserialize, Serialize};

use crate::protocol::methods::tempo::stream_receipt::StreamReceipt;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// SSE event emitted when session balance is exhausted mid-stream.
///
/// The client responds by sending a new voucher credential.
///
/// # Example
///
/// ```
/// use mpp::server::sse::NeedVoucherEvent;
///
/// let event = NeedVoucherEvent {
///     channel_id: "0xabc".into(),
///     required_cumulative: "2000000".into(),
///     accepted_cumulative: "1000000".into(),
///     deposit: "5000000".into(),
/// };
/// assert_eq!(event.channel_id, "0xabc");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NeedVoucherEvent {
    pub channel_id: String,
    pub required_cumulative: String,
    pub accepted_cumulative: String,
    pub deposit: String,
}

impl PartialEq for NeedVoucherEvent {
    fn eq(&self, other: &Self) -> bool {
        self.channel_id == other.channel_id
            && self.required_cumulative == other.required_cumulative
            && self.accepted_cumulative == other.accepted_cumulative
            && self.deposit == other.deposit
    }
}

/// Parsed SSE event (discriminated union).
///
/// # Example
///
/// ```
/// use mpp::server::sse::{parse_event, SseEvent};
///
/// let raw = "event: message\ndata: hello\n\n";
/// assert_eq!(parse_event(raw), Some(SseEvent::Message("hello".into())));
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum SseEvent {
    /// Application data.
    Message(String),
    /// Balance exhausted — client should send a new voucher.
    PaymentNeedVoucher(NeedVoucherEvent),
    /// Final receipt for the stream session.
    PaymentReceipt(StreamReceipt),
}

// ---------------------------------------------------------------------------
// Event formatting
// ---------------------------------------------------------------------------

/// Format a stream receipt as a Server-Sent Event.
///
/// # Example
///
/// ```
/// use mpp::server::sse::format_receipt_event;
/// use mpp::protocol::methods::tempo::stream_receipt::StreamReceipt;
///
/// let receipt = StreamReceipt::new(
///     "2025-01-01T00:00:00Z",
///     "ch-1",
///     "0xabc",
///     "1000000",
///     "500000",
/// );
/// let event = format_receipt_event(&receipt);
/// assert!(event.starts_with("event: payment-receipt\ndata: "));
/// assert!(event.ends_with("\n\n"));
/// ```
pub fn format_receipt_event(receipt: &StreamReceipt) -> String {
    format!(
        "event: payment-receipt\ndata: {}\n\n",
        serde_json::to_string(receipt).expect("StreamReceipt serialization cannot fail")
    )
}

/// Format a need-voucher event as a Server-Sent Event.
///
/// Emitted when the channel balance is exhausted mid-stream.
///
/// # Example
///
/// ```
/// use mpp::server::sse::{format_need_voucher_event, NeedVoucherEvent};
///
/// let event = format_need_voucher_event(&NeedVoucherEvent {
///     channel_id: "0xabc".into(),
///     required_cumulative: "2000000".into(),
///     accepted_cumulative: "1000000".into(),
///     deposit: "5000000".into(),
/// });
/// assert!(event.starts_with("event: payment-need-voucher\ndata: "));
/// ```
pub fn format_need_voucher_event(event: &NeedVoucherEvent) -> String {
    format!(
        "event: payment-need-voucher\ndata: {}\n\n",
        serde_json::to_string(event).expect("NeedVoucherEvent serialization cannot fail")
    )
}

/// Format application data as a Server-Sent Event.
///
/// # Example
///
/// ```
/// use mpp::server::sse::format_message_event;
///
/// assert_eq!(format_message_event("hello"), "event: message\ndata: hello\n\n");
/// ```
pub fn format_message_event(data: &str) -> String {
    format!("event: message\ndata: {data}\n\n")
}

// ---------------------------------------------------------------------------
// Event parsing
// ---------------------------------------------------------------------------

/// Parse a raw SSE event string into a typed event.
///
/// Handles the three event types used by mpp streaming:
/// - `message` (default / no event field) — application data
/// - `payment-need-voucher` — balance exhausted
/// - `payment-receipt` — final receipt
///
/// Returns `None` if no `data:` lines are present.
///
/// # Example
///
/// ```
/// use mpp::server::sse::{parse_event, SseEvent};
///
/// let raw = "event: message\ndata: hello world\n\n";
/// assert_eq!(parse_event(raw), Some(SseEvent::Message("hello world".into())));
///
/// assert_eq!(parse_event(""), None);
/// ```
pub fn parse_event(raw: &str) -> Option<SseEvent> {
    let mut event_type = "message";
    let mut data_lines: Vec<&str> = Vec::new();

    for line in raw.split('\n') {
        if let Some(rest) = line.strip_prefix("event: ") {
            event_type = rest.trim();
        } else if let Some(rest) = line.strip_prefix("data: ") {
            data_lines.push(rest);
        } else if line == "data:" {
            data_lines.push("");
        }
    }

    if data_lines.is_empty() {
        return None;
    }

    let data = data_lines.join("\n");

    match event_type {
        "message" => Some(SseEvent::Message(data)),
        "payment-need-voucher" => serde_json::from_str::<NeedVoucherEvent>(&data)
            .ok()
            .map(SseEvent::PaymentNeedVoucher),
        "payment-receipt" => serde_json::from_str::<StreamReceipt>(&data)
            .ok()
            .map(SseEvent::PaymentReceipt),
        _ => Some(SseEvent::Message(data)),
    }
}

/// Check whether a content type header starts with `text/event-stream`.
///
/// Comparison is case-insensitive and ignores parameters (e.g., `charset`).
///
/// # Example
///
/// ```
/// use mpp::server::sse::is_event_stream;
///
/// assert!(is_event_stream("text/event-stream"));
/// assert!(is_event_stream("Text/Event-Stream; charset=utf-8"));
/// assert!(!is_event_stream("application/json"));
/// ```
pub fn is_event_stream(content_type: &str) -> bool {
    content_type.to_lowercase().starts_with("text/event-stream")
}

// ---------------------------------------------------------------------------
// Metered SSE stream
// ---------------------------------------------------------------------------

/// Options for [`serve`].
#[cfg(feature = "tempo")]
pub struct ServeOptions<G> {
    /// Channel store for balance tracking.
    pub store: std::sync::Arc<dyn crate::protocol::methods::tempo::session_method::ChannelStore>,
    /// Channel ID (hex).
    pub channel_id: String,
    /// Challenge ID for the receipt.
    pub challenge_id: String,
    /// Cost per tick (emitted value) in base units.
    pub tick_cost: u128,
    /// The async generator producing application data.
    pub generate: G,
    /// Polling interval in ms when `wait_for_update` is not available. Default: 100.
    pub poll_interval_ms: u64,
}

/// Wrap an async stream with payment metering, producing SSE event bytes.
///
/// For each value from `generate`:
/// 1. Deducts `tick_cost` from the channel balance atomically
/// 2. If balance sufficient, yields `event: message\ndata: {value}\n\n`
/// 3. If balance exhausted, yields `event: payment-need-voucher\n...` and
///    waits for the client to top up
/// 4. On completion, yields a final `event: payment-receipt\n...`
///
/// Returns a [`tokio::sync::mpsc::Receiver`] that yields `String` SSE events.
#[cfg(feature = "tempo")]
pub fn serve<G>(options: ServeOptions<G>) -> tokio::sync::mpsc::Receiver<String>
where
    G: futures_core::Stream<Item = String> + Send + Unpin + 'static,
{
    use crate::protocol::methods::tempo::session_method::deduct_from_channel;

    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let ServeOptions {
        store,
        channel_id,
        challenge_id,
        tick_cost,
        generate,
        poll_interval_ms,
    } = options;

    tokio::spawn(async move {
        let mut stream = std::pin::pin!(generate);

        while let Some(value) = next_item(&mut stream).await {
            // Try to charge, waiting for top-up if insufficient
            loop {
                match deduct_from_channel(&*store, &channel_id, tick_cost).await {
                    Ok(_state) => break,
                    Err(_) => {
                        // Emit need-voucher event
                        if let Ok(Some(ch)) = store.get_channel(&channel_id).await {
                            let event = format_need_voucher_event(&NeedVoucherEvent {
                                channel_id: channel_id.clone(),
                                required_cumulative: (ch.spent + tick_cost).to_string(),
                                accepted_cumulative: ch.highest_voucher_amount.to_string(),
                                deposit: ch.deposit.to_string(),
                            });
                            if tx.send(event).await.is_err() {
                                return;
                            }
                        }

                        // Wait for channel update or poll interval
                        tokio::select! {
                            _ = store.wait_for_update(&channel_id) => {},
                            _ = tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)) => {},
                        }
                    }
                }
            }

            let event = format_message_event(&value);
            if tx.send(event).await.is_err() {
                return;
            }
        }

        // Emit final receipt
        if let Ok(Some(ch)) = store.get_channel(&channel_id).await {
            let mut receipt = StreamReceipt::new(
                &now_iso8601(),
                &challenge_id,
                &channel_id,
                &ch.highest_voucher_amount.to_string(),
                &ch.spent.to_string(),
            );
            receipt.units = Some(ch.units);
            let event = format_receipt_event(&receipt);
            let _ = tx.send(event).await;
        }
    });

    rx
}

/// Poll the next item from a stream (avoids depending on StreamExt).
#[cfg(feature = "tempo")]
async fn next_item<S: futures_core::Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
    use std::future::poll_fn;
    use std::pin::Pin;

    poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

#[cfg(feature = "tempo")]
fn now_iso8601() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

// ---------------------------------------------------------------------------
// SSE response helpers
// ---------------------------------------------------------------------------

/// SSE response headers.
///
/// Returns the standard headers required for an SSE response:
/// `Cache-Control`, `Connection`, and `Content-Type`.
///
/// # Example
///
/// ```
/// use mpp::server::sse::sse_headers;
///
/// let headers = sse_headers();
/// assert_eq!(headers.len(), 3);
/// assert!(headers.iter().any(|(k, _)| *k == "Content-Type"));
/// ```
pub fn sse_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Cache-Control", "no-cache, no-transform"),
        ("Connection", "keep-alive"),
        ("Content-Type", "text/event-stream; charset=utf-8"),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Format tests --

    #[test]
    fn test_format_receipt_event() {
        let mut receipt =
            StreamReceipt::new("2025-01-01T00:00:00Z", "ch-1", "0xabc", "1000000", "500000");
        receipt.units = Some(5);
        let event = format_receipt_event(&receipt);
        assert!(event.starts_with("event: payment-receipt\ndata: "));
        assert!(event.ends_with("\n\n"));
        assert!(event.contains("\"challengeId\":\"ch-1\""));
    }

    #[test]
    fn test_format_need_voucher_event() {
        let nv = NeedVoucherEvent {
            channel_id: "0xabc".into(),
            required_cumulative: "2000000".into(),
            accepted_cumulative: "1000000".into(),
            deposit: "5000000".into(),
        };
        let event = format_need_voucher_event(&nv);
        assert!(event.starts_with("event: payment-need-voucher\ndata: "));
        assert!(event.ends_with("\n\n"));
        assert!(event.contains("\"channelId\":\"0xabc\""));
    }

    #[test]
    fn test_format_message_event() {
        let event = format_message_event("hello world");
        assert_eq!(event, "event: message\ndata: hello world\n\n");
    }

    // -- Parse tests --

    #[test]
    fn test_parse_event_message() {
        let raw = "event: message\ndata: hello world\n\n";
        assert_eq!(
            parse_event(raw),
            Some(SseEvent::Message("hello world".into()))
        );
    }

    #[test]
    fn test_parse_event_default_message() {
        let raw = "data: no event field\n\n";
        assert_eq!(
            parse_event(raw),
            Some(SseEvent::Message("no event field".into()))
        );
    }

    #[test]
    fn test_parse_event_need_voucher() {
        let data = serde_json::json!({
            "channelId": "0xabc",
            "requiredCumulative": "2000000",
            "acceptedCumulative": "1000000",
            "deposit": "5000000"
        });
        let raw = format!("event: payment-need-voucher\ndata: {}\n\n", data);
        let parsed = parse_event(&raw);
        assert!(matches!(parsed, Some(SseEvent::PaymentNeedVoucher(_))));
        if let Some(SseEvent::PaymentNeedVoucher(nv)) = parsed {
            assert_eq!(nv.channel_id, "0xabc");
            assert_eq!(nv.required_cumulative, "2000000");
        }
    }

    #[test]
    fn test_parse_event_receipt() {
        let data = serde_json::json!({
            "method": "tempo",
            "intent": "session",
            "status": "success",
            "timestamp": "2025-01-01T00:00:00Z",
            "reference": "0xabc",
            "challengeId": "ch-1",
            "channelId": "0xabc",
            "acceptedCumulative": "1000000",
            "spent": "500000",
            "units": 5
        });
        let raw = format!("event: payment-receipt\ndata: {}\n\n", data);
        let parsed = parse_event(&raw);
        assert!(matches!(parsed, Some(SseEvent::PaymentReceipt(_))));
        if let Some(SseEvent::PaymentReceipt(r)) = parsed {
            assert_eq!(r.challenge_id, "ch-1");
            assert_eq!(r.units, Some(5));
            assert_eq!(r.tx_hash, None);
        }
    }

    #[test]
    fn test_parse_event_empty() {
        assert_eq!(parse_event(""), None);
        assert_eq!(parse_event("\n\n"), None);
    }

    #[test]
    fn test_parse_event_unknown_type() {
        let raw = "event: custom-type\ndata: fallback\n\n";
        assert_eq!(parse_event(raw), Some(SseEvent::Message("fallback".into())));
    }

    #[test]
    fn test_parse_event_multiline_data() {
        let raw = "event: message\ndata: line1\ndata: line2\ndata: line3\n\n";
        assert_eq!(
            parse_event(raw),
            Some(SseEvent::Message("line1\nline2\nline3".into()))
        );
    }

    // -- is_event_stream tests --

    #[test]
    fn test_is_event_stream() {
        assert!(is_event_stream("text/event-stream"));
        assert!(is_event_stream("text/event-stream; charset=utf-8"));
        assert!(is_event_stream("Text/Event-Stream"));
        assert!(is_event_stream("TEXT/EVENT-STREAM; charset=utf-8"));
        assert!(!is_event_stream("application/json"));
        assert!(!is_event_stream("text/plain"));
        assert!(!is_event_stream(""));
    }

    // -- StreamReceipt tests --

    #[test]
    fn test_stream_receipt_new() {
        let mut receipt =
            StreamReceipt::new("2025-01-01T00:00:00Z", "ch-1", "0xabc", "1000000", "500000");
        receipt.units = Some(5);
        receipt.tx_hash = Some("0xtx".into());
        assert_eq!(receipt.method, "tempo");
        assert_eq!(receipt.intent, "session");
        assert_eq!(receipt.status, "success");
        assert_eq!(receipt.reference, "0xabc");
        assert_eq!(receipt.challenge_id, "ch-1");
        assert_eq!(receipt.channel_id, "0xabc");
        assert_eq!(receipt.units, Some(5));
        assert_eq!(receipt.tx_hash, Some("0xtx".into()));
        assert!(!receipt.timestamp.is_empty());
    }

    #[test]
    fn test_stream_receipt_serialization() {
        let mut receipt =
            StreamReceipt::new("2025-01-01T00:00:00Z", "ch-1", "0xabc", "1000000", "500000");
        receipt.units = Some(5);
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"challengeId\":\"ch-1\""));
        assert!(json.contains("\"acceptedCumulative\":\"1000000\""));
        assert!(!json.contains("\"txHash\""));

        let roundtrip: StreamReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.challenge_id, "ch-1");
        assert_eq!(roundtrip.units, Some(5));
        assert_eq!(roundtrip.tx_hash, None);
    }

    #[test]
    fn test_need_voucher_event_serialization() {
        let event = NeedVoucherEvent {
            channel_id: "0xabc".into(),
            required_cumulative: "2000000".into(),
            accepted_cumulative: "1000000".into(),
            deposit: "5000000".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"channelId\":\"0xabc\""));
        assert!(json.contains("\"requiredCumulative\":\"2000000\""));
        assert!(json.contains("\"acceptedCumulative\":\"1000000\""));
        assert!(json.contains("\"deposit\":\"5000000\""));

        let roundtrip: NeedVoucherEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.channel_id, "0xabc");
        assert_eq!(roundtrip.required_cumulative, "2000000");
    }
}
