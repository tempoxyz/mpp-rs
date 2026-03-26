//! SSE (Server-Sent Events) utilities for metered session payments.
//!
//! Provides event formatting/parsing and helpers for building HTTP responses
//! from SSE streams.
//!
//! # Event types
//!
//! Three SSE event types are used by mpp sessions:
//! - `message` — application data
//! - `payment-need-voucher` — balance exhausted, client should send voucher
//! - `payment-receipt` — final receipt

use serde::{Deserialize, Serialize};

#[cfg(feature = "tempo")]
use crate::protocol::methods::tempo::session_receipt::SessionReceipt;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// SSE event emitted when session balance is exhausted mid-session.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NeedVoucherEvent {
    pub channel_id: String,
    pub required_cumulative: String,
    pub accepted_cumulative: String,
    pub deposit: String,
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
    /// Final receipt for the session.
    #[cfg(feature = "tempo")]
    PaymentReceipt(SessionReceipt),
}

// ---------------------------------------------------------------------------
// Event formatting
// ---------------------------------------------------------------------------

/// Format a session receipt as a Server-Sent Event.
///
/// # Example
///
/// ```
/// use mpp::server::sse::format_receipt_event;
/// use mpp::protocol::methods::tempo::session_receipt::SessionReceipt;
///
/// let receipt = SessionReceipt::new(
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
#[cfg(feature = "tempo")]
pub fn format_receipt_event(receipt: &SessionReceipt) -> String {
    format!(
        "event: payment-receipt\ndata: {}\n\n",
        serde_json::to_string(receipt).expect("SessionReceipt serialization cannot fail")
    )
}

/// Format a need-voucher event as a Server-Sent Event.
///
/// Emitted when the channel balance is exhausted mid-session.
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
/// Handles the three event types used by mpp sessions:
/// - `message` (default / no event field) — application data
/// - `payment-need-voucher` — balance exhausted
/// - `payment-receipt` — final receipt (requires `tempo` feature;
///   without it, receipt events are returned as `Message`)
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
        #[cfg(feature = "tempo")]
        "payment-receipt" => serde_json::from_str::<SessionReceipt>(&data)
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
/// Returns a [`Stream`](futures_core::Stream) that yields `String` SSE events.
#[cfg(feature = "tempo")]
pub fn serve<G>(
    options: ServeOptions<G>,
) -> std::pin::Pin<Box<dyn futures_core::Stream<Item = String> + Send>>
where
    G: futures_core::Stream<Item = String> + Send + Unpin + 'static,
{
    use crate::protocol::methods::tempo::session_method::deduct_from_channel;

    let ServeOptions {
        store,
        channel_id,
        challenge_id,
        tick_cost,
        generate,
        poll_interval_ms,
    } = options;

    Box::pin(async_stream::stream! {
        let mut stream = std::pin::pin!(generate);

        while let Some(value) = next_item(&mut stream).await {
            // Try to charge, waiting for top-up if insufficient
            loop {
                match deduct_from_channel(&*store, &channel_id, tick_cost).await {
                    Ok(_state) => break,
                    Err(e) if e.code == Some(crate::protocol::traits::ErrorCode::ChannelClosed) => {
                        // Channel is finalized/closed — emit final receipt, then stop
                        if let Ok(Some(ch)) = store.get_channel(&channel_id).await {
                            let mut receipt = SessionReceipt::new(
                                now_iso8601(),
                                &challenge_id,
                                &channel_id,
                                ch.highest_voucher_amount.to_string(),
                                ch.spent.to_string(),
                            );
                            receipt.units = Some(ch.units);
                            yield format_receipt_event(&receipt);
                        }
                        return;
                    }
                    Err(_) => {
                        // Emit need-voucher event
                        if let Ok(Some(ch)) = store.get_channel(&channel_id).await {
                            let event = format_need_voucher_event(&NeedVoucherEvent {
                                channel_id: channel_id.clone(),
                                required_cumulative: (ch.spent + tick_cost).to_string(),
                                accepted_cumulative: ch.highest_voucher_amount.to_string(),
                                deposit: ch.deposit.to_string(),
                            });
                            yield event;
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
            yield event;
        }

        // Emit final receipt
        if let Ok(Some(ch)) = store.get_channel(&channel_id).await {
            let mut receipt = SessionReceipt::new(
                now_iso8601(),
                &challenge_id,
                &channel_id,
                ch.highest_voucher_amount.to_string(),
                ch.spent.to_string(),
            );
            receipt.units = Some(ch.units);
            let event = format_receipt_event(&receipt);
            yield event;
        }
    })
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

    #[cfg(feature = "tempo")]
    #[test]
    fn test_format_receipt_event() {
        let mut receipt =
            SessionReceipt::new("2025-01-01T00:00:00Z", "ch-1", "0xabc", "1000000", "500000");
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

    #[cfg(feature = "tempo")]
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

    // -- SessionReceipt tests --

    #[cfg(feature = "tempo")]
    #[test]
    fn test_session_receipt_new() {
        let mut receipt =
            SessionReceipt::new("2025-01-01T00:00:00Z", "ch-1", "0xabc", "1000000", "500000");
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

    #[cfg(feature = "tempo")]
    #[test]
    fn test_session_receipt_serialization() {
        let mut receipt =
            SessionReceipt::new("2025-01-01T00:00:00Z", "ch-1", "0xabc", "1000000", "500000");
        receipt.units = Some(5);
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("\"challengeId\":\"ch-1\""));
        assert!(json.contains("\"acceptedCumulative\":\"1000000\""));
        assert!(!json.contains("\"txHash\""));

        let roundtrip: SessionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.challenge_id, "ch-1");
        assert_eq!(roundtrip.units, Some(5));
        assert_eq!(roundtrip.tx_hash, None);
    }

    // -- serve() metered streaming tests --

    #[cfg(feature = "tempo")]
    fn test_channel_state(
        channel_id: &str,
        voucher_amount: u128,
        deposit: u128,
    ) -> crate::protocol::methods::tempo::session_method::ChannelState {
        use crate::protocol::methods::tempo::session_method::ChannelState;
        ChannelState {
            channel_id: channel_id.to_string(),
            chain_id: 42431,
            escrow_contract: "0x5555555555555555555555555555555555555555"
                .parse()
                .unwrap(),
            payer: "0x1111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            payee: "0x2222222222222222222222222222222222222222"
                .parse()
                .unwrap(),
            token: "0x3333333333333333333333333333333333333333"
                .parse()
                .unwrap(),
            authorized_signer: "0x4444444444444444444444444444444444444444"
                .parse()
                .unwrap(),
            deposit,
            settled_on_chain: 0,
            highest_voucher_amount: voucher_amount,
            highest_voucher_signature: None,
            spent: 0,
            units: 0,
            finalized: false,
            close_requested_at: 0,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    #[cfg(feature = "tempo")]
    async fn collect_stream(
        mut stream: std::pin::Pin<Box<dyn futures_core::Stream<Item = String> + Send>>,
    ) -> Vec<String> {
        let mut events = Vec::new();
        while let Some(item) = next_item(&mut stream).await {
            events.push(item);
        }
        events
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_serve_balance_sufficient() {
        use crate::protocol::methods::tempo::session_method::InMemoryChannelStore;

        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let channel_id = "0xchannel_ok";
        // 3 items × tick_cost 100 = 300 needed; voucher has 1000
        store.insert(channel_id, test_channel_state(channel_id, 1000, 5000));

        let gen = Box::pin(async_stream::stream! {
            yield "hello".to_string();
            yield "world".to_string();
            yield "end".to_string();
        });

        let stream = serve(ServeOptions {
            store: store.clone(),
            channel_id: channel_id.to_string(),
            challenge_id: "ch-test".to_string(),
            tick_cost: 100,
            generate: gen,
            poll_interval_ms: 10,
        });

        let events = collect_stream(stream).await;

        // 3 message events + 1 receipt = 4
        assert_eq!(events.len(), 4);
        for (i, event) in events.iter().enumerate().take(3) {
            assert!(
                event.starts_with("event: message\ndata: "),
                "event {i} should be a message"
            );
        }
        assert_eq!(
            parse_event(&events[0]),
            Some(SseEvent::Message("hello".into()))
        );
        assert_eq!(
            parse_event(&events[1]),
            Some(SseEvent::Message("world".into()))
        );
        assert_eq!(
            parse_event(&events[2]),
            Some(SseEvent::Message("end".into()))
        );

        // Verify receipt
        let receipt_event = parse_event(&events[3]);
        assert!(matches!(receipt_event, Some(SseEvent::PaymentReceipt(_))));
        if let Some(SseEvent::PaymentReceipt(r)) = receipt_event {
            assert_eq!(r.challenge_id, "ch-test");
            assert_eq!(r.channel_id, channel_id);
            assert_eq!(r.accepted_cumulative, "1000");
            assert_eq!(r.spent, "300");
            assert_eq!(r.units, Some(3));
        }

        // Verify store accounting
        let ch = store.get_channel_sync(channel_id).unwrap();
        assert_eq!(ch.spent, 300);
        assert_eq!(ch.units, 3);
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_serve_empty_generator() {
        use crate::protocol::methods::tempo::session_method::InMemoryChannelStore;

        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let channel_id = "0xchannel_empty";
        store.insert(channel_id, test_channel_state(channel_id, 1000, 5000));

        let gen = Box::pin(async_stream::stream! {
            if false { yield String::new(); }
        });

        let stream = serve(ServeOptions {
            store: store.clone(),
            channel_id: channel_id.to_string(),
            challenge_id: "ch-empty".to_string(),
            tick_cost: 100,
            generate: gen,
            poll_interval_ms: 10,
        });

        let events = collect_stream(stream).await;

        // Only the final receipt
        assert_eq!(events.len(), 1);
        let receipt_event = parse_event(&events[0]);
        assert!(matches!(receipt_event, Some(SseEvent::PaymentReceipt(_))));
        if let Some(SseEvent::PaymentReceipt(r)) = receipt_event {
            assert_eq!(r.spent, "0");
            assert_eq!(r.units, Some(0));
        }

        let ch = store.get_channel_sync(channel_id).unwrap();
        assert_eq!(ch.spent, 0);
        assert_eq!(ch.units, 0);
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_serve_balance_exhausted_then_topup() {
        use crate::protocol::methods::tempo::session_method::{
            ChannelState, ChannelStore, InMemoryChannelStore,
        };

        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let channel_id = "0xchannel_exhaust";
        // Only enough for 2 ticks (200), third will exhaust
        store.insert(channel_id, test_channel_state(channel_id, 200, 5000));

        // Use a channel to control the generator so we can observe intermediate events
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(10);
        let gen = Box::pin(async_stream::stream! {
            while let Some(val) = rx.recv().await {
                yield val;
            }
        });

        let store2 = store.clone();
        let cid = channel_id.to_string();
        let handle = tokio::spawn(async move {
            let stream = serve(ServeOptions {
                store: store2,
                channel_id: cid,
                challenge_id: "ch-exhaust".to_string(),
                tick_cost: 100,
                generate: gen,
                poll_interval_ms: 10,
            });
            collect_stream(stream).await
        });

        // Send 2 items that will succeed
        tx.send("a".to_string()).await.unwrap();
        tx.send("b".to_string()).await.unwrap();
        // Send 3rd item — this will trigger need-voucher
        tx.send("c".to_string()).await.unwrap();

        // Wait for need-voucher to be emitted (store spent should be 200)
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Top up: increase highest_voucher_amount
        store
            .update_channel(
                channel_id,
                Box::new(|current: Option<ChannelState>| {
                    let state = current.unwrap();
                    Ok(Some(ChannelState {
                        highest_voucher_amount: 500,
                        ..state
                    }))
                }),
            )
            .await
            .unwrap();

        // Send one more item then close
        tx.send("d".to_string()).await.unwrap();
        drop(tx);

        let events = handle.await.unwrap();

        // Verify event sequence: msg(a), msg(b), need-voucher, msg(c), msg(d), receipt
        // There may be multiple need-voucher events if poll fires before top-up
        let mut messages = Vec::new();
        let mut need_vouchers = Vec::new();
        let mut receipts = Vec::new();
        for e in &events {
            match parse_event(e) {
                Some(SseEvent::Message(m)) => messages.push(m),
                Some(SseEvent::PaymentNeedVoucher(nv)) => need_vouchers.push(nv),
                Some(SseEvent::PaymentReceipt(r)) => receipts.push(r),
                None => {}
            }
        }

        assert_eq!(messages, vec!["a", "b", "c", "d"]);
        assert!(
            !need_vouchers.is_empty(),
            "should have emitted at least one need-voucher event"
        );
        // Verify need-voucher content
        let nv = &need_vouchers[0];
        assert_eq!(nv.channel_id, channel_id);
        assert_eq!(nv.deposit, "5000");

        assert_eq!(receipts.len(), 1);
        let r = &receipts[0];
        assert_eq!(r.challenge_id, "ch-exhaust");
        assert_eq!(r.spent, "400"); // 4 messages × 100
        assert_eq!(r.units, Some(4));
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_serve_deduct_accounting() {
        use crate::protocol::methods::tempo::session_method::InMemoryChannelStore;

        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let channel_id = "0xchannel_accounting";
        store.insert(channel_id, test_channel_state(channel_id, 10_000, 50_000));

        let gen = Box::pin(async_stream::stream! {
            for i in 0..5 {
                yield format!("item-{i}");
            }
        });

        let stream = serve(ServeOptions {
            store: store.clone(),
            channel_id: channel_id.to_string(),
            challenge_id: "ch-acc".to_string(),
            tick_cost: 250,
            generate: gen,
            poll_interval_ms: 10,
        });

        let events = collect_stream(stream).await;

        // 5 messages + 1 receipt
        assert_eq!(events.len(), 6);

        // Verify final store state: 5 × 250 = 1250 spent, 5 units
        let ch = store.get_channel_sync(channel_id).unwrap();
        assert_eq!(ch.spent, 1250);
        assert_eq!(ch.units, 5);

        // Verify receipt matches
        if let Some(SseEvent::PaymentReceipt(r)) = parse_event(&events[5]) {
            assert_eq!(r.spent, "1250");
            assert_eq!(r.units, Some(5));
            assert_eq!(r.accepted_cumulative, "10000");
        } else {
            panic!("last event should be a receipt");
        }
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn test_serve_finalized_channel_emits_receipt() {
        use crate::protocol::methods::tempo::session_method::{
            ChannelState, ChannelStore, InMemoryChannelStore,
        };

        let store = std::sync::Arc::new(InMemoryChannelStore::new());
        let channel_id = "0xchannel_finalized";
        // Enough balance for several ticks, but channel starts un-finalized
        store.insert(channel_id, test_channel_state(channel_id, 1000, 5000));

        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(10);
        let gen = Box::pin(async_stream::stream! {
            while let Some(val) = rx.recv().await {
                yield val;
            }
        });

        let store2 = store.clone();
        let cid = channel_id.to_string();
        let handle = tokio::spawn(async move {
            let stream = serve(ServeOptions {
                store: store2,
                channel_id: cid,
                challenge_id: "ch-fin".to_string(),
                tick_cost: 100,
                generate: gen,
                poll_interval_ms: 10,
            });
            collect_stream(stream).await
        });

        // Send 2 items that succeed
        tx.send("a".to_string()).await.unwrap();
        tx.send("b".to_string()).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Finalize the channel
        store
            .update_channel(
                channel_id,
                Box::new(|current: Option<ChannelState>| {
                    let state = current.unwrap();
                    Ok(Some(ChannelState {
                        finalized: true,
                        ..state
                    }))
                }),
            )
            .await
            .unwrap();

        // Send another item — deduction should hit ChannelClosed
        tx.send("c".to_string()).await.unwrap();
        // Give the stream time to process and terminate
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        drop(tx);

        let events = handle.await.unwrap();

        // Should have: msg(a), msg(b), receipt (stream stops before emitting "c")
        let message_count = events
            .iter()
            .filter(|e| matches!(parse_event(e), Some(SseEvent::Message(_))))
            .count();
        assert_eq!(message_count, 2, "only 2 messages before finalization");

        // Last event must be a receipt
        let last = events.last().expect("should have at least one event");
        match parse_event(last) {
            Some(SseEvent::PaymentReceipt(r)) => {
                assert_eq!(r.challenge_id, "ch-fin");
                assert_eq!(r.channel_id, channel_id);
                assert_eq!(r.spent, "200"); // 2 × 100
                assert_eq!(r.units, Some(2));
            }
            other => panic!("last event should be a receipt, got: {other:?}"),
        }
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
