//! WebSocket session handler with metered streaming.
//!
//! Implements the full session payment flow over WebSocket, equivalent to
//! the SSE metering loop in [`sse::serve`](super::sse::serve) but with
//! bidirectional communication — clients send vouchers inline as WS frames
//! instead of separate HTTP requests.
//!
//! # Flow
//!
//! 1. Server sends session challenge
//! 2. Client sends open credential (with deposit transaction)
//! 3. Server verifies, begins streaming data
//! 4. Per tick: deduct from channel balance
//! 5. When exhausted: send `needVoucher`, wait for voucher frame
//! 6. Client sends voucher credential → server verifies, resumes
//! 7. On completion: send session receipt, close
//!
//! # Example
//!
//! ```ignore
//! use mpp::server::ws_session::{WsSessionOptions, ws_session};
//!
//! ws_session(socket, WsSessionOptions {
//!     store,
//!     mpp: &mpp,
//!     channel_id: "0xabc",
//!     challenge_id: "ch-1",
//!     tick_cost: 1000,
//!     generate: my_stream,
//!     poll_interval_ms: 100,
//! }).await;
//! ```

#[cfg(feature = "tempo")]
use std::sync::Arc;

#[cfg(feature = "tempo")]
use super::ws::WsResponse;

/// Options for [`ws_session`].
#[cfg(feature = "tempo")]
pub struct WsSessionOptions<G> {
    /// Channel store for balance tracking.
    pub store: Arc<dyn crate::protocol::methods::tempo::session_method::ChannelStore>,
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

/// Run a metered session over a split WebSocket connection.
///
/// `sender` emits data frames and payment control messages (needVoucher, receipt).
/// `receiver` listens for incoming voucher credentials and updates the channel store.
///
/// This is the WebSocket equivalent of [`sse::serve`](super::sse::serve), with the
/// key advantage that vouchers arrive on the same connection (no separate HTTP POST).
#[cfg(feature = "tempo")]
pub async fn ws_session<G, S>(sender: &mut S, options: WsSessionOptions<G>)
where
    G: futures_core::Stream<Item = String> + Send + Unpin + 'static,
    S: futures_util::Sink<String, Error = Box<dyn std::error::Error + Send + Sync>> + Send + Unpin,
{
    use crate::protocol::methods::tempo::session_method::deduct_from_channel;
    use crate::protocol::methods::tempo::session_receipt::SessionReceipt;

    let WsSessionOptions {
        store,
        channel_id,
        challenge_id,
        tick_cost,
        generate,
        poll_interval_ms,
    } = options;

    let mut stream = std::pin::pin!(generate);

    while let Some(value) = next_item(&mut stream).await {
        // Deduct, waiting for voucher top-up if insufficient
        loop {
            match deduct_from_channel(&*store, &channel_id, tick_cost).await {
                Ok(_state) => break,
                Err(_) => {
                    // Emit needVoucher frame
                    if let Ok(Some(ch)) = store.get_channel(&channel_id).await {
                        let msg = WsResponse::NeedVoucher {
                            channel_id: channel_id.clone(),
                            required_cumulative: (ch.spent + tick_cost).to_string(),
                            accepted_cumulative: ch.highest_voucher_amount.to_string(),
                            deposit: ch.deposit.to_string(),
                        };
                        let _ = futures_util::SinkExt::send(&mut *sender, msg.to_text()).await;
                    }

                    // Wait for channel update (voucher from receiver) or poll
                    tokio::select! {
                        _ = store.wait_for_update(&channel_id) => {},
                        _ = tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)) => {},
                    }
                }
            }
        }

        // Send data frame
        let msg = WsResponse::Data { data: value };
        if futures_util::SinkExt::send(&mut *sender, msg.to_text())
            .await
            .is_err()
        {
            break;
        }
    }

    // Emit final session receipt
    if let Ok(Some(ch)) = store.get_channel(&channel_id).await {
        let mut receipt = SessionReceipt::new(
            now_iso8601(),
            &challenge_id,
            &channel_id,
            ch.highest_voucher_amount.to_string(),
            ch.spent.to_string(),
        );
        receipt.units = Some(ch.units);

        let msg = WsResponse::Receipt {
            receipt: serde_json::to_value(&receipt)
                .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"})),
        };
        let _ = futures_util::SinkExt::send(&mut *sender, msg.to_text()).await;
    }
}

/// Process incoming WebSocket messages for voucher credentials.
///
/// Call this concurrently with [`ws_session`] on the receiver half of a
/// split WebSocket. When a voucher credential arrives, it's verified via
/// the session method, which updates the channel store and unblocks the
/// sender's `wait_for_update`.
#[cfg(feature = "tempo")]
pub async fn process_incoming_vouchers<M, S, R>(receiver: &mut R, mpp: &crate::server::Mpp<M, S>)
where
    M: crate::protocol::traits::ChargeMethod,
    S: crate::protocol::traits::SessionMethod,
    R: futures_util::Stream<Item = Result<String, Box<dyn std::error::Error + Send + Sync>>>
        + Send
        + Unpin,
{
    use super::ws::WsMessage;
    use futures_util::StreamExt;

    while let Some(Ok(text)) = receiver.next().await {
        let ws_msg: WsMessage = match serde_json::from_str(&text) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if let WsMessage::Credential { credential } = ws_msg {
            if let Ok(parsed) = crate::protocol::core::parse_authorization(&credential) {
                // verify_session updates the channel store, which wakes the sender
                let _ = mpp.verify_session(&parsed).await;
            }
        }
    }
}

#[cfg(feature = "tempo")]
fn now_iso8601() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Poll the next item from a stream.
#[cfg(feature = "tempo")]
async fn next_item<S: futures_core::Stream + Unpin>(
    stream: &mut std::pin::Pin<&mut S>,
) -> Option<S::Item> {
    use std::future::poll_fn;
    use std::pin::Pin;

    poll_fn(|cx| Pin::new(&mut **stream).poll_next(cx)).await
}

#[cfg(test)]
#[cfg(feature = "tempo")]
mod tests {
    use super::*;

    #[test]
    fn test_ws_session_options_fields() {
        // Verify WsSessionOptions can be constructed
        let store =
            Arc::new(crate::protocol::methods::tempo::session_method::InMemoryChannelStore::new());
        let _opts = WsSessionOptions {
            store,
            channel_id: "0xabc".to_string(),
            challenge_id: "ch-1".to_string(),
            tick_cost: 1000,
            generate: futures_util::stream::empty::<String>(),
            poll_interval_ms: 100,
        };
    }
}
