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
//! 6. Client sends voucher credential → server verifies, replies with a
//!    receipt and resumes (or replies with an error and ends the session)
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

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use time::format_description::well_known::Iso8601;
use time::OffsetDateTime;

use super::ws::{WsMessage, WsResponse};
use crate::protocol::core::parse_authorization;
use crate::protocol::methods::tempo::session_method::{
    deduct_from_channel, normalize_channel_id, ChannelStore,
};
use crate::protocol::methods::tempo::session_receipt::SessionReceipt;
use crate::protocol::traits::{ChargeMethod, ErrorCode, SessionMethod, VerificationError};

/// Options for [`ws_session`].
pub struct WsSessionOptions<G> {
    /// Channel store for balance tracking.
    pub store: Arc<dyn ChannelStore>,
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
pub async fn ws_session<G, S>(sender: &mut S, options: WsSessionOptions<G>)
where
    G: futures_core::Stream<Item = String> + Send + Unpin + 'static,
    S: futures_util::Sink<String, Error = Box<dyn std::error::Error + Send + Sync>> + Send + Unpin,
{
    let WsSessionOptions {
        store,
        channel_id,
        challenge_id,
        tick_cost,
        generate,
        poll_interval_ms,
    } = options;
    let channel_id = normalize_channel_id(&channel_id);

    let mut stream = std::pin::pin!(generate);

    while let Some(value) = stream.next().await {
        // Deduct, waiting for voucher top-up if insufficient
        loop {
            match deduct_from_channel(&*store, &channel_id, tick_cost).await {
                Ok(_state) => break,
                Err(e) if e.code == Some(ErrorCode::InsufficientBalance) => {
                    // Emit needVoucher frame
                    if let Ok(Some(ch)) = store.get_channel(&channel_id).await {
                        let msg = WsResponse::NeedVoucher {
                            channel_id: channel_id.clone(),
                            required_cumulative: (ch.spent + tick_cost).to_string(),
                            accepted_cumulative: ch.highest_voucher_amount.to_string(),
                            deposit: ch.deposit.to_string(),
                        };
                        if sender.send(msg.to_text()).await.is_err() {
                            return; // client disconnected
                        }
                    }

                    // Wait for channel update (voucher from receiver) or poll
                    tokio::select! {
                        _ = store.wait_for_update(&channel_id) => {},
                        _ = tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)) => {},
                    }
                }
                Err(_) => {
                    // Closed, missing, or unreadable channel — no voucher can fix
                    // that, so emit the final receipt and stop instead of waiting forever.
                    send_receipt(sender, &*store, &channel_id, &challenge_id).await;
                    return;
                }
            }
        }

        // Send data frame
        let msg = WsResponse::Data { data: value };
        if sender.send(msg.to_text()).await.is_err() {
            break;
        }
    }

    // Emit final session receipt
    send_receipt(sender, &*store, &channel_id, &challenge_id).await;
}

/// Send the final session receipt for `channel_id`, if the channel still exists.
async fn send_receipt<S>(
    sender: &mut S,
    store: &dyn ChannelStore,
    channel_id: &str,
    challenge_id: &str,
) where
    S: futures_util::Sink<String> + Unpin,
{
    if let Ok(Some(ch)) = store.get_channel(channel_id).await {
        let timestamp = OffsetDateTime::now_utc()
            .format(&Iso8601::DEFAULT)
            .expect("ISO 8601 formatting cannot fail");

        let mut receipt = SessionReceipt::new(
            timestamp,
            challenge_id,
            channel_id,
            ch.highest_voucher_amount.to_string(),
            ch.spent.to_string(),
        );
        receipt.units = Some(ch.units);

        let msg = WsResponse::Receipt {
            receipt: serde_json::to_value(&receipt)
                .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"})),
        };
        let _ = sender.send(msg.to_text()).await;
    }
}

/// Process incoming WebSocket messages for voucher credentials.
///
/// Call this concurrently with [`ws_session`] on the receiver half of a
/// split WebSocket. When a voucher credential arrives, it's verified via
/// the session method, which updates the channel store and unblocks the
/// sender's `wait_for_update`.
///
/// The verification result is not reported to the client, which cannot tell
/// a rejected voucher from an accepted one. Use [`process_vouchers`] instead.
#[deprecated(note = "use `process_vouchers`, which reports each voucher result to the client")]
pub async fn process_incoming_vouchers<M, S, R>(receiver: &mut R, mpp: &crate::server::Mpp<M, S>)
where
    M: ChargeMethod,
    S: SessionMethod,
    R: futures_util::Stream<Item = Result<String, Box<dyn std::error::Error + Send + Sync>>>
        + Send
        + Unpin,
{
    while let Some(Ok(text)) = receiver.next().await {
        let Ok(WsMessage::Credential { credential }) = serde_json::from_str(&text) else {
            continue;
        };
        let Ok(parsed) = parse_authorization(&credential) else {
            continue;
        };
        let _ = mpp.verify_session(&parsed).await;
    }
}

/// Process incoming WebSocket messages for voucher credentials and report
/// each result to the client.
///
/// Call this concurrently with [`ws_session`] on the receiver half of a
/// split WebSocket. `sender` must write to the same socket as the sink
/// given to [`ws_session`], e.g. both are clones of a channel that is
/// drained into the socket's write half.
///
/// Every `credential` frame is verified via the session method:
/// - accepted: the channel store is updated, which unblocks the sender's
///   `wait_for_update`, and the receipt is sent as a `receipt` frame
/// - rejected or malformed: an `error` frame is sent and processing stops,
///   since clients treat `error` as terminal
///
/// Frames that are not credentials are ignored.
///
/// Returns `Ok(())` once the connection ends and the verification error
/// after a credential was refused. Either way the session is over, while
/// [`ws_session`] would keep waiting for a voucher: stop it (e.g. by running
/// both futures in `tokio::select!`) and close the socket.
pub async fn process_vouchers<M, S, R, W>(
    receiver: &mut R,
    sender: &mut W,
    mpp: &crate::server::Mpp<M, S>,
) -> Result<(), VerificationError>
where
    M: ChargeMethod,
    S: SessionMethod,
    R: futures_util::Stream<Item = Result<String, Box<dyn std::error::Error + Send + Sync>>>
        + Send
        + Unpin,
    W: futures_util::Sink<String> + Unpin,
{
    while let Some(Ok(text)) = receiver.next().await {
        let Ok(WsMessage::Credential { credential }) = serde_json::from_str(&text) else {
            continue;
        };
        let result = match parse_authorization(&credential) {
            Ok(parsed) => mpp.verify_session(&parsed).await,
            Err(e) => Err(VerificationError::with_code(
                format!("malformed credential: {e}"),
                ErrorCode::InvalidCredential,
            )),
        };
        match result {
            Ok(verified) => {
                let msg = WsResponse::Receipt {
                    receipt: serde_json::to_value(&verified.receipt)
                        .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"})),
                };
                if sender.send(msg.to_text()).await.is_err() {
                    return Ok(()); // client disconnected
                }
            }
            Err(error) => {
                let msg = WsResponse::Error {
                    error: error.message.clone(),
                };
                let _ = sender.send(msg.to_text()).await;
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{format_authorization, PaymentCredential, Receipt};
    use crate::protocol::intents::{ChargeRequest, SessionRequest};
    use crate::protocol::methods::tempo::session_method::{ChannelState, InMemoryChannelStore};

    fn test_channel_state(channel_id: &str, voucher_amount: u128, deposit: u128) -> ChannelState {
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
            settlement_route: None,
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
            closing: false,
            close_requested_at: 0,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    /// Sink that records every frame sent over the session.
    fn recording_sink() -> (
        impl futures_util::Sink<String, Error = Box<dyn std::error::Error + Send + Sync>> + Send + Unpin,
        Arc<std::sync::Mutex<Vec<WsResponse>>>,
    ) {
        let frames = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink_frames = frames.clone();
        let sink = futures_util::sink::unfold((), move |(), text: String| {
            let frames = sink_frames.clone();
            async move {
                let response: WsResponse = serde_json::from_str(&text)?;
                frames.lock().unwrap().push(response);
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            }
        });
        (Box::pin(sink), frames)
    }

    #[tokio::test]
    async fn test_ws_session_finalized_channel_emits_receipt_and_stops() {
        let store = Arc::new(InMemoryChannelStore::new());
        let channel_id = "0xchannel_ws_finalized";
        store.insert(channel_id, test_channel_state(channel_id, 1000, 5000));

        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(10);
        let generate = Box::pin(async_stream::stream! {
            while let Some(value) = rx.recv().await {
                yield value;
            }
        });

        let (mut sink, frames) = recording_sink();
        let session_store = store.clone();
        let session = tokio::spawn(async move {
            ws_session(
                &mut sink,
                WsSessionOptions {
                    store: session_store,
                    channel_id: channel_id.to_string(),
                    challenge_id: "ch-fin".to_string(),
                    tick_cost: 100,
                    generate,
                    poll_interval_ms: 10,
                },
            )
            .await;
        });

        tx.send("a".to_string()).await.unwrap();
        tx.send("b".to_string()).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

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

        // The next deduction hits ChannelClosed. Without the closed-channel arm the
        // session loops on needVoucher forever and this join times out.
        tx.send("c".to_string()).await.unwrap();
        tokio::time::timeout(tokio::time::Duration::from_secs(2), session)
            .await
            .expect("session must terminate once the channel is finalized")
            .unwrap();

        let frames = frames.lock().unwrap();
        let data: Vec<&str> = frames
            .iter()
            .filter_map(|frame| match frame {
                WsResponse::Data { data } => Some(data.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(data, vec!["a", "b"], "no data frame after finalization");
        assert!(
            !frames
                .iter()
                .any(|frame| matches!(frame, WsResponse::NeedVoucher { .. })),
            "a finalized channel must not request vouchers"
        );

        match frames.last() {
            Some(WsResponse::Receipt { receipt }) => {
                assert_eq!(receipt["challengeId"], "ch-fin");
                assert_eq!(receipt["channelId"], channel_id);
                assert_eq!(receipt["spent"], "200");
                assert_eq!(receipt["units"], 2);
            }
            other => panic!("last frame should be a receipt, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_ws_session_normalizes_channel_id() {
        let store = Arc::new(InMemoryChannelStore::new());
        let lower = format!("0x{}", "ab".repeat(32));
        store.insert(&lower, test_channel_state(&lower, 1000, 5000));

        let (mut sink, frames) = recording_sink();
        ws_session(
            &mut sink,
            WsSessionOptions {
                store,
                channel_id: format!("0x{}", "AB".repeat(32)),
                challenge_id: "ch-case".to_string(),
                tick_cost: 100,
                generate: Box::pin(async_stream::stream! { yield "a".to_string(); }),
                poll_interval_ms: 10,
            },
        )
        .await;

        let frames = frames.lock().unwrap();
        assert!(matches!(&frames[0], WsResponse::Data { data } if data == "a"));
        match frames.last() {
            Some(WsResponse::Receipt { receipt }) => assert_eq!(receipt["channelId"], lower),
            other => panic!("last frame should be a receipt, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_ws_session_missing_channel_stops() {
        let (mut sink, frames) = recording_sink();
        let generate = Box::pin(async_stream::stream! {
            yield "a".to_string();
        });

        // No voucher can create the channel, so the session must end instead of polling.
        tokio::time::timeout(
            tokio::time::Duration::from_secs(2),
            ws_session(
                &mut sink,
                WsSessionOptions {
                    store: Arc::new(InMemoryChannelStore::new()),
                    channel_id: "0xchannel_ws_missing".to_string(),
                    challenge_id: "ch-missing".to_string(),
                    tick_cost: 100,
                    generate,
                    poll_interval_ms: 10,
                },
            ),
        )
        .await
        .expect("session must terminate when the channel does not exist");

        let frames = frames.lock().unwrap();
        assert!(frames.is_empty(), "unexpected frames: {frames:?}");
    }

    #[derive(Clone)]
    struct MockCharge;

    impl ChargeMethod for MockCharge {
        fn method(&self) -> &str {
            "tempo"
        }

        async fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &ChargeRequest,
        ) -> Result<Receipt, VerificationError> {
            Err(VerificationError::new("charge is not used"))
        }
    }

    /// Session method that accepts every voucher except those signed `0xbad`.
    #[derive(Clone)]
    struct MockSession;

    impl SessionMethod for MockSession {
        fn method(&self) -> &str {
            "tempo"
        }

        async fn verify_session(
            &self,
            credential: &PaymentCredential,
            _request: &SessionRequest,
        ) -> Result<Receipt, VerificationError> {
            if credential.payload["signature"] == "0xbad" {
                return Err(VerificationError::invalid_signature(
                    "invalid voucher signature",
                ));
            }
            let amount = credential.payload["cumulativeAmount"].as_str().unwrap();
            Ok(Receipt::success("tempo", format!("accepted-{amount}")))
        }
    }

    /// Voucher results are reported in-band: a receipt per accepted voucher,
    /// and an error that ends processing for a rejected or malformed one.
    #[tokio::test]
    async fn test_process_vouchers_reports_results() {
        let mpp = crate::server::Mpp::new(MockCharge, "ws.test", "secret")
            .with_session_method(MockSession);
        let voucher = |amount: &str, signature: &str| {
            let challenge = mpp
                .session_challenge(
                    "100",
                    "0x20c0000000000000000000000000000000000000",
                    "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                )
                .unwrap();
            let credential = PaymentCredential::new(
                challenge.to_echo(),
                serde_json::json!({
                    "action": "voucher",
                    "channelId": "0xabc",
                    "cumulativeAmount": amount,
                    "signature": signature,
                }),
            );
            serde_json::json!({
                "type": "credential",
                "credential": format_authorization(&credential).unwrap(),
            })
            .to_string()
        };
        let data = serde_json::json!({"type": "message", "data": "hi"}).to_string();
        let malformed =
            serde_json::json!({"type": "credential", "credential": "Payment !"}).to_string();

        // (incoming frames, receipts sent, error sent, error code returned)
        let cases = [
            (
                vec![
                    data,
                    "not json".to_string(),
                    voucher("200", "0xok"),
                    voucher("300", "0xok"),
                ],
                vec!["accepted-200", "accepted-300"],
                None,
                None,
            ),
            (
                vec![
                    voucher("200", "0xok"),
                    voucher("300", "0xbad"),
                    voucher("400", "0xok"),
                ],
                vec!["accepted-200"],
                Some("invalid voucher signature"),
                Some(ErrorCode::InvalidSignature),
            ),
            (
                vec![malformed, voucher("200", "0xok")],
                vec![],
                Some("malformed credential"),
                Some(ErrorCode::InvalidCredential),
            ),
        ];

        for (incoming, receipts, error, code) in cases {
            let mut receiver = futures_util::stream::iter(incoming.into_iter().map(Ok));
            let (mut sink, frames) = recording_sink();

            let result = process_vouchers(&mut receiver, &mut sink, &mpp).await;
            assert_eq!(result.err().and_then(|e| e.code), code);

            let frames = frames.lock().unwrap();
            let mut expected = receipts.len();
            for (frame, reference) in frames.iter().zip(&receipts) {
                assert!(
                    matches!(frame, WsResponse::Receipt { receipt }
                        if receipt["status"] == "success" && receipt["reference"] == *reference),
                    "expected a receipt for {reference}, got: {frame:?}"
                );
            }
            if let Some(error) = error {
                expected += 1;
                assert!(
                    matches!(frames.last(), Some(WsResponse::Error { error: sent })
                        if sent.contains(error)),
                    "expected error {error:?}, got: {:?}",
                    frames.last()
                );
            }
            assert_eq!(frames.len(), expected, "unexpected frames: {frames:?}");
        }
    }

    #[test]
    fn test_ws_session_options_fields() {
        let store = Arc::new(InMemoryChannelStore::new());
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
