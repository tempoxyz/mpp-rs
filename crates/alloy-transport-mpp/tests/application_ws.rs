use alloy_transport_mpp::{
    CloseProvider, CloseRequest, MppApplicationWsConnect, VoucherProvider, VoucherRequest,
};
use axum::{
    extract::{
        ws::{rejection::WebSocketUpgradeRejection, Message, WebSocketUpgrade},
        State,
    },
    http::{header::WWW_AUTHENTICATE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures::StreamExt;
use mpp::{
    client::{PaymentContext, PaymentProvider},
    parse_authorization,
    protocol::core::Base64UrlJson,
    MppError, PaymentChallenge, PaymentCredential, PaymentPayload,
};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[derive(Clone)]
struct StubProvider;

impl PaymentProvider for StubProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == "tempo" && intent == "session"
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::hash("0xopen"),
        ))
    }
}

#[derive(Clone)]
struct ContextProvider {
    observed: Arc<Mutex<Option<PaymentContext>>>,
}

impl PaymentProvider for ContextProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == "tempo" && intent == "session"
    }

    async fn pay(&self, _: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        panic!("application transport must call pay_with_context")
    }

    async fn pay_with_context(
        &self,
        challenge: &PaymentChallenge,
        _: PaymentContext,
    ) -> Result<PaymentCredential, MppError> {
        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::hash("0xopen"),
        ))
    }

    async fn prepare_application_websocket_challenge(
        &self,
        challenge: &PaymentChallenge,
        context: PaymentContext,
    ) -> Result<PaymentChallenge, MppError> {
        *self.observed.lock().await = Some(context);
        Ok(challenge.clone())
    }

    fn accept_payment_header(&self) -> Option<String> {
        Some("tempo/session".into())
    }
}

impl VoucherProvider for ContextProvider {
    async fn next_voucher(&self, _: &VoucherRequest) -> Result<PaymentCredential, MppError> {
        Err(MppError::bad_request("unexpected voucher request"))
    }
}

impl CloseProvider for ContextProvider {
    async fn close_credential(&self, _: &CloseRequest) -> Result<PaymentCredential, MppError> {
        Err(MppError::bad_request("unexpected close request"))
    }
}

impl VoucherProvider for StubProvider {
    async fn next_voucher(&self, _: &VoucherRequest) -> Result<PaymentCredential, MppError> {
        Err(MppError::bad_request(
            "socket-bound voucher challenge was not forwarded",
        ))
    }

    async fn next_voucher_for_challenge(
        &self,
        challenge: &PaymentChallenge,
        _: &VoucherRequest,
    ) -> Result<PaymentCredential, MppError> {
        assert_eq!(challenge.id, "challenge-1");
        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::hash("0xvoucher"),
        ))
    }
}

impl CloseProvider for StubProvider {
    async fn close_credential(&self, _: &CloseRequest) -> Result<PaymentCredential, MppError> {
        Err(MppError::bad_request(
            "socket-bound close challenge was not forwarded",
        ))
    }

    async fn close_credential_for_challenge(
        &self,
        challenge: &PaymentChallenge,
        request: &CloseRequest,
    ) -> Result<PaymentCredential, MppError> {
        assert_eq!(challenge.id, "challenge-1");
        assert_eq!(request.channel_id, "0xchannel");
        assert_eq!(request.cumulative_amount, "37");
        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::hash("0xclose"),
        ))
    }
}

fn challenge() -> PaymentChallenge {
    challenge_with_id("challenge-1")
}

fn challenge_with_id(id: &str) -> PaymentChallenge {
    PaymentChallenge::new(
        id,
        "application-test",
        "tempo",
        "session",
        Base64UrlJson::from_value(&json!({
            "amount": "0",
            "currency": "0x0000000000000000000000000000000000000001",
            "recipient": "0x0000000000000000000000000000000000000002"
        }))
        .unwrap(),
    )
}

#[derive(Clone)]
struct RefreshProvider {
    voucher_challenges: Arc<Mutex<Vec<String>>>,
}

impl PaymentProvider for RefreshProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == "tempo" && intent == "session"
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::hash("0xopen"),
        ))
    }
}

impl VoucherProvider for RefreshProvider {
    async fn next_voucher(&self, _: &VoucherRequest) -> Result<PaymentCredential, MppError> {
        Err(MppError::bad_request(
            "socket-bound voucher challenge was not forwarded",
        ))
    }

    async fn next_voucher_for_challenge(
        &self,
        challenge: &PaymentChallenge,
        _: &VoucherRequest,
    ) -> Result<PaymentCredential, MppError> {
        self.voucher_challenges
            .lock()
            .await
            .push(challenge.id.clone());
        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::hash("0xvoucher"),
        ))
    }
}

#[derive(Clone, Default)]
struct RefreshState {
    challenge_requests: Arc<AtomicUsize>,
}

async fn refresh_route(
    State(state): State<RefreshState>,
    headers: HeaderMap,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let Ok(upgrade) = upgrade else {
        let request = state.challenge_requests.fetch_add(1, Ordering::SeqCst) + 1;
        if request > 1 {
            assert_eq!(headers["payment-session"], "0xchannel");
        }
        let expires = (OffsetDateTime::now_utc() + Duration::seconds(2))
            .format(&Rfc3339)
            .unwrap();
        let header = HeaderValue::from_str(
            &challenge_with_id(&format!("challenge-{request}"))
                .with_expires(expires)
                .to_header()
                .unwrap(),
        )
        .unwrap();
        return (StatusCode::PAYMENT_REQUIRED, [(WWW_AUTHENTICATE, header)]).into_response();
    };

    upgrade
        .on_upgrade(|mut socket| async move {
            let opening = socket.next().await.unwrap().unwrap();
            assert!(matches!(opening, Message::Text(_)));
            socket
                .send(Message::Text(
                    json!({ "mpp": "payment-receipt", "data": receipt() })
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();

            tokio::time::sleep(std::time::Duration::from_millis(2_200)).await;
            socket
                .send(Message::Text(
                    json!({
                        "mpp": "payment-need-voucher",
                        "data": {
                            "channelId": "0xchannel",
                            "requiredCumulative": "100",
                            "acceptedCumulative": "0",
                            "deposit": "100"
                        }
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .unwrap();

            let voucher = socket.next().await.unwrap().unwrap();
            let Message::Text(voucher) = voucher else {
                panic!("expected voucher authorization text frame")
            };
            let voucher: Value = serde_json::from_str(&voucher).unwrap();
            let credential =
                parse_authorization(voucher["authorization"].as_str().unwrap()).unwrap();
            assert_eq!(credential.challenge.id, "challenge-2");

            socket
                .send(Message::Text(
                    json!({ "mpp": "message", "data": "after-refresh" })
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
        })
        .into_response()
}

fn receipt() -> Value {
    json!({
        "method": "tempo",
        "intent": "session",
        "status": "success",
        "timestamp": "2026-07-19T00:00:00Z",
        "reference": "0xchannel",
        "challengeId": "challenge-1",
        "channelId": "0xchannel",
        "acceptedCumulative": "100",
        "spent": "37"
    })
}

async fn route(upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>) -> Response {
    let Ok(upgrade) = upgrade else {
        let header = HeaderValue::from_str(&challenge().to_header().unwrap()).unwrap();
        return (StatusCode::PAYMENT_REQUIRED, [(WWW_AUTHENTICATE, header)]).into_response();
    };

    upgrade
        .on_upgrade(|mut socket| async move {
            let authorization = socket.next().await.unwrap().unwrap();
            let Message::Text(authorization) = authorization else {
                panic!("expected authorization text frame")
            };
            let authorization: Value = serde_json::from_str(&authorization).unwrap();
            assert_eq!(authorization["mpp"], "authorization");
            assert!(authorization["authorization"]
                .as_str()
                .unwrap()
                .starts_with("Payment "));

            socket
                .send(Message::Text(
                    json!({ "mpp": "payment-receipt", "data": receipt() })
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();

            let application = socket.next().await.unwrap().unwrap();
            let Message::Text(application) = application else {
                panic!("expected application text frame")
            };
            let application: Value = serde_json::from_str(&application).unwrap();
            assert_eq!(application, json!({ "mpp": "message", "data": "hello" }));

            socket
                .send(Message::Text(
                    json!({
                        "mpp": "payment-need-voucher",
                        "data": {
                            "channelId": "0xchannel",
                            "requiredCumulative": "100",
                            "acceptedCumulative": "0",
                            "deposit": "100"
                        }
                    })
                    .to_string()
                    .into(),
                ))
                .await
                .unwrap();
            let voucher = socket.next().await.unwrap().unwrap();
            let Message::Text(voucher) = voucher else {
                panic!("expected voucher authorization text frame")
            };
            assert_eq!(
                serde_json::from_str::<Value>(&voucher).unwrap()["mpp"],
                "authorization"
            );

            socket
                .send(Message::Text(
                    json!({ "mpp": "message", "data": "world" })
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();

            let close_request = socket.next().await.unwrap().unwrap();
            let Message::Text(close_request) = close_request else {
                panic!("expected close request text frame")
            };
            assert_eq!(
                serde_json::from_str::<Value>(&close_request).unwrap(),
                json!({ "mpp": "payment-close-request" })
            );

            socket
                .send(Message::Text(
                    json!({ "mpp": "payment-close-ready", "data": receipt() })
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();

            let close_authorization = socket.next().await.unwrap().unwrap();
            let Message::Text(close_authorization) = close_authorization else {
                panic!("expected close authorization text frame")
            };
            let close_authorization: Value = serde_json::from_str(&close_authorization).unwrap();
            assert_eq!(close_authorization["mpp"], "authorization");

            socket
                .send(Message::Text(
                    json!({ "mpp": "payment-receipt", "data": receipt() })
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();
        })
        .into_response()
}

type DisconnectSignal = Arc<Mutex<Option<oneshot::Sender<bool>>>>;

async fn disconnect_route(
    State(signal): State<DisconnectSignal>,
    upgrade: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
) -> Response {
    let Ok(upgrade) = upgrade else {
        let header = HeaderValue::from_str(&challenge().to_header().unwrap()).unwrap();
        return (StatusCode::PAYMENT_REQUIRED, [(WWW_AUTHENTICATE, header)]).into_response();
    };

    upgrade
        .on_upgrade(|mut socket| async move {
            let authorization = socket.next().await.unwrap().unwrap();
            assert!(matches!(authorization, Message::Text(_)));
            socket
                .send(Message::Text(
                    json!({ "mpp": "payment-receipt", "data": receipt() })
                        .to_string()
                        .into(),
                ))
                .await
                .unwrap();

            let transport_only_close = matches!(socket.next().await, Some(Ok(Message::Close(_))));
            if let Some(signal) = signal.lock().await.take() {
                let _ = signal.send(transport_only_close);
            }
        })
        .into_response()
}

#[tokio::test]
async fn probes_then_authorizes_and_translates_application_messages() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/", get(route)))
            .await
            .unwrap();
    });

    let connector =
        MppApplicationWsConnect::new(format!("ws://{address}/"), StubProvider, StubProvider);
    let mut socket = connector.connect().await.unwrap();
    socket.send("hello").await.unwrap();
    assert_eq!(socket.next().await.unwrap(), "world");
    assert_eq!(socket.close().await.unwrap()["channelId"], "0xchannel");
}

#[tokio::test]
async fn refreshes_expiring_challenge_before_later_voucher() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = RefreshState::default();
    let server_state = state.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", get(refresh_route))
                .with_state(server_state),
        )
        .await
        .unwrap();
    });

    let voucher_challenges = Arc::new(Mutex::new(Vec::new()));
    let provider = RefreshProvider {
        voucher_challenges: Arc::clone(&voucher_challenges),
    };
    let connector =
        MppApplicationWsConnect::new(format!("ws://{address}/"), provider.clone(), provider);
    let mut socket = connector.connect().await.unwrap();

    assert_eq!(socket.next().await.unwrap(), "after-refresh");
    assert_eq!(state.challenge_requests.load(Ordering::SeqCst), 2);
    assert_eq!(*voucher_challenges.lock().await, ["challenge-2"]);
}

#[tokio::test]
async fn payment_provider_receives_probe_url_and_headers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (signal_tx, signal_rx) = oneshot::channel();
    let signal = Arc::new(Mutex::new(Some(signal_tx)));
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", get(disconnect_route))
                .with_state(signal),
        )
        .await
        .unwrap();
    });

    let observed = Arc::new(Mutex::new(None));
    let provider = ContextProvider {
        observed: Arc::clone(&observed),
    };
    let connector =
        MppApplicationWsConnect::new(format!("ws://{address}/"), provider.clone(), provider)
            .with_header(
                "x-test-routing".parse().unwrap(),
                HeaderValue::from_static("preserved"),
            );
    connector
        .connect()
        .await
        .unwrap()
        .disconnect()
        .await
        .unwrap();

    assert!(signal_rx.await.unwrap());
    let context = observed.lock().await.take().unwrap();
    assert_eq!(context.url.as_str(), format!("http://{address}/"));
    assert_eq!(context.headers["x-test-routing"], "preserved");
    assert_eq!(context.headers["accept-payment"], "tempo/session");
}

#[tokio::test]
async fn disconnect_closes_transport_without_requesting_session_settlement() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (signal_tx, signal_rx) = oneshot::channel();
    let signal = Arc::new(Mutex::new(Some(signal_tx)));
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/", get(disconnect_route))
                .with_state(signal),
        )
        .await
        .unwrap();
    });

    let connector =
        MppApplicationWsConnect::new(format!("ws://{address}/"), StubProvider, StubProvider);
    connector
        .connect()
        .await
        .unwrap()
        .disconnect()
        .await
        .unwrap();

    assert!(signal_rx.await.unwrap());
}
