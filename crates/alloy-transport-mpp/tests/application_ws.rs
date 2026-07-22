use alloy_transport_mpp::{
    CloseProvider, CloseRequest, MppApplicationWsConnect, VoucherProvider, VoucherRequest,
};
use axum::{
    extract::ws::{rejection::WebSocketUpgradeRejection, Message, WebSocketUpgrade},
    http::{header::WWW_AUTHENTICATE, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures::StreamExt;
use mpp::{
    client::PaymentProvider, protocol::core::Base64UrlJson, MppError, PaymentChallenge,
    PaymentCredential, PaymentPayload,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;

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
    PaymentChallenge::new(
        "challenge-1",
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
