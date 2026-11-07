//! Zone payments from the Tempo charge client, as mppx's
//! `client/Charge.zone.test.ts`.

use std::sync::atomic::{AtomicUsize, Ordering};

use alloy::primitives::{address, Address, B256};
use alloy::sol_types::SolEvent;
use axum::{extract::State, routing::post, Json, Router};
use serde_json::{json, Value};

use super::*;
use crate::client::{PaymentProvider, TempoProvider};
use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

const MERCHANT: Address = address!("2222222222222222222222222222222222222222");
const CURRENCY: Address = address!("20c0000000000000000000000000000000000001");
const MODERATO_ZONE_3: u64 = 1_424_310_003;
const PAYER_KEY: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

type Handler = Arc<dyn Fn(&str, &Value) -> Result<Value, (i64, String)> + Send + Sync>;

/// A JSON-RPC server answering with `handler` and recording each method.
async fn spawn_rpc(handler: Handler) -> (String, Arc<Mutex<Vec<String>>>) {
    #[derive(Clone)]
    struct Rpc {
        handler: Handler,
        calls: Arc<Mutex<Vec<String>>>,
    }
    async fn rpc(State(state): State<Rpc>, Json(request): Json<Value>) -> Json<Value> {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request["method"].as_str().unwrap_or_default().to_string();
        state.calls.lock().unwrap().push(method.clone());
        // Let concurrent payments overlap, as a real RPC would.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        Json(match (state.handler)(&method, &params) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => {
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
            }
        })
    }
    let calls = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new().route("/", post(rpc)).with_state(Rpc {
        handler,
        calls: calls.clone(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, calls)
}

/// A Moderato RPC that only knows its chain ID and answers `logs` to
/// `eth_getLogs`.
async fn tempo_rpc(logs: Arc<Mutex<Value>>) -> (String, Arc<Mutex<Vec<String>>>) {
    spawn_rpc(Arc::new(move |method, _| match method {
        "eth_chainId" => Ok(json!("0xa5bf")),
        "eth_blockNumber" => Ok(json!("0x10")),
        "eth_getLogs" => Ok(logs.lock().unwrap().clone()),
        _ => Err((-32000, format!("l1: {method}"))),
    }))
    .await
}

/// A Zone RPC whose every call fails loudly, to show whether the client used it.
async fn unused_zone_rpc() -> (String, Arc<Mutex<Vec<String>>>) {
    spawn_rpc(Arc::new(|_, _| Err((-32000, "zone used".into())))).await
}

fn payer() -> alloy::signers::local::PrivateKeySigner {
    PAYER_KEY.parse().unwrap()
}

fn challenge_with(details: Value, expires: Option<String>) -> PaymentChallenge {
    let mut method_details = json!({ "chainId": 42431, "zones": [3] });
    method_details
        .as_object_mut()
        .unwrap()
        .extend(details.as_object().unwrap().clone());
    let request = json!({
        "amount": "1000000",
        "currency": format!("{CURRENCY:#x}"),
        "recipient": format!("{MERCHANT:#x}"),
        "methodDetails": method_details,
    });
    let mut challenge = PaymentChallenge::new(
        "zone-challenge",
        "api.example.com",
        "tempo",
        "charge",
        Base64UrlJson::from_value(&request).unwrap(),
    );
    challenge.expires = expires;
    challenge
}

fn expires_in(seconds: i64) -> Option<String> {
    Some(
        (time::OffsetDateTime::now_utc() + time::Duration::seconds(seconds))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap(),
    )
}

async fn provider_with_zone(zone: TempoZone) -> (TempoProvider, Arc<Mutex<Vec<String>>>) {
    let (tempo_url, tempo_calls) = tempo_rpc(Arc::new(Mutex::new(json!([])))).await;
    let provider = TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_zone(zone)
        .unwrap();
    (provider, tempo_calls)
}

#[tokio::test]
async fn test_pays_from_zone_on_challenge_chain() {
    for zones in [json!([3]), json!(true)] {
        let (zone_url, zone_calls) = unused_zone_rpc().await;
        let (provider, _) =
            provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
        let challenge = challenge_with(json!({ "zones": zones }), None);
        let error = provider.pay(&challenge).await.unwrap_err();
        assert!(error.to_string().contains("zone used"), "{zones}: {error}");
        assert!(!zone_calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn test_pays_from_zone_for_challenge_with_line_breaks_in_description() {
    let (zone_url, _) = unused_zone_rpc().await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    // MCP challenges are not HTTP headers, so their fields may hold line breaks.
    let mut challenge = challenge_with(json!({}), None);
    challenge.description = Some("line one\nline two".into());
    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(error.to_string().contains("zone used"), "{error}");
}

#[tokio::test]
async fn test_pays_on_tempo_when_the_zone_is_not_used() {
    let cases = [
        // The challenge does not accept the Zone.
        (1_424_310_004, json!({}), None, Duration::from_secs(60)),
        // The Zone settles on another parent chain.
        (421_700_003, json!({}), None, Duration::from_secs(60)),
        // The challenge only accepts pull payments.
        (
            MODERATO_ZONE_3,
            json!({ "supportedModes": ["pull"] }),
            None,
            Duration::from_secs(60),
        ),
        // The challenge has splits.
        (
            MODERATO_ZONE_3,
            json!({ "splits": [{ "amount": "100000", "recipient": format!("{MERCHANT:#x}") }] }),
            None,
            Duration::from_secs(60),
        ),
        // The challenge expires before the withdrawal could settle.
        (
            MODERATO_ZONE_3,
            json!({}),
            expires_in(30),
            Duration::from_secs(60),
        ),
        // The challenge leaves no time to send the withdrawal.
        (
            MODERATO_ZONE_3,
            json!({}),
            expires_in(65),
            Duration::from_secs(60),
        ),
    ];
    for (zone_chain_id, details, expires, timeout) in cases {
        let (zone_url, zone_calls) = unused_zone_rpc().await;
        let zone = TempoZone::new(zone_url, zone_chain_id)
            .unwrap()
            .with_settlement_timeout(timeout);
        let (provider, tempo_calls) = provider_with_zone(zone).await;
        let challenge = challenge_with(details.clone(), expires);
        let error = provider.pay(&challenge).await.unwrap_err();
        assert!(
            !error.to_string().contains("zone used"),
            "{details}: {error}"
        );
        assert!(zone_calls.lock().unwrap().is_empty(), "{details}");
        // It went on to pay on Tempo.
        assert!(tempo_calls.lock().unwrap().len() > 1, "{details}");
    }
}

#[test]
fn test_rejects_zone_id_that_does_not_match_zone_chain() {
    let error = TempoZone::new("http://127.0.0.1:1", MODERATO_ZONE_3)
        .unwrap()
        .with_zone_id(4)
        .unwrap_err();
    assert!(
        error.to_string().contains("does not match Zone 3"),
        "{error}"
    );
    assert!(TempoZone::new("http://127.0.0.1:1", MODERATO_ZONE_3)
        .unwrap()
        .with_zone_id(3)
        .is_ok());
}

#[test]
fn test_rejects_zone_without_zone_id() {
    let zone = TempoZone::new("http://127.0.0.1:1", 42_431).unwrap();
    let error = TempoProvider::new(payer(), "http://127.0.0.1:1")
        .unwrap()
        .with_zone(zone)
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("cannot derive a Zone ID"),
        "{error}"
    );
}

/// The outbox's `WithdrawalRequested` for `sender` as a JSON-RPC log.
fn withdrawal_requested_log(sender: Address) -> Value {
    let data = IZoneOutbox::WithdrawalRequested {
        withdrawalIndex: 0,
        sender,
        token: CURRENCY,
        to: MERCHANT,
        amount: 1_000_000,
        fee: 1,
        memo: B256::ZERO,
        gasLimit: 0,
        fallbackNonce: 7,
        data: Bytes::new(),
        revealTo: Bytes::new(),
    }
    .encode_log_data();
    json!({
        "address": format!("{:#x}", zone::ZONE_OUTBOX),
        "topics": data.topics().iter().map(|topic| format!("{topic:#x}")).collect::<Vec<_>>(),
        "data": format!("{}", data.data),
        "blockHash": format!("{:#x}", B256::repeat_byte(0x11)),
        "blockNumber": "0x1",
        "transactionHash": format!("{:#x}", B256::repeat_byte(0x22)),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

fn zone_receipt(status: &str, logs: Value) -> Value {
    json!({
        "type": "0x76",
        "status": status,
        "cumulativeGasUsed": "0x1",
        "logs": logs,
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "transactionHash": format!("{:#x}", B256::repeat_byte(0x22)),
        "transactionIndex": "0x0",
        "blockHash": format!("{:#x}", B256::repeat_byte(0x11)),
        "blockNumber": "0x1",
        "gasUsed": "0x1",
        "effectiveGasPrice": "0x1",
        "from": format!("{:#x}", payer().address()),
        "to": format!("{:#x}", zone::ZONE_OUTBOX),
        "contractAddress": null,
    })
}

/// A Zone RPC that prepares and signs withdrawals, then answers the send with
/// `send`; once a send failed, every later call fails.
fn zone_handler(
    send: impl Fn() -> Result<Value, (i64, String)> + Send + Sync + 'static,
) -> Handler {
    let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    Arc::new(move |method, _| {
        if failed.load(Ordering::SeqCst) {
            return Err((-32000, "connection lost".into()));
        }
        match method {
            "eth_chainId" => Ok(json!(format!("{MODERATO_ZONE_3:#x}"))),
            "eth_call" => Ok(json!(format!("0x{}", "00".repeat(32)))),
            "eth_sendRawTransactionSync" => {
                let result = send();
                if result.is_err() {
                    failed.store(true, Ordering::SeqCst);
                }
                result
            }
            _ => Ok(json!("0x1")),
        }
    })
}

#[tokio::test]
async fn test_does_not_withdraw_again_after_unknown_outcome() {
    let (zone_url, zone_calls) =
        spawn_rpc(zone_handler(|| Err((-32000, "connection lost".into())))).await;
    let mut zone = TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap();
    zone.receipt_recovery_timeout = Duration::from_millis(600);
    let (provider, _) = provider_with_zone(zone).await;
    let challenge = challenge_with(json!({}), None);

    // The client looks for the receipt of the signed transaction before it gives up.
    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(
        matches!(error, MppError::PaymentOutcomeUnknown { .. }),
        "{error}"
    );
    {
        let calls = zone_calls.lock().unwrap();
        assert!(calls
            .iter()
            .any(|call| call == "eth_sendRawTransactionSync"));
        assert!(calls.iter().any(|call| call == "eth_getTransactionReceipt"));
    }
    let sent = zone_calls.lock().unwrap().len();
    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(
        matches!(error, MppError::PaymentOutcomeUnknown { .. }),
        "{error}"
    );
    assert_eq!(zone_calls.lock().unwrap().len(), sent);
}

#[tokio::test]
async fn test_retries_withdrawal_that_reverted() {
    let (zone_url, zone_calls) =
        spawn_rpc(zone_handler(|| Ok(zone_receipt("0x0", json!([]))))).await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    let challenge = challenge_with(json!({}), None);
    for _ in 0..2 {
        let error = provider.pay(&challenge).await.unwrap_err();
        assert!(error.to_string().contains("reverted"), "{error}");
    }
    let sends = zone_calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| *call == "eth_sendRawTransactionSync")
        .count();
    assert_eq!(sends, 2);
}

#[tokio::test]
async fn test_retries_withdrawal_that_failed_before_it_was_sent() {
    let (zone_url, zone_calls) =
        spawn_rpc(Arc::new(|_, _| Err((-32000, "connection lost".into())))).await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    let challenge = challenge_with(json!({}), None);
    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(
        !matches!(error, MppError::PaymentOutcomeUnknown { .. }),
        "{error}"
    );
    let sent = zone_calls.lock().unwrap().len();
    provider.pay(&challenge).await.unwrap_err();
    assert!(zone_calls.lock().unwrap().len() > sent);
    assert!(!zone_calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| call == "eth_sendRawTransactionSync"));
}

#[tokio::test]
async fn test_shares_one_withdrawal_request_between_concurrent_payments() {
    let (zone_url, zone_calls) = unused_zone_rpc().await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    let challenge = challenge_with(json!({}), None);
    let other = provider.clone();
    let (first, second) = tokio::join!(provider.pay(&challenge), other.pay(&challenge));
    assert!(first.is_err() && second.is_err());
    assert_eq!(zone_calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_pays_and_resumes_a_settlement_wait_without_withdrawing_again() {
    let sends = Arc::new(AtomicUsize::new(0));
    let sends_in_zone = sends.clone();
    let (zone_url, _) = spawn_rpc(zone_handler(move || {
        sends_in_zone.fetch_add(1, Ordering::SeqCst);
        Ok(zone_receipt(
            "0x1",
            json!([withdrawal_requested_log(payer().address())]),
        ))
    }))
    .await;
    let logs = Arc::new(Mutex::new(json!([])));
    let (tempo_url, tempo_calls) = tempo_rpc(logs.clone()).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let provider = TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_zone(zone)
        .unwrap();
    let challenge = challenge_with(json!({}), None);
    let sender_tag = zone::sender_tag(payer().address(), B256::repeat_byte(0x22), 7);

    // Give up on settlement at once, as a timeout would.
    let error = provider.pay(&challenge).await.unwrap_err();
    // The error carries the challenge, so a caller that would otherwise
    // re-send the request (and get a fresh challenge) can pay this one again.
    let pending_challenge = match error {
        MppError::ZoneSettlementPending {
            challenge: pending_challenge,
            challenge_id,
            sender_tag: pending_tag,
            zone_id,
        } => {
            assert_eq!(challenge_id, "zone-challenge");
            assert_eq!(pending_tag, format!("{sender_tag:#x}"));
            assert_eq!(zone_id, 3);
            *pending_challenge
        }
        error => panic!("unexpected error: {error}"),
    };
    assert!(tempo_calls
        .lock()
        .unwrap()
        .iter()
        .any(|call| call == "eth_getLogs"));

    // The withdrawal settles; the retry finds it instead of paying again.
    let settlement = B256::repeat_byte(0x33);
    *logs.lock().unwrap() = json!([{
        "address": format!("{:#x}", zone::portal_address(3)),
        "topics": [
            format!("{:#x}", IZonePortal::WithdrawalProcessed::SIGNATURE_HASH),
            format!("{:#x}", MERCHANT.into_word()),
            format!("{sender_tag:#x}"),
        ],
        "data": "0x",
        "blockHash": format!("{:#x}", B256::repeat_byte(0x44)),
        "blockNumber": "0x10",
        "transactionHash": format!("{settlement:#x}"),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    }]);
    let credential = provider.pay(&pending_challenge).await.unwrap();
    let payload = credential.charge_payload().unwrap();
    assert!(payload.is_zone());
    assert_eq!(payload.data(), format!("{settlement:#x}"));
    assert_eq!(
        payload.zone_sender_tag(),
        Some(format!("{sender_tag:#x}").as_str())
    );
    assert_eq!(payload.zone_id(), Some(3));
    assert_eq!(sends.load(Ordering::SeqCst), 1);
}

#[test]
fn test_zone_settlement_pending_message() {
    let error = MppError::ZoneSettlementPending {
        challenge: Box::new(challenge_with(json!({}), None)),
        challenge_id: "abc".into(),
        sender_tag: "0x01".into(),
        zone_id: 3,
    };
    assert_eq!(
        error.to_string(),
        "Zone 3 withdrawal 0x01 for challenge \"abc\" has not settled on Tempo yet. Pay this challenge again to resume waiting: a fresh challenge would withdraw again."
    );
}

#[tokio::test]
async fn test_withdrawal_without_its_event_is_outcome_unknown() {
    // The withdrawal succeeded, but its WithdrawalRequested event is missing.
    let (zone_url, zone_calls) =
        spawn_rpc(zone_handler(|| Ok(zone_receipt("0x1", json!([]))))).await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    let challenge = challenge_with(json!({}), None);
    for _ in 0..2 {
        let error = provider.pay(&challenge).await.unwrap_err();
        assert!(
            matches!(error, MppError::PaymentOutcomeUnknown { .. }),
            "{error}"
        );
    }
    let sends = zone_calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| *call == "eth_sendRawTransactionSync")
        .count();
    assert_eq!(sends, 1);
}

/// A Zone handler recording the raw transactions it is sent.
fn recording_zone_handler(sent: Arc<Mutex<Vec<String>>>) -> Handler {
    let inner = zone_handler(|| {
        Ok(zone_receipt(
            "0x1",
            json!([withdrawal_requested_log(payer().address())]),
        ))
    });
    Arc::new(move |method, params| {
        if method == "eth_sendRawTransactionSync" {
            sent.lock()
                .unwrap()
                .push(params[0].as_str().unwrap_or_default().to_string());
        }
        inner(method, params)
    })
}

#[tokio::test]
async fn test_cancelled_payment_does_not_withdraw_again() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, zone_calls) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let (provider, _) = provider_with_zone(zone).await;
    let challenge = challenge_with(json!({}), None);

    // Cancel the payment once the Zone has the transaction but before it answers.
    let sending = async {
        while !zone_calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call == "eth_sendRawTransactionSync")
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::select! {
        result = provider.pay(&challenge) => panic!("payment was not cancelled: {result:?}"),
        () = sending => {}
    }

    // The retry reconciles the withdrawal the cancelled payment sent.
    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(
        matches!(error, MppError::ZoneSettlementPending { .. }),
        "{error}"
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_serializes_nonces_across_challenges() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, zone_calls) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let (provider, _) = provider_with_zone(zone).await;
    let first = challenge_with(json!({}), None);
    let mut second = first.clone();
    second.id = "other-challenge".into();
    let other = provider.clone();
    let (a, b) = tokio::join!(provider.pay(&first), other.pay(&second));
    assert!(a.is_err() && b.is_err());

    // The second nonce lookup waits for the first withdrawal's outcome.
    let calls = zone_calls.lock().unwrap();
    let order: Vec<&str> = calls
        .iter()
        .map(String::as_str)
        .filter(|call| {
            matches!(
                *call,
                "eth_getTransactionCount" | "eth_sendRawTransactionSync"
            )
        })
        .collect();
    assert_eq!(
        order,
        [
            "eth_getTransactionCount",
            "eth_sendRawTransactionSync",
            "eth_getTransactionCount",
            "eth_sendRawTransactionSync",
        ]
    );
    assert_eq!(sent.lock().unwrap().len(), 2);
}

/// The fee token of the first withdrawal sent to the Zone.
fn sent_fee_token(sent: &Mutex<Vec<String>>) -> Option<Address> {
    use alloy::eips::Decodable2718;
    use tempo_alloy::primitives::AASigned;

    let raw = sent.lock().unwrap()[0].clone();
    let bytes = alloy::hex::decode(raw.trim_start_matches("0x")).unwrap();
    AASigned::decode_2718(&mut bytes.as_slice())
        .unwrap()
        .tx()
        .fee_token
}

#[tokio::test]
async fn test_withdrawal_pays_fees_in_the_charge_currency_by_default() {
    // The provider's fee token is a Tempo token the payer may not hold in the
    // Zone, so the withdrawal pays its gas in the currency it withdraws.
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, _) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let (tempo_url, _) = tempo_rpc(Arc::new(Mutex::new(json!([])))).await;
    let provider = TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_fee_token(address!("20c0000000000000000000000000000000000000"))
        .with_zone(zone)
        .unwrap();
    provider
        .pay(&challenge_with(json!({}), None))
        .await
        .unwrap_err();
    assert_eq!(sent_fee_token(&sent), Some(CURRENCY));
}

#[tokio::test]
async fn test_withdrawal_pays_fees_in_the_zone_fee_token() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, _) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let fee_token = address!("20c0000000000000000000000000000000000000");
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO)
        .with_fee_token(fee_token);
    let (provider, _) = provider_with_zone(zone).await;
    provider
        .pay(&challenge_with(json!({}), None))
        .await
        .unwrap_err();
    assert_eq!(sent_fee_token(&sent), Some(fee_token));
}

#[tokio::test]
async fn test_queued_withdrawal_rechecks_expiry_before_sending() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, zone_calls) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let (provider, _) = provider_with_zone(zone.clone()).await;
    // Leaves time to settle when the payment starts, but not after another
    // withdrawal from the account holds the nonce lock for a few seconds.
    let challenge = challenge_with(
        json!({}),
        expires_in(SUBMISSION_MARGIN.as_secs() as i64 + 3),
    );
    let lock = zone.nonce_lock(payer().address());
    let guard = lock.lock().await;
    let payment = tokio::spawn(async move { provider.pay(&challenge).await });
    tokio::time::sleep(Duration::from_secs(4)).await;
    drop(guard);

    let error = payment.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("expires"), "{error}");
    assert!(
        !matches!(error, MppError::PaymentOutcomeUnknown { .. }),
        "{error}"
    );
    assert!(!zone_calls.lock().unwrap().iter().any(|call| matches!(
        call.as_str(),
        "eth_getTransactionCount" | "eth_sendRawTransactionSync"
    )));
    assert!(sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_retries_withdrawal_the_zone_refused() {
    // The node refuses the transaction, say for fees the payer can't pay, and
    // doesn't know it afterwards: nothing was withdrawn.
    let handler = zone_handler(|| Ok(Value::Null));
    let (zone_url, zone_calls) = spawn_rpc(Arc::new(move |method, params| match method {
        "eth_sendRawTransactionSync" => {
            Err((-32003, "insufficient funds for gas * price + value".into()))
        }
        "eth_getTransactionByHash" => Ok(Value::Null),
        _ => handler(method, params),
    }))
    .await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    let challenge = challenge_with(json!({}), None);
    for _ in 0..2 {
        let error = provider.pay(&challenge).await.unwrap_err();
        assert!(error.to_string().contains("insufficient funds"), "{error}");
        assert!(
            !matches!(error, MppError::PaymentOutcomeUnknown { .. }),
            "{error}"
        );
    }
    let calls = zone_calls.lock().unwrap();
    let sends = calls
        .iter()
        .filter(|call| *call == "eth_sendRawTransactionSync")
        .count();
    assert_eq!(sends, 2);
    assert!(!calls.iter().any(|call| call == "eth_getTransactionReceipt"));
}

#[tokio::test]
async fn test_unrecognized_send_error_with_an_unknown_transaction_is_outcome_unknown() {
    // The node answered with an error that doesn't prove it refused the
    // transaction, and doesn't know it yet: a load-balanced or still-indexing
    // node may have accepted it, so nothing pays the challenge again.
    for message in [
        "internal error",
        "nonce too low",
        "already known",
        "replacement transaction underpriced",
    ] {
        let handler = zone_handler(|| Ok(Value::Null));
        let (zone_url, zone_calls) = spawn_rpc(Arc::new(move |method, params| match method {
            "eth_sendRawTransactionSync" => Err((-32000, message.into())),
            "eth_getTransactionByHash" => Ok(Value::Null),
            "eth_getTransactionReceipt" => Ok(Value::Null),
            _ => handler(method, params),
        }))
        .await;
        let mut zone = TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap();
        zone.receipt_recovery_timeout = Duration::ZERO;
        let (provider, _) = provider_with_zone(zone).await;
        let challenge = challenge_with(json!({}), None);
        let error = provider.pay(&challenge).await.unwrap_err();
        assert!(
            matches!(error, MppError::PaymentOutcomeUnknown { .. }),
            "{message}: {error}"
        );
        // A retry doesn't send it again.
        let retry = provider.pay(&challenge).await.unwrap_err();
        assert!(
            matches!(retry, MppError::PaymentOutcomeUnknown { .. }),
            "{message}: {retry}"
        );
        let sends = zone_calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| *call == "eth_sendRawTransactionSync")
            .count();
        assert_eq!(sends, 1, "{message}");
    }
}

#[test]
fn test_rejected_before_admission() {
    for message in [
        "insufficient funds for gas * price + value",
        "Insufficient balance for transfer",
        "intrinsic gas too low",
        "exceeds block gas limit",
        "invalid signature",
        "max fee per gas less than block base fee",
    ] {
        assert!(super::rejected_before_admission(message), "{message}");
    }
    for message in [
        "internal error",
        "rejected",
        "nonce too low",
        "already known",
        "replacement transaction underpriced",
        "transaction underpriced: insufficient funds",
    ] {
        assert!(!super::rejected_before_admission(message), "{message}");
    }
}

#[tokio::test]
async fn test_withdrawal_known_to_the_zone_after_a_send_error_is_outcome_unknown() {
    // The node answered with an error but knows the transaction, or timed out
    // waiting for its receipt: it may run.
    for (code, known) in [(-32003, json!({ "hash": "0x22" })), (4, Value::Null)] {
        let handler = zone_handler(|| Ok(Value::Null));
        let (zone_url, _) = spawn_rpc(Arc::new(move |method, params| match method {
            "eth_sendRawTransactionSync" => Err((code, "rejected".into())),
            "eth_getTransactionByHash" => Ok(known.clone()),
            "eth_getTransactionReceipt" => Ok(Value::Null),
            _ => handler(method, params),
        }))
        .await;
        let mut zone = TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap();
        zone.receipt_recovery_timeout = Duration::ZERO;
        let (provider, _) = provider_with_zone(zone).await;
        let error = provider
            .pay(&challenge_with(json!({}), None))
            .await
            .unwrap_err();
        assert!(
            matches!(error, MppError::PaymentOutcomeUnknown { .. }),
            "{code}: {error}"
        );
    }
}

/// A WithdrawalProcessed log the portal of Zone 3 emits for sender_tag.
fn settlement_log(sender_tag: B256, callback_success: bool, transaction_hash: B256) -> Value {
    let data = IZonePortal::WithdrawalProcessed {
        to: MERCHANT,
        senderTag: sender_tag,
        token: CURRENCY,
        amount: 1_000_000,
        callbackSuccess: callback_success,
    }
    .encode_log_data();
    json!({
        "address": format!("{:#x}", zone::portal_address(3)),
        "topics": data.topics().iter().map(|topic| format!("{topic:#x}")).collect::<Vec<_>>(),
        "data": format!("{}", data.data),
        "blockHash": format!("{:#x}", B256::repeat_byte(0x44)),
        "blockNumber": "0x10",
        "transactionHash": format!("{transaction_hash:#x}"),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

#[tokio::test]
async fn test_bounced_withdrawal_fails_without_a_credential_and_may_be_paid_again() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, _) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let sender_tag = zone::sender_tag(payer().address(), B256::repeat_byte(0x22), 7);
    let logs = Arc::new(Mutex::new(json!([settlement_log(
        sender_tag,
        false,
        B256::repeat_byte(0x33)
    )])));
    let (tempo_url, _) = tempo_rpc(logs.clone()).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let provider = TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_zone(zone)
        .unwrap();
    let challenge = challenge_with(json!({}), None);

    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(error.to_string().contains("bounced"), "{error}");
    match &error {
        MppError::ZoneWithdrawalBounced {
            challenge_id,
            sender_tag: tag,
            zone_id,
        } => {
            assert_eq!(challenge_id, &challenge.id);
            assert_eq!(tag, &format!("{sender_tag:#x}"));
            assert_eq!(*zone_id, 3);
        }
        other => panic!("expected ZoneWithdrawalBounced, got {other}"),
    }

    // The amount came back to the payer, so a retry withdraws again.
    *logs.lock().unwrap() = json!([settlement_log(sender_tag, true, B256::repeat_byte(0x55))]);
    let credential = provider.pay(&challenge).await.unwrap();
    assert_eq!(
        credential.charge_payload().unwrap().data(),
        format!("{:#x}", B256::repeat_byte(0x55))
    );
    assert_eq!(sent.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn test_resumed_settlement_wait_searches_from_where_the_first_one_started() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, _) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let block = Arc::new(std::sync::atomic::AtomicU64::new(10_000));
    let from_blocks = Arc::new(Mutex::new(Vec::new()));
    let (tempo_url, _) = {
        let block = block.clone();
        let from_blocks = from_blocks.clone();
        spawn_rpc(Arc::new(move |method, params| match method {
            "eth_chainId" => Ok(json!("0xa5bf")),
            "eth_blockNumber" => Ok(json!(format!("{:#x}", block.load(Ordering::SeqCst)))),
            "eth_getLogs" => {
                from_blocks.lock().unwrap().push(
                    params[0]["fromBlock"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                );
                Ok(json!([]))
            }
            _ => Err((-32000, format!("l1: {method}"))),
        }))
        .await
    };
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let provider = TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_zone(zone)
        .unwrap();
    let challenge = challenge_with(json!({}), None);
    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(
        matches!(error, MppError::ZoneSettlementPending { .. }),
        "{error}"
    );

    // Far more than the lookback window later, the retry still searches
    // every block since the first wait.
    block.store(20_000, Ordering::SeqCst);
    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(
        matches!(error, MppError::ZoneSettlementPending { .. }),
        "{error}"
    );
    assert_eq!(
        *from_blocks.lock().unwrap(),
        [
            format!("{:#x}", 10_000 - LOOKBACK_BLOCKS),
            format!("{:#x}", 10_000 - LOOKBACK_BLOCKS)
        ]
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}
