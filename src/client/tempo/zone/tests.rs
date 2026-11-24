//! Zone payments from the Tempo charge client, as mppx's
//! `client/Charge.zone.test.ts`.

use std::collections::HashMap;
use std::sync::atomic::Ordering;

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
fn test_rejects_zone_id_in_zone_chain_id_range() {
    let error = TempoZone::new("http://127.0.0.1:1", 1_000)
        .unwrap()
        .with_zone_id(421_700_003)
        .unwrap_err();
    assert!(error.to_string().contains("invalid Zone ID"), "{error}");
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
fn test_rejects_parent_chain_id_that_does_not_match_zone_chain() {
    // Zone 3 of Moderato settles on Moderato, not on mainnet.
    let zone = TempoZone::new("http://127.0.0.1:1", MODERATO_ZONE_3)
        .unwrap()
        .with_parent_chain_id(4217);
    let error = TempoProvider::new(payer(), "http://127.0.0.1:1")
        .unwrap()
        .with_zone(zone)
        .err()
        .unwrap();
    assert!(
        error
            .to_string()
            .contains("does not match Tempo chain 42431 of the Zone chain 1424310003"),
        "{error}"
    );
    // The parent the chain ID names, and any parent of a Zone chain ID that
    // follows no known scheme, are accepted.
    for zone in [
        TempoZone::new("http://127.0.0.1:1", MODERATO_ZONE_3)
            .unwrap()
            .with_parent_chain_id(42_431),
        TempoZone::new("http://127.0.0.1:1", 7)
            .unwrap()
            .with_zone_id(3)
            .unwrap()
            .with_parent_chain_id(4217),
    ] {
        assert!(TempoProvider::new(payer(), "http://127.0.0.1:1")
            .unwrap()
            .with_zone(zone)
            .is_ok());
    }
}

#[tokio::test]
async fn test_never_withdraws_on_a_parent_chain_that_does_not_match_zone_chain() {
    let (zone_url, zone_calls) = unused_zone_rpc().await;
    let (tempo_url, tempo_calls) = tempo_rpc(Arc::new(Mutex::new(json!([])))).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_parent_chain_id(4217);
    // A Challenge on the overridden chain.
    let challenge = challenge_with(json!({ "chainId": 4217 }), None);
    let request: ChargeRequest = challenge.request.decode().unwrap();
    let signer = TempoPrimitiveSigner::from(payer());
    let signing_mode = TempoSigningMode::Direct;
    let error = zone
        .pays(&challenge, &request, 4217, &signer, &signing_mode)
        .unwrap_err();
    assert!(error.to_string().contains("does not match"), "{error}");
    let tempo = super::super::rpc_provider(tempo_url.parse().unwrap(), None);
    let error = zone
        .pay(
            &challenge,
            None,
            None,
            ZoneCaps::default(),
            &signer,
            &signing_mode,
            &tempo,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("does not match"), "{error}");
    assert!(zone_calls.lock().unwrap().is_empty());
    assert!(tempo_calls.lock().unwrap().is_empty());
}

/// An unpinned provider with a Zone on its RPC chain refuses a Challenge
/// naming another chain, as the ordinary path does, without touching the Zone.
#[tokio::test]
async fn test_never_withdraws_for_a_challenge_on_another_chain() {
    let (zone_url, zone_calls) = unused_zone_rpc().await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    let challenge = challenge_with(json!({ "chainId": 4217 }), None);
    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(
        matches!(
            error,
            MppError::ChainIdMismatch {
                expected: 42431,
                got: 4217
            }
        ),
        "{error:?}"
    );
    assert!(zone_calls.lock().unwrap().is_empty());
}

/// The Zone predicate checks the Challenge's chain, not only the signing chain.
#[tokio::test]
async fn test_does_not_pay_a_challenge_on_another_chain_from_the_zone() {
    let (zone_url, zone_calls) = unused_zone_rpc().await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap();
    let challenge = challenge_with(json!({ "chainId": 4217 }), None);
    let request: ChargeRequest = challenge.request.decode().unwrap();
    let signer = TempoPrimitiveSigner::from(payer());
    assert!(!zone
        .pays(
            &challenge,
            &request,
            42431,
            &signer,
            &TempoSigningMode::Direct
        )
        .unwrap());
    assert!(zone_calls.lock().unwrap().is_empty());
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

/// The hash of the raw transaction `raw`.
fn tx_hash(raw: &str) -> B256 {
    alloy::primitives::keccak256(alloy::hex::decode(raw.trim_start_matches("0x")).unwrap())
}

/// The outbox's `WithdrawalRequested` for the withdrawal the raw transaction
/// `raw` requests, as a JSON-RPC log, after `edit`.
fn withdrawal_requested_log_with(
    raw: &str,
    edit: impl FnOnce(&mut IZoneOutbox::WithdrawalRequested),
) -> Value {
    use alloy::consensus::transaction::SignerRecoverable;
    use alloy::eips::Decodable2718;
    use tempo_alloy::primitives::AASigned;

    let bytes = alloy::hex::decode(raw.trim_start_matches("0x")).unwrap();
    let signed = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();
    let request = signed
        .tx()
        .calls
        .iter()
        .find(|call| call.to == TxKind::Call(zone::ZONE_OUTBOX))
        .map(|call| IZoneOutbox::requestWithdrawalCall::abi_decode(&call.input).unwrap())
        .unwrap();
    let mut event = IZoneOutbox::WithdrawalRequested {
        withdrawalIndex: 0,
        sender: signed.recover_signer().unwrap(),
        token: request.token,
        to: request.to,
        amount: request.amount,
        fee: 1,
        memo: request.memo,
        gasLimit: 0,
        fallbackNonce: 7,
        data: Bytes::new(),
        revealTo: Bytes::new(),
    };
    edit(&mut event);
    let data = event.encode_log_data();
    json!({
        "address": format!("{:#x}", zone::ZONE_OUTBOX),
        "topics": data.topics().iter().map(|topic| format!("{topic:#x}")).collect::<Vec<_>>(),
        "data": format!("{}", data.data),
        "blockHash": format!("{:#x}", B256::repeat_byte(0x11)),
        "blockNumber": "0x1",
        "transactionHash": format!("{:#x}", tx_hash(raw)),
        "transactionIndex": "0x0",
        "logIndex": "0x0",
        "removed": false,
    })
}

/// The outbox's `WithdrawalRequested` for the withdrawal the raw transaction
/// `raw` requests, as a JSON-RPC log.
fn withdrawal_requested_log(raw: &str) -> Value {
    withdrawal_requested_log_with(raw, |_| {})
}

/// The receipt of the raw transaction `raw`.
fn zone_receipt(raw: &str, status: &str, logs: Value) -> Value {
    json!({
        "type": "0x76",
        "status": status,
        "cumulativeGasUsed": "0x1",
        "logs": logs,
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "transactionHash": format!("{:#x}", tx_hash(raw)),
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

/// The sender tag of the last withdrawal sent to the Zone.
fn sent_sender_tag(sent: &Mutex<Vec<String>>) -> B256 {
    let raw = sent.lock().unwrap().last().unwrap().clone();
    zone::sender_tag(payer().address(), tx_hash(&raw), 7)
}

/// A Moderato RPC that settles the last withdrawal sent to the Zone with the
/// `(callback_success, transaction_hash)` in `settlement`.
async fn settling_tempo_rpc(
    sent: Arc<Mutex<Vec<String>>>,
    settlement: Arc<Mutex<(bool, B256)>>,
) -> (String, Arc<Mutex<Vec<String>>>) {
    spawn_rpc(Arc::new(move |method, _| match method {
        "eth_chainId" => Ok(json!("0xa5bf")),
        "eth_blockNumber" => Ok(json!("0x10")),
        "eth_getLogs" => {
            let (callback_success, hash) = *settlement.lock().unwrap();
            Ok(json!([settlement_log(
                sent_sender_tag(&sent),
                callback_success,
                hash
            )]))
        }
        _ => Err((-32000, format!("l1: {method}"))),
    }))
    .await
}

/// A Zone RPC that prepares and signs withdrawals, then answers the send with
/// `send`; once a send failed, every later call fails.
fn zone_handler(
    send: impl Fn(&str) -> Result<Value, (i64, String)> + Send + Sync + 'static,
) -> Handler {
    let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    Arc::new(move |method, params| {
        if failed.load(Ordering::SeqCst) {
            return Err((-32000, "connection lost".into()));
        }
        match method {
            "eth_chainId" => Ok(json!(format!("{MODERATO_ZONE_3:#x}"))),
            "eth_call" => Ok(json!(format!("0x{}", "00".repeat(32)))),
            "eth_sendRawTransactionSync" => {
                let result = send(params[0].as_str().unwrap_or_default());
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
        spawn_rpc(zone_handler(|_| Err((-32000, "connection lost".into())))).await;
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
        spawn_rpc(zone_handler(|raw| Ok(zone_receipt(raw, "0x0", json!([]))))).await;
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
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, _) = spawn_rpc(recording_zone_handler(sent.clone())).await;
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

    // Give up on settlement at once, as a timeout would.
    let error = provider.pay(&challenge).await.unwrap_err();
    let sender_tag = sent_sender_tag(&sent);
    // The error carries the challenge, so a caller that would otherwise
    // re-send the request (and get a fresh challenge) can pay this one again.
    let pending_challenge = match error {
        MppError::ZoneSettlementPending {
            challenge: pending_challenge,
            challenge_id,
            sender_tag: pending_tag,
            sender_tags,
            zone_id,
        } => {
            assert_eq!(challenge_id, "zone-challenge");
            assert_eq!(pending_tag, format!("{sender_tag:#x}"));
            assert_eq!(sender_tags, [pending_tag]);
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
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[test]
fn test_zone_settlement_pending_message() {
    let error = MppError::ZoneSettlementPending {
        challenge: Box::new(challenge_with(json!({}), None)),
        challenge_id: "abc".into(),
        sender_tag: "0x01".into(),
        sender_tags: vec!["0x01".into()],
        zone_id: 3,
    };
    assert_eq!(
        error.to_string(),
        "Zone 3 withdrawal 0x01 for challenge \"abc\" has not settled on Tempo yet. Pay this challenge again to resume waiting: a fresh challenge would withdraw again."
    );
    let error = settlement_pending(
        &challenge_with(json!({}), None),
        vec!["0x01".into(), "0x02".into()],
        3,
    );
    assert_eq!(
        error.to_string(),
        "Zone 3 withdrawal with sender tag 0x01 or 0x02 for challenge \"zone-challenge\" has not settled on Tempo yet. Pay this challenge again to resume waiting: a fresh challenge would withdraw again."
    );
}

/// The Zone chain a redacting Zone RPC serves: each block's number, parent
/// hash and outbox `lastFallbackNonce`, which blocks are canonical, and the
/// block the withdrawal's receipt names.
struct ZoneChain {
    blocks: HashMap<B256, (u64, B256, u64)>,
    canonical: Vec<B256>,
    receipt_block: B256,
}

/// The block the receipts of `zone_receipt` name, and its parent.
const RECEIPT_BLOCK: B256 = B256::repeat_byte(0x11);
const RECEIPT_PARENT: B256 = B256::repeat_byte(0x10);

impl ZoneChain {
    /// A chain whose outbox reports `before` at block 0 and `after` at the
    /// withdrawal's block 1.
    fn new(before: u64, after: u64) -> Self {
        Self {
            blocks: HashMap::from([
                (RECEIPT_PARENT, (0, B256::ZERO, before)),
                (RECEIPT_BLOCK, (1, RECEIPT_PARENT, after)),
            ]),
            canonical: vec![RECEIPT_PARENT, RECEIPT_BLOCK],
            receipt_block: RECEIPT_BLOCK,
        }
    }
}

/// A Zone RPC that leaves the outbox's events out of receipts, as a
/// production Zone RPC does with other contracts' logs, and whose outbox
/// reports `before` as its `lastFallbackNonce` at block 0 and `after` at the
/// withdrawal's block 1. While `fail_reads` is set, those reads fail.
fn redacting_zone_handler(
    sent: Arc<Mutex<Vec<String>>>,
    before: u64,
    after: u64,
    fail_reads: Arc<std::sync::atomic::AtomicBool>,
) -> Handler {
    redacting_zone_handler_on(
        sent,
        Arc::new(Mutex::new(ZoneChain::new(before, after))),
        fail_reads,
    )
}

/// A redacting Zone RPC serving `chain`: it answers outbox reads only by
/// block hash, refusing a block that is no longer canonical, as EIP-1898's
/// `requireCanonical` does.
fn redacting_zone_handler_on(
    sent: Arc<Mutex<Vec<String>>>,
    chain: Arc<Mutex<ZoneChain>>,
    fail_reads: Arc<std::sync::atomic::AtomicBool>,
) -> Handler {
    let inner = zone_handler(|raw| Ok(zone_receipt(raw, "0x1", json!([]))));
    let selector = format!(
        "0x{}",
        alloy::hex::encode(IZoneOutbox::lastFallbackNonceCall::SELECTOR)
    );
    Arc::new(move |method, params| {
        if method == "eth_sendRawTransactionSync" {
            sent.lock()
                .unwrap()
                .push(params[0].as_str().unwrap_or_default().to_string());
        }
        let chain = chain.lock().unwrap();
        match method {
            "eth_call" if params[0]["data"].as_str() == Some(selector.as_str()) => {
                if fail_reads.load(Ordering::SeqCst) {
                    return Err((-32000, "read failed".into()));
                }
                assert_eq!(params[1]["requireCanonical"], json!(true));
                let hash: B256 = params[1]["blockHash"]
                    .as_str()
                    .expect("outbox read not pinned to a block hash")
                    .parse()
                    .unwrap();
                if !chain.canonical.contains(&hash) {
                    return Err((-32000, "block is not canonical".into()));
                }
                let (_, _, nonce) = chain.blocks[&hash];
                Ok(json!(format!("{:#066x}", nonce)))
            }
            "eth_getBlockByHash" => {
                let hash: B256 = params[0].as_str().unwrap().parse().unwrap();
                Ok(match chain.blocks.get(&hash) {
                    Some((number, parent, _)) => json!({
                        "hash": format!("{hash:#x}"),
                        "number": format!("{number:#x}"),
                        "parentHash": format!("{parent:#x}"),
                    }),
                    None => Value::Null,
                })
            }
            "eth_getTransactionReceipt" => {
                let Some(raw) = sent.lock().unwrap().last().cloned() else {
                    return Ok(Value::Null);
                };
                let mut receipt = zone_receipt(&raw, "0x1", json!([]));
                receipt["blockHash"] = json!(format!("{:#x}", chain.receipt_block));
                Ok(receipt)
            }
            _ => {
                drop(chain);
                inner(method, params)
            }
        }
    })
}

#[tokio::test]
async fn test_pays_when_the_zone_rpc_redacts_outbox_events() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    // The withdrawal took fallback nonce 7, the one its block added.
    let (zone_url, _) = spawn_rpc(redacting_zone_handler(sent.clone(), 6, 7, Arc::default())).await;
    let settlement = Arc::new(Mutex::new((true, B256::repeat_byte(0x33))));
    let (tempo_url, _) = settling_tempo_rpc(sent.clone(), settlement).await;
    let provider = TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap())
        .unwrap();
    let challenge = challenge_with(json!({}), None);

    let credential = provider.pay(&challenge).await.unwrap();
    let payload = credential.charge_payload().unwrap();
    assert_eq!(payload.data(), format!("{:#x}", B256::repeat_byte(0x33)));
    assert_eq!(
        payload.zone_sender_tag(),
        Some(format!("{:#x}", sent_sender_tag(&sent)).as_str())
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_retries_a_failed_sender_tag_read_without_withdrawing_again() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let fail_reads = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (zone_url, _) = spawn_rpc(redacting_zone_handler(
        sent.clone(),
        6,
        7,
        fail_reads.clone(),
    ))
    .await;
    let settlement = Arc::new(Mutex::new((true, B256::repeat_byte(0x33))));
    let (tempo_url, _) = settling_tempo_rpc(sent.clone(), settlement).await;
    let provider = TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap())
        .unwrap();
    let challenge = challenge_with(json!({}), None);

    // A failed read is resumable: HTTP and MCP flows retry this error.
    match provider.pay(&challenge).await.unwrap_err() {
        MppError::ZoneSettlementPending {
            challenge_id,
            sender_tags,
            ..
        } => {
            assert_eq!(challenge_id, "zone-challenge");
            assert!(sender_tags.is_empty());
        }
        error => panic!("expected ZoneSettlementPending, got {error}"),
    }
    fail_reads.store(false, Ordering::SeqCst);
    let credential = provider.pay(&challenge).await.unwrap();
    assert_eq!(
        credential.charge_payload().unwrap().zone_sender_tag(),
        Some(format!("{:#x}", sent_sender_tag(&sent)).as_str())
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_failed_sender_tag_read_pins_the_settlement_search() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let fail_reads = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let (zone_url, _) = spawn_rpc(redacting_zone_handler(
        sent.clone(),
        6,
        7,
        fail_reads.clone(),
    ))
    .await;
    let block = Arc::new(std::sync::atomic::AtomicU64::new(10_000));
    let from_blocks = Arc::new(Mutex::new(Vec::new()));
    let pinned = format!("{:#x}", 10_000 - LOOKBACK_BLOCKS);
    let (tempo_url, _) = {
        let sent = sent.clone();
        let block = block.clone();
        let from_blocks = from_blocks.clone();
        let pinned = pinned.clone();
        spawn_rpc(Arc::new(move |method, params| match method {
            "eth_chainId" => Ok(json!("0xa5bf")),
            "eth_blockNumber" => Ok(json!(format!("{:#x}", block.load(Ordering::SeqCst)))),
            "eth_getLogs" => {
                let from = params[0]["fromBlock"].as_str().unwrap_or_default();
                from_blocks.lock().unwrap().push(from.to_string());
                // The withdrawal settled within the window before the
                // first failed read, and nowhere a later window covers.
                if from == pinned {
                    Ok(json!([settlement_log(
                        sent_sender_tag(&sent),
                        true,
                        B256::repeat_byte(0x33)
                    )]))
                } else {
                    Ok(json!([]))
                }
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
    // Tempo moved far past the lookback window before the tags could be
    // read: the search still starts where it would have at the failed read.
    block.store(30_000, Ordering::SeqCst);
    fail_reads.store(false, Ordering::SeqCst);
    let credential = provider.pay(&challenge).await.unwrap();
    assert_eq!(from_blocks.lock().unwrap().first(), Some(&pinned));
    assert_eq!(
        credential.charge_payload().unwrap().zone_sender_tag(),
        Some(format!("{:#x}", sent_sender_tag(&sent)).as_str())
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_sender_tag_read_ends_at_the_challenge_expiry() {
    // The Zone redacts outbox events and never answers the outbox's
    // lastFallbackNonce, so the sender tag read stalls.
    let sent = Arc::new(Mutex::new(Vec::new()));
    let selector = format!(
        "0x{}",
        alloy::hex::encode(IZoneOutbox::lastFallbackNonceCall::SELECTOR)
    );
    let (zone_url, _) = spawn_rpc_stalling_when(
        redacting_zone_handler(sent.clone(), 6, 7, Arc::default()),
        move |method, params| {
            method == "eth_call" && params[0]["data"].as_str() == Some(selector.as_str())
        },
    )
    .await;
    let mut zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    // Longer than the challenge has left: the expiry, not this, ends the read.
    zone.rpc_timeout = Duration::from_secs(60);
    let (provider, _) = provider_with_zone(zone).await;
    // Leaves just over the settlement timeout plus the submission margin
    // the send check reserves.
    let lifetime = SUBMISSION_MARGIN.as_secs() as i64 + 2;
    let challenge = challenge_with(json!({}), expires_in(lifetime));

    let started = std::time::Instant::now();
    let error = tokio::time::timeout(Duration::from_secs(30), provider.pay(&challenge))
        .await
        .expect("the sender tag read outlived the challenge")
        .unwrap_err();
    assert!(
        matches!(error, MppError::ZoneSettlementPending { .. }),
        "{error}"
    );
    assert!(started.elapsed() < Duration::from_secs(lifetime as u64 + 2));
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_sender_tag_read_error_omits_the_zone_rpc_url() {
    // Nothing listens on port 1, so the read fails in the transport, whose
    // error names the request URL.
    let zone = super::super::rpc_provider(
        "http://127.0.0.1:1/zone-path-key?apikey=query-key"
            .parse()
            .unwrap(),
        None,
    );
    let error = sender_tag_candidates(&zone, 10, Address::ZERO, B256::repeat_byte(0xab))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("lastFallbackNonce"), "{error}");
    for part in ["zone-path-key", "query-key", "127.0.0.1"] {
        assert!(!error.contains(part), "{error}");
    }
}

#[tokio::test]
async fn test_withdrawal_whose_block_added_no_withdrawal_is_never_sent_again() {
    // The withdrawal succeeded, but neither its event nor the outbox shows it.
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, _) = spawn_rpc(redacting_zone_handler(sent.clone(), 7, 7, Arc::default())).await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    let challenge = challenge_with(json!({}), None);
    for _ in 0..2 {
        let error = provider.pay(&challenge).await.unwrap_err();
        let hash = tx_hash(sent.lock().unwrap().last().unwrap());
        match error {
            MppError::PaymentOutcomeUnknown { transaction_hash } => {
                assert_eq!(transaction_hash, format!("{hash:#x}"));
            }
            error => panic!("expected PaymentOutcomeUnknown, got {error}"),
        }
    }
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_withdrawal_whose_block_added_too_many_withdrawals_is_outcome_unknown() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, _) =
        spawn_rpc(redacting_zone_handler(sent.clone(), 0, 100, Arc::default())).await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    let error = provider
        .pay(&challenge_with(json!({}), None))
        .await
        .unwrap_err();
    assert!(
        matches!(error, MppError::PaymentOutcomeUnknown { .. }),
        "{error}"
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_resumed_wait_reuses_derived_sender_tags_without_reading_the_outbox() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let fail_reads = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (zone_url, _) = spawn_rpc(redacting_zone_handler(
        sent.clone(),
        6,
        7,
        fail_reads.clone(),
    ))
    .await;
    // Tempo shows no settlement until settled is set.
    let settled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (tempo_url, _) = {
        let sent = sent.clone();
        let settled = settled.clone();
        spawn_rpc(Arc::new(move |method, _| match method {
            "eth_chainId" => Ok(json!("0xa5bf")),
            "eth_blockNumber" => Ok(json!("0x10")),
            "eth_getLogs" if settled.load(Ordering::SeqCst) => Ok(json!([settlement_log(
                sent_sender_tag(&sent),
                true,
                B256::repeat_byte(0x33)
            )])),
            "eth_getLogs" => Ok(json!([])),
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
    // The Zone can no longer be read, but the tags were kept.
    fail_reads.store(true, Ordering::SeqCst);
    settled.store(true, Ordering::SeqCst);
    let credential = provider.pay(&challenge).await.unwrap();
    assert_eq!(
        credential.charge_payload().unwrap().zone_sender_tag(),
        Some(format!("{:#x}", sent_sender_tag(&sent)).as_str())
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_settlement_pending_error_carries_every_candidate_sender_tag() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    // The withdrawal's block added two, so either may be the payer's.
    let (zone_url, _) = spawn_rpc(redacting_zone_handler(sent.clone(), 5, 7, Arc::default())).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let (provider, _) = provider_with_zone(zone).await;
    let challenge = challenge_with(json!({}), None);

    let error = provider.pay(&challenge).await.unwrap_err();
    let hash = tx_hash(sent.lock().unwrap().last().unwrap());
    let candidates =
        [6, 7].map(|nonce| format!("{:#x}", zone::sender_tag(payer().address(), hash, nonce)));
    match &error {
        MppError::ZoneSettlementPending {
            sender_tag,
            sender_tags,
            ..
        } => {
            assert!(sender_tag.is_empty());
            assert_eq!(sender_tags, &candidates);
        }
        error => panic!("expected ZoneSettlementPending, got {error}"),
    }
    assert!(
        error.to_string().contains(&format!(
            "with sender tag {} or {}",
            candidates[0], candidates[1]
        )),
        "{error}"
    );
}

/// A Tempo RPC that settles the last withdrawal sent to the Zone under
/// fallback nonce 7, and whose settlement wait gives up at once.
async fn provider_settling_nonce_7(
    zone_url: String,
    sent: Arc<Mutex<Vec<String>>>,
) -> TempoProvider {
    let settlement = Arc::new(Mutex::new((true, B256::repeat_byte(0x33))));
    let (tempo_url, _) = settling_tempo_rpc(sent, settlement).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_zone(zone)
        .unwrap()
}

/// Moves the withdrawal to block 0x22 (number 2), whose outbox added nonce 7,
/// and drops block `RECEIPT_BLOCK` from the canonical chain.
fn reinclude_at_nonce_7(chain: &Mutex<ZoneChain>) {
    let mut chain = chain.lock().unwrap();
    let parent = B256::repeat_byte(0x21);
    let block = B256::repeat_byte(0x22);
    chain.blocks.insert(parent, (1, RECEIPT_PARENT, 6));
    chain.blocks.insert(block, (2, parent, 7));
    chain.canonical = vec![RECEIPT_PARENT, parent, block];
    chain.receipt_block = block;
}

#[tokio::test]
async fn test_rederives_sender_tags_when_the_withdrawal_moves_to_another_block() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    // The send's receipt names a block whose outbox added nonce 4, so the
    // derived tag is not the one that settles.
    let chain = Arc::new(Mutex::new(ZoneChain::new(3, 4)));
    let (zone_url, _) = spawn_rpc(redacting_zone_handler_on(
        sent.clone(),
        chain.clone(),
        Arc::default(),
    ))
    .await;
    let provider = provider_settling_nonce_7(zone_url, sent.clone()).await;
    let challenge = challenge_with(json!({}), None);

    let hash = || tx_hash(sent.lock().unwrap().last().unwrap());
    match provider.pay(&challenge).await.unwrap_err() {
        MppError::ZoneSettlementPending { sender_tags, .. } => assert_eq!(
            sender_tags,
            [format!(
                "{:#x}",
                zone::sender_tag(payer().address(), hash(), 4)
            )]
        ),
        error => panic!("expected ZoneSettlementPending, got {error}"),
    }
    // A reorg includes the transaction in another block: the retry follows
    // its receipt there rather than reusing the tags of the first block.
    reinclude_at_nonce_7(&chain);
    let credential = provider.pay(&challenge).await.unwrap();
    assert_eq!(
        credential.charge_payload().unwrap().zone_sender_tag(),
        Some(format!("{:#x}", sent_sender_tag(&sent)).as_str())
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_sender_tag_read_of_a_block_no_longer_canonical_is_retried_from_its_new_block() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let chain = Arc::new(Mutex::new(ZoneChain::new(6, 7)));
    // The send's block left the canonical chain before its state was read,
    // and the receipt lookup does not show the new block yet.
    chain.lock().unwrap().canonical = vec![RECEIPT_PARENT];
    let (zone_url, _) = spawn_rpc(redacting_zone_handler_on(
        sent.clone(),
        chain.clone(),
        Arc::default(),
    ))
    .await;
    let provider = provider_settling_nonce_7(zone_url, sent.clone()).await;
    let challenge = challenge_with(json!({}), None);

    for _ in 0..2 {
        match provider.pay(&challenge).await.unwrap_err() {
            MppError::ZoneSettlementPending { sender_tags, .. } => {
                assert!(sender_tags.is_empty());
            }
            error => panic!("expected ZoneSettlementPending, got {error}"),
        }
    }
    reinclude_at_nonce_7(&chain);
    let credential = provider.pay(&challenge).await.unwrap();
    assert_eq!(
        credential.charge_payload().unwrap().zone_sender_tag(),
        Some(format!("{:#x}", sent_sender_tag(&sent)).as_str())
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_receipt_lookup_that_proves_nothing_keeps_the_derived_sender_tags() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let chain = Arc::new(Mutex::new(ZoneChain::new(6, 7)));
    let fail_reads = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let handler = redacting_zone_handler_on(sent.clone(), chain.clone(), fail_reads.clone());
    // Once the tags are read, the Zone no longer answers receipt lookups.
    let (zone_url, zone_calls) = {
        let fail_reads = fail_reads.clone();
        spawn_rpc(Arc::new(move |method, params| {
            if method == "eth_getTransactionReceipt" && fail_reads.load(Ordering::SeqCst) {
                return Ok(Value::Null);
            }
            handler(method, params)
        }))
        .await
    };
    let settled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (tempo_url, _) = {
        let sent = sent.clone();
        let settled = settled.clone();
        spawn_rpc(Arc::new(move |method, _| match method {
            "eth_chainId" => Ok(json!("0xa5bf")),
            "eth_blockNumber" => Ok(json!("0x10")),
            "eth_getLogs" if settled.load(Ordering::SeqCst) => Ok(json!([settlement_log(
                sent_sender_tag(&sent),
                true,
                B256::repeat_byte(0x33)
            )])),
            "eth_getLogs" => Ok(json!([])),
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

    assert!(matches!(
        provider.pay(&challenge).await.unwrap_err(),
        MppError::ZoneSettlementPending { .. }
    ));
    fail_reads.store(true, Ordering::SeqCst);
    settled.store(true, Ordering::SeqCst);
    provider.pay(&challenge).await.unwrap();
    // The lookup runs beside the search for the kept tags, which may find
    // the settlement before the lookup is sent.
    let calls = zone_calls.lock().unwrap();
    assert!(
        calls
            .iter()
            .filter(|call| *call == "eth_getTransactionReceipt")
            .count()
            <= 1
    );
}

#[tokio::test]
async fn test_stalled_receipt_lookup_does_not_delay_a_search_for_kept_sender_tags() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let chain = Arc::new(Mutex::new(ZoneChain::new(6, 7)));
    let stall = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Once the tags are read, the Zone stops answering receipt lookups.
    let (zone_url, _) = {
        let stall = stall.clone();
        spawn_rpc_stalling_when(
            redacting_zone_handler_on(sent.clone(), chain.clone(), Arc::default()),
            move |method, _| method == "eth_getTransactionReceipt" && stall.load(Ordering::SeqCst),
        )
        .await
    };
    let settled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (tempo_url, _) = {
        let sent = sent.clone();
        let settled = settled.clone();
        spawn_rpc(Arc::new(move |method, _| match method {
            "eth_chainId" => Ok(json!("0xa5bf")),
            "eth_blockNumber" => Ok(json!("0x10")),
            "eth_getLogs" if settled.load(Ordering::SeqCst) => Ok(json!([settlement_log(
                sent_sender_tag(&sent),
                true,
                B256::repeat_byte(0x33)
            )])),
            "eth_getLogs" => Ok(json!([])),
            _ => Err((-32000, format!("l1: {method}"))),
        }))
        .await
    };
    let mut zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    zone.rpc_timeout = Duration::from_secs(30);
    let provider = TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_zone(zone)
        .unwrap();
    let challenge = challenge_with(json!({}), expires_in(120));

    assert!(matches!(
        provider.pay(&challenge).await.unwrap_err(),
        MppError::ZoneSettlementPending { .. }
    ));
    stall.store(true, Ordering::SeqCst);
    settled.store(true, Ordering::SeqCst);
    // The kept tags find the settlement without waiting out the lookup.
    let started = std::time::Instant::now();
    let credential = provider.pay(&challenge).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        credential.charge_payload().unwrap().zone_sender_tag(),
        Some(format!("{:#x}", sent_sender_tag(&sent)).as_str())
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_sender_tag_candidates_refuses_a_block_header_for_another_block() {
    let (url, _) = spawn_rpc(Arc::new(|method, _| match method {
        "eth_getBlockByNumber" => Ok(json!({
            "hash": format!("{:#x}", B256::repeat_byte(0xaa)),
            "number": "0xb",
            "parentHash": format!("{:#x}", B256::repeat_byte(0x99)),
        })),
        _ => Err((-32000, format!("unexpected {method}"))),
    }))
    .await;
    let zone = super::super::rpc_provider(url.parse().unwrap(), None);
    let error = sender_tag_candidates(&zone, 10, Address::ZERO, B256::repeat_byte(0xab))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("invalid block header"),
        "{error}"
    );
}

/// A Zone RPC whose outbox reports `before` as its `lastFallbackNonce` at
/// block 9 and `after` at block 10, answering outbox reads only by the
/// blocks' hashes.
async fn outbox_rpc(before: u64, after: u64) -> alloy::providers::RootProvider<TempoNetwork> {
    let parent = format!("{:#x}", B256::repeat_byte(0x99));
    let block = format!("{:#x}", B256::repeat_byte(0xaa));
    let (url, _) = spawn_rpc(Arc::new(move |method, params| match method {
        "eth_getBlockByNumber" if params[0] == json!("0xa") => Ok(json!({
            "hash": block,
            "number": "0xa",
            "parentHash": parent,
        })),
        "eth_call" => {
            // A read by height could come from another history.
            let pinned = params[1]["blockHash"].as_str();
            if pinned == Some(parent.as_str()) {
                Ok(json!(format!("{:#066x}", before)))
            } else if pinned == Some(block.as_str()) {
                Ok(json!(format!("{:#066x}", after)))
            } else {
                Err((-32000, format!("unpinned read at {}", params[1])))
            }
        }
        _ => Err((-32000, format!("unexpected {method}"))),
    }))
    .await;
    super::super::rpc_provider(url.parse().unwrap(), None)
}

#[tokio::test]
async fn test_sender_tag_candidates_derives_one_tag_per_nonce_the_block_added() {
    let sender = address!("0000000000000000000000000000000000000001");
    let hash = B256::repeat_byte(0xab);
    let tags = sender_tag_candidates(&outbox_rpc(4, 6).await, 10, sender, hash)
        .await
        .unwrap();
    assert_eq!(
        tags,
        [
            zone::sender_tag(sender, hash, 5),
            zone::sender_tag(sender, hash, 6)
        ]
    );
}

#[tokio::test]
async fn test_sender_tag_candidates_rejects_a_block_that_added_no_withdrawal() {
    let error = sender_tag_candidates(
        &outbox_rpc(4, 4).await,
        10,
        Address::ZERO,
        B256::repeat_byte(0xab),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("did not request a withdrawal"),
        "{error}"
    );
}

#[tokio::test]
async fn test_sender_tag_candidates_rejects_a_nonce_range_no_block_could_hold() {
    let error = sender_tag_candidates(
        &outbox_rpc(0, 1 << 63).await,
        10,
        Address::ZERO,
        B256::repeat_byte(0xab),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("more than 64"), "{error}");
}

#[tokio::test]
async fn test_settlement_wait_needs_a_sender_tag() {
    let (tempo_url, _) = tempo_rpc(Arc::new(Mutex::new(json!([])))).await;
    let tempo = super::super::rpc_provider(tempo_url.parse().unwrap(), None);
    let error =
        wait_for_settled_withdrawal(&tempo, zone::portal_address(3), &[], None, Duration::ZERO)
            .await
            .unwrap_err();
    assert!(
        error.to_string().contains("at least one sender tag"),
        "{error}"
    );
}

/// A Zone handler recording the raw transactions it is sent.
fn recording_zone_handler(sent: Arc<Mutex<Vec<String>>>) -> Handler {
    let inner = zone_handler(|raw| {
        Ok(zone_receipt(
            raw,
            "0x1",
            json!([withdrawal_requested_log(raw)]),
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
    // Another payment: a challenge for the same terms would share the
    // first withdrawal.
    let mut second = first.clone();
    second.id = "other-challenge".into();
    let mut request = second.request.decode_value().unwrap();
    request["amount"] = json!("2000000");
    second.request = Base64UrlJson::from_value(&request).unwrap();
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

#[tokio::test]
async fn test_providers_with_different_signers_never_share_a_withdrawal() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, _) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let (provider, _) = provider_with_zone(zone.clone()).await;
    let (tempo_url, _) = tempo_rpc(Arc::new(Mutex::new(json!([])))).await;
    let other_signer: alloy::signers::local::PrivateKeySigner =
        "0x0000000000000000000000000000000000000000000000000000000000000002"
            .parse()
            .unwrap();
    let other = TempoProvider::new(other_signer, tempo_url)
        .unwrap()
        .with_zone(zone)
        .unwrap();
    let challenge = challenge_with(json!({}), None);

    // Each signer withdraws for itself; a retry by the same signer does not.
    for provider in [&provider, &other, &provider] {
        provider.pay(&challenge).await.unwrap_err();
    }
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
    let handler = zone_handler(|_| Ok(Value::Null));
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
        let handler = zone_handler(|_| Ok(Value::Null));
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
        let handler = zone_handler(|_| Ok(Value::Null));
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
    let settlement = Arc::new(Mutex::new((false, B256::repeat_byte(0x33))));
    let (tempo_url, _) = settling_tempo_rpc(sent.clone(), settlement.clone()).await;
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
    let sender_tag = sent_sender_tag(&sent);
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
    *settlement.lock().unwrap() = (true, B256::repeat_byte(0x55));
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

#[tokio::test]
async fn test_settlement_timeout_of_duration_max_does_not_overflow() {
    // With an expiry, no withdrawal can wait that long before it, and the
    // wait is cut short at the expiry.
    let expiring = challenge_with(json!({}), expires_in(3600));
    assert!(!settles_before_expiry(&expiring, Duration::MAX));
    assert!(settlement_timeout(&expiring, Duration::MAX) <= Duration::from_secs(3600));

    // Without one, the withdrawal is sent and waited on with no deadline.
    let challenge = challenge_with(json!({}), None);
    assert!(settles_before_expiry(&challenge, Duration::MAX));
    assert_eq!(settlement_timeout(&challenge, Duration::MAX), Duration::MAX);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, _) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let (tempo_url, _) = settling_tempo_rpc(
        sent.clone(),
        Arc::new(Mutex::new((true, B256::repeat_byte(0x55)))),
    )
    .await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::MAX);
    let provider = TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_zone(zone)
        .unwrap();
    let credential = provider.pay(&challenge).await.unwrap();
    assert_eq!(
        credential.charge_payload().unwrap().data(),
        format!("{:#x}", B256::repeat_byte(0x55))
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_withdrawal_receipt_of_another_transaction_is_outcome_unknown() {
    // The send answered with a successful receipt for a transaction other
    // than the one signed here.
    let sent = Arc::new(Mutex::new(Vec::new()));
    let recording = recording_zone_handler(sent.clone());
    let (zone_url, zone_calls) = spawn_rpc(Arc::new(move |method, params| {
        let mut result = recording(method, params);
        if method == "eth_sendRawTransactionSync" {
            if let Ok(receipt) = &mut result {
                receipt["transactionHash"] = json!(format!("{:#x}", B256::repeat_byte(0x22)));
            }
        }
        result
    }))
    .await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    let challenge = challenge_with(json!({}), None);
    for _ in 0..2 {
        match provider.pay(&challenge).await.unwrap_err() {
            MppError::PaymentOutcomeUnknown { transaction_hash } => {
                let raw = sent.lock().unwrap()[0].clone();
                assert_eq!(transaction_hash, format!("{:#x}", tx_hash(&raw)));
            }
            error => panic!("unexpected error: {error}"),
        }
    }
    let sends = zone_calls
        .lock()
        .unwrap()
        .iter()
        .filter(|call| *call == "eth_sendRawTransactionSync")
        .count();
    assert_eq!(sends, 1);
}

#[tokio::test]
async fn test_withdrawal_event_that_does_not_match_the_withdrawal_is_outcome_unknown() {
    let edits: [fn(&mut IZoneOutbox::WithdrawalRequested); 5] = [
        |event| event.sender = Address::repeat_byte(0x99),
        |event| event.token = Address::repeat_byte(0x99),
        |event| event.to = Address::repeat_byte(0x99),
        |event| event.amount += 1,
        |event| event.memo = B256::repeat_byte(0x99),
    ];
    for edit in edits {
        let (zone_url, zone_calls) = spawn_rpc(zone_handler(move |raw| {
            Ok(zone_receipt(
                raw,
                "0x1",
                json!([withdrawal_requested_log_with(raw, edit)]),
            ))
        }))
        .await;
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
}

#[tokio::test(flavor = "multi_thread")]
async fn test_withdrawal_rechecks_expiry_after_preparation() {
    // The nonce lookup is slow enough that the challenge would expire before
    // the withdrawal settles: nothing is sent.
    let sent = Arc::new(Mutex::new(Vec::new()));
    let recording = recording_zone_handler(sent.clone());
    let (zone_url, zone_calls) = spawn_rpc(Arc::new(move |method, params| {
        if method == "eth_getTransactionCount" {
            std::thread::sleep(Duration::from_secs(4));
        }
        recording(method, params)
    }))
    .await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let (provider, _) = provider_with_zone(zone).await;
    let challenge = challenge_with(
        json!({}),
        expires_in(SUBMISSION_MARGIN.as_secs() as i64 + 3),
    );

    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(error.to_string().contains("expires"), "{error}");
    assert!(
        !matches!(error, MppError::PaymentOutcomeUnknown { .. }),
        "{error}"
    );
    let calls = zone_calls.lock().unwrap();
    assert!(calls.iter().any(|call| call == "eth_getTransactionCount"));
    assert!(!calls
        .iter()
        .any(|call| call == "eth_sendRawTransactionSync"));
    assert!(sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_settlement_wait_bounds_a_stalled_rpc() {
    // A Tempo RPC that accepts connections and never answers.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(url.parse().unwrap());
    let started = std::time::Instant::now();
    let result = wait_for_settlement_from(
        &provider,
        zone::portal_address(3),
        &[B256::repeat_byte(0x01)],
        None,
        Duration::ZERO,
        Duration::from_millis(200),
        &Mutex::new(None),
    )
    .await;
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn test_settlement_wait_retries_a_failed_tempo_rpc_call() {
    // The first block-number and log lookups fail; the wait keeps polling and
    // finds the settlement instead of giving up at once.
    let sender_tag = B256::repeat_byte(0x01);
    let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (tempo_url, _) = {
        let calls = calls.clone();
        spawn_rpc(Arc::new(move |method, _params| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            match method {
                "eth_blockNumber" if n == 0 => Err((-32000, "temporarily unavailable".into())),
                "eth_blockNumber" => Ok(json!("0x2710")),
                "eth_getLogs" if n < 3 => Err((-32000, "temporarily unavailable".into())),
                "eth_getLogs" => Ok(json!([settlement_log(
                    sender_tag,
                    true,
                    B256::repeat_byte(0x55)
                )])),
                _ => Err((-32000, format!("l1: {method}"))),
            }
        }))
        .await
    };
    let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_http(tempo_url.parse().unwrap());
    let settlement = wait_for_settlement_from(
        &provider,
        zone::portal_address(3),
        &[sender_tag],
        None,
        Duration::from_secs(30),
        Duration::from_secs(30),
        &Mutex::new(None),
    )
    .await
    .unwrap();
    assert_eq!(settlement.hash, B256::repeat_byte(0x55));
    assert!(!settlement.bounced);
}

/// A payment context for a request to BTurlBT.
fn context_for(url: &str) -> crate::client::PaymentContext {
    crate::client::PaymentContext {
        url: url.parse().unwrap(),
        headers: Default::default(),
        http_client: None,
    }
}

/// A new challenge for the same terms as BTchallenge_with(details, ..)BT.
fn same_terms(details: Value, id: &str) -> PaymentChallenge {
    let mut challenge = challenge_with(details, expires_in(900));
    challenge.id = id.into();
    challenge
}

/// A provider paying from Zone 3 whose settlement wait gives up at once, with
/// the Zone sends it records and the Tempo logs it reads.
async fn resumable_provider() -> (TempoProvider, Arc<Mutex<Vec<String>>>, Arc<Mutex<Value>>) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, _) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let logs = Arc::new(Mutex::new(json!([])));
    let (tempo_url, _) = tempo_rpc(logs.clone()).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let provider = TempoProvider::new(payer(), tempo_url)
        .unwrap()
        .with_zone(zone)
        .unwrap();
    (provider, sent, logs)
}

fn pending_challenge_id(error: MppError) -> String {
    match error {
        MppError::ZoneSettlementPending { challenge_id, .. } => challenge_id,
        error => panic!("expected ZoneSettlementPending, got {error}"),
    }
}

#[tokio::test]
async fn test_new_challenge_for_same_terms_resumes_the_withdrawal_from_its_origin() {
    let (provider, sent, logs) = resumable_provider().await;
    let first = challenge_with(json!({}), expires_in(600));
    let origin = "https://api.example.com/paid";
    let error = provider
        .pay_with_context(&first, context_for(origin))
        .await
        .unwrap_err();
    assert_eq!(pending_challenge_id(error), first.id);
    let sender_tag = sent_sender_tag(&sent);

    // A new challenge for the same terms, from another origin or from one
    // the caller did not verify, fails closed and names the first challenge.
    let second = same_terms(json!({}), "zone-challenge-2");
    for error in [
        provider
            .pay_with_context(&second, context_for("https://other.example.com/paid"))
            .await
            .unwrap_err(),
        provider.pay(&second).await.unwrap_err(),
    ] {
        assert_eq!(pending_challenge_id(error), first.id);
    }
    assert_eq!(sent.lock().unwrap().len(), 1);

    // From its origin, it resumes the first withdrawal and answers the first
    // challenge.
    *logs.lock().unwrap() = json!([settlement_log(sender_tag, true, B256::repeat_byte(0x33))]);
    let credential = provider
        .pay_with_context(&second, context_for(origin))
        .await
        .unwrap();
    assert_eq!(credential.challenge.id, first.id);
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_new_challenge_for_other_terms_withdraws_again() {
    let (provider, sent, _) = resumable_provider().await;
    let origin = "https://api.example.com/paid";
    let first = challenge_with(json!({}), expires_in(600));
    provider
        .pay_with_context(&first, context_for(origin))
        .await
        .unwrap_err();
    let mut other = same_terms(json!({}), "zone-challenge-2");
    let mut request = other.request.decode_value().unwrap();
    request["amount"] = json!("2000000");
    other.request = Base64UrlJson::from_value(&request).unwrap();
    let error = provider
        .pay_with_context(&other, context_for(origin))
        .await
        .unwrap_err();
    assert_eq!(pending_challenge_id(error), other.id);
    assert_eq!(sent.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn test_withdrawal_past_its_redemption_window_is_never_paid_again() {
    let (provider, sent, _) = resumable_provider().await;
    let zone = provider.zone.as_ref().unwrap();
    // A withdrawal whose challenge expired more than the largest server grace
    // ago, as one left outstanding would be by then.
    let expired = challenge_with(
        json!({}),
        Some(
            (time::OffsetDateTime::now_utc() - time::Duration::seconds(301))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        ),
    );
    let signer = TempoPrimitiveSigner::from(payer());
    let signing_mode = TempoSigningMode::Direct;
    let key = zone.pending_key(&expired, &signer, &signing_mode);
    zone.pending.lock().unwrap().insert(
        key,
        Arc::new(PendingWithdrawal {
            challenge: expired.clone(),
            origin: Some("https://api.example.com".into()),
            terms: zone.terms_key(&expired, &signer, &signing_mode),
            request: OnceCell::new(),
            derived: Mutex::default(),
            redeemed_late: Mutex::default(),
            waiters: Default::default(),
            sending: Default::default(),
            settlement_cursor: Mutex::default(),
        }),
    );
    // A retry of its own challenge still fails closed.
    let error = provider
        .pay_with_context(&expired, context_for("https://api.example.com/paid"))
        .await
        .unwrap_err();
    assert_eq!(pending_challenge_id(error), expired.id);
    assert!(sent.lock().unwrap().is_empty());

    // No server accepts its Credential any more, so it no longer blocks a new
    // challenge for its terms, which withdraws on its own.
    let next = same_terms(json!({}), "zone-challenge-2");
    let error = provider
        .pay_with_context(&next, context_for("https://api.example.com/paid"))
        .await
        .unwrap_err();
    assert_eq!(pending_challenge_id(error), next.id);
    assert_eq!(sent.lock().unwrap().len(), 1);
    assert!(!zone
        .pending
        .lock()
        .unwrap()
        .values()
        .any(|entry| entry.challenge.id == expired.id));
}

/// Inserts a withdrawal for `challenge` whose request already returned
/// `sender_tag`, as one an earlier payment started.
fn insert_withdrawal(
    provider: &TempoProvider,
    challenge: &PaymentChallenge,
    origin: &str,
    sender_tag: B256,
) -> Arc<PendingWithdrawal> {
    let zone = provider.zone.as_ref().unwrap();
    let signer = TempoPrimitiveSigner::from(payer());
    let signing_mode = TempoSigningMode::Direct;
    let entry = Arc::new(PendingWithdrawal {
        challenge: challenge.clone(),
        origin: Some(origin.into()),
        terms: zone.terms_key(challenge, &signer, &signing_mode),
        request: OnceCell::new_with(Some(Ok(SentWithdrawal {
            block_hash: Some(RECEIPT_BLOCK),
            sender: payer().address(),
            transaction_hash: B256::ZERO,
            sender_tags: Some(vec![sender_tag]),
        }))),
        derived: Mutex::default(),
        redeemed_late: Mutex::default(),
        waiters: Default::default(),
        sending: Default::default(),
        settlement_cursor: Mutex::default(),
    });
    zone.pending.lock().unwrap().insert(
        zone.pending_key(challenge, &signer, &signing_mode),
        entry.clone(),
    );
    entry
}

#[tokio::test]
async fn test_late_credential_is_reused_only_for_its_own_challenge() {
    let (provider, sent, logs) = resumable_provider().await;
    let origin = "https://api.example.com/paid";
    // A withdrawal whose challenge expired before its settlement was found,
    // within the largest server grace.
    let expired = challenge_with(
        json!({}),
        Some(
            (time::OffsetDateTime::now_utc() - time::Duration::seconds(10))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        ),
    );
    let sender_tag = B256::repeat_byte(0x77);
    insert_withdrawal(&provider, &expired, "https://api.example.com", sender_tag);
    let settlement = B256::repeat_byte(0x33);
    *logs.lock().unwrap() = json!([settlement_log(sender_tag, true, settlement)]);

    // Its own challenge gets the late Credential, and a retry of it gets the
    // same one rather than paying again on Tempo.
    for _ in 0..2 {
        let credential = provider
            .pay_with_context(&expired, context_for(origin))
            .await
            .unwrap();
        assert_eq!(credential.challenge.id, expired.id);
        assert_eq!(
            credential.charge_payload().unwrap().data(),
            format!("{settlement:#x}")
        );
    }

    // Another challenge for its terms neither gets it nor pays again until
    // its window ends: the error names the paid challenge and its sender tag.
    let next = same_terms(json!({}), "zone-challenge-2");
    match provider
        .pay_with_context(&next, context_for(origin))
        .await
        .unwrap_err()
    {
        MppError::ZoneSettlementPending {
            challenge_id,
            sender_tag: pending_tag,
            ..
        } => {
            assert_eq!(challenge_id, expired.id);
            assert_eq!(pending_tag, format!("{sender_tag:#x}"));
        }
        error => panic!("expected ZoneSettlementPending, got {error}"),
    }
    assert!(sent.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_withdrawal_another_payment_waits_on_is_not_shared() {
    let (provider, sent, _) = resumable_provider().await;
    let origin = "https://api.example.com/paid";
    let first = challenge_with(json!({}), expires_in(600));
    let entry = insert_withdrawal(
        &provider,
        &first,
        "https://api.example.com",
        B256::repeat_byte(0x77),
    );
    // Another payment is still waiting on it: a concurrent request with the
    // same terms is a payment of its own.
    let waiting = Waiting::new(&entry);
    let second = same_terms(json!({}), "zone-challenge-2");
    let error = provider
        .pay_with_context(&second, context_for(origin))
        .await
        .unwrap_err();
    assert_eq!(pending_challenge_id(error), second.id);
    assert_eq!(sent.lock().unwrap().len(), 1);
    drop(waiting);
    assert_eq!(entry.waiters.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_refuses_an_expired_challenge_before_paying() {
    let (zone_url, zone_calls) = unused_zone_rpc().await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    let expired = challenge_with(
        json!({}),
        Some(
            (time::OffsetDateTime::now_utc() - time::Duration::seconds(10))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        ),
    );
    let error = provider.pay(&expired).await.unwrap_err();
    assert!(matches!(error, MppError::PaymentExpired(_)), "{error}");
    assert!(zone_calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_opaque_origin_never_resumes_a_withdrawal() {
    let (provider, sent, logs) = resumable_provider().await;
    let first = challenge_with(json!({}), expires_in(600));
    let sender_tag = B256::repeat_byte(0x77);
    insert_withdrawal(&provider, &first, "null", sender_tag);
    *logs.lock().unwrap() = json!([settlement_log(sender_tag, true, B256::repeat_byte(0x33))]);
    // Every opaque origin serializes as "null", so it is no proof that the
    // new challenge came from where the first one did.
    let second = same_terms(json!({}), "zone-challenge-2");
    let error = provider
        .pay_with_context(&second, context_for("file:///tmp/paid"))
        .await
        .unwrap_err();
    assert_eq!(pending_challenge_id(error), first.id);
    assert!(sent.lock().unwrap().is_empty());
}

#[test]
fn test_far_future_expiry_is_redeemable() {
    let challenge = challenge_with(json!({}), Some("9999-12-31T23:59:59Z".into()));
    assert!(is_redeemable(&challenge));
}

/// A provider paying from Zone 3, whose outbox charges a fee of 5, with the
/// Zone sends it records.
async fn fee_provider(
    caps: impl FnOnce(TempoProvider) -> TempoProvider,
) -> (TempoProvider, Arc<Mutex<Vec<String>>>) {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let inner = recording_zone_handler(sent.clone());
    let (zone_url, _) = spawn_rpc(Arc::new(move |method, params| {
        if method == "eth_call" {
            return Ok(json!(format!("{:#066x}", 5)));
        }
        inner(method, params)
    }))
    .await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let (provider, _) = provider_with_zone(zone).await;
    (
        caps(provider.with_currencies([format!("{CURRENCY:#x}")])),
        sent,
    )
}

#[tokio::test]
async fn test_withdrawal_fee_counts_against_client_caps() {
    type Caps = fn(TempoProvider) -> TempoProvider;
    let over: [(Caps, &str); 2] = [
        (
            |p| p.with_max_atomic_amount(U256::from(1_000_004u64)),
            "max_atomic_amount",
        ),
        (|p| p.with_max_amount("1.000004", 6).unwrap(), "max_amount"),
    ];
    for (caps, name) in over {
        let (provider, sent) = fee_provider(caps).await;
        let challenge = challenge_with(json!({}), None);
        let error = provider.pay(&challenge).await.unwrap_err();
        assert!(
            error.to_string().contains(&format!(
                "Tempo charge amount plus Zone withdrawal fee exceeds {name}."
            )),
            "{error}"
        );
        assert!(sent.lock().unwrap().is_empty());
        // Nothing was sent, so the same challenge may be paid again.
        assert!(provider
            .zone
            .as_ref()
            .unwrap()
            .pending
            .lock()
            .unwrap()
            .is_empty());
    }

    let at: [Caps; 2] = [
        |p| p.with_max_atomic_amount(U256::from(1_000_005u64)),
        |p| p.with_max_amount("1.000005", 6).unwrap(),
    ];
    for caps in at {
        let (provider, sent) = fee_provider(caps).await;
        let challenge = challenge_with(json!({}), None);
        let error = provider.pay(&challenge).await.unwrap_err();
        assert_eq!(pending_challenge_id(error), challenge.id);
        assert_eq!(sent.lock().unwrap().len(), 1);
    }
}

#[test]
fn test_settlement_pending_message_omits_unknown_sender_tag() {
    let challenge = challenge_with(json!({}), None);
    let error = MppError::ZoneSettlementPending {
        challenge: Box::new(challenge.clone()),
        challenge_id: challenge.id.clone(),
        sender_tag: String::new(),
        sender_tags: Vec::new(),
        zone_id: 3,
    };
    assert_eq!(
        error.to_string(),
        "Zone 3 withdrawal for challenge \"zone-challenge\" has not settled on Tempo yet. Pay this challenge again to resume waiting: a fresh challenge would withdraw again."
    );
}

/// Waits until the Zone RPC has been asked for `method`.
async fn called(calls: &Mutex<Vec<String>>, method: &str) {
    while !calls.lock().unwrap().iter().any(|call| call == method) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

#[tokio::test]
async fn test_payment_cancelled_before_sending_sends_nothing() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, zone_calls) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let (provider, _) = provider_with_zone(zone).await;
    let challenge = challenge_with(json!({}), None);

    // Cancel the payment while it looks up the withdrawal fee.
    tokio::select! {
        result = provider.pay(&challenge) => panic!("payment was not cancelled: {result:?}"),
        () = called(&zone_calls, "eth_call") => {}
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(sent.lock().unwrap().is_empty());

    // Nothing was sent, so a retry withdraws.
    let error = provider.pay(&challenge).await.unwrap_err();
    assert!(
        matches!(error, MppError::ZoneSettlementPending { .. }),
        "{error}"
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_cancelled_payment_does_not_stop_a_concurrent_one() {
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (zone_url, zone_calls) = spawn_rpc(recording_zone_handler(sent.clone())).await;
    let zone = TempoZone::new(zone_url, MODERATO_ZONE_3)
        .unwrap()
        .with_settlement_timeout(Duration::ZERO);
    let (provider, _) = provider_with_zone(zone).await;
    let challenge = challenge_with(json!({}), None);

    let waiting = {
        let provider = provider.clone();
        let challenge = challenge.clone();
        tokio::spawn(async move { provider.pay(&challenge).await })
    };
    // The other payment of the same challenge is dropped mid-request.
    tokio::select! {
        result = provider.pay(&challenge) => panic!("payment was not cancelled: {result:?}"),
        () = called(&zone_calls, "eth_call") => {}
    }
    let error = waiting.await.unwrap().unwrap_err();
    assert!(
        matches!(error, MppError::ZoneSettlementPending { .. }),
        "{error}"
    );
    assert_eq!(sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn test_challenge_without_a_recipient_stores_no_withdrawal() {
    let (zone_url, zone_calls) = unused_zone_rpc().await;
    let (provider, _) =
        provider_with_zone(TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap()).await;
    for id in ["zone-challenge", "zone-challenge-2"] {
        let mut challenge = same_terms(json!({}), id);
        let mut request: Value = challenge.request.decode_value().unwrap();
        request.as_object_mut().unwrap().remove("recipient");
        challenge.request = Base64UrlJson::from_value(&request).unwrap();
        let error = provider.pay(&challenge).await.unwrap_err();
        assert!(error.to_string().contains("No recipient"), "{error}");
    }
    assert!(zone_calls.lock().unwrap().is_empty());
    assert!(provider
        .zone
        .as_ref()
        .unwrap()
        .pending
        .lock()
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn test_payment_under_another_origin_keeps_an_earlier_withdrawal() {
    let (provider, sent, _) = resumable_provider().await;
    let zone = provider.zone.as_ref().unwrap();
    let earlier = same_terms(json!({}), "zone-challenge");
    let signer = TempoPrimitiveSigner::from(payer());
    let signing_mode = TempoSigningMode::Direct;
    // A withdrawal an earlier payment started and whose request has not yet
    // returned, as one whose caller was dropped mid-send would be.
    let entry = Arc::new(PendingWithdrawal {
        challenge: earlier.clone(),
        origin: Some("https://api.example.com".into()),
        terms: zone.terms_key(&earlier, &signer, &signing_mode),
        request: OnceCell::new(),
        derived: Mutex::default(),
        redeemed_late: Mutex::default(),
        waiters: Default::default(),
        sending: Default::default(),
        settlement_cursor: Mutex::default(),
    });
    zone.pending.lock().unwrap().insert(
        zone.pending_key(&earlier, &signer, &signing_mode),
        entry.clone(),
    );
    let next = same_terms(json!({}), "zone-challenge-2");
    let error = provider
        .pay_with_context(&next, context_for("https://other.example.com/paid"))
        .await
        .unwrap_err();
    assert_eq!(pending_challenge_id(error), earlier.id);
    assert!(sent.lock().unwrap().is_empty());
    assert!(zone
        .pending
        .lock()
        .unwrap()
        .values()
        .any(|current| Arc::ptr_eq(current, &entry)));
}

#[tokio::test]
async fn test_withdrawal_being_sent_is_never_forgotten_as_abandoned() {
    let (provider, _, _) = resumable_provider().await;
    let zone = provider.zone.as_ref().unwrap();
    let challenge = same_terms(json!({}), "zone-challenge");
    let signer = TempoPrimitiveSigner::from(payer());
    let signing_mode = TempoSigningMode::Direct;
    let key = zone.pending_key(&challenge, &signer, &signing_mode);
    let entry = Arc::new(PendingWithdrawal {
        challenge: challenge.clone(),
        origin: None,
        terms: zone.terms_key(&challenge, &signer, &signing_mode),
        request: OnceCell::new(),
        derived: Mutex::default(),
        redeemed_late: Mutex::default(),
        waiters: Default::default(),
        sending: std::sync::atomic::AtomicBool::new(true),
        settlement_cursor: Mutex::default(),
    });
    zone.pending
        .lock()
        .unwrap()
        .insert(key.clone(), entry.clone());
    zone.forget_abandoned(&key, &entry);
    assert!(zone.pending.lock().unwrap().contains_key(&key));
    entry
        .sending
        .store(false, std::sync::atomic::Ordering::SeqCst);
    zone.forget_abandoned(&key, &entry);
    assert!(!zone.pending.lock().unwrap().contains_key(&key));
}

/// A JSON-RPC server that never answers the methods in `stalled` and answers
/// every other call with `handler`, recording each method.
async fn spawn_stalling_rpc(
    handler: Handler,
    stalled: &'static [&'static str],
) -> (String, Arc<Mutex<Vec<String>>>) {
    spawn_rpc_stalling_when(handler, move |method, _| stalled.contains(&method)).await
}

/// A JSON-RPC server that never answers a call `stalls` matches and answers
/// every other call with `handler`, recording each method.
async fn spawn_rpc_stalling_when(
    handler: Handler,
    stalls: impl Fn(&str, &Value) -> bool + Send + Sync + 'static,
) -> (String, Arc<Mutex<Vec<String>>>) {
    type Stalls = Arc<dyn Fn(&str, &Value) -> bool + Send + Sync>;
    #[derive(Clone)]
    struct Rpc {
        handler: Handler,
        stalled: Stalls,
        calls: Arc<Mutex<Vec<String>>>,
    }
    async fn rpc(State(state): State<Rpc>, Json(request): Json<Value>) -> Json<Value> {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request["method"].as_str().unwrap_or_default().to_string();
        state.calls.lock().unwrap().push(method.clone());
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        if (state.stalled)(&method, &params) {
            std::future::pending::<()>().await;
        }
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
        stalled: Arc::new(stalls),
        calls: calls.clone(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, calls)
}

#[tokio::test]
async fn test_stalled_zone_rpc_does_not_hold_the_account() {
    // The Zone never answers the send or the receipt lookup: the withdrawal's
    // outcome is unknown, and the account's next withdrawal still goes out.
    let (zone_url, zone_calls) = spawn_stalling_rpc(
        zone_handler(|_| Ok(Value::Null)),
        &["eth_sendRawTransactionSync", "eth_getTransactionReceipt"],
    )
    .await;
    let mut zone = TempoZone::new(zone_url, MODERATO_ZONE_3).unwrap();
    zone.rpc_timeout = Duration::from_millis(200);
    zone.receipt_recovery_timeout = Duration::from_millis(300);
    let (provider, _) = provider_with_zone(zone).await;
    let first = challenge_with(json!({}), None);
    let mut second = first.clone();
    second.id = "other-challenge".into();
    let mut request = second.request.decode_value().unwrap();
    request["amount"] = json!("2000000");
    second.request = Base64UrlJson::from_value(&request).unwrap();

    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let first = provider.pay(&first).await.unwrap_err();
        let second = provider.pay(&second).await.unwrap_err();
        (first, second)
    })
    .await
    .expect("a stalled Zone RPC held the account");
    for error in [result.0, result.1] {
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
    assert_eq!(sends, 2);
}
