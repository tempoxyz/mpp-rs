//! Hosted fee payer (mppx `feePayer: url`): `eth_fillTransaction` co-signing,
//! preserved sender fields, the fee-token allowlist, and simulation around it.

use std::sync::{Arc, Mutex};

use alloy::signers::SignerSync;

use super::super::super::FeePayerEnvelope78;
use super::super::hosted_fee_payer::{HostedFeePayer, RemoteFeePayer};
use super::simulate::sponsored_charge_envelope;
use super::*;

type Requests = Arc<Mutex<Vec<(serde_json::Value, Option<String>)>>>;

/// Serve a hosted fee payer that answers every request with `response` and
/// records each request body with its `Authorization` header.
async fn mock_fee_payer(response: serde_json::Value) -> (String, Requests) {
    use axum::{routing::post, Json, Router};

    let requests: Requests = Arc::default();
    let app = Router::new().route(
        "/",
        post({
            let requests = requests.clone();
            move |headers: axum::http::HeaderMap, Json(body): Json<serde_json::Value>| {
                let (requests, response) = (requests.clone(), response.clone());
                async move {
                    assert_eq!(
                        headers.get("content-type").unwrap(),
                        "application/json",
                        "fee-payer requests are always JSON"
                    );
                    let authorization = headers
                        .get("authorization")
                        .map(|value| value.to_str().unwrap().to_owned());
                    requests.lock().unwrap().push((body, authorization));
                    Json(response)
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, requests)
}

fn hosted(url: &str) -> RemoteFeePayer {
    RemoteFeePayer::new(url)
        .with_header("Authorization", "Bearer sponsor-secret")
        .with_header("Content-Type", "text/plain")
}

/// The answer of a hosted fee payer that sponsors `envelope` with `sponsor`,
/// paying gas in `fee_token`, signing the transaction `mutate` returns.
fn fill_answer(
    envelope: &[u8],
    sponsor: &alloy::signers::local::PrivateKeySigner,
    fee_token: Address,
    mutate: impl FnOnce(&mut tempo_alloy::primitives::TempoTransaction),
) -> serde_json::Value {
    let env = FeePayerEnvelope78::decode_envelope(envelope).unwrap();
    let mut tx = env.to_recoverable_signed().tx().clone();
    tx.fee_token = Some(fee_token);
    tx.fee_payer_signature = None;
    mutate(&mut tx);
    let signature = sponsor
        .sign_hash_sync(&tx.fee_payer_signature_hash(env.sender))
        .unwrap();
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tx": {
                "feePayerSignature": {
                    "r": format!("{:#x}", signature.r()),
                    "s": format!("{:#x}", signature.s()),
                    "yParity": format!("{:#x}", u8::from(signature.v())),
                },
                "feeToken": format!("{fee_token:#x}"),
            }
        }
    })
}

fn node(
    responses: Vec<Result<serde_json::Value, alloy_json_rpc::ErrorPayload>>,
) -> (
    ChargeMethod<impl alloy::providers::Provider<TempoNetwork> + Clone + 'static>,
    alloy::providers::mock::Asserter,
) {
    let asserter = alloy::providers::mock::Asserter::new();
    for response in responses {
        match response {
            Ok(value) => asserter.push_success(&value),
            Err(error) => asserter.push_failure(error),
        }
    }
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    (ChargeMethod::new(provider), asserter)
}

fn resolved(remote: RemoteFeePayer) -> HostedFeePayer {
    remote.resolve().unwrap()
}

/// The receipt of the sponsored pathUSD charge `sponsored_charge_envelope` builds.
fn receipt(
    client: Address,
    sponsor: Address,
    fee_token: Address,
    tx_hash: B256,
) -> serde_json::Value {
    let currency = PATH_USD.parse::<Address>().unwrap();
    let block_hash = B256::repeat_byte(0x22);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let mut log = make_transfer_with_memo_log(
        currency,
        client,
        Address::repeat_byte(0x33),
        U256::from(1_000_000u64),
        memo,
    );
    log.as_object_mut().unwrap().extend(
        serde_json::json!({
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x1",
            "transactionHash": format!("{tx_hash:#x}"),
            "transactionIndex": "0x0",
            "logIndex": "0x0",
            "removed": false,
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    serde_json::json!({
        "type": "0x76",
        "status": "0x1",
        "cumulativeGasUsed": "0x5208",
        "logs": [log],
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "transactionHash": format!("{tx_hash:#x}"),
        "transactionIndex": "0x0",
        "blockHash": format!("{block_hash:#x}"),
        "blockNumber": "0x1",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x1",
        "from": format!("{client:#x}"),
        "to": format!("{currency:#x}"),
        "contractAddress": null,
        "feePayer": format!("{sponsor:#x}"),
        "feeToken": format!("{fee_token:#x}"),
    })
}

async fn broadcast(
    method: &ChargeMethod<impl alloy::providers::Provider<TempoNetwork> + Clone + 'static>,
    envelope: &[u8],
    request: &ChargeRequest,
) -> Result<B256, crate::protocol::traits::VerificationError> {
    method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(envelope),
            request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            None,
        )
        .await
}

/// The hosted fee payer co-signs over `eth_fillTransaction`; the server
/// simulates the sender's calls before asking it and the co-signed
/// transaction after, then broadcasts through its own RPC.
#[tokio::test]
async fn test_hosted_fee_payer_sponsors_and_server_broadcasts() {
    let client = alloy::signers::local::PrivateKeySigner::random();
    let sponsor = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = USDC.parse::<Address>().unwrap();
    let (envelope, request) = sponsored_charge_envelope(&client);
    let (url, requests) = mock_fee_payer(fill_answer(&envelope, &sponsor, fee_token, |_| {})).await;
    let tx_hash = B256::repeat_byte(0x11);
    let (method, asserter) = node(vec![
        Ok(serde_json::json!("0x")),
        Ok(serde_json::json!("0x")),
        Ok(receipt(
            client.address(),
            sponsor.address(),
            fee_token,
            tx_hash,
        )),
    ]);
    let method = method.with_remote_fee_payer(hosted(&url)).unwrap();

    assert_eq!(
        broadcast(&method, &envelope, &request).await.unwrap(),
        tx_hash
    );
    assert!(asserter.read_q().is_empty(), "all node calls consumed");

    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let (body, authorization) = &requests[0];
    assert_eq!(authorization.as_deref(), Some("Bearer sponsor-secret"));
    assert_eq!(body["method"], "eth_fillTransaction");
    let params = &body["params"][0];
    assert_eq!(params["feePayer"], true);
    assert_eq!(params["from"], format!("{:#x}", client.address()));
    assert_eq!(params["type"], "0x76");
    assert_eq!(params["gas"], "0xf4240");
    assert_eq!(params["nonce"], "0x0");
    assert_eq!(params["nonceKey"], format!("{:#x}", U256::MAX));
    assert!(params["validBefore"].is_string());
    assert!(params.get("validAfter").is_none());
    assert_eq!(
        params["calls"][0]["to"],
        format!("{:#x}", PATH_USD.parse::<Address>().unwrap())
    );
    assert_eq!(params["calls"][0]["value"], "0x");
    assert!(params["calls"][0]["data"].is_string());
    assert!(params.get("feeToken").is_none() && params.get("accessList").is_none());
}

/// Only the sponsor's signature and fee token are taken from its answer: a
/// signature over changed sender fields recovers to another address, and the
/// broadcast transaction keeps the client's fields.
#[tokio::test]
async fn test_hosted_fee_payer_cannot_change_sender_committed_fields() {
    use alloy::eips::Decodable2718;

    let client = alloy::signers::local::PrivateKeySigner::random();
    let sponsor = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = PATH_USD.parse::<Address>().unwrap();
    let (envelope, _) = sponsored_charge_envelope(&client);
    let (method, _) = node(vec![]);

    let (url, _) = mock_fee_payer(fill_answer(&envelope, &sponsor, fee_token, |_| {})).await;
    let (cosigned, recovered) = method
        .fill_hosted_fee_payer_transaction(&resolved(hosted(&url)), &envelope)
        .await
        .unwrap();
    assert_eq!(recovered, sponsor.address());
    let decoded = tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    assert_eq!(decoded.recover_signer().unwrap(), client.address());
    assert_eq!(decoded.tx().fee_token, Some(fee_token));

    let (url, _) = mock_fee_payer(fill_answer(&envelope, &sponsor, fee_token, |tx| {
        tx.gas_limit = 1_500_000;
    }))
    .await;
    let (cosigned, recovered) = method
        .fill_hosted_fee_payer_transaction(&resolved(hosted(&url)), &envelope)
        .await
        .unwrap();
    assert_ne!(recovered, sponsor.address());
    let decoded = tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    assert_eq!(decoded.tx().gas_limit, 1_000_000);
}

/// The hosted fee payer's token is checked only against an explicit
/// allowlist (mppx leaves a hosted sponsor's choice unrestricted otherwise).
#[tokio::test]
async fn test_hosted_fee_token_respects_explicit_allowlist() {
    let client = alloy::signers::local::PrivateKeySigner::random();
    let sponsor = alloy::signers::local::PrivateKeySigner::random();
    let other_token = Address::repeat_byte(0x77);
    let (envelope, _) = sponsored_charge_envelope(&client);
    let (url, _) = mock_fee_payer(fill_answer(&envelope, &sponsor, other_token, |_| {})).await;

    let (method, _) = node(vec![]);
    method
        .fill_hosted_fee_payer_transaction(&resolved(hosted(&url)), &envelope)
        .await
        .expect("no allowlist: any token");

    let (method, _) = node(vec![]);
    let method = method.with_fee_payer_allowed_fee_tokens(vec![PATH_USD.parse().unwrap()]);
    let err = method
        .fill_hosted_fee_payer_transaction(&resolved(hosted(&url)), &envelope)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("feeToken is not allowed"), "{err}");
}

#[tokio::test]
async fn test_hosted_fee_payer_failures_are_rejected() {
    let client = alloy::signers::local::PrivateKeySigner::random();
    let (envelope, _) = sponsored_charge_envelope(&client);
    let cases = [
        (
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "out of funds"}}),
            "out of funds",
        ),
        (
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tx": {"feeToken": PATH_USD}}}),
            "failed to sponsor transaction",
        ),
        (
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tx": {"feePayerSignature": {"r": "0x1", "s": "0x1", "yParity": "0x0"}}}}),
            "did not return a feeToken",
        ),
        (
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tx": {"feePayerSignature": {"r": "0x0", "s": "0x1", "yParity": "0x5"}, "feeToken": PATH_USD}}}),
            "invalid feePayerSignature",
        ),
    ];
    for (answer, expected) in cases {
        let (url, _) = mock_fee_payer(answer).await;
        let (method, _) = node(vec![]);
        let err = method
            .fill_hosted_fee_payer_transaction(&resolved(hosted(&url)), &envelope)
            .await
            .unwrap_err();
        assert!(err.to_string().contains(expected), "{expected}: {err}");
    }
}

/// The hosted fee payer is not asked to sponsor a transaction that breaks
/// the sponsor policy or whose calls revert.
#[tokio::test]
async fn test_hosted_fee_payer_is_not_asked_to_sponsor_rejected_transactions() {
    let client = alloy::signers::local::PrivateKeySigner::random();
    let sponsor = alloy::signers::local::PrivateKeySigner::random();
    let (envelope, request) = sponsored_charge_envelope(&client);
    let (url, requests) = mock_fee_payer(fill_answer(
        &envelope,
        &sponsor,
        PATH_USD.parse().unwrap(),
        |_| {},
    ))
    .await;

    // Reverting sender calls.
    let (method, _) = node(vec![Err(alloy_json_rpc::ErrorPayload {
        code: 3,
        message: "execution reverted".into(),
        data: None,
    })]);
    let method = method.with_remote_fee_payer(hosted(&url)).unwrap();
    let err = broadcast(&method, &envelope, &request).await.unwrap_err();
    assert!(err.to_string().contains("would revert"), "{err}");

    // A fee above the sponsor policy.
    let mut tx = make_fee_payer_tx(60);
    let env = FeePayerEnvelope78::decode_envelope(&envelope).unwrap();
    tx.calls = env.calls.clone();
    tx.max_fee_per_gas = 1_000_000_000_000;
    let expensive = sign_and_encode_0x78(tx, &client);
    let (method, _) = node(vec![]);
    let method = method.with_remote_fee_payer(hosted(&url)).unwrap();
    let err = broadcast(&method, &expensive, &request).await.unwrap_err();
    assert!(err.to_string().contains("max_fee_per_gas"), "{err}");

    assert!(requests.lock().unwrap().is_empty());
}

/// A hosted sponsorship whose final simulation reverts is not broadcast.
#[tokio::test]
async fn test_hosted_sponsorship_is_not_broadcast_when_final_simulation_reverts() {
    let client = alloy::signers::local::PrivateKeySigner::random();
    let sponsor = alloy::signers::local::PrivateKeySigner::random();
    let (envelope, request) = sponsored_charge_envelope(&client);
    let (url, requests) = mock_fee_payer(fill_answer(
        &envelope,
        &sponsor,
        PATH_USD.parse().unwrap(),
        |_| {},
    ))
    .await;
    let (method, asserter) = node(vec![
        Ok(serde_json::json!("0x")),
        Err(alloy_json_rpc::ErrorPayload {
            code: 3,
            message: "execution reverted: sponsor".into(),
            data: None,
        }),
        Ok(serde_json::json!(null)),
    ]);
    let method = method.with_remote_fee_payer(hosted(&url)).unwrap();

    let err = broadcast(&method, &envelope, &request).await.unwrap_err();
    assert!(err.to_string().contains("sponsor"), "{err}");
    assert_eq!(requests.lock().unwrap().len(), 1);
    assert_eq!(asserter.read_q().len(), 1, "nothing is broadcast");
}

#[test]
fn test_remote_fee_payer_config_is_validated() {
    assert!(RemoteFeePayer::new("not a url").resolve().is_err());
    assert!(RemoteFeePayer::new("ftp://sponsor.example")
        .resolve()
        .is_err());
    assert!(RemoteFeePayer::new("https://sponsor.example")
        .with_header("bad header", "x")
        .resolve()
        .is_err());
    let debug = format!("{:?}", hosted("https://sponsor.example"));
    assert!(!debug.contains("sponsor-secret"), "{debug}");
}

/// A retry after an unknown broadcast outcome reconciles the transaction the
/// hosted fee payer already signed instead of asking it again, which could
/// return another fee token and so another transaction.
#[tokio::test]
async fn test_hosted_sponsorship_retry_reconciles_the_signed_transaction() {
    let client = alloy::signers::local::PrivateKeySigner::random();
    let sponsor = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = USDC.parse::<Address>().unwrap();
    let (envelope, request) = sponsored_charge_envelope(&client);
    let (url, requests) = mock_fee_payer(fill_answer(&envelope, &sponsor, fee_token, |_| {})).await;
    let tx_hash = B256::repeat_byte(0x11);
    let (method, asserter) = node(vec![
        Ok(serde_json::json!("0x")),
        Ok(serde_json::json!("0x")),
        Err(alloy_json_rpc::ErrorPayload {
            code: -32000,
            message: "upstream timeout".into(),
            data: None,
        }),
        Ok(serde_json::Value::Null),
        Ok(receipt(
            client.address(),
            sponsor.address(),
            fee_token,
            tx_hash,
        )),
    ]);
    let method = method
        .with_remote_fee_payer(hosted(&url))
        .unwrap()
        .with_store(Arc::new(crate::store::MemoryStore::new()));

    assert!(broadcast(&method, &envelope, &request).await.is_err());
    assert_eq!(
        broadcast(&method, &envelope, &request).await.unwrap(),
        tx_hash
    );
    assert!(asserter.read_q().is_empty(), "all node calls consumed");
    assert_eq!(requests.lock().unwrap().len(), 1, "the sponsor signed once");
}
