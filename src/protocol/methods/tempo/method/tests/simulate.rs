use super::*;

/// Build a co-signed `0x76` transaction the same way `broadcast_transaction`
/// does, for exercising `simulate_before_broadcast` against a mocked node.
async fn make_cosigned_fee_payer_tx() -> Vec<u8> {
    use super::super::super::FeePayerEnvelope78;
    use alloy::signers::SignerSync;

    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();

    let tx = make_fee_payer_tx(60);
    let sig_hash = tx.signature_hash();
    let sig = client_signer.sign_hash_sync(&sig_hash).unwrap();
    let signature: tempo_alloy::primitives::transaction::TempoSignature = sig.into();
    let envelope = FeePayerEnvelope78::from_signing_tx(tx, client_signer.address(), signature)
        .encoded_envelope();

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);
    method
        .cosign_fee_payer_transaction(
            &envelope,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect("cosign should succeed")
}

/// Co-signed `0x76` tx whose client signature is a keychain (access-key)
/// signature. Returns `(cosigned bytes, wallet, access key)`.
async fn make_keychain_cosigned_fee_payer_tx() -> (Vec<u8>, Address, Address) {
    use super::super::super::FeePayerEnvelope78;
    use alloy::signers::SignerSync;
    use tempo_alloy::primitives::transaction::{
        KeychainSignature, PrimitiveSignature, TempoSignature,
    };

    let wallet = Address::repeat_byte(0xab);
    let access_key_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_token = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();

    let tx = make_fee_payer_tx(60);
    let sig_hash = tx.signature_hash();
    // V1 keychain signs sig_hash directly; inner signer is the access key.
    let inner = access_key_signer.sign_hash_sync(&sig_hash).unwrap();
    let keychain_sig = KeychainSignature::new_v1(wallet, PrimitiveSignature::Secp256k1(inner));
    let signature = TempoSignature::Keychain(keychain_sig);
    let envelope = FeePayerEnvelope78::from_signing_tx(tx, wallet, signature).encoded_envelope();

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);
    let cosigned = method
        .cosign_fee_payer_transaction(
            &envelope,
            method.fee_payer_signer.as_deref().unwrap(),
            fee_token,
        )
        .await
        .expect("cosign should succeed");

    (cosigned, wallet, access_key_signer.address())
}

/// A keychain tx's request sets `from` to the wallet and carries the access
/// key as `keyId`/`keyType`, serialized onto the wire.
#[tokio::test]
async fn test_build_simulate_payload_includes_keychain_fields() {
    let (cosigned, wallet, access_key) = make_keychain_cosigned_fee_payer_tx().await;

    let payload =
        ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::build_simulate_payload(
            &cosigned,
        )
        .expect("payload must build");

    let call = &payload.block_state_calls[0].calls[0];

    assert_eq!(call.inner.from, Some(wallet), "from must be the wallet");
    assert_eq!(
        call.key_id,
        Some(access_key),
        "keyId must be the access key, not the wallet"
    );
    assert_eq!(
        call.key_type,
        Some(tempo_alloy::primitives::SignatureType::Secp256k1)
    );
    // Otherwise the assertions above would be vacuous.
    assert_ne!(wallet, access_key);

    // Confirm the keychain fields serialize onto the wire.
    let p = serde_json::to_value(&payload).unwrap();
    let wire_call = &p["blockStateCalls"][0]["calls"][0];
    assert_eq!(
        wire_call["keyId"].as_str().unwrap().to_lowercase(),
        format!("{:#x}", access_key),
    );
    assert!(wire_call["keyType"].is_string() || wire_call["keyType"].is_number());
}

/// A plain EOA tx carries no `keyId` but still advertises its `keyType`
/// so the node sizes signature gas correctly.
#[tokio::test]
async fn test_build_simulate_payload_omits_keychain_for_primitive_sig() {
    let cosigned = make_cosigned_fee_payer_tx().await;

    let payload =
        ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::build_simulate_payload(
            &cosigned,
        )
        .expect("payload must build");

    let call = &payload.block_state_calls[0].calls[0];
    assert!(call.key_id.is_none(), "plain EOA tx must not set keyId");
    assert_eq!(
        call.key_type,
        Some(tempo_alloy::primitives::SignatureType::Secp256k1),
        "primitive tx must advertise its keyType for gas sizing"
    );
    assert!(
        call.key_data.is_none(),
        "secp256k1 tx has no WebAuthn auth data"
    );
}

/// The `tempo_simulateV1` request must carry the full sponsor/cosign ABI:
/// `from` (recovered sender), `feeToken`, `feePayerSignature`, `nonceKey`,
/// the validity window, and `validation: false`. The single payment call is
/// folded into `to`/`input` (not left in `calls`) so the node does not read
/// the empty `to` as a CREATE.
#[tokio::test]
async fn test_build_simulate_payload_request_abi() {
    let cosigned = make_cosigned_fee_payer_tx().await;

    // The from we expect is the client sender recovered from the cosigned tx.
    let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    let expected_from = signed.recover_signer().unwrap();
    let expected_calls = signed.tx().calls.clone();

    let payload =
        ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::build_simulate_payload(
            &cosigned,
        )
        .expect("payload must build");

    // `build_aa()` must reproduce the original call list exactly, so the
    // fee-payer signature still recovers.
    let rebuilt = payload.block_state_calls[0].calls[0]
        .clone()
        .build_aa()
        .expect("request must rebuild into an AA tx");
    assert_eq!(
        rebuilt.calls, expected_calls,
        "rebuilt batch must match the signed tx's calls"
    );

    // Serialize exactly as it goes over the wire (single-element param array).
    let params = serde_json::to_value((payload,)).unwrap();
    let arr = params.as_array().expect("params serialize to a JSON array");
    assert_eq!(
        arr.len(),
        1,
        "tempo_simulateV1 takes a single payload param"
    );

    let p = &arr[0];
    assert_eq!(p["validation"], serde_json::json!(false));

    let call = &p["blockStateCalls"][0]["calls"][0];
    assert_eq!(
        call["from"].as_str().unwrap().to_lowercase(),
        format!("{:#x}", expected_from),
        "request must set the recovered sender as `from`"
    );
    // The single payment call must be folded into `to` (so the node does
    // not treat the empty `to` as a CREATE) — not left in `calls`.
    assert!(
        call["to"].is_string(),
        "payment call must be folded into `to`: {call}"
    );
    assert!(
        call["calls"]
            .as_array()
            .map(|c| c.is_empty())
            .unwrap_or(true),
        "single-call request must leave `calls` empty: {call}"
    );
    // Fee-sponsor fields the node needs to model gas affordability/execution.
    assert!(call["feeToken"].is_string(), "feeToken must be present");
    assert!(
        call["feePayerSignature"].is_string() || call["feePayerSignature"].is_object(),
        "feePayerSignature must be present: {call}"
    );
    assert!(call["nonceKey"].is_string(), "nonceKey must be present");
    assert!(
        call["validBefore"].is_string(),
        "validBefore must be present"
    );
}

/// A multi-call AA batch must round-trip with its order preserved: the
/// last call is folded into `to`, the rest stay in `calls`, and the node's
/// `calls ++ [inner.to call]` reconstruction reproduces the original order.
#[test]
fn test_build_simulate_payload_preserves_multi_call_order() {
    use alloy::eips::Encodable2718;
    use alloy::signers::SignerSync;

    let signer = alloy::signers::local::PrivateKeySigner::random();

    // Three distinct calls so a reordering bug (e.g. moving the first call)
    // would be observable.
    let calls = vec![
        tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(Address::repeat_byte(0x11)),
            value: U256::ZERO,
            input: Bytes::from(vec![0xaa]),
        },
        tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(Address::repeat_byte(0x22)),
            value: U256::from(7u64),
            input: Bytes::from(vec![0xbb, 0xbb]),
        },
        tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(Address::repeat_byte(0x33)),
            value: U256::ZERO,
            input: Bytes::from(vec![0xcc, 0xcc, 0xcc]),
        },
    ];

    let mut tx = make_fee_payer_tx(60);
    tx.calls = calls.clone();
    let signature: tempo_alloy::primitives::transaction::TempoSignature =
        signer.sign_hash_sync(&tx.signature_hash()).unwrap().into();
    let signed_bytes = tx.into_signed(signature).encoded_2718();

    let payload =
        ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::build_simulate_payload(
            &signed_bytes,
        )
        .expect("payload must build");

    let req = &payload.block_state_calls[0].calls[0];
    // N-1 calls stay in `calls`, the last is folded into `to`.
    assert_eq!(req.calls, calls[..2], "first N-1 calls stay in `calls`");
    assert_eq!(req.inner.to, Some(calls[2].to), "last call folds into `to`");
    assert_eq!(req.inner.value, Some(calls[2].value));

    // The node reconstructs `calls ++ [inner.to call]`; verify it matches.
    let rebuilt = req.clone().build_aa().expect("must rebuild");
    assert_eq!(
        rebuilt.calls, calls,
        "reconstructed batch must preserve the original order"
    );
}

/// A reverting simulation must block the broadcast so the sponsor never
/// pays gas for a failing transaction.
#[tokio::test]
async fn test_simulate_before_broadcast_rejects_revert() {
    use alloy::providers::mock::Asserter;

    let cosigned = make_cosigned_fee_payer_tx().await;

    let asserter = Asserter::new();
    asserter.push_success(&serde_json::json!({
        "blocks": [{
            "calls": [{
                "returnData": "0x",
                "gasUsed": "0x5208",
                "status": "0x0",
                "error": { "code": 3, "message": "execution reverted" }
            }]
        }]
    }));

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);
    let method = ChargeMethod::new(provider);

    let err = method
        .simulate_before_broadcast(&cosigned)
        .await
        .expect_err("reverting simulation must be rejected");
    assert!(
        err.to_string().contains("would revert"),
        "unexpected error: {err}"
    );
    assert!(err.to_string().contains("execution reverted"));
}

/// A successful simulation must allow the broadcast to proceed.
#[tokio::test]
async fn test_simulate_before_broadcast_accepts_success() {
    use alloy::providers::mock::Asserter;

    let cosigned = make_cosigned_fee_payer_tx().await;

    let asserter = Asserter::new();
    asserter.push_success(&serde_json::json!({
        "blocks": [{
            "calls": [{
                "returnData": "0x",
                "gasUsed": "0x5208",
                "status": "0x1"
            }]
        }]
    }));

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);
    let method = ChargeMethod::new(provider);

    method
        .simulate_before_broadcast(&cosigned)
        .await
        .expect("successful simulation must pass");
}

/// If the simulation RPC itself errors, fail closed: the sponsor must not
/// broadcast a transaction it could not simulate.
#[tokio::test]
async fn test_simulate_before_broadcast_fails_closed_on_rpc_error() {
    use alloy::providers::mock::Asserter;

    let cosigned = make_cosigned_fee_payer_tx().await;

    let asserter = Asserter::new();
    asserter.push_failure_msg("tempo_simulateV1 unavailable");

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);
    let method = ChargeMethod::new(provider);

    let err = method
        .simulate_before_broadcast(&cosigned)
        .await
        .expect_err("RPC failure must fail closed");
    assert!(
        err.to_string().contains("Pre-broadcast simulation failed"),
        "unexpected error: {err}"
    );
}

/// A node that doesn't implement `tempo_simulateV1` (JSON-RPC "method not
/// found", -32601) is asked to `eth_call` the calls from the sender, so a
/// reverting transaction is still caught before the sponsor pays for it.
#[tokio::test]
async fn test_simulate_before_broadcast_falls_back_to_eth_call() {
    use alloy::providers::mock::Asserter;

    let cosigned = make_cosigned_fee_payer_tx().await;

    let method_with = |eth_call: Result<Bytes, alloy_json_rpc::ErrorPayload>| {
        let asserter = Asserter::new();
        asserter.push_failure(alloy_json_rpc::ErrorPayload {
            code: -32601,
            message: "the method tempo_simulateV1 does not exist/is not available".into(),
            data: None,
        });
        match eth_call {
            Ok(output) => asserter.push_success(&output),
            Err(error) => asserter.push_failure(error),
        }
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_mocked_client(asserter.clone());
        (ChargeMethod::new(provider), asserter)
    };

    let (method, asserter) = method_with(Ok(Bytes::from(U256::from(1).to_be_bytes::<32>())));
    method
        .simulate_before_broadcast(&cosigned)
        .await
        .expect("successful eth_call must pass");
    assert!(asserter.read_q().is_empty(), "eth_call must be issued");

    let (method, _) = method_with(Err(alloy_json_rpc::ErrorPayload {
        code: 3,
        message: "execution reverted: InsufficientBalance".into(),
        data: None,
    }));
    let err = method
        .simulate_before_broadcast(&cosigned)
        .await
        .expect_err("reverting eth_call must be rejected");
    assert!(err.to_string().contains("would revert"), "got: {err}");
    assert!(err.to_string().contains("InsufficientBalance"));

    let (method, _) = method_with(Err(alloy_json_rpc::ErrorPayload {
        code: -32601,
        message: "the method eth_call does not exist/is not available".into(),
        data: None,
    }));
    let err = method
        .simulate_before_broadcast(&cosigned)
        .await
        .expect_err("a node that cannot simulate at all must fail closed");
    assert!(
        err.to_string().contains("Pre-broadcast simulation failed"),
        "got: {err}"
    );
}

/// The `eth_call` fallback runs the calls from the sender without fee
/// fields, so it does not depend on the sender holding a fee token.
#[tokio::test]
async fn test_sender_call_request_preserves_execution_gas_without_fee_fields() {
    let cosigned = make_cosigned_fee_payer_tx().await;
    let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    let sender = signed.recover_signer().unwrap();

    let mut payload =
        ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::build_simulate_payload(
            &cosigned,
        )
        .unwrap();
    let request =
        ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::sender_call_request(
            payload.block_state_calls.remove(0).calls.remove(0),
        );

    let wire = serde_json::to_value(&request).unwrap();
    assert_eq!(
        wire["from"].as_str().unwrap().to_lowercase(),
        format!("{sender:#x}")
    );
    assert!(wire["to"].is_string() && wire["input"].is_string());
    for field in [
        "feePayerSignature",
        "nonceKey",
        "validBefore",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
    ] {
        assert!(wire.get(field).is_none(), "{field} must be omitted: {wire}");
    }
    assert_eq!(wire["gas"], format!("0x{:x}", signed.tx().gas_limit));
    assert!(wire["feeToken"].is_null());
}

#[tokio::test]
async fn test_fallback_rejects_out_of_gas_with_signed_limit() {
    use axum::{routing::post, Json, Router};
    use serde_json::{json, Value};

    let cosigned = make_cosigned_fee_payer_tx().await;
    let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    let expected_gas = format!("0x{:x}", signed.tx().gas_limit);
    let app = Router::new().route(
        "/",
        post(move |Json(request): Json<Value>| {
            let expected_gas = expected_gas.clone();
            async move {
                let mut response = json!({"jsonrpc": "2.0", "id": request["id"]});
                match request["method"].as_str().unwrap() {
                    "tempo_simulateV1" => {
                        response["error"] = json!({"code": -32601, "message": "unsupported"})
                    }
                    "eth_call" if request["params"][0]["gas"] == expected_gas => {
                        response["error"] = json!({"code": 3, "message": "out of gas"});
                    }
                    "eth_call" => response["result"] = json!("0x"),
                    method => panic!("unexpected RPC: {method}"),
                }
                Json(response)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http(url.parse().unwrap());
    let result = ChargeMethod::new(provider)
        .simulate_before_broadcast(&cosigned)
        .await;
    server.abort();
    let error = result.expect_err("fallback must simulate the signed gas limit");
    assert!(error.to_string().contains("out of gas"), "{error}");
}
