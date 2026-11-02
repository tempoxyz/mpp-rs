use super::*;

/// Build a co-signed `0x76` transaction the same way `broadcast_transaction`
/// does, for exercising the sponsored simulation against a mocked node.
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

fn sim_method_with(
    responses: Vec<Result<serde_json::Value, alloy_json_rpc::ErrorPayload>>,
) -> (
    ChargeMethod<impl alloy::providers::Provider<tempo_alloy::TempoNetwork> + Clone + 'static>,
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

fn revert(message: &str) -> alloy_json_rpc::ErrorPayload {
    alloy_json_rpc::ErrorPayload {
        code: 3,
        message: message.to_owned().into(),
        data: None,
    }
}

fn is_absent(wire: &serde_json::Value, field: &str) -> bool {
    wire.get(field).is_none_or(serde_json::Value::is_null)
}

/// The first simulation runs the sender's calls alone: only `from` and the
/// calls, without gas, fee fields or signatures, so it does not depend on the
/// sender holding a fee token (mppx `simulationTransaction(tx, { feePayer:
/// true })`).
#[tokio::test]
async fn test_sender_simulation_request_carries_only_sender_and_calls() {
    let cosigned = make_cosigned_fee_payer_tx().await;
    let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    let sender = signed.recover_signer().unwrap();

    let wire =
        ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::sender_simulation_request(
            &signed, sender,
        )
        .unwrap();

    assert_eq!(
        wire["from"].as_str().unwrap().to_lowercase(),
        format!("{sender:#x}")
    );
    // The single call is folded into `to`/`input`.
    assert!(
        wire["to"].is_string() && wire["input"].is_string(),
        "{wire}"
    );
    for field in [
        "gas",
        "feeToken",
        "feePayer",
        "feePayerSignature",
        "nonce",
        "nonceKey",
        "validBefore",
        "maxFeePerGas",
        "maxPriorityFeePerGas",
        "keyType",
        "keyId",
        "keyAuthorization",
    ] {
        assert!(is_absent(&wire, field), "{field} must be omitted: {wire}");
    }
}

/// The final simulation is the co-signed transaction with its concrete fee
/// payer and fee token and neither signature (mppx
/// `sponsoredSimulationTransaction`): the node rejects `feePayer: true` in
/// `eth_call`, so the sponsor is named.
#[tokio::test]
async fn test_sponsored_simulation_request_names_the_fee_payer() {
    let cosigned = make_cosigned_fee_payer_tx().await;
    let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    let sender = signed.recover_signer().unwrap();
    let sponsor = Address::repeat_byte(0x5e);

    let wire =
        ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::sponsored_simulation_request(
            &cosigned, sponsor,
        )
        .unwrap();

    assert_eq!(
        wire["from"].as_str().unwrap().to_lowercase(),
        format!("{sender:#x}")
    );
    assert_eq!(wire["feePayer"], format!("{sponsor:#x}"));
    assert_eq!(
        wire["feeToken"].as_str().unwrap().to_lowercase(),
        format!("{:#x}", signed.tx().fee_token.unwrap())
    );
    assert_eq!(wire["gas"], format!("{:#x}", signed.tx().gas_limit));
    assert!(wire["nonceKey"].is_string() && wire["validBefore"].is_string());
    assert!(is_absent(&wire, "feePayerSignature"), "{wire}");
    assert!(is_absent(&wire, "signature"), "{wire}");
    assert!(wire["keyType"].is_string(), "{wire}");
    assert!(is_absent(&wire, "keyId"), "{wire}");
}

/// A keychain sender simulates as the wallet, with the access key as `keyId`
/// so the node applies the key's verification gas and spending limits.
#[tokio::test]
async fn test_sponsored_simulation_request_includes_keychain_fields() {
    let (cosigned, wallet, access_key) = make_keychain_cosigned_fee_payer_tx().await;
    assert_ne!(wallet, access_key);

    let wire =
        ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::sponsored_simulation_request(
            &cosigned,
            Address::repeat_byte(0x5e),
        )
        .unwrap();

    assert_eq!(
        wire["from"].as_str().unwrap().to_lowercase(),
        format!("{wallet:#x}")
    );
    assert_eq!(
        wire["keyId"].as_str().unwrap().to_lowercase(),
        format!("{access_key:#x}")
    );
}

/// A multi-call batch keeps its order: the last call is folded into `to` and
/// the node's `calls ++ [to call]` reconstruction reproduces the original.
#[test]
fn test_simulation_requests_preserve_multi_call_order() {
    use alloy::eips::Encodable2718;
    use alloy::signers::SignerSync;

    let signer = alloy::signers::local::PrivateKeySigner::random();
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
    tx.fee_token = Some(Address::repeat_byte(0x20));
    let signature: tempo_alloy::primitives::transaction::TempoSignature =
        signer.sign_hash_sync(&tx.signature_hash()).unwrap().into();
    let signed = tx.into_signed(signature);
    let encoded = signed.encoded_2718();

    type M = ChargeMethod<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>;
    for wire in [
        M::sender_simulation_request(&signed, signer.address()).unwrap(),
        M::sponsored_simulation_request(&encoded, Address::repeat_byte(0x5e)).unwrap(),
    ] {
        let request: tempo_alloy::rpc::TempoTransactionRequest =
            serde_json::from_value(wire).unwrap();
        assert_eq!(request.calls, calls[..2], "first N-1 calls stay in calls");
        assert_eq!(
            request.inner.to,
            Some(calls[2].to),
            "last call folds into to"
        );
        assert_eq!(request.inner.value, Some(calls[2].value));
    }
}

/// Simulation fails closed: a revert is a failed transaction and an RPC
/// error a failed check.
#[tokio::test]
async fn test_simulation_fails_closed() {
    let cosigned = make_cosigned_fee_payer_tx().await;
    let sponsor = Address::repeat_byte(0x5e);

    let (method, asserter) = sim_method_with(vec![Ok(serde_json::json!("0x"))]);
    method
        .simulate_sponsored_transaction(&cosigned, sponsor)
        .await
        .expect("a successful eth_call passes");
    assert!(asserter.read_q().is_empty(), "eth_call must be issued");

    let (method, _) = sim_method_with(vec![Err(revert("execution reverted: InsufficientBalance"))]);
    let err = method
        .simulate_sponsored_transaction(&cosigned, sponsor)
        .await
        .expect_err("a reverting eth_call is rejected");
    assert!(err.to_string().contains("would revert"), "{err}");
    assert!(err.to_string().contains("InsufficientBalance"), "{err}");

    let (method, _) = sim_method_with(vec![Err(alloy_json_rpc::ErrorPayload {
        code: -32601,
        message: "the method eth_call does not exist/is not available".into(),
        data: None,
    })]);
    let err = method
        .simulate_sponsored_transaction(&cosigned, sponsor)
        .await
        .expect_err("a node that cannot simulate fails closed");
    assert!(
        err.to_string().contains("Pre-broadcast simulation failed"),
        "{err}"
    );
}

/// A sponsored pathUSD charge's client envelope and request.
pub(super) fn sponsored_charge_envelope(
    client_signer: &alloy::signers::local::PrivateKeySigner,
) -> (Vec<u8>, ChargeRequest) {
    let currency = PATH_USD.parse::<Address>().unwrap();
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(1_000_000u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let mut tx = make_fee_payer_tx(60);
    tx.calls = vec![tempo_alloy::primitives::transaction::Call {
        to: TxKind::Call(currency),
        value: U256::ZERO,
        input: make_transfer_with_memo_input(recipient, amount, memo),
    }];
    let request = ChargeRequest {
        amount: amount.to_string(),
        currency: PATH_USD.to_string(),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({ "chainId": CHAIN_ID, "feePayer": true })),
        ..Default::default()
    };
    (sign_and_encode_0x78(tx, client_signer), request)
}

/// The sender's calls are simulated before the fee payer signs: a reverting
/// transaction never reaches the signer, and nothing else is asked of the node.
#[tokio::test]
async fn test_reverting_sender_calls_never_reach_the_fee_payer() {
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let (envelope, request) = sponsored_charge_envelope(&client_signer);
    let (method, asserter) = sim_method_with(vec![Err(revert("execution reverted"))]);
    // Balance lookups for fee-token selection would follow the signer's turn.
    let method = method.with_fee_payer(alloy::signers::local::PrivateKeySigner::random());

    let err = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(&envelope),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            None,
        )
        .await
        .expect_err("a reverting sender simulation stops sponsorship");
    assert!(err.to_string().contains("would revert"), "{err}");
    assert!(asserter.read_q().is_empty());
}

/// A co-signed transaction whose final simulation reverts is not broadcast.
#[tokio::test]
async fn test_sponsored_transaction_is_not_broadcast_when_final_simulation_reverts() {
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let (envelope, request) = sponsored_charge_envelope(&client_signer);
    let (method, asserter) = sim_method_with(vec![
        Ok(serde_json::json!("0x")),
        Err(revert("execution reverted: fee token")),
        // Would be the broadcast's receipt if one were sent.
        Ok(serde_json::json!(null)),
    ]);
    let method = method
        .with_fee_payer(alloy::signers::local::PrivateKeySigner::random())
        .with_fee_payer_fee_token(PATH_USD.parse().unwrap());

    let err = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(&envelope),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            None,
        )
        .await
        .expect_err("a reverting final simulation stops the broadcast");
    assert!(err.to_string().contains("fee token"), "{err}");
    assert_eq!(asserter.read_q().len(), 1, "nothing is broadcast");
}
