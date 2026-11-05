use super::super::simulate::{rpc_signature, SPONSORED_SIMULATION_GAS_BUFFER};
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
/// payer, fee token and fee payer signature, without the sender's signature
/// (mppx `sponsoredSimulationTransaction`): the node rejects `feePayer: true`
/// in `eth_call`, so the sponsor is named, and bills the fee payer it recovers
/// from `feePayerSignature`, so the sponsor's signature is sent.
#[tokio::test]
async fn test_sponsored_simulation_request_names_the_fee_payer() {
    let cosigned = make_cosigned_fee_payer_tx().await;
    let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    let sender = signed.recover_signer().unwrap();
    let sponsor = Address::repeat_byte(0x5e);

    let wire =
        ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::sponsored_simulation_request(
            &cosigned, sponsor, None,
        )
        .unwrap();

    assert_eq!(
        wire["from"].as_str().unwrap().to_lowercase(),
        format!("{sender:#x}")
    );
    assert_eq!(wire["feePayer"], format!("{sponsor:#x}"));
    assert_eq!(
        wire["feePayerSignature"],
        rpc_signature(&signed.tx().fee_payer_signature.unwrap())
    );
    assert_eq!(
        wire["feeToken"].as_str().unwrap().to_lowercase(),
        format!("{:#x}", signed.tx().fee_token.unwrap())
    );
    assert_eq!(wire["gas"], format!("{:#x}", signed.tx().gas_limit));
    assert!(wire["nonceKey"].is_string() && wire["validBefore"].is_string());
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
            None,
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
    tx.fee_payer_signature = Some(signer.sign_hash_sync(&B256::repeat_byte(1)).unwrap());
    let signature: tempo_alloy::primitives::transaction::TempoSignature =
        signer.sign_hash_sync(&tx.signature_hash()).unwrap().into();
    let signed = tx.into_signed(signature);
    let encoded = signed.encoded_2718();

    type M = ChargeMethod<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>;
    for wire in [
        M::sender_simulation_request(&signed, signer.address()).unwrap(),
        M::sponsored_simulation_request(&encoded, Address::repeat_byte(0x5e), None).unwrap(),
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
        .simulate_sponsored_transaction(&cosigned, sponsor, None)
        .await
        .expect("a successful eth_call passes");
    assert!(asserter.read_q().is_empty(), "eth_call must be issued");

    let (method, _) = sim_method_with(vec![Err(revert("execution reverted: InsufficientBalance"))]);
    let err = method
        .simulate_sponsored_transaction(&cosigned, sponsor, None)
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
        .simulate_sponsored_transaction(&cosigned, sponsor, None)
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

/// The fee payer signature is sent in JSON-RPC form, with §yParity§ 0 or 1 as
/// a hex quantity.
#[test]
fn test_rpc_signature_encodes_both_parities() {
    for parity in [false, true] {
        let signature =
            alloy::primitives::Signature::new(U256::from(0xabu64), U256::from(0xcdu64), parity);
        assert_eq!(
            rpc_signature(&signature),
            serde_json::json!({
                "r": "0xab",
                "s": "0xcd",
                "yParity": if parity { "0x1" } else { "0x0" },
            })
        );
    }
}

/// A local fee payer signs a simulation-only copy with
/// §SPONSORED_SIMULATION_GAS_BUFFER§ more gas, over the same payload as its
/// broadcast co-signature; the final simulation carries that gas and
/// signature, and the broadcast transaction keeps its own.
#[tokio::test]
async fn test_local_fee_payer_simulation_copy_has_gas_headroom() {
    use super::super::super::FeePayerEnvelope78;
    use alloy::signers::SignerSync;

    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let fee_payer = fee_payer_signer.address();
    let tx = make_fee_payer_tx(60);
    let signature: tempo_alloy::primitives::transaction::TempoSignature = client_signer
        .sign_hash_sync(&tx.signature_hash())
        .unwrap()
        .into();
    let envelope = FeePayerEnvelope78::from_signing_tx(tx, client_signer.address(), signature)
        .encoded_envelope();
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);
    let signer = method.fee_payer_signer.as_deref().unwrap();
    let cosigned = method
        .cosign_fee_payer_transaction(&envelope, signer, PATH_USD.parse().unwrap())
        .await
        .unwrap();
    let broadcast =
        tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    let gas_limit = broadcast.tx().gas_limit;

    let simulation = method
        .sign_fee_payer_simulation(&cosigned, signer)
        .await
        .unwrap();
    assert_eq!(
        simulation.gas_limit,
        gas_limit + SPONSORED_SIMULATION_GAS_BUFFER
    );
    assert_eq!(SPONSORED_SIMULATION_GAS_BUFFER, 10_000);
    assert_ne!(
        Some(simulation.fee_payer_signature),
        broadcast.tx().fee_payer_signature,
        "the copy's signature covers its own gas limit"
    );

    // The signature recovers to the fee payer over the simulation copy.
    let mut copy = broadcast.tx().clone();
    copy.gas_limit = simulation.gas_limit;
    copy.fee_payer_signature = Some(simulation.fee_payer_signature);
    assert_eq!(
        copy.recover_fee_payer(client_signer.address()).unwrap(),
        fee_payer
    );

    let wire = ChargeMethod::<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>>::sponsored_simulation_request(
        &cosigned,
        fee_payer,
        Some(&simulation),
    )
    .unwrap();
    assert_eq!(wire["gas"], format!("{:#x}", simulation.gas_limit));
    assert_eq!(
        wire["feePayerSignature"],
        rpc_signature(&simulation.fee_payer_signature)
    );
    assert!(is_absent(&wire, "signature"), "{wire}");

    // The broadcast transaction is untouched.
    let again = tempo_alloy::primitives::AASigned::decode_2718(&mut cosigned.as_slice()).unwrap();
    assert_eq!(again.tx().gas_limit, gas_limit);
}

/// A fee payer signer that records how many mocked node responses remain
/// each time it signs.
struct RecordingSigner {
    inner: alloy::signers::local::PrivateKeySigner,
    asserter: alloy::providers::mock::Asserter,
    remaining: Arc<std::sync::Mutex<Vec<usize>>>,
}

#[async_trait::async_trait]
impl alloy::signers::Signer for RecordingSigner {
    async fn sign_hash(&self, hash: &B256) -> alloy::signers::Result<alloy::primitives::Signature> {
        use alloy::signers::SignerSync;

        self.remaining
            .lock()
            .unwrap()
            .push(self.asserter.read_q().len());
        self.inner.sign_hash_sync(hash)
    }

    fn address(&self) -> Address {
        alloy::signers::Signer::address(&self.inner)
    }

    fn chain_id(&self) -> Option<u64> {
        None
    }

    fn set_chain_id(&mut self, _chain_id: Option<u64>) {}
}

fn recording_method(
    responses: Vec<Result<serde_json::Value, alloy_json_rpc::ErrorPayload>>,
) -> (
    ChargeMethod<impl alloy::providers::Provider<tempo_alloy::TempoNetwork> + Clone + 'static>,
    alloy::providers::mock::Asserter,
    Arc<std::sync::Mutex<Vec<usize>>>,
) {
    let (method, asserter) = sim_method_with(responses);
    let remaining = Arc::default();
    let method = method
        .with_fee_payer(RecordingSigner {
            inner: alloy::signers::local::PrivateKeySigner::random(),
            asserter: asserter.clone(),
            remaining: Arc::clone(&remaining),
        })
        .with_fee_payer_fee_token(PATH_USD.parse().unwrap());
    (method, asserter, remaining)
}

/// A local fee payer signs only after the sender's calls pass simulation:
/// the sender simulation, then the broadcast co-signature, then the
/// simulation copy's signature, then the final simulation.
#[tokio::test]
async fn test_local_fee_payer_signs_after_sender_simulation() {
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let (envelope, request) = sponsored_charge_envelope(&client_signer);
    let (method, asserter, remaining) = recording_method(vec![
        Ok(serde_json::json!("0x")),
        Err(revert("execution reverted: stop before broadcast")),
    ]);

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
        .expect_err("the final simulation reverts");
    assert!(err.to_string().contains("stop before broadcast"), "{err}");
    // Both signatures come after the sender simulation (1 response left) and
    // before the final simulation, which consumed the last response.
    assert_eq!(*remaining.lock().unwrap(), vec![1, 1]);
    assert!(asserter.read_q().is_empty());
}

/// A sender simulation that fails leaves the local fee payer unsigned.
#[tokio::test]
async fn test_local_fee_payer_never_signs_when_sender_simulation_fails() {
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let (envelope, request) = sponsored_charge_envelope(&client_signer);
    let (method, _, remaining) = recording_method(vec![Err(revert("execution reverted"))]);

    method
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
        .expect_err("the sender simulation reverts");
    assert!(remaining.lock().unwrap().is_empty(), "nothing was signed");
}
