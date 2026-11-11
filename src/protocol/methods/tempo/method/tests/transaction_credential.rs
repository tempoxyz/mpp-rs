use super::*;

#[tokio::test]
async fn test_broadcast_rejects_unbound_memo_before_rpc() {
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let wrong_memo = attribution::encode("challenge-456", "api.example.com", None);
    let tx_bytes = encode_signed_tx(
        vec![tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(currency),
            value: U256::ZERO,
            input: make_transfer_with_memo_input(recipient, amount, wrong_memo),
        }],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let request = ChargeRequest {
        amount: amount.to_string(),
        currency: format!("{currency:#x}"),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({ "chainId": CHAIN_ID })),
        ..Default::default()
    };

    // No mock responses are queued: reaching the provider would produce a
    // different error and fail the assertion below.
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(Asserter::new());
    let method = ChargeMethod::new(provider);

    let error = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(tx_bytes),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            None,
        )
        .await
        .expect_err("unbound memo must be rejected before broadcast");

    assert!(
        error
            .to_string()
            .contains("memo is not bound to this challenge"),
        "unexpected error: {error}"
    );
    // Nothing settled yet, so this stays a retryable 402 failure.
    assert_ne!(
        error.code,
        Some(crate::protocol::traits::ErrorCode::CredentialReplayed)
    );
}

#[tokio::test]
async fn test_fee_payer_rejects_unbound_memo_before_cosign_or_rpc() {
    use alloy::providers::mock::Asserter;

    let currency = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let wrong_memo = attribution::encode("challenge-456", "api.example.com", None);
    let mut tx = make_fee_payer_tx(60);
    tx.calls = vec![tempo_alloy::primitives::transaction::Call {
        to: TxKind::Call(currency),
        value: U256::ZERO,
        input: make_transfer_with_memo_input(recipient, amount, wrong_memo),
    }];
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let tx_bytes = sign_and_encode_0x78(tx, &client_signer);
    let request = ChargeRequest {
        amount: amount.to_string(),
        currency: format!("{currency:#x}"),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({
            "chainId": CHAIN_ID,
            "feePayer": true,
        })),
        ..Default::default()
    };

    let signer_calls = Arc::new(AtomicUsize::new(0));
    let fee_payer_signer = AsyncOnlySigner {
        inner: alloy::signers::local::PrivateKeySigner::random(),
        calls: Arc::clone(&signer_calls),
    };
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(Asserter::new());
    let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

    let error = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(tx_bytes),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            None,
        )
        .await
        .expect_err("unbound memo must be rejected before sponsorship");

    assert!(
        error
            .to_string()
            .contains("memo is not bound to this challenge"),
        "unexpected error: {error}"
    );
    assert_eq!(signer_calls.load(Ordering::Relaxed), 0);
}

// ==================== Transaction credential source validation ====================

const TRANSACTION_SOURCE_INVALID: &str = "Transaction credential source is invalid.";
const TRANSACTION_SOURCE_MISMATCH: &str =
    "Transaction credential source does not match the transaction sender.";

fn challenge_bound_transfer_call(
    currency: Address,
    recipient: Address,
    amount: U256,
) -> tempo_alloy::primitives::transaction::Call {
    tempo_alloy::primitives::transaction::Call {
        to: TxKind::Call(currency),
        value: U256::ZERO,
        input: make_transfer_with_memo_input(
            recipient,
            amount,
            attribution::encode("challenge-123", "api.example.com", None),
        ),
    }
}

fn transaction_credential(
    request: &ChargeRequest,
    tx_bytes: &[u8],
    source: Option<String>,
) -> PaymentCredential {
    let mut credential = PaymentCredential::new(
        PaymentChallenge::new(
            "challenge-123",
            "api.example.com",
            "tempo",
            "charge",
            Base64UrlJson::from_typed(request).unwrap(),
        )
        .to_echo(),
        crate::protocol::core::PaymentPayload::transaction(alloy::hex::encode_prefixed(tx_bytes)),
    );
    credential.source = source;
    credential
}

#[tokio::test]
async fn test_validate_binds_transaction_credential_source_to_sender() {
    use alloy::eips::Decodable2718;
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let tx_bytes = encode_signed_tx(
        vec![challenge_bound_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let sender = tempo_alloy::primitives::AASigned::decode_2718(&mut &tx_bytes[..])
        .unwrap()
        .recover_signer()
        .unwrap();
    let request = ChargeRequest {
        amount: amount.to_string(),
        currency: format!("{currency:#x}"),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({ "chainId": CHAIN_ID })),
        ..Default::default()
    };

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(Asserter::new());
    let method = ChargeMethod::new(provider);
    method.cached_chain_id.set(CHAIN_ID).unwrap();

    let lowercase_source = format!("did:pkh:eip155:{CHAIN_ID}:{sender:#x}");
    let accepted = [
        (None, did_pkh(CHAIN_ID, sender)),
        (Some(lowercase_source.clone()), lowercase_source),
    ];
    for (source, expected) in accepted {
        let credential = transaction_credential(&request, &tx_bytes, source);
        let validation = ChargeMethodTrait::validate(&method, &credential, &request)
            .await
            .unwrap();
        assert_eq!(validation.source, Some(expected));
        assert_eq!(validation.payer, Some(format!("{sender:#x}")));
    }

    let rejected = [
        (
            did_pkh(CHAIN_ID, Address::repeat_byte(0x99)),
            TRANSACTION_SOURCE_MISMATCH,
        ),
        (
            did_pkh(MODERATO_CHAIN_ID, sender),
            TRANSACTION_SOURCE_INVALID,
        ),
        (format!("{sender:#x}"), TRANSACTION_SOURCE_INVALID),
    ];
    for (source, expected) in rejected {
        let credential = transaction_credential(&request, &tx_bytes, Some(source.clone()));
        let error = ChargeMethodTrait::validate(&method, &credential, &request)
            .await
            .expect_err(&source);
        assert_eq!(error.message, expected, "{source}");
    }
}

#[tokio::test]
async fn test_verify_rejects_transaction_source_mismatch_before_cosign_or_rpc() {
    use alloy::eips::Encodable2718;
    use alloy::providers::mock::Asserter;
    use alloy::signers::SignerSync;

    let currency = KnownTempoNetwork::Mainnet
        .default_currency()
        .parse::<Address>()
        .unwrap();
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let client_signer = alloy::signers::local::PrivateKeySigner::random();
    let claimed_source = did_pkh(CHAIN_ID, Address::repeat_byte(0x99));

    let mut tx = make_fee_payer_tx(60);
    tx.calls = vec![challenge_bound_transfer_call(currency, recipient, amount)];
    let sponsored_tx_bytes = sign_and_encode_0x78(tx.clone(), &client_signer);
    tx.fee_payer_signature = None;
    tx.fee_token = Some(currency);
    let signature: tempo_alloy::primitives::transaction::TempoSignature = client_signer
        .sign_hash_sync(&tx.signature_hash())
        .unwrap()
        .into();
    let tx_bytes = tx.into_signed(signature).encoded_2718();

    // No mock responses are queued: reaching the provider would produce a
    // different error and fail the assertions below.
    for (fee_payer, tx_bytes) in [(false, tx_bytes), (true, sponsored_tx_bytes)] {
        let request = ChargeRequest {
            amount: amount.to_string(),
            currency: format!("{currency:#x}"),
            recipient: Some(format!("{recipient:#x}")),
            method_details: Some(serde_json::json!({
                "chainId": CHAIN_ID,
                "feePayer": fee_payer,
            })),
            ..Default::default()
        };
        let signer_calls = Arc::new(AtomicUsize::new(0));
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_mocked_client(Asserter::new());
        let method = ChargeMethod::new(provider).with_fee_payer(AsyncOnlySigner {
            inner: alloy::signers::local::PrivateKeySigner::random(),
            calls: Arc::clone(&signer_calls),
        });
        method.cached_chain_id.set(CHAIN_ID).unwrap();

        let credential = transaction_credential(&request, &tx_bytes, Some(claimed_source.clone()));
        let error = ChargeMethodTrait::verify(&method, &credential, &request)
            .await
            .expect_err("mismatched source must be rejected before broadcast");

        assert_eq!(
            error.message, TRANSACTION_SOURCE_MISMATCH,
            "fee_payer={fee_payer}"
        );
        assert_eq!(signer_calls.load(Ordering::Relaxed), 0);
    }
}

// ==================== Expiry before broadcast ====================

fn rfc3339_from_now(offset: time::Duration) -> String {
    (time::OffsetDateTime::now_utc() + offset)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}

fn challenge_bound_request(currency: Address, recipient: Address, amount: U256) -> ChargeRequest {
    ChargeRequest {
        amount: amount.to_string(),
        currency: format!("{currency:#x}"),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({ "chainId": CHAIN_ID })),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_broadcast_rejects_challenge_expired_before_send() {
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let tx_bytes = encode_signed_tx(
        vec![challenge_bound_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let request = challenge_bound_request(currency, recipient, amount);

    // No mock responses are queued: a broadcast would fail with a different
    // error than the expiry asserted below.
    let asserter = Asserter::new();
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let method = ChargeMethod::new(provider);
    let expires = rfc3339_from_now(-time::Duration::seconds(1));

    let error = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(tx_bytes),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            Some(&expires),
        )
        .await
        .expect_err("an expired challenge must not be broadcast");

    assert_eq!(
        error.code,
        Some(crate::protocol::traits::ErrorCode::Expired),
        "unexpected error: {error}"
    );
}

/// Mock transport that answers `eth_sendRawTransactionSync` only after a
/// delay, so the challenge expires while settlement is in flight.
#[derive(Clone)]
struct SlowSendTransport {
    inner: alloy::transports::mock::MockTransport,
    delay: std::time::Duration,
}

impl tower::Service<alloy_json_rpc::RequestPacket> for SlowSendTransport {
    type Response = alloy_json_rpc::ResponsePacket;
    type Error = alloy::transports::TransportError;
    type Future = alloy::transports::TransportFut<'static>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: alloy_json_rpc::RequestPacket) -> Self::Future {
        let delay = match &request {
            alloy_json_rpc::RequestPacket::Single(request) => {
                request.method() == "eth_sendRawTransactionSync"
            }
            alloy_json_rpc::RequestPacket::Batch(_) => false,
        }
        .then_some(self.delay);
        let response = self.inner.call(request);
        Box::pin(async move {
            let response = response.await;
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }
            response
        })
    }
}

#[tokio::test]
async fn test_broadcast_returns_receipt_when_expiry_crosses_send() {
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let sender = Address::repeat_byte(0x44);
    let amount = U256::from(100u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let tx_bytes = encode_signed_tx(
        vec![challenge_bound_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let request = challenge_bound_request(currency, recipient, amount);

    let tx_hash = B256::repeat_byte(0x11);
    let block_hash = B256::repeat_byte(0x22);
    let mut log = make_transfer_with_memo_log(currency, sender, recipient, amount, memo);
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
    let asserter = Asserter::new();
    asserter.push_success(&serde_json::Value::Null);
    asserter.push_success(&serde_json::json!({
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
        "from": format!("{sender:#x}"),
        "to": format!("{currency:#x}"),
        "contractAddress": null,
        "feePayer": format!("{sender:#x}"),
        "feeToken": format!("{currency:#x}"),
    }));

    let expires_in = time::Duration::milliseconds(500);
    let transport = SlowSendTransport {
        inner: alloy::transports::mock::MockTransport::new(asserter.clone()),
        delay: std::time::Duration::from_millis(1_000),
    };
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_client(alloy::rpc::client::RpcClient::new(transport, true));
    let method = ChargeMethod::new(provider);
    let expires = rfc3339_from_now(expires_in);

    let hash = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(tx_bytes),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            Some(&expires),
        )
        .await
        .expect("expiry crossing after the send must not reject a settled payment");

    assert_eq!(hash, tx_hash);
    assert!(
        time::OffsetDateTime::now_utc()
            > time::OffsetDateTime::parse(&expires, &time::format_description::well_known::Rfc3339)
                .unwrap(),
        "the challenge must have expired during settlement"
    );
}

#[tokio::test]
async fn test_failed_broadcast_releases_submission_claim() {
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let tx_bytes = encode_signed_tx(
        vec![challenge_bound_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let request = challenge_bound_request(currency, recipient, amount);

    // Both broadcasts are refused before the transaction lands: the receipt
    // lookups before and after each refused broadcast find nothing. A refusal
    // leaves no broadcast record, so the retry checks inclusion again.
    let asserter = Asserter::new();
    for _ in 0..2 {
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_failure(node_refusal("node unavailable"));
        asserter.push_success(&serde_json::Value::Null);
    }
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let store = Arc::new(crate::store::MemoryStore::new());
    let method = ChargeMethod::new(provider).with_store(store.clone());
    let submission_key = format!("mpp:charge:submission:{:#x}", keccak256(&tx_bytes));

    for attempt in 0..2 {
        let error = method
            .broadcast_transaction(
                &alloy::hex::encode_prefixed(&tx_bytes),
                &request,
                None,
                CHAIN_ID,
                "challenge-123",
                "api.example.com",
                None,
            )
            .await
            .expect_err("broadcast fails");
        // Resending after a failed broadcast retries it, never a final replay.
        assert_eq!(
            error.code,
            Some(crate::protocol::traits::ErrorCode::NetworkError),
            "attempt {attempt}: {error}"
        );
        assert!(store.get(&submission_key).await.unwrap().is_none());
    }
    assert!(asserter.read_q().is_empty(), "both attempts broadcast");
}

// ==================== Broadcast receipt recovery ====================

#[derive(Clone, Copy, PartialEq)]
enum RecoveryLookup {
    Included,
    Reverted,
    Missing,
    WrongHash,
    LookupError,
}

/// Broadcast a challenge-bound transfer whose eth_sendRawTransactionSync call
/// fails, with the receipt lookup that follows answering per `lookup`.
async fn broadcast_with_failed_sync_reply(
    lookup: RecoveryLookup,
) -> (B256, Result<B256, VerificationError>) {
    let store = Arc::new(crate::store::MemoryStore::new());
    broadcast_with_failed_sync_reply_and_store(lookup, Some(store)).await
}

async fn broadcast_with_failed_sync_reply_and_store(
    lookup: RecoveryLookup,
    store: Option<Arc<crate::store::MemoryStore>>,
) -> (B256, Result<B256, VerificationError>) {
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let sender = Address::repeat_byte(0x44);
    let amount = U256::from(100u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let tx_bytes = encode_signed_tx(
        vec![challenge_bound_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let tx_hash = keccak256(&tx_bytes);
    let request = ChargeRequest {
        amount: amount.to_string(),
        currency: format!("{currency:#x}"),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({ "chainId": CHAIN_ID })),
        ..Default::default()
    };

    let receipt_hash = if lookup == RecoveryLookup::WrongHash {
        B256::repeat_byte(0x12)
    } else {
        tx_hash
    };
    let mut log = make_transfer_with_memo_log(currency, sender, recipient, amount, memo);
    log["blockHash"] = serde_json::json!(B256::repeat_byte(0xdd));
    log["blockNumber"] = serde_json::json!("0x1");
    log["transactionHash"] = serde_json::json!(receipt_hash);
    log["transactionIndex"] = serde_json::json!("0x0");
    log["logIndex"] = serde_json::json!("0x0");
    log["removed"] = serde_json::json!(false);

    let asserter = Asserter::new();
    // Not yet on chain when checked before the broadcast.
    asserter.push_success(&serde_json::Value::Null);
    asserter.push_failure_msg("Broadcast reply unavailable");
    match lookup {
        RecoveryLookup::Missing => asserter.push_success(&serde_json::Value::Null),
        RecoveryLookup::LookupError => asserter.push_failure_msg("Lookup unavailable"),
        _ => asserter.push_success(&serde_json::json!({
            "transactionHash": receipt_hash,
            "transactionIndex": "0x0",
            "blockHash": B256::repeat_byte(0xdd),
            "blockNumber": "0x1",
            "from": sender,
            "to": currency,
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x1",
            "contractAddress": null,
            "logs": [log],
            "logsBloom": alloy::primitives::Bloom::ZERO,
            "status": if lookup == RecoveryLookup::Reverted { "0x0" } else { "0x1" },
            "type": "0x76",
            "feePayer": sender,
        })),
    }
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);
    let mut method = ChargeMethod::new(provider).without_store();
    if let Some(store) = store {
        method = method.with_store(store);
    }

    let result = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(tx_bytes),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            None,
        )
        .await;
    (tx_hash, result)
}

/// A node can include a transaction and still fail the synchronous reply; the
/// receipt for the broadcast hash then proves the payment.
#[tokio::test]
async fn test_broadcast_recovers_included_transaction_after_rpc_error() {
    let (tx_hash, result) = broadcast_with_failed_sync_reply(RecoveryLookup::Included).await;
    assert_eq!(result.expect("included charge must be recovered"), tx_hash);
}

#[tokio::test]
async fn test_broadcast_recovery_rejects_reverted_receipt() {
    let (_, result) = broadcast_with_failed_sync_reply(RecoveryLookup::Reverted).await;
    let error = result.expect_err("reverted charge must fail");
    assert!(error.to_string().contains("reverted"), "got: {error}");
}

#[tokio::test]
async fn test_broadcast_recovery_reports_broadcast_error_without_matching_receipt() {
    for lookup in [
        RecoveryLookup::Missing,
        RecoveryLookup::WrongHash,
        RecoveryLookup::LookupError,
    ] {
        let (_, result) = broadcast_with_failed_sync_reply(lookup).await;
        let error = result.expect_err("unconfirmed charge must fail");
        assert!(
            error.to_string().contains("Broadcast reply unavailable"),
            "got: {error}"
        );
    }
}

/// Without a store nothing reserved the submission, so a receipt for the same
/// bytes may come from an earlier accepted credential: it must not be reused.
#[tokio::test]
async fn test_broadcast_without_store_does_not_recover_receipt() {
    let (_, result) =
        broadcast_with_failed_sync_reply_and_store(RecoveryLookup::Included, None).await;
    let error = result.expect_err("replayed charge must not be recovered without a store");
    assert!(
        error.to_string().contains("Broadcast reply unavailable"),
        "got: {error}"
    );
}

/// An unrecovered broadcast releases its submission reservation, so a retry of
/// the same bytes can reach recovery once the transaction lands.
#[tokio::test]
async fn test_broadcast_releases_submission_reservation_when_unrecovered() {
    use crate::store::Store;

    let store = Arc::new(crate::store::MemoryStore::new());
    let (tx_hash, result) =
        broadcast_with_failed_sync_reply_and_store(RecoveryLookup::Missing, Some(store.clone()))
            .await;
    assert!(result.is_err());
    let reservation = store
        .get(&format!("mpp:charge:submission:{tx_hash:#x}"))
        .await
        .unwrap();
    assert!(
        reservation.is_none(),
        "reservation was kept: {reservation:?}"
    );
}

/// A broadcast whose reply and recovery lookup both failed may still land.
/// Its broadcast record lets a retry of the same credential recover the
/// receipt this server's own broadcast produced, instead of rejecting it as
/// already on chain.
#[tokio::test]
async fn test_retry_recovers_transaction_that_landed_after_failed_broadcast() {
    use crate::store::Store;
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let sender = Address::repeat_byte(0x44);
    let amount = U256::from(100u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let tx_bytes = encode_signed_tx(
        vec![challenge_bound_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let tx_hash = keccak256(&tx_bytes);
    let request = challenge_bound_request(currency, recipient, amount);
    let mut log = make_transfer_with_memo_log(currency, sender, recipient, amount, memo);
    log["blockHash"] = serde_json::json!(B256::repeat_byte(0xdd));
    log["blockNumber"] = serde_json::json!("0x1");
    log["transactionHash"] = serde_json::json!(tx_hash);
    log["transactionIndex"] = serde_json::json!("0x0");
    log["logIndex"] = serde_json::json!("0x0");
    log["removed"] = serde_json::json!(false);
    let receipt = serde_json::json!({
        "transactionHash": tx_hash,
        "transactionIndex": "0x0",
        "blockHash": B256::repeat_byte(0xdd),
        "blockNumber": "0x1",
        "from": sender,
        "to": currency,
        "cumulativeGasUsed": "0x5208",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x1",
        "contractAddress": null,
        "logs": [log],
        "logsBloom": alloy::primitives::Bloom::ZERO,
        "status": "0x1",
        "type": "0x76",
        "feePayer": sender,
    });

    let asserter = Asserter::new();
    // First attempt: not on chain yet, the broadcast times out and the
    // recovery lookup finds nothing.
    asserter.push_success(&serde_json::Value::Null);
    asserter.push_failure_msg("request timed out");
    asserter.push_success(&serde_json::Value::Null);
    // Retry, after the transaction landed: the node refuses the duplicate and
    // the recovery lookup finds this server's own transaction.
    asserter.push_failure(node_refusal("already known"));
    asserter.push_success(&receipt);
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let store = Arc::new(crate::store::MemoryStore::new());
    let method = ChargeMethod::new(provider).with_store(store.clone());
    let signed_tx = alloy::hex::encode_prefixed(&tx_bytes);
    let broadcast = || {
        method.broadcast_transaction(
            &signed_tx,
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            None,
        )
    };

    let error = broadcast().await.expect_err("the first attempt fails");
    assert_eq!(
        error.code,
        Some(crate::protocol::traits::ErrorCode::NetworkError),
        "{error}"
    );
    let broadcast_key = format!("mpp:charge:broadcast-pending:{tx_hash:#x}");
    assert!(store.get(&broadcast_key).await.unwrap().is_some());

    let hash = broadcast()
        .await
        .expect("the retry recovers this server's own transaction");
    assert_eq!(hash, tx_hash);
    assert!(asserter.read_q().is_empty());
    assert!(
        store.get(&broadcast_key).await.unwrap().is_none(),
        "settled: the transaction hash claim guards it"
    );
    assert!(store
        .get(&format!("mpp:charge:{tx_hash:#x}"))
        .await
        .unwrap()
        .is_some());

    // A broadcast the node refused outright leaves no record: once the same
    // transaction is on chain (settled elsewhere), a retry here is rejected
    // as a replay instead of recovering it.
    let asserter = Asserter::new();
    asserter.push_success(&serde_json::Value::Null);
    asserter.push_failure(node_refusal("insufficient funds"));
    asserter.push_success(&serde_json::Value::Null);
    asserter.push_success(&receipt);
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let store = Arc::new(crate::store::MemoryStore::new());
    let method = ChargeMethod::new(provider).with_store(store.clone());
    for expected in [
        crate::protocol::traits::ErrorCode::NetworkError,
        crate::protocol::traits::ErrorCode::CredentialReplayed,
    ] {
        let error = method
            .broadcast_transaction(
                &signed_tx,
                &request,
                None,
                CHAIN_ID,
                "challenge-123",
                "api.example.com",
                None,
            )
            .await
            .expect_err("refused, then already on chain");
        assert_eq!(error.code, Some(expected), "{error}");
        assert!(store.get(&broadcast_key).await.unwrap().is_none());
    }
    assert!(asserter.read_q().is_empty());
}

/// A pull credential whose signed transaction is already on chain was
/// settled before this server's broadcast, by another server or an earlier
/// settlement whose replay record is gone: it is rejected before
/// broadcasting, even with no replay record here.
#[tokio::test]
async fn test_broadcast_rejects_transaction_already_on_chain() {
    use crate::store::Store;
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let sender = Address::repeat_byte(0x44);
    let amount = U256::from(100u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let tx_bytes = encode_signed_tx(
        vec![challenge_bound_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let tx_hash = keccak256(&tx_bytes);
    let request = challenge_bound_request(currency, recipient, amount);
    let mut log = make_transfer_with_memo_log(currency, sender, recipient, amount, memo);
    log["blockHash"] = serde_json::json!(B256::repeat_byte(0xdd));
    log["blockNumber"] = serde_json::json!("0x1");
    log["transactionHash"] = serde_json::json!(tx_hash);
    log["transactionIndex"] = serde_json::json!("0x0");
    log["logIndex"] = serde_json::json!("0x0");
    log["removed"] = serde_json::json!(false);

    for with_store in [true, false] {
        // Only the pre-broadcast receipt lookup is answered: a broadcast
        // would find no response and fail with another error.
        let asserter = Asserter::new();
        asserter.push_success(&serde_json::json!({
            "transactionHash": tx_hash,
            "transactionIndex": "0x0",
            "blockHash": B256::repeat_byte(0xdd),
            "blockNumber": "0x1",
            "from": sender,
            "to": currency,
            "cumulativeGasUsed": "0x5208",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x1",
            "contractAddress": null,
            "logs": [log.clone()],
            "logsBloom": alloy::primitives::Bloom::ZERO,
            "status": "0x1",
            "type": "0x76",
            "feePayer": sender,
        }));
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_mocked_client(asserter.clone());
        let store = Arc::new(crate::store::MemoryStore::new());
        let mut method = ChargeMethod::new(provider).without_store();
        if with_store {
            method = method.with_store(store.clone());
        }

        let error = method
            .broadcast_transaction(
                &alloy::hex::encode_prefixed(&tx_bytes),
                &request,
                None,
                CHAIN_ID,
                "challenge-123",
                "api.example.com",
                None,
            )
            .await
            .expect_err("a transaction already on chain must be rejected");
        // Answered as a replay (invalid-challenge), which clients treat as
        // final rather than paying a fresh Challenge.
        assert_eq!(
            error.code,
            Some(crate::protocol::traits::ErrorCode::CredentialReplayed),
            "store {with_store}: {error}"
        );
        assert!(!error.retryable, "store {with_store}: {error}");
        assert!(
            matches!(
                crate::error::MppError::from(error.clone()),
                crate::error::MppError::CredentialReplayed(_)
            ),
            "store {with_store}: {error}"
        );
        assert!(asserter.read_q().is_empty(), "store {with_store}");
        assert!(
            store
                .get(&format!("mpp:charge:{tx_hash:#x}"))
                .await
                .unwrap()
                .is_none(),
            "store {with_store}: a rejected transaction is not recorded"
        );
        assert!(
            store
                .get(&format!("mpp:charge:submission:{tx_hash:#x}"))
                .await
                .unwrap()
                .is_none(),
            "store {with_store}: the submission claim is released"
        );
    }
}

/// The pre-broadcast lookup fails closed: without it the transaction is not
/// broadcast, and resending the credential retries.
#[tokio::test]
async fn test_broadcast_fails_closed_when_pre_broadcast_lookup_fails() {
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let tx_bytes = encode_signed_tx(
        vec![challenge_bound_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let request = challenge_bound_request(currency, recipient, amount);
    let asserter = Asserter::new();
    asserter.push_failure_msg("Lookup unavailable");
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let method = ChargeMethod::new(provider).with_store(Arc::new(crate::store::MemoryStore::new()));

    let error = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(&tx_bytes),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            None,
        )
        .await
        .expect_err("an unchecked transaction must not be broadcast");
    assert_eq!(
        error.code,
        Some(crate::protocol::traits::ErrorCode::NetworkError),
        "{error}"
    );
    assert!(!error.to_string().contains("Lookup unavailable"), "{error}");
    assert!(asserter.read_q().is_empty(), "nothing was broadcast");
}

/// A first broadcast that fails because someone else already submitted the
/// transaction (here: "already known") must not settle an unbound plain
/// transfer from its receipt: anyone who saw it pending could otherwise
/// claim it. Once it lands, a retry is rejected as already on chain.
#[tokio::test]
async fn test_first_attempt_does_not_recover_unbound_transfer_submitted_elsewhere() {
    use crate::store::Store;
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let sender = Address::repeat_byte(0x44);
    let amount = U256::from(100u64);
    let tx_bytes = encode_signed_tx(
        vec![tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(currency),
            value: U256::ZERO,
            input: make_transfer_input(recipient, amount),
        }],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let tx_hash = keccak256(&tx_bytes);
    let request = challenge_bound_request(currency, recipient, amount);
    let mut log = make_transfer_log(currency, sender, recipient, amount);
    log["blockHash"] = serde_json::json!(B256::repeat_byte(0xdd));
    log["blockNumber"] = serde_json::json!("0x1");
    log["transactionHash"] = serde_json::json!(tx_hash);
    log["transactionIndex"] = serde_json::json!("0x0");
    log["logIndex"] = serde_json::json!("0x0");
    log["removed"] = serde_json::json!(false);
    let receipt = serde_json::json!({
        "transactionHash": tx_hash,
        "transactionIndex": "0x0",
        "blockHash": B256::repeat_byte(0xdd),
        "blockNumber": "0x1",
        "from": sender,
        "to": currency,
        "cumulativeGasUsed": "0x5208",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x1",
        "contractAddress": null,
        "logs": [log],
        "logsBloom": alloy::primitives::Bloom::ZERO,
        "status": "0x1",
        "type": "0x76",
        "feePayer": sender,
    });

    let asserter = Asserter::new();
    asserter.push_success(&serde_json::Value::Null);
    asserter.push_failure(node_refusal("already known"));
    asserter.push_success(&receipt);
    asserter.push_success(&receipt);
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let store = Arc::new(crate::store::MemoryStore::new());
    let method = ChargeMethod::new(provider).with_store(store.clone());
    let signed_tx = alloy::hex::encode_prefixed(&tx_bytes);
    for expected in [
        crate::protocol::traits::ErrorCode::NetworkError,
        crate::protocol::traits::ErrorCode::CredentialReplayed,
    ] {
        let error = method
            .broadcast_transaction(
                &signed_tx,
                &request,
                None,
                CHAIN_ID,
                "challenge-123",
                "api.example.com",
                None,
            )
            .await
            .expect_err("an unbound transfer submitted elsewhere is not settled");
        assert_eq!(error.code, Some(expected), "{error}");
    }
    assert!(asserter.read_q().is_empty());
    assert!(store
        .get(&format!("mpp:charge:{tx_hash:#x}"))
        .await
        .unwrap()
        .is_none());
}

/// A JSON-RPC error with which the node definitely refuses a transaction,
/// unlike `push_failure_msg`'s internal error (-32603), whose outcome is
/// unknown.
fn node_refusal(message: &'static str) -> alloy_json_rpc::ErrorPayload {
    alloy_json_rpc::ErrorPayload {
        code: -32000,
        message: message.into(),
        data: None,
    }
}
