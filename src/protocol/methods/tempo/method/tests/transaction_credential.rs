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
        asserter.push_failure(node_refusal("insufficient funds for gas * price + value"));
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
        crate::protocol::traits::ErrorCode::CredentialReplayed,
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

/// A first broadcast whose outcome is unknown (a timeout) keeps its
/// broadcast record: the transaction is this server's own, so its receipt
/// settles the same request instead of asking the client to resend.
#[tokio::test]
async fn test_first_attempt_settles_own_broadcast_after_timeout() {
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
    asserter.push_failure(alloy_json_rpc::ErrorPayload {
        code: 4,
        message: "timeout".into(),
        data: None,
    });
    asserter.push_success(&receipt);
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let store = Arc::new(crate::store::MemoryStore::new());
    let method = ChargeMethod::new(provider).with_store(store.clone());
    let signed_tx = alloy::hex::encode_prefixed(&tx_bytes);
    method
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
        .expect("the server's own broadcast settles after a timeout");
    assert!(asserter.read_q().is_empty());
    assert!(store
        .get(&format!("mpp:charge:{tx_hash:#x}"))
        .await
        .unwrap()
        .is_some());
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

/// A broadcast record names the challenge it was sent for: a credential for
/// another challenge presenting the same unbound bytes cannot settle from
/// it, while the original challenge's retry still does.
#[tokio::test]
async fn test_broadcast_record_settles_only_its_own_challenge() {
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
    // Challenge A: the send times out and nothing is found yet.
    asserter.push_success(&serde_json::Value::Null);
    asserter.push_failure_msg("request timed out");
    asserter.push_success(&serde_json::Value::Null);
    // Challenge B, after the transaction landed: A's record does not count,
    // so the pre-broadcast lookup rejects it.
    asserter.push_success(&receipt);
    // Challenge A's retry recovers its own transaction.
    asserter.push_failure(node_refusal("already known"));
    asserter.push_success(&receipt);
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let store = Arc::new(crate::store::MemoryStore::new());
    let method = ChargeMethod::new(provider).with_store(store);
    let signed_tx = alloy::hex::encode_prefixed(&tx_bytes);
    let broadcast = |challenge_id: &'static str| {
        method.broadcast_transaction(
            &signed_tx,
            &request,
            None,
            CHAIN_ID,
            challenge_id,
            "api.example.com",
            None,
        )
    };

    let error = broadcast("challenge-a").await.expect_err("outcome unknown");
    assert_eq!(
        error.code,
        Some(crate::protocol::traits::ErrorCode::NetworkError),
        "{error}"
    );
    let error = broadcast("challenge-b")
        .await
        .expect_err("another challenge cannot settle from A's record");
    assert_eq!(
        error.code,
        Some(crate::protocol::traits::ErrorCode::CredentialReplayed),
        "{error}"
    );
    assert_eq!(
        broadcast("challenge-a")
            .await
            .expect("A's retry recovers its own transaction"),
        tx_hash
    );
    assert!(asserter.read_q().is_empty());
}

fn plain_transfer_receipt(
    currency: Address,
    sender: Address,
    recipient: Address,
    amount: U256,
    tx_hash: B256,
) -> serde_json::Value {
    let mut log = make_transfer_log(currency, sender, recipient, amount);
    log["blockHash"] = serde_json::json!(B256::repeat_byte(0xdd));
    log["blockNumber"] = serde_json::json!("0x1");
    log["transactionHash"] = serde_json::json!(tx_hash);
    log["transactionIndex"] = serde_json::json!("0x0");
    log["logIndex"] = serde_json::json!("0x0");
    log["removed"] = serde_json::json!(false);
    serde_json::json!({
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
    })
}

fn plain_transfer_call(
    currency: Address,
    recipient: Address,
    amount: U256,
) -> tempo_alloy::primitives::transaction::Call {
    tempo_alloy::primitives::transaction::Call {
        to: TxKind::Call(currency),
        value: U256::ZERO,
        input: make_transfer_input(recipient, amount),
    }
}

/// The receipt matcher takes a memo transfer before a plain one, so the
/// pre-broadcast call matcher does too: a plain transfer followed by an
/// equal transfer carrying another challenge's attribution is rejected
/// before broadcast, instead of moving funds and then failing.
#[tokio::test]
async fn test_broadcast_matches_calls_as_receipt_logs_before_rpc() {
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let foreign = attribution::encode("challenge-456", "api.example.com", None);
    let tx_bytes = encode_signed_tx(
        vec![
            plain_transfer_call(currency, recipient, amount),
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_with_memo_input(recipient, amount, foreign),
            },
        ],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let request = challenge_bound_request(currency, recipient, amount);

    // No mock responses: reaching the provider fails with another error.
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
        .expect_err("the memo transfer is matched and its attribution rejected");
    assert!(
        error
            .to_string()
            .contains("memo is not bound to this challenge"),
        "unexpected error: {error}"
    );
}

/// Proof reservations that fill a capped MemoryStore do not block the
/// broadcast record of a pull payment.
#[tokio::test]
async fn test_full_expiring_capacity_does_not_block_pull_broadcast() {
    use crate::store::Store;
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let sender = Address::repeat_byte(0x44);
    let amount = U256::from(100u64);
    let tx_bytes = encode_signed_tx(
        vec![plain_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let tx_hash = keccak256(&tx_bytes);
    let request = challenge_bound_request(currency, recipient, amount);

    let asserter = Asserter::new();
    asserter.push_success(&serde_json::Value::Null);
    asserter.push_success(&plain_transfer_receipt(
        currency, sender, recipient, amount, tx_hash,
    ));
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let store = Arc::new(crate::store::MemoryStore::with_expiring_capacity(1));
    assert!(store
        .put_if_absent_with_ttl(
            "mpp:proof:reservation",
            serde_json::json!(true),
            std::time::Duration::from_secs(60),
        )
        .await
        .unwrap());
    let method = ChargeMethod::new(provider).with_store(store.clone());

    let hash = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(&tx_bytes),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            Some(&rfc3339_from_now(time::Duration::minutes(5))),
        )
        .await
        .expect("a full proof cap does not block the pull");
    assert_eq!(hash, tx_hash);
    assert!(asserter.read_q().is_empty());
    assert!(
        store
            .put_if_absent_with_ttl(
                "mpp:proof:another",
                serde_json::json!(true),
                std::time::Duration::from_secs(60),
            )
            .await
            .is_err(),
        "proof reservations stay capped"
    );
}

/// A challenge that expires during the pre-broadcast lookups and writes is
/// not broadcast, and the broadcast record that attempt wrote is removed,
/// so a later credential for the same bytes still gets the inclusion check.
#[tokio::test]
async fn test_broadcast_rechecks_expiry_right_before_send() {
    use crate::store::Store;
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let tx_bytes = encode_signed_tx(
        vec![plain_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let tx_hash = keccak256(&tx_bytes);
    let request = challenge_bound_request(currency, recipient, amount);

    // Only the pre-broadcast lookup is answered: a send would fail with a
    // network error instead of the expiry asserted below.
    let asserter = Asserter::new();
    asserter.push_success(&serde_json::Value::Null);
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let store = Arc::new(TestStore {
        reservation_delay: std::time::Duration::from_millis(1_500),
        ..TestStore::default()
    });
    let method = ChargeMethod::new(provider).with_store(store.clone());
    let expires = rfc3339_from_now(time::Duration::milliseconds(1_000));

    let error = method
        .broadcast_transaction(
            &alloy::hex::encode_prefixed(&tx_bytes),
            &request,
            None,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
            Some(&expires),
        )
        .await
        .expect_err("expired before the send");
    assert_eq!(
        error.code,
        Some(crate::protocol::traits::ErrorCode::Expired),
        "{error}"
    );
    assert!(asserter.read_q().is_empty());
    for key in [
        format!("mpp:charge:broadcast-pending:{tx_hash:#x}"),
        format!("mpp:charge:submission:{tx_hash:#x}"),
    ] {
        assert!(store.get(&key).await.unwrap().is_none(), "{key}");
    }
}

/// A broadcast record lives until the challenge expires, since a retry
/// after that is refused, and never longer than an hour without one, so a
/// far-future `valid_before` neither fails the write nor pins the record.
#[test]
fn test_broadcast_record_ttl_is_bounded() {
    use alloy::eips::Encodable2718;
    use alloy::signers::SignerSync;
    use std::time::Duration;

    let signed_with_valid_before = |valid_before: u64| {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let mut tx = make_fee_payer_tx(0);
        tx.fee_payer_signature = None;
        tx.valid_before = NonZeroU64::new(valid_before);
        let signature: tempo_alloy::primitives::transaction::TempoSignature =
            signer.sign_hash_sync(&tx.signature_hash()).unwrap().into();
        tx.into_signed(signature).encoded_2718()
    };
    let ttl = super::super::transaction_credential::broadcast_record_ttl;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let far = signed_with_valid_before(u64::MAX);

    assert_eq!(ttl(None, &far).unwrap(), Duration::from_secs(3_660));
    assert_eq!(ttl(None, &[]).unwrap(), Duration::from_secs(3_660));
    let soon = ttl(None, &signed_with_valid_before(now + 30)).unwrap();
    assert!(
        (Duration::from_secs(85)..=Duration::from_secs(90)).contains(&soon),
        "{soon:?}"
    );
    let expires = rfc3339_from_now(time::Duration::seconds(120));
    let bounded = ttl(Some(&expires), &far).unwrap();
    assert!(
        (Duration::from_secs(175)..=Duration::from_secs(181)).contains(&bounded),
        "{bounded:?}"
    );
}

/// Only errors that name a validation failure prove the node never admitted
/// the transaction; anything else leaves the outcome open.
#[test]
fn test_broadcast_refused_only_for_definite_validation_errors() {
    let refused = |code: i64, message: &'static str| {
        super::super::transaction_credential::broadcast_refused(
            &alloy::transports::TransportError::ErrorResp(alloy_json_rpc::ErrorPayload {
                code,
                message: message.into(),
                data: None,
            }),
        )
    };
    for message in [
        "already known",
        "insufficient funds for gas * price + value",
        "invalid signature",
        "intrinsic gas too low",
        "transaction underpriced",
        "max fee per gas less than block base fee",
        "valid_before has passed",
    ] {
        assert!(refused(-32000, message), "{message}");
    }
    assert!(refused(-32602, "invalid params"));
    for (code, message) in [
        (-32000, "nonce too low"),
        (-32000, "nonce already used"),
        (-32000, "node unavailable"),
        (-32000, "upstream request failed"),
        (-32000, "request timed out"),
        (4, "transaction was not included in time"),
        (-32603, "insufficient funds"),
    ] {
        assert!(!refused(code, message), "{code} {message}");
    }
    assert!(!super::super::transaction_credential::broadcast_refused(
        &alloy::transports::TransportErrorKind::custom_str("connection reset")
    ));
}

/// Store whose deletes of broadcast records fail.
struct UndeletableBroadcastRecords(crate::store::MemoryStore);

impl crate::store::Store for UndeletableBroadcastRecords {
    fn get(
        &self,
        key: &str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Option<serde_json::Value>, crate::store::StoreError>,
                > + Send
                + '_,
        >,
    > {
        self.0.get(key)
    }

    fn put(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), crate::store::StoreError>> + Send + '_>,
    > {
        self.0.put(key, value)
    }

    fn delete(
        &self,
        key: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), crate::store::StoreError>> + Send + '_>,
    > {
        if key.starts_with(crate::store::TEMPO_BROADCAST_PENDING_PREFIX) {
            return Box::pin(async {
                Err(crate::store::StoreError::Internal("unavailable".into()))
            });
        }
        self.0.delete(key)
    }

    fn put_if_absent(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<bool, crate::store::StoreError>> + Send + '_>,
    > {
        self.0.put_if_absent(key, value)
    }

    fn put_if_absent_with_ttl(
        &self,
        key: &str,
        value: serde_json::Value,
        ttl: std::time::Duration,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<bool, crate::store::StoreError>> + Send + '_>,
    > {
        self.0.put_if_absent_with_ttl(key, value, ttl)
    }
}

/// A refused broadcast whose record cannot be removed fails without
/// recovering a receipt: the surviving record would otherwise exempt this
/// attempt's settlement, and a retry, from the inclusion check.
#[tokio::test]
async fn test_refused_broadcast_fails_when_its_record_cannot_be_removed() {
    use crate::store::Store;
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let tx_bytes = encode_signed_tx(
        vec![challenge_bound_transfer_call(currency, recipient, amount)],
        MAX_FEE_PAYER_GAS_LIMIT,
    );
    let tx_hash = keccak256(&tx_bytes);
    let request = challenge_bound_request(currency, recipient, amount);

    // Not on chain before the send, then refused. No receipt lookup follows.
    let asserter = Asserter::new();
    asserter.push_success(&serde_json::Value::Null);
    asserter.push_failure(node_refusal("insufficient funds"));
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let store = Arc::new(UndeletableBroadcastRecords(crate::store::MemoryStore::new()));
    let method = ChargeMethod::new(provider).with_store(store.clone());

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
        .expect_err("a refused broadcast with a surviving record must fail");
    assert_eq!(
        error.code,
        Some(crate::protocol::traits::ErrorCode::Internal),
        "{error}"
    );
    assert!(asserter.read_q().is_empty(), "no receipt was looked up");
    assert!(store
        .get(&format!("mpp:charge:submission:{tx_hash:#x}"))
        .await
        .unwrap()
        .is_none());
}

/// A broadcast that fails with an error the node does not explain, such as
/// a nonce error the transaction itself may have caused, keeps its record:
/// once the transaction lands, a retry settles it instead of rejecting it
/// as already on chain.
#[tokio::test]
async fn test_unexplained_broadcast_error_keeps_record_for_retry() {
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

    for message in ["nonce too low", "upstream request failed"] {
        let asserter = Asserter::new();
        // First attempt: not on chain yet, the node answers with an error that
        // does not say it refused the transaction, and nothing is found.
        asserter.push_success(&serde_json::Value::Null);
        asserter.push_failure(node_refusal(message));
        asserter.push_success(&serde_json::Value::Null);
        // Retry, after the transaction landed: no inclusion check, the
        // duplicate is refused and the receipt recovered.
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
            "{message}: {error}"
        );
        let broadcast_key = format!("mpp:charge:broadcast-pending:{tx_hash:#x}");
        assert!(
            store.get(&broadcast_key).await.unwrap().is_some(),
            "{message}"
        );

        let hash = broadcast()
            .await
            .expect("the retry settles this server's own transaction");
        assert_eq!(hash, tx_hash, "{message}");
        assert!(asserter.read_q().is_empty(), "{message}");
    }
}
