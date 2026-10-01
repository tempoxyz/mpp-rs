use super::*;

#[tokio::test]
async fn test_verify_hash_rejects_single_transfer_with_memo_for_two_transfers() {
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let payer = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(1000u64);
    let request = ChargeRequest {
        amount: "2000".to_string(),
        currency: format!("{currency:#x}"),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({
            "chainId": MODERATO_CHAIN_ID,
            "splits": [{ "amount": "1000", "recipient": format!("{recipient:#x}") }],
        })),
        ..Default::default()
    };
    let challenge = test_proof_challenge(&request);
    let memo = attribution::encode(&challenge.id, &challenge.realm, None);
    let tx_hash = B256::repeat_byte(0x11);
    let block_hash = B256::repeat_byte(0x22);
    let credential = PaymentCredential::new(
        challenge.to_echo(),
        crate::protocol::core::PaymentPayload::hash(format!("{tx_hash:#x}")),
    );

    // Receipt of a transaction with `calls` transferWithMemo calls.
    let verify = |calls: usize| {
        let logs: Vec<_> = (0..calls)
            .flat_map(|_| {
                [
                    make_transfer_log(currency, payer, recipient, amount),
                    make_transfer_with_memo_log(currency, payer, recipient, amount, memo),
                ]
            })
            .enumerate()
            .map(|(index, mut log)| {
                log.as_object_mut().unwrap().extend(
                    serde_json::json!({
                        "blockHash": format!("{block_hash:#x}"),
                        "blockNumber": "0x1",
                        "transactionHash": format!("{tx_hash:#x}"),
                        "transactionIndex": "0x0",
                        "logIndex": format!("{index:#x}"),
                        "removed": false,
                    })
                    .as_object()
                    .unwrap()
                    .clone(),
                );
                log
            })
            .collect();
        let asserter = Asserter::new();
        asserter.push_success(&serde_json::json!({
            "type": "0x76",
            "status": "0x1",
            "cumulativeGasUsed": "0x5208",
            "logs": logs,
            "logsBloom": format!("0x{}", "00".repeat(256)),
            "transactionHash": format!("{tx_hash:#x}"),
            "transactionIndex": "0x0",
            "blockHash": format!("{block_hash:#x}"),
            "blockNumber": "0x1",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x1",
            "from": format!("{payer:#x}"),
            "to": format!("{currency:#x}"),
            "contractAddress": null,
            "feePayer": format!("{payer:#x}"),
            "feeToken": format!("{currency:#x}"),
        }));
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_mocked_client(asserter);
        let method = ChargeMethod::new(provider);
        method.cached_chain_id.set(MODERATO_CHAIN_ID).unwrap();
        let (credential, request) = (credential.clone(), request.clone());
        async move { method.verify(&credential, &request).await }
    };

    let error = verify(1).await.unwrap_err();
    assert!(
        error.to_string().contains("No matching transfer event"),
        "unexpected error: {error}"
    );
    assert!(verify(2).await.is_ok());
}

/// The receipt reference is the canonical transaction hash, however the
/// credential spelled it.
#[tokio::test]
async fn test_verify_hash_returns_canonical_reference() {
    use alloy::providers::mock::Asserter;

    let currency = Address::repeat_byte(0x20);
    let payer = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(1000u64);
    let request = ChargeRequest {
        amount: "1000".to_string(),
        currency: format!("{currency:#x}"),
        recipient: Some(format!("{recipient:#x}")),
        method_details: Some(serde_json::json!({ "chainId": MODERATO_CHAIN_ID })),
        ..Default::default()
    };
    let challenge = test_proof_challenge(&request);
    let memo = attribution::encode(&challenge.id, &challenge.realm, None);
    let tx_hash = B256::repeat_byte(0xab);
    let block_hash = B256::repeat_byte(0x22);

    let mut log = make_transfer_with_memo_log(currency, payer, recipient, amount, memo);
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
        "from": format!("{payer:#x}"),
        "to": format!("{currency:#x}"),
        "contractAddress": null,
        "feePayer": format!("{payer:#x}"),
        "feeToken": format!("{currency:#x}"),
    }));
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);
    let method = ChargeMethod::new(provider);
    method.cached_chain_id.set(MODERATO_CHAIN_ID).unwrap();

    // Upper case and without the `0x` prefix.
    let credential = PaymentCredential::new(
        challenge.to_echo(),
        crate::protocol::core::PaymentPayload::hash(format!("{tx_hash:X}")),
    );
    let receipt = method.verify(&credential, &request).await.unwrap();
    assert_eq!(receipt.reference, format!("{tx_hash:#x}"));
}

// ==================== Hash credential source validation ====================

const HASH_SOURCE_INVALID: &str = "Hash credential source is invalid.";

#[test]
fn test_parse_hash_credential_source_absent_is_none() {
    assert_eq!(
        parse_hash_credential_source(None, MODERATO_CHAIN_ID).unwrap(),
        None
    );
}

#[test]
fn test_parse_hash_credential_source_valid_returns_address() {
    let address = Address::repeat_byte(0x11);
    let source = did_pkh(MODERATO_CHAIN_ID, address);
    let parsed = parse_hash_credential_source(Some(&source), MODERATO_CHAIN_ID).unwrap();
    assert_eq!(parsed, Some(address));
}

#[test]
fn test_parse_hash_credential_source_chain_id_mismatch_is_rejected() {
    let source = did_pkh(1, Address::repeat_byte(0x11));
    let err = parse_hash_credential_source(Some(&source), MODERATO_CHAIN_ID).unwrap_err();
    assert_eq!(err.to_string(), HASH_SOURCE_INVALID);
}

#[test]
fn test_parse_hash_credential_source_rejects_malformed_variants() {
    let address = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2";
    let cases = [
        "not-a-valid-did",
        "did:pkh:solana:42431:0xa5cc3c03994db5b0d9ba5e4f6d2efbd9f213b141",
        &format!("did:pkh:eip155:042431:{address}"),
        &format!("did:pkh:eip155:not-a-number:{address}"),
        &format!("did:pkh:eip155:42431:extra:{address}"),
        "did:pkh:eip155:42431:not-an-address",
    ];
    for case in cases {
        let err = parse_hash_credential_source(Some(case), MODERATO_CHAIN_ID).unwrap_err();
        assert_eq!(err.to_string(), HASH_SOURCE_INVALID, "case: {case}");
    }
}

#[tokio::test]
async fn test_store_rejects_replayed_hash() {
    use crate::store::{MemoryStore, Store};

    let store = Arc::new(MemoryStore::new());
    let hash = "0xabc123def456";

    // Simulate first successful verification: record the hash
    let key = format!("mpp:charge:{hash}");
    store
        .put(&key, serde_json::Value::Bool(true))
        .await
        .unwrap();

    // Verify the hash is now in the store
    let seen = store.get(&key).await.unwrap();
    assert!(seen.is_some(), "hash should be recorded after first use");

    // A second lookup should find it (replay detected)
    let seen_again = store.get(&key).await.unwrap();
    assert!(
        seen_again.is_some(),
        "replayed hash should be detected via store"
    );
}

#[tokio::test]
async fn test_store_allows_unseen_hash() {
    use crate::store::{MemoryStore, Store};

    let store = Arc::new(MemoryStore::new());

    // A hash that was never recorded should not be found
    let key = "mpp:charge:0xnever_seen";
    let seen = store.get(key).await.unwrap();
    assert!(seen.is_none(), "unseen hash should not be in store");
}

#[tokio::test]
async fn test_store_dedup_case_insensitive() {
    use crate::store::{MemoryStore, Store};

    let store = Arc::new(MemoryStore::new());

    // Simulate the canonical key construction used by verify_hash:
    // parse to B256, then format with {:#x} for canonical lowercase 0x-prefixed output.
    let mixed_case = "0xABCdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let hash = mixed_case.parse::<B256>().unwrap();
    let key1 = format!("mpp:charge:{:#x}", hash);
    store
        .put(&key1, serde_json::Value::Bool(true))
        .await
        .unwrap();

    // Same hash submitted with different casing produces same canonical key
    let lower_case = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let hash2 = lower_case.parse::<B256>().unwrap();
    let key2 = format!("mpp:charge:{:#x}", hash2);
    let seen = store.get(&key2).await.unwrap();
    assert!(
        seen.is_some(),
        "same hash with different case should be detected as replay"
    );

    // Without 0x prefix should also parse to the same canonical key
    let no_prefix = "ABCdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let hash3 = no_prefix.parse::<B256>().unwrap();
    let key3 = format!("mpp:charge:{:#x}", hash3);
    assert_eq!(
        key1, key3,
        "0x-prefixed and unprefixed should produce same key"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_replay_rejected_via_put_if_absent() {
    use crate::store::{MemoryStore, Store};
    use std::sync::Arc;

    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let hash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let key = format!("mpp:charge:{}", hash.parse::<B256>().unwrap());

    let start = Arc::new(tokio::sync::Barrier::new(8));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        let key = key.clone();
        let start = start.clone();
        handles.push(tokio::spawn(async move {
            start.wait().await;
            store
                .put_if_absent(&key, serde_json::Value::Bool(true))
                .await
                .unwrap()
        }));
    }
    let mut claims = 0;
    for h in handles {
        if h.await.unwrap() {
            claims += 1;
        }
    }
    assert_eq!(
        claims, 1,
        "exactly one concurrent verifier may claim the tx hash"
    );
}

#[tokio::test]
async fn test_store_dedup_different_hashes_independent() {
    use crate::store::{MemoryStore, Store};

    let store = Arc::new(MemoryStore::new());

    // Record one hash
    store
        .put("mpp:charge:0xhash_a", serde_json::Value::Bool(true))
        .await
        .unwrap();

    // Different hash should not be affected
    let seen = store.get("mpp:charge:0xhash_b").await.unwrap();
    assert!(seen.is_none(), "different hash should not be blocked");

    // Original hash should still be blocked
    let seen = store.get("mpp:charge:0xhash_a").await.unwrap();
    assert!(seen.is_some(), "original hash should still be recorded");
}
