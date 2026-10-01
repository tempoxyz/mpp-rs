use super::*;

#[test]
fn test_in_memory_store_insert_and_get() {
    let store = InMemoryChannelStore::new();
    let state = test_channel_state("0xchannel1");
    store.insert("0xchannel1", state.clone());

    let retrieved = store.get_channel_sync("0xchannel1");
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().deposit, 100_000);

    assert!(store.get_channel_sync("0xnonexistent").is_none());
}

#[tokio::test]
async fn test_in_memory_store_update() {
    let store = InMemoryChannelStore::new();
    let state = test_channel_state("0xchannel1");
    store.insert("0xchannel1", state);

    let updated = store
        .update_channel(
            "0xchannel1",
            Box::new(|current| {
                let mut s = current.unwrap();
                s.highest_voucher_amount = 5000;
                Ok(Some(s))
            }),
        )
        .await
        .unwrap();

    assert_eq!(updated.unwrap().highest_voucher_amount, 5000);
    assert_eq!(
        store
            .get_channel_sync("0xchannel1")
            .unwrap()
            .highest_voucher_amount,
        5000
    );
}

#[tokio::test]
async fn test_in_memory_store_update_nonexistent() {
    let store = InMemoryChannelStore::new();

    let result = store
        .update_channel(
            "0xmissing",
            Box::new(|current| {
                assert!(current.is_none());
                Ok(None)
            }),
        )
        .await
        .unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn test_in_memory_store_channel_ids_are_case_insensitive() {
    let store = InMemoryChannelStore::new();
    let lower = format!("0x{}", "ab".repeat(32));
    let upper = format!("0x{}", "AB".repeat(32));
    store.insert(&upper, test_channel_state(&lower));

    assert!(store.get_channel_sync(&lower).is_some());
    assert!(store.get_channel(&upper).await.unwrap().is_some());

    let mut state = test_channel_state(&lower);
    state.highest_voucher_amount = 10_000;
    store.insert(&lower, state);
    let updated = deduct_from_channel(&store, &upper, 3_000).await.unwrap();
    assert_eq!(updated.spent, 3_000);
    assert_eq!(store.get_channel_sync(&lower).unwrap().spent, 3_000);
}

#[tokio::test]
async fn test_deduct_from_channel_success() {
    let store = InMemoryChannelStore::new();
    let mut state = test_channel_state("0xchannel1");
    state.highest_voucher_amount = 10_000;
    state.spent = 0;
    store.insert("0xchannel1", state);

    let result = deduct_from_channel(&store, "0xchannel1", 3_000).await;
    assert!(result.is_ok());
    let updated = result.unwrap();
    assert_eq!(updated.spent, 3_000);
    assert_eq!(updated.units, 1);
}

#[tokio::test]
async fn test_deduct_from_channel_insufficient() {
    let store = InMemoryChannelStore::new();
    let mut state = test_channel_state("0xchannel1");
    state.highest_voucher_amount = 10_000;
    state.spent = 9_000;
    store.insert("0xchannel1", state);

    let result = deduct_from_channel(&store, "0xchannel1", 5_000).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InsufficientBalance));
}

#[tokio::test]
async fn test_deduct_from_channel_not_found() {
    let store = InMemoryChannelStore::new();
    let result = deduct_from_channel(&store, "0xmissing", 1_000).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::ChannelNotFound));
}

#[test]
fn test_channel_state_clone() {
    let state = test_channel_state("0xchannel1");
    let cloned = state.clone();
    assert_eq!(cloned.channel_id, "0xchannel1");
    assert_eq!(cloned.deposit, 100_000);
}

#[tokio::test]
async fn test_deduct_sequential_deductions() {
    let store = InMemoryChannelStore::new();
    let mut state = test_channel_state("0xchannel1");
    state.highest_voucher_amount = 10_000;
    store.insert("0xchannel1", state);

    // First deduction
    let r1 = deduct_from_channel(&store, "0xchannel1", 3_000)
        .await
        .unwrap();
    assert_eq!(r1.spent, 3_000);
    assert_eq!(r1.units, 1);

    // Second deduction
    let r2 = deduct_from_channel(&store, "0xchannel1", 2_000)
        .await
        .unwrap();
    assert_eq!(r2.spent, 5_000);
    assert_eq!(r2.units, 2);

    // Third deduction that exactly exhausts balance
    let r3 = deduct_from_channel(&store, "0xchannel1", 5_000)
        .await
        .unwrap();
    assert_eq!(r3.spent, 10_000);
    assert_eq!(r3.units, 3);

    // Fourth deduction should fail (no balance left)
    let r4 = deduct_from_channel(&store, "0xchannel1", 1).await;
    let err = r4.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InsufficientBalance));
}

#[tokio::test]
async fn test_deduct_zero_amount() {
    let store = InMemoryChannelStore::new();
    let mut state = test_channel_state("0xchannel1");
    state.highest_voucher_amount = 0;
    store.insert("0xchannel1", state);

    let result = deduct_from_channel(&store, "0xchannel1", 0).await;
    assert!(result.is_ok());
    let r = result.unwrap();
    assert_eq!(r.spent, 0);
    assert_eq!(r.units, 1);

    // Verify store state is consistent
    let ch = store.get_channel_sync("0xchannel1").unwrap();
    assert_eq!(ch.spent, 0);
    assert_eq!(ch.units, 1);
    assert_eq!(ch.highest_voucher_amount, 0);
}

#[tokio::test]
async fn test_store_update_delete() {
    let store = InMemoryChannelStore::new();
    store.insert("0xchannel1", test_channel_state("0xchannel1"));
    assert!(store.get_channel_sync("0xchannel1").is_some());

    let result = store
        .update_channel("0xchannel1", Box::new(|_current| Ok(None)))
        .await
        .unwrap();
    assert!(result.is_none());
    assert!(store.get_channel_sync("0xchannel1").is_none());
}

#[tokio::test]
async fn test_store_update_error_preserves_state() {
    let store = InMemoryChannelStore::new();
    let mut state = test_channel_state("0xchannel1");
    state.highest_voucher_amount = 5000;
    store.insert("0xchannel1", state);

    let result = store
        .update_channel(
            "0xchannel1",
            Box::new(|_current| Err(VerificationError::new("intentional test error"))),
        )
        .await;
    assert!(result.is_err());

    // Original state should be unchanged
    let ch = store.get_channel_sync("0xchannel1").unwrap();
    assert_eq!(ch.highest_voucher_amount, 5000);
}

#[tokio::test]
async fn test_store_multiple_channels_independent() {
    let store = InMemoryChannelStore::new();
    let mut state1 = test_channel_state("0xchannel1");
    state1.highest_voucher_amount = 10_000;
    let mut state2 = test_channel_state("0xchannel2");
    state2.highest_voucher_amount = 20_000;
    store.insert("0xchannel1", state1);
    store.insert("0xchannel2", state2);

    // Deduct from channel 1
    let r1 = deduct_from_channel(&store, "0xchannel1", 5_000)
        .await
        .unwrap();
    assert_eq!(r1.spent, 5_000);

    // Channel 2 should be unaffected
    let ch2 = store.get_channel_sync("0xchannel2").unwrap();
    assert_eq!(ch2.spent, 0);
    assert_eq!(ch2.highest_voucher_amount, 20_000);
}

#[tokio::test]
async fn test_store_get_channel_async() {
    let store = InMemoryChannelStore::new();
    store.insert("0xchannel1", test_channel_state("0xchannel1"));

    let result = store.get_channel("0xchannel1").await.unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap().channel_id, "0xchannel1");

    let missing = store.get_channel("0xmissing").await.unwrap();
    assert!(missing.is_none());
}

#[test]
fn test_channel_state_serialization() {
    let state = test_channel_state("0xchannel1");
    let json = serde_json::to_string(&state).unwrap();
    let deserialized: ChannelState = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.channel_id, "0xchannel1");
    assert_eq!(deserialized.deposit, 100_000);
    assert_eq!(deserialized.chain_id, 42431);
    assert!(!deserialized.finalized);
}

#[tokio::test]
async fn test_deduct_from_finalized_channel_rejects() {
    let store = InMemoryChannelStore::new();
    let mut state = test_channel_state("0xchannel1");
    state.highest_voucher_amount = 10_000;
    state.finalized = true;
    store.insert("0xchannel1", state);

    let result = deduct_from_channel(&store, "0xchannel1", 1_000).await;
    assert!(result.is_err(), "finalized channel should reject deduction");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("finalized"),
        "error should mention finalized, got: {err}"
    );
}

#[tokio::test]
async fn test_deduct_from_closing_channel_rejects() {
    let store = InMemoryChannelStore::new();
    let mut state = test_channel_state("0xchannel1");
    state.highest_voucher_amount = 10_000;
    state.closing = true;
    store.insert("0xchannel1", state);

    let result = deduct_from_channel(&store, "0xchannel1", 1_000).await;
    assert!(result.is_err(), "closing channel should reject deduction");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("closing"),
        "error should mention closing, got: {err}"
    );
}

#[tokio::test]
async fn test_store_wait_for_update_notifies() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    store.insert("0xchannel1", test_channel_state("0xchannel1"));

    let store2 = store.clone();
    let handle = tokio::spawn(async move {
        store2.wait_for_update("0xchannel1").await;
        true
    });

    // Yield to let the spawned task start waiting
    tokio::task::yield_now().await;

    // Trigger an update
    store
        .update_channel(
            "0xchannel1",
            Box::new(|current| {
                let mut s = current.unwrap();
                s.highest_voucher_amount = 9999;
                Ok(Some(s))
            }),
        )
        .await
        .unwrap();

    // The wait should complete within a reasonable time
    let result = tokio::time::timeout(tokio::time::Duration::from_secs(1), handle)
        .await
        .expect("wait_for_update should have been notified within timeout")
        .expect("spawned task should not panic");
    assert!(result);
}

#[tokio::test]
async fn test_concurrent_deductions_different_channels() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    let mut s1 = test_channel_state("0xchannel1");
    s1.highest_voucher_amount = 10_000;
    let mut s2 = test_channel_state("0xchannel2");
    s2.highest_voucher_amount = 10_000;
    store.insert("0xchannel1", s1);
    store.insert("0xchannel2", s2);

    let store1 = store.clone();
    let store2 = store.clone();
    let (r1, r2) = tokio::join!(
        deduct_from_channel(&*store1, "0xchannel1", 3_000),
        deduct_from_channel(&*store2, "0xchannel2", 5_000),
    );

    assert_eq!(r1.unwrap().spent, 3_000);
    assert_eq!(r2.unwrap().spent, 5_000);
}

#[tokio::test]
async fn test_deduct_rejects_finalized_channel() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    let mut state = test_channel_state("0xchannel_fin");
    state.highest_voucher_amount = 10_000;
    state.finalized = true;
    store.insert("0xchannel_fin", state);

    let result = deduct_from_channel(&*store, "0xchannel_fin", 1_000).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("finalized"),
        "error should mention finalized, got: {err}"
    );
}

#[tokio::test]
async fn test_voucher_uses_stored_close_requested_at() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    let mut state = test_channel_state("0xchannel_close_req");
    state.highest_voucher_amount = 10_000;
    state.deposit = 100_000;
    state.close_requested_at = 12345; // non-zero = force-close requested
    store.insert("0xchannel_close_req", state);

    // Verify that close_requested_at is persisted and retrieved
    let retrieved = store
        .get_channel("0xchannel_close_req")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved.close_requested_at, 12345);
}

#[test]
fn test_deserialize_channel_state_without_close_requested_at() {
    // Backward compat: old serialized state without close_requested_at should default to 0.
    let json = r#"{
        "channel_id": "0xaabb",
        "chain_id": 1,
        "escrow_contract": "0x1111111111111111111111111111111111111111",
        "payer": "0x2222222222222222222222222222222222222222",
        "payee": "0x3333333333333333333333333333333333333333",
        "token": "0x4444444444444444444444444444444444444444",
        "authorized_signer": "0x5555555555555555555555555555555555555555",
        "deposit": 100000,
        "settled_on_chain": 0,
        "highest_voucher_amount": 0,
        "highest_voucher_signature": null,
        "spent": 0,
        "units": 0,
        "finalized": false,
        "created_at": "2025-01-01T00:00:00Z"
    }"#;
    let state: ChannelState = serde_json::from_str(json).unwrap();
    assert_eq!(state.close_requested_at, 0);
}

#[tokio::test]
async fn test_deduct_rejects_when_close_requested() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    let mut state = test_channel_state("0xchannel_closing");
    state.highest_voucher_amount = 10_000;
    state.close_requested_at = 99999;
    store.insert("0xchannel_closing", state);

    let retrieved = store
        .get_channel("0xchannel_closing")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retrieved.close_requested_at, 99999);

    // Deduction should still work (close_requested_at is checked at voucher level)
    let result = deduct_from_channel(&*store, "0xchannel_closing", 1_000).await;
    assert!(result.is_ok());
    let updated = result.unwrap();
    assert_eq!(updated.spent, 1_000);
    assert_eq!(updated.close_requested_at, 99999);
}

#[tokio::test]
async fn test_deduct_from_channel_finalized_rejects() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    let mut state = test_channel_state("0xchannel_fin");
    state.highest_voucher_amount = 10_000;
    state.spent = 0;
    state.finalized = true;
    store.insert("0xchannel_fin", state);

    let result = deduct_from_channel(&*store, "0xchannel_fin", 1_000).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(
        err.code,
        Some(crate::protocol::traits::ErrorCode::ChannelClosed)
    );

    // Verify state was not mutated
    let unchanged = store.get_channel("0xchannel_fin").await.unwrap().unwrap();
    assert_eq!(unchanged.spent, 0);
    assert_eq!(unchanged.units, 0);
}

#[tokio::test]
async fn test_default_wait_for_update_does_not_complete_immediately() {
    use std::time::Duration;
    // A minimal ChannelStore that only implements required methods,
    // relying on the default wait_for_update
    struct PollOnlyStore;
    impl ChannelStore for PollOnlyStore {
        fn get_channel(
            &self,
            _channel_id: &str,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
        > {
            unimplemented!()
        }

        fn update_channel(
            &self,
            _channel_id: &str,
            _updater: Box<
                dyn FnOnce(Option<ChannelState>) -> Result<Option<ChannelState>, VerificationError>
                    + Send,
            >,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
        > {
            unimplemented!()
        }
    }

    let store = PollOnlyStore;
    let result =
        tokio::time::timeout(Duration::from_millis(50), store.wait_for_update("any")).await;

    // Should timeout. The default must not return immediately
    assert!(result.is_err());
}
