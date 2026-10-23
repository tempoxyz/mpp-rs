use super::*;
use alloy::providers::mock::Asserter;

/// Queues the on-chain `getChannel` result for the test channel.
fn push_escrow(asserter: &Asserter, deposit: u128, close_requested_at: u64) {
    use alloy::sol_types::SolValue;

    let state = test_channel_state("0x00");
    asserter.push_success(&Bytes::from(
        (
            false,
            close_requested_at,
            state.payer,
            state.payee,
            state.token,
            state.authorized_signer,
            deposit,
            0u128,
        )
            .abi_encode_params(),
    ));
}

fn streaming_method(
    asserter: Asserter,
) -> (
    String,
    SessionMethod<impl Provider<TempoNetwork> + Clone + 'static>,
) {
    let channel_id = format!("0x{}", "ab".repeat(32));
    let store = Arc::new(InMemoryChannelStore::new());
    store.insert(&channel_id, test_channel_state(&channel_id));
    (channel_id, mocked_session_method(store, asserter))
}

#[tokio::test]
async fn test_verify_stream_caches_successful_reads() {
    let asserter = Asserter::new();
    push_escrow(&asserter, 100_000, 0);
    let (channel_id, method) = streaming_method(asserter);

    method.verify_stream(&channel_id).await.unwrap();
    // No second RPC response is queued: the read is reused.
    method.verify_stream(&channel_id).await.unwrap();
}

#[tokio::test]
async fn test_verify_stream_rejects_pending_close() {
    let asserter = Asserter::new();
    push_escrow(&asserter, 100_000, 1);
    let (channel_id, method) = streaming_method(asserter);

    let err = method.verify_stream(&channel_id).await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::ChannelClosed));
}

#[tokio::test]
async fn test_verify_stream_rejects_withdrawn_escrow() {
    let asserter = Asserter::new();
    push_escrow(&asserter, 0, 0);
    let (channel_id, method) = streaming_method(asserter);

    let err = method.verify_stream(&channel_id).await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::ChannelNotFound));
}

#[tokio::test]
async fn test_verify_stream_fails_on_rpc_error_without_caching() {
    let asserter = Asserter::new();
    asserter.push_failure_msg("RPC unavailable at https://private-rpc.example/secret-api-key");
    push_escrow(&asserter, 100_000, 0);
    let (channel_id, method) = streaming_method(asserter);

    let err = method.verify_stream(&channel_id).await.unwrap_err();
    assert_eq!(err.message, "Unable to verify stream escrow");
    // The failure was not cached: the next check reads the escrow again.
    method.verify_stream(&channel_id).await.unwrap();
}

#[tokio::test]
async fn test_verify_stream_rejects_closing_channel_without_rpc() {
    let (channel_id, method) = streaming_method(Asserter::new());
    let store = method.store.clone();
    store
        .update_channel(
            &channel_id,
            Box::new(|state| {
                Ok(state.map(|state| ChannelState {
                    closing: true,
                    ..state
                }))
            }),
        )
        .await
        .unwrap();

    let err = method.verify_stream(&channel_id).await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::ChannelClosed));
}
