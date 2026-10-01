use super::*;
use crate::protocol::methods::tempo::session_method::close::{
    machine_session_close_calls, validate_close_amount,
};
use crate::protocol::methods::tempo::voucher;

struct AsyncOnlyCloseSigner(alloy::signers::local::PrivateKeySigner);

#[async_trait::async_trait]
impl alloy::signers::Signer for AsyncOnlyCloseSigner {
    async fn sign_hash(&self, hash: &B256) -> alloy::signers::Result<alloy::primitives::Signature> {
        use alloy::signers::SignerSync;

        tokio::task::yield_now().await;
        self.0.sign_hash_sync(hash)
    }

    fn address(&self) -> Address {
        alloy::signers::Signer::address(&self.0)
    }

    fn chain_id(&self) -> Option<u64> {
        alloy::signers::Signer::chain_id(&self.0)
    }

    fn set_chain_id(&mut self, chain_id: Option<u64>) {
        alloy::signers::Signer::set_chain_id(&mut self.0, chain_id);
    }
}

#[test]
fn test_close_signer_accepts_async_only_alloy_signer() {
    let signer = AsyncOnlyCloseSigner(alloy::signers::local::PrivateKeySigner::random());
    let address = alloy::signers::Signer::address(&signer);
    let method =
        test_session_method(Arc::new(InMemoryChannelStore::new())).with_close_signer(signer);

    assert_eq!(method.close_signer.as_deref().unwrap().address(), address);
}

/// A close referencing a channel with a mismatched payee must be
/// rejected to prevent cross-session channel reuse.
#[tokio::test]
async fn test_close_rejects_channel_with_wrong_payee() {
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id = format!("0x{}", "ab".repeat(32));

    let mut state = test_channel_state(&channel_id);
    state.highest_voucher_amount = 500;
    state.deposit = 100_000;
    store.insert(&channel_id, state);

    let method = test_session_method(store);

    let (request, credential) = build_session_credential(
        Some("0x9999999999999999999999999999999999999999"), // wrong payee
        "0x3333333333333333333333333333333333333333",
        SessionCredentialPayload::Close {
            channel_id,
            descriptor: None,
            settlement_route: None,
            cumulative_amount: "1000".to_string(),
            signature: format!("0x{}", "aa".repeat(65)),
        },
    );

    let err = method
        .verify_session(&credential, &request)
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
    assert!(
        err.message.contains("payee"),
        "expected payee mismatch error, got: {}",
        err.message
    );
}

/// Stores an open channel, queues its on-chain `getChannel` state on the
/// mocked provider and returns a valid close credential for it.
async fn close_setup(
    store: &InMemoryChannelStore,
    asserter: &alloy::providers::mock::Asserter,
) -> (
    String,
    crate::protocol::intents::SessionRequest,
    crate::protocol::core::PaymentCredential,
) {
    close_setup_with(store, asserter, 500, 0, 1_000).await
}

/// Like [`close_setup`], for a channel that spent `spent`, has `settled`
/// settled on-chain and is closed with a voucher for `close_amount`.
async fn close_setup_with(
    store: &InMemoryChannelStore,
    asserter: &alloy::providers::mock::Asserter,
    spent: u128,
    settled: u128,
    close_amount: u128,
) -> (
    String,
    crate::protocol::intents::SessionRequest,
    crate::protocol::core::PaymentCredential,
) {
    use alloy::sol_types::SolValue;

    let signer = alloy::signers::local::PrivateKeySigner::random();
    let channel_id = format!("0x{}", "ab".repeat(32));
    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    state.spent = spent;
    state.settled_on_chain = settled;
    store.insert(&channel_id, state.clone());

    asserter.push_success(&Bytes::from(
        (
            false,
            0u64,
            state.payer,
            state.payee,
            state.token,
            state.authorized_signer,
            state.deposit,
            settled,
        )
            .abi_encode_params(),
    ));

    let signature = voucher::sign_voucher(
        &signer,
        channel_id.parse().unwrap(),
        close_amount,
        state.escrow_contract,
        state.chain_id,
    )
    .await
    .unwrap();
    let (request, credential) = build_session_credential(
        Some("0x2222222222222222222222222222222222222222"),
        "0x3333333333333333333333333333333333333333",
        SessionCredentialPayload::Close {
            channel_id: channel_id.clone(),
            descriptor: None,
            settlement_route: None,
            cumulative_amount: close_amount.to_string(),
            signature: alloy::hex::encode_prefixed(signature),
        },
    );
    (channel_id, request, credential)
}

/// Without a close signer nothing can be settled on-chain, so a close must
/// not report success or finalize the channel in the store.
#[tokio::test]
async fn test_close_without_close_signer_is_rejected() {
    let store = Arc::new(InMemoryChannelStore::new());
    let asserter = alloy::providers::mock::Asserter::new();
    let (channel_id, request, credential) = close_setup(&store, &asserter).await;
    let method = mocked_session_method(store.clone(), asserter);

    let err = method
        .verify_session(&credential, &request)
        .await
        .unwrap_err();
    assert!(
        err.message.contains("close signer"),
        "expected missing close signer error, got: {}",
        err.message
    );

    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert!(!stored.finalized);
    assert!(!stored.closing);
}

/// Queues the RPC responses for a close transaction that is mined with the
/// given receipt status, and returns its hash.
fn push_close_transaction(asserter: &alloy::providers::mock::Asserter, success: bool) -> B256 {
    use alloy::primitives::{U128, U64};

    let tx_hash = B256::repeat_byte(0xcc);
    let receipt = serde_json::json!({
        "transactionHash": tx_hash,
        "transactionIndex": "0x0",
        "blockHash": B256::repeat_byte(0xdd),
        "blockNumber": "0x1",
        "from": Address::repeat_byte(0x22),
        "to": Address::repeat_byte(0x55),
        "cumulativeGasUsed": "0x5208",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x1",
        "contractAddress": null,
        "logs": [],
        "logsBloom": alloy::primitives::Bloom::ZERO,
        "status": if success { "0x1" } else { "0x0" },
        "type": "0x76",
        "feePayer": Address::repeat_byte(0x22),
    });
    asserter.push_success(&U64::ZERO); // eth_getTransactionCount
    asserter.push_success(&U128::from(1)); // eth_gasPrice
    asserter.push_success(&tx_hash); // eth_sendRawTransaction
    asserter.push_success(&receipt); // receipt lookup when registering the watcher
    asserter.push_success(&receipt); // receipt fetch
    tx_hash
}

#[tokio::test]
async fn test_close_finalizes_after_successful_transaction() {
    let store = Arc::new(InMemoryChannelStore::new());
    let asserter = alloy::providers::mock::Asserter::new();
    let (channel_id, request, credential) = close_setup(&store, &asserter).await;
    let tx_hash = push_close_transaction(&asserter, true);
    let method = mocked_session_method(store.clone(), asserter)
        .with_close_signer(alloy::signers::local::PrivateKeySigner::random());

    let receipt = method.verify_session(&credential, &request).await.unwrap();
    assert_eq!(
        receipt_json(&receipt),
        serde_json::json!({
            "method": "tempo",
            "intent": "session",
            "status": "success",
            "timestamp": receipt.timestamp,
            "reference": channel_id,
            "challengeId": "test-id",
            "channelId": channel_id,
            "acceptedCumulative": "1000",
            "spent": "500",
            "units": 0,
            "txHash": tx_hash.to_string(),
        })
    );

    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert!(stored.finalized);
    assert!(!stored.closing);
}

/// A channel nothing was spent or settled on can be closed at zero, which
/// refunds the whole deposit to the payer.
#[tokio::test]
async fn test_close_at_zero_closes_untouched_channel() {
    let store = Arc::new(InMemoryChannelStore::new());
    let asserter = alloy::providers::mock::Asserter::new();
    let (channel_id, request, credential) = close_setup_with(&store, &asserter, 0, 0, 0).await;
    let tx_hash = push_close_transaction(&asserter, true);
    let method = mocked_session_method(store.clone(), asserter.clone())
        .with_close_signer(alloy::signers::local::PrivateKeySigner::random());

    let receipt = method.verify_session(&credential, &request).await.unwrap();
    let receipt = receipt_json(&receipt);
    assert_eq!(receipt["spent"], "0");
    assert_eq!(receipt["txHash"], tx_hash.to_string());
    assert!(asserter.read_q().is_empty(), "close was not submitted");

    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert!(stored.finalized);
    assert!(!stored.closing);
}

/// GHSA-mv9j-8jvg-j8mr: a voucher that was already settled is public
/// on-chain, so presenting it again must not close the channel.
#[tokio::test]
async fn test_close_at_settled_amount_is_rejected() {
    let store = Arc::new(InMemoryChannelStore::new());
    let asserter = alloy::providers::mock::Asserter::new();
    let (channel_id, request, credential) =
        close_setup_with(&store, &asserter, 1_000, 1_000, 1_000).await;
    push_close_transaction(&asserter, true);
    let queued = asserter.read_q().len();
    let method = mocked_session_method(store.clone(), asserter.clone())
        .with_close_signer(alloy::signers::local::PrivateKeySigner::random());

    let err = method
        .verify_session(&credential, &request)
        .await
        .unwrap_err();
    assert_eq!(
        err.message,
        "close voucher amount must be > 1000 (on-chain settled)"
    );

    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert!(!stored.finalized);
    assert!(!stored.closing);
    // Only the on-chain channel read reached the provider.
    assert_eq!(asserter.read_q().len(), queued - 1);
}

/// A mined-but-reverted close leaves the channel open on-chain, so it must
/// stay open in the store too.
#[tokio::test]
async fn test_close_with_reverted_transaction_is_not_finalized() {
    let store = Arc::new(InMemoryChannelStore::new());
    let asserter = alloy::providers::mock::Asserter::new();
    let (channel_id, request, credential) = close_setup(&store, &asserter).await;
    push_close_transaction(&asserter, false);
    let method = mocked_session_method(store.clone(), asserter)
        .with_close_signer(alloy::signers::local::PrivateKeySigner::random());

    let err = method
        .verify_session(&credential, &request)
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::TransactionFailed));

    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert!(!stored.finalized);
    assert!(!stored.closing);
}

/// A close that fails before the transaction is mined must not leave the
/// channel stuck in `closing`.
#[tokio::test]
async fn test_close_resets_closing_when_submission_fails() {
    let store = Arc::new(InMemoryChannelStore::new());
    let asserter = alloy::providers::mock::Asserter::new();
    let (channel_id, request, credential) = close_setup(&store, &asserter).await;
    // No further responses queued: the nonce lookup fails.
    let method = mocked_session_method(store.clone(), asserter)
        .with_close_signer(alloy::signers::local::PrivateKeySigner::random());

    let err = method
        .verify_session(&credential, &request)
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::NetworkError));

    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert!(!stored.finalized);
    assert!(!stored.closing);
}

/// Units deducted between the close's snapshot and its `closing` update
/// must be covered by the close amount, otherwise the channel would be
/// closed on-chain for less than was spent.
#[tokio::test]
async fn test_close_rechecks_spent_under_lock() {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Store that deducts from a channel right after its first read, like
    /// a request metered while the close awaits the on-chain channel.
    struct DeductAfterRead {
        inner: InMemoryChannelStore,
        deducted: AtomicBool,
    }

    impl ChannelStore for DeductAfterRead {
        fn get_channel(
            &self,
            channel_id: &str,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
        > {
            let channel_id = channel_id.to_string();
            Box::pin(async move {
                let snapshot = self.inner.get_channel(&channel_id).await?;
                if !self.deducted.swap(true, Ordering::SeqCst) {
                    deduct_from_channel(&self.inner, &channel_id, 1_000).await?;
                }
                Ok(snapshot)
            })
        }

        fn update_channel(
            &self,
            channel_id: &str,
            updater: Box<
                dyn FnOnce(Option<ChannelState>) -> Result<Option<ChannelState>, VerificationError>
                    + Send,
            >,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
        > {
            self.inner.update_channel(channel_id, updater)
        }
    }

    let store = Arc::new(DeductAfterRead {
        inner: InMemoryChannelStore::new(),
        deducted: AtomicBool::new(false),
    });
    let asserter = alloy::providers::mock::Asserter::new();
    let (channel_id, request, credential) = close_setup(&store.inner, &asserter).await;
    // The close voucher (1_000) covers the 500 spent so far, but the channel
    // holds a higher voucher that requests can still be metered against.
    let mut state = store.inner.get_channel_sync(&channel_id).unwrap();
    state.highest_voucher_amount = 2_000;
    store.inner.insert(&channel_id, state);
    push_close_transaction(&asserter, true);
    let queued = asserter.read_q().len();
    let method = mocked_session_method(store.clone(), asserter.clone())
        .with_close_signer(alloy::signers::local::PrivateKeySigner::random());

    let err = method
        .verify_session(&credential, &request)
        .await
        .unwrap_err();
    assert_eq!(err.message, "close voucher amount must be >= 1500 (spent)");

    let stored = store.inner.get_channel_sync(&channel_id).unwrap();
    assert!(!stored.finalized);
    assert!(!stored.closing);
    // Only the on-chain channel read reached the provider, so the queued
    // close transaction was not submitted.
    assert_eq!(asserter.read_q().len(), queued - 1);
}

// ==================== validate_close_amount tests ====================
// Mirror the mppx Session.test.ts close tests:
// https://github.com/wevm/mppx/blob/c526ea6/src/tempo/server/Session.test.ts#L1105-L1315

#[test]
fn test_close_accepts_voucher_at_spent_amount() {
    // spent=500, settled=0, deposit=10_000_000
    // close at 500 (== spent) should succeed
    assert!(validate_close_amount(500, 500, 0, 10_000_000).is_ok());
}

#[test]
fn test_close_accepts_voucher_above_spent() {
    // spent=500, settled=0, deposit=10_000_000
    // close at 5_000_000 (well above spent) should succeed
    assert!(validate_close_amount(5_000_000, 500, 0, 10_000_000).is_ok());
}

#[test]
fn test_close_accepts_voucher_above_settled() {
    // spent=0, settled=1_000, deposit=10_000_000
    // close at 1_001 (above settled) should succeed
    assert!(validate_close_amount(1_001, 0, 1_000, 10_000_000).is_ok());
}

#[test]
fn test_close_rejects_voucher_below_spent() {
    // spent=500_000, settled=0, deposit=10_000_000
    // close at 100_000 (below spent) should fail
    let err = validate_close_amount(100_000, 500_000, 0, 10_000_000).unwrap_err();
    assert!(
        err.message
            .contains("close voucher amount must be >= 500000 (spent)"),
        "got: {}",
        err.message,
    );
}

#[test]
fn test_close_rejects_voucher_equal_to_settled() {
    // spent=0, settled=1_000_000, deposit=10_000_000
    // close at 1_000_000 (== settled) should fail (strict >)
    let err = validate_close_amount(1_000_000, 0, 1_000_000, 10_000_000).unwrap_err();
    assert!(
        err.message
            .contains("close voucher amount must be > 1000000 (on-chain settled)"),
        "got: {}",
        err.message,
    );
}

#[test]
fn test_close_rejects_voucher_below_settled() {
    // spent=0, settled=1_000_000, deposit=10_000_000
    // close at 500_000 (below settled) should fail
    let err = validate_close_amount(500_000, 0, 1_000_000, 10_000_000).unwrap_err();
    assert!(
        err.message
            .contains("close voucher amount must be > 1000000 (on-chain settled)"),
        "got: {}",
        err.message,
    );
}

#[test]
fn test_close_rejects_voucher_exceeding_deposit() {
    // spent=0, settled=0, deposit=10_000_000
    // close at 99_999_999 (above deposit) should fail
    let err = validate_close_amount(99_999_999, 0, 0, 10_000_000).unwrap_err();
    assert!(
        err.message
            .contains("close voucher amount exceeds on-chain deposit"),
        "got: {}",
        err.message,
    );
}

#[test]
fn test_close_spent_check_takes_priority_over_settled() {
    // When both spent and settled would reject, spent error comes first
    // spent=500_000, settled=1_000_000, deposit=10_000_000
    // close at 100 (below both) should fail with spent error
    let err = validate_close_amount(100, 500_000, 1_000_000, 10_000_000).unwrap_err();
    assert!(
        err.message.contains("(spent)"),
        "expected spent error first, got: {}",
        err.message,
    );
}

#[test]
fn test_close_at_zero_spent_zero_settled() {
    // Edge case: nothing spent, nothing settled, close at 1 should succeed
    assert!(validate_close_amount(1, 0, 0, 10_000_000).is_ok());
}

#[test]
fn test_close_at_zero_accepted_for_untouched_channel() {
    // Nothing spent, nothing settled: closing at 0 refunds the deposit.
    assert!(validate_close_amount(0, 0, 0, 10_000_000).is_ok());
}

#[test]
fn test_close_at_zero_rejects_unfunded_channel() {
    // No deposit on-chain: there is nothing to refund.
    let err = validate_close_amount(0, 0, 0, 0).unwrap_err();
    assert!(
        err.message.contains("on-chain settled"),
        "got: {}",
        err.message,
    );
}

#[test]
fn test_close_at_exact_deposit() {
    // close at deposit boundary should succeed
    assert!(validate_close_amount(10_000_000, 0, 0, 10_000_000).is_ok());
}

#[test]
fn machine_session_close_is_settle_swap_close_and_requires_full_consumption() {
    use alloy::{
        primitives::{Address, B256},
        sol_types::SolCall,
    };
    use tempo_alloy::contracts::precompiles::ITIP20ChannelReserve;
    let recipient = Address::repeat_byte(0x22);
    let target = Address::repeat_byte(0x33);
    let route_salt = B256::repeat_byte(0x44);
    let salt = crate::protocol::methods::tempo::machine_token::compute_session_salt(
        recipient, target, route_salt,
    );
    let (_, adapter) =
        crate::protocol::methods::tempo::machine_token::session_addresses(42431).unwrap();
    let (token, _) =
        crate::protocol::methods::tempo::machine_token::session_addresses(42431).unwrap();
    let descriptor = crate::protocol::methods::tempo::session::ChannelDescriptor {
        payer: Address::repeat_byte(0x11).to_string(),
        payee: adapter.to_string(),
        operator: Address::repeat_byte(0x55).to_string(),
        token: token.to_string(),
        salt: salt.to_string(),
        authorized_signer: Address::repeat_byte(0x66).to_string(),
        expiring_nonce_hash: B256::repeat_byte(0x77).to_string(),
    };
    let route = crate::protocol::methods::tempo::session::SettlementRoute {
        adapter: adapter.to_string(),
        recipient: recipient.to_string(),
        target_token: target.to_string(),
        route_salt: route_salt.to_string(),
    };
    let calls = machine_session_close_calls(
        42431,
        Address::repeat_byte(0x88),
        &descriptor,
        &route,
        100,
        100,
        0,
        &[1; 64],
    )
    .unwrap();
    assert_eq!(
        &calls[0].input[..4],
        &ITIP20ChannelReserve::settleCall::SELECTOR
    );
    assert_eq!(calls[1].to, alloy::primitives::TxKind::Call(adapter));
    assert_eq!(
        &calls[2].input[..4],
        &ITIP20ChannelReserve::closeCall::SELECTOR
    );
    assert!(machine_session_close_calls(
        42431,
        Address::repeat_byte(0x88),
        &descriptor,
        &route,
        99,
        100,
        0,
        &[1; 64],
    )
    .unwrap_err()
    .message
    .contains("nonzero refund"));
    let already_settled = machine_session_close_calls(
        42431,
        Address::repeat_byte(0x88),
        &descriptor,
        &route,
        100,
        100,
        100,
        &[1; 64],
    )
    .unwrap();
    assert_eq!(already_settled.len(), 1);
    assert_eq!(
        &already_settled[0].input[..4],
        &ITIP20ChannelReserve::closeCall::SELECTOR
    );
}
