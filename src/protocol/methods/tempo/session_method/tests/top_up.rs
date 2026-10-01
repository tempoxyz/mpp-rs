use super::*;

#[tokio::test]
async fn test_topup_refreshes_on_chain_fields() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    let mut state = test_channel_state("0xchannel_topup");
    state.deposit = 100_000;
    state.close_requested_at = 12345;
    state.settled_on_chain = 1_000;
    state.spent = 2_000;
    let on_chain = on_chain_channel(&state, 200_000, 1_000);
    store.insert("0xchannel_topup", state);

    let result = store
        .update_channel(
            "0xchannel_topup",
            Box::new(move |current| Ok(Some(current.unwrap().refresh_on_chain(&on_chain)))),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.deposit, 200_000);
    assert_eq!(
        result.close_requested_at, 0,
        "topUp should refresh close_requested_at"
    );
    assert_eq!(result.settled_on_chain, 1_000);
    assert_eq!(result.spent, 2_000); // max(1000, 2000) = 2000
}

/// A topUp referencing a channel with a mismatched token must be
/// rejected before the transaction is broadcast.
#[tokio::test]
async fn test_top_up_rejects_channel_with_wrong_token() {
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id = format!("0x{}", "ab".repeat(32));

    let mut state = test_channel_state(&channel_id);
    state.highest_voucher_amount = 500;
    state.deposit = 100_000;
    store.insert(&channel_id, state);

    let method = test_session_method(store);

    let (request, credential) = build_session_credential(
        Some("0x2222222222222222222222222222222222222222"),
        "0x9999999999999999999999999999999999999999", // wrong token
        SessionCredentialPayload::TopUp {
            payload_type: "transaction".to_string(),
            channel_id,
            descriptor: None,
            settlement_route: None,
            additional_deposit: "5000".to_string(),
            transaction: format!("0x{}", "bb".repeat(32)),
        },
    );

    let err = method
        .verify_session(&credential, &request)
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::CredentialMismatch));
    assert!(
        err.message.contains("token"),
        "expected token mismatch error, got: {}",
        err.message
    );
}

fn top_up_credential(
    channel_id: &str,
    additional_deposit: &str,
    transaction: String,
) -> (
    crate::protocol::intents::SessionRequest,
    crate::protocol::core::PaymentCredential,
) {
    build_session_credential(
        Some(&TEST_PAYEE.to_string()),
        &TEST_TOKEN.to_string(),
        SessionCredentialPayload::TopUp {
            payload_type: "transaction".to_string(),
            channel_id: channel_id.to_string(),
            descriptor: None,
            settlement_route: None,
            additional_deposit: additional_deposit.to_string(),
            transaction,
        },
    )
}

/// Only the escrow top-up of the credential's channel, for the declared
/// amount, may be relayed.
#[tokio::test]
async fn test_top_up_rejects_unrelated_transaction_before_broadcast() {
    use alloy::primitives::U256;
    use alloy::sol_types::SolCall;

    let payer = alloy::signers::local::PrivateKeySigner::random();
    let channel_id = B256::repeat_byte(0xab);
    let top_up = |channel_id: B256, amount: u128| {
        ITestEscrow::topUpCall::new((channel_id, U256::from(amount))).abi_encode()
    };

    let other_contract = signed_call_transaction(
        &payer,
        Address::repeat_byte(0x99),
        top_up(channel_id, 5_000),
    );
    let other_call = signed_call_transaction(
        &payer,
        TEST_ESCROW,
        ITestEscrow::openCall::new((TEST_PAYEE, TEST_TOKEN, 5_000, B256::ZERO, Address::ZERO))
            .abi_encode(),
    );
    let other_channel =
        signed_call_transaction(&payer, TEST_ESCROW, top_up(B256::repeat_byte(0xcd), 5_000));
    let other_amount = signed_call_transaction(&payer, TEST_ESCROW, top_up(channel_id, 1));

    for (transaction, expected) in [
        (other_contract, "does not contain an escrow.topUp() call"),
        (other_call, "does not contain an escrow.topUp() call"),
        (other_channel, "does not match claimed channelId"),
        (other_amount, "does not match additionalDeposit"),
    ] {
        let store = Arc::new(InMemoryChannelStore::new());
        store.insert(
            &channel_id.to_string(),
            test_channel_state(&channel_id.to_string()),
        );
        let asserter = alloy::providers::mock::Asserter::new();
        push_mined_transaction(&asserter);
        let method = mocked_session_method(store, asserter.clone());

        let (request, credential) = top_up_credential(&channel_id.to_string(), "5000", transaction);
        let err = method
            .verify_session(&credential, &request)
            .await
            .unwrap_err();
        assert!(err.message.contains(expected), "{}", err.message);
        assert_eq!(asserter.read_q().len(), 3, "transaction was broadcast");
    }
}

#[tokio::test]
async fn test_top_up_rejects_finalized_channel_before_broadcast() {
    use alloy::primitives::U256;
    use alloy::sol_types::SolCall;

    let payer = alloy::signers::local::PrivateKeySigner::random();
    let channel_id = B256::repeat_byte(0xab);
    let mut state = test_channel_state(&channel_id.to_string());
    state.finalized = true;
    let store = Arc::new(InMemoryChannelStore::new());
    store.insert(&channel_id.to_string(), state);

    let asserter = alloy::providers::mock::Asserter::new();
    push_mined_transaction(&asserter);
    let method = mocked_session_method(store, asserter.clone());

    let (request, credential) = top_up_credential(
        &channel_id.to_string(),
        "5000",
        signed_call_transaction(
            &payer,
            TEST_ESCROW,
            ITestEscrow::topUpCall::new((channel_id, U256::from(5_000))).abi_encode(),
        ),
    );
    let err = method
        .verify_session(&credential, &request)
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::ChannelClosed));
    assert_eq!(asserter.read_q().len(), 3, "transaction was broadcast");
}

#[tokio::test]
async fn test_top_up_updates_deposit_after_broadcast() {
    use alloy::primitives::U256;
    use alloy::sol_types::SolCall;

    let payer = alloy::signers::local::PrivateKeySigner::random();
    let channel_id = B256::repeat_byte(0xab);
    let state = test_channel_state(&channel_id.to_string());
    let store = Arc::new(InMemoryChannelStore::new());
    store.insert(&channel_id.to_string(), state.clone());

    let asserter = alloy::providers::mock::Asserter::new();
    push_mined_transaction(&asserter);
    push_on_chain_channel(
        &asserter,
        state.payer,
        state.authorized_signer,
        state.deposit + 5_000,
    );
    let method = mocked_session_method(store.clone(), asserter);

    let (request, credential) = top_up_credential(
        &channel_id.to_string(),
        "5000",
        signed_call_transaction(
            &payer,
            TEST_ESCROW,
            ITestEscrow::topUpCall::new((channel_id, U256::from(5_000))).abi_encode(),
        ),
    );
    method.verify_session(&credential, &request).await.unwrap();

    assert_eq!(
        store
            .get_channel_sync(&channel_id.to_string())
            .unwrap()
            .deposit,
        state.deposit + 5_000
    );
}

/// Two top-ups can finish out of order: the one that read the chain first
/// must not lower the deposit the other one already recorded.
#[tokio::test]
async fn test_top_up_keeps_higher_recorded_deposit() {
    use alloy::primitives::U256;
    use alloy::sol_types::SolCall;

    let payer = alloy::signers::local::PrivateKeySigner::random();
    let channel_id = B256::repeat_byte(0xab);
    let state = test_channel_state(&channel_id.to_string());
    let store = Arc::new(ChangeAfterRead::new(|state| ChannelState {
        deposit: state.deposit + 20_000,
        ..state
    }));
    store.inner.insert(&channel_id.to_string(), state.clone());

    let asserter = alloy::providers::mock::Asserter::new();
    push_mined_transaction(&asserter);
    push_on_chain_channel(
        &asserter,
        state.payer,
        state.authorized_signer,
        state.deposit + 5_000,
    );
    let method = mocked_session_method(store.clone(), asserter);

    let (request, credential) = top_up_credential(
        &channel_id.to_string(),
        "5000",
        signed_call_transaction(
            &payer,
            TEST_ESCROW,
            ITestEscrow::topUpCall::new((channel_id, U256::from(5_000))).abi_encode(),
        ),
    );
    method.verify_session(&credential, &request).await.unwrap();

    assert_eq!(
        store
            .inner
            .get_channel_sync(&channel_id.to_string())
            .unwrap()
            .deposit,
        state.deposit + 20_000
    );
}
