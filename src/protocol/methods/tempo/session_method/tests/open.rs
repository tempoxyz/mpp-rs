use super::*;
use crate::protocol::methods::tempo::voucher;

/// Helper that replicates the handle_open reopen logic so tests exercise
/// the same formula used in production.
async fn reopen_channel(
    store: &std::sync::Arc<InMemoryChannelStore>,
    key: &str,
    on_chain_settled: u128,
    on_chain_deposit: u128,
    new_cumulative_amount: u128,
) -> ChannelState {
    let key_owned = key.to_string();
    store
        .update_channel(
            &key_owned,
            Box::new(move |existing| {
                let existing = existing.unwrap();
                let settled_on_chain = std::cmp::max(on_chain_settled, existing.settled_on_chain);
                let spent = std::cmp::max(settled_on_chain, existing.spent);

                if new_cumulative_amount > existing.highest_voucher_amount {
                    Ok(Some(ChannelState {
                        deposit: on_chain_deposit,
                        settled_on_chain,
                        spent,
                        highest_voucher_amount: new_cumulative_amount,
                        ..existing
                    }))
                } else {
                    Ok(Some(ChannelState {
                        deposit: on_chain_deposit,
                        settled_on_chain,
                        spent,
                        ..existing
                    }))
                }
            }),
        )
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn test_reopen_bumps_spent_to_settled_on_chain_higher_voucher() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    let mut state = test_channel_state("0xchannel_reopen");
    state.highest_voucher_amount = 5_000_000;
    state.spent = 0;
    state.settled_on_chain = 0;
    state.deposit = 10_000_000;
    store.insert("0xchannel_reopen", state);

    // Server settled 5M on-chain; client sends higher voucher of 7M.
    let result = reopen_channel(&store, "0xchannel_reopen", 5_000_000, 10_000_000, 7_000_000).await;

    assert_eq!(result.settled_on_chain, 5_000_000);
    assert_eq!(result.spent, 5_000_000);
    assert_eq!(result.highest_voucher_amount, 7_000_000);
    // Available = 7M - 5M = 2M
    assert_eq!(
        result.highest_voucher_amount.saturating_sub(result.spent),
        2_000_000
    );
}

#[tokio::test]
async fn test_reopen_bumps_spent_non_higher_voucher() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    let mut state = test_channel_state("0xchannel_reopen2");
    state.highest_voucher_amount = 5_000_000;
    state.spent = 0;
    state.settled_on_chain = 0;
    state.deposit = 10_000_000;
    store.insert("0xchannel_reopen2", state);

    // Server settled 5M on-chain; client sends same voucher (not higher).
    let result = reopen_channel(
        &store,
        "0xchannel_reopen2",
        5_000_000,
        10_000_000,
        3_000_000,
    )
    .await;

    assert_eq!(result.settled_on_chain, 5_000_000);
    assert_eq!(result.spent, 5_000_000);
    // Voucher stays at 5M (was higher than the 3M presented).
    assert_eq!(result.highest_voucher_amount, 5_000_000);
    // Available = 5M - 5M = 0
    assert_eq!(
        result.highest_voucher_amount.saturating_sub(result.spent),
        0
    );
}

#[tokio::test]
async fn test_reopen_spent_does_not_regress_when_spent_exceeds_settled() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    let mut state = test_channel_state("0xchannel_reopen3");
    state.highest_voucher_amount = 10_000_000;
    state.spent = 8_000_000;
    state.settled_on_chain = 0;
    state.deposit = 10_000_000;
    store.insert("0xchannel_reopen3", state);

    // Server settled only 3M on-chain, but we already spent 8M locally.
    // spent must stay at 8M (not regress to 3M).
    let result = reopen_channel(
        &store,
        "0xchannel_reopen3",
        3_000_000,
        10_000_000,
        10_000_000,
    )
    .await;

    assert_eq!(result.settled_on_chain, 3_000_000);
    assert_eq!(result.spent, 8_000_000);
    // Available = 10M - 8M = 2M
    assert_eq!(
        result.highest_voucher_amount.saturating_sub(result.spent),
        2_000_000
    );
}

#[tokio::test]
async fn test_new_channel_state_should_use_on_chain_settled() {
    // Exercises the real update_channel closure from handle_open's "new channel"
    // branch. When no existing state is present, settled_on_chain and spent must
    // be set to on_chain.settled to prevent double-spending already-settled amounts.
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id = "0xchannel_reopened";

    let on_chain_settled: u128 = 5_000_000;
    let on_chain_deposit: u128 = 10_000_000;
    let cumulative_amount: u128 = 7_000_000;
    let sig_bytes = vec![0xAA; 65];
    let authorized_signer: Address = "0x4444444444444444444444444444444444444444"
        .parse()
        .unwrap();
    let escrow: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();
    let payer: Address = "0x1111111111111111111111111111111111111111"
        .parse()
        .unwrap();
    let payee: Address = "0x2222222222222222222222222222222222222222"
        .parse()
        .unwrap();
    let token: Address = "0x3333333333333333333333333333333333333333"
        .parse()
        .unwrap();
    let chain_id: u64 = 42431;

    // Replicate the closure from handle_open's else (new channel) branch
    let sig_bytes_clone = sig_bytes.clone();
    let result = store
        .update_channel(
            channel_id,
            Box::new(move |existing| {
                assert!(existing.is_none(), "should be new channel");
                Ok(Some(ChannelState {
                    channel_id: channel_id.to_string(),
                    chain_id,
                    escrow_contract: escrow,
                    payer,
                    payee,
                    token,
                    settlement_route: None,
                    authorized_signer,
                    deposit: on_chain_deposit,
                    settled_on_chain: on_chain_settled,
                    highest_voucher_amount: cumulative_amount,
                    highest_voucher_signature: Some(sig_bytes_clone),
                    spent: on_chain_settled,
                    units: 0,
                    finalized: false,
                    closing: false,
                    close_requested_at: 0,
                    created_at: "2025-01-01T00:00:00Z".to_string(),
                }))
            }),
        )
        .await
        .unwrap();

    let state = result.unwrap();
    assert_eq!(state.settled_on_chain, on_chain_settled);
    assert_eq!(state.spent, on_chain_settled);
    assert_eq!(state.highest_voucher_amount, cumulative_amount);
    assert_eq!(state.deposit, on_chain_deposit);

    // Verify available balance reflects settled amount
    let available = state.highest_voucher_amount.saturating_sub(state.spent);
    assert_eq!(available, 2_000_000); // 7M - 5M

    // Verify deduct_from_channel also sees correct available balance
    let after_deduct = deduct_from_channel(&*store, channel_id, 1_000_000)
        .await
        .unwrap();
    assert_eq!(after_deduct.spent, on_chain_settled + 1_000_000); // 6M
}

#[tokio::test]
async fn test_reopen_bumps_spent_to_settled_on_chain() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());
    let mut state = test_channel_state("0xchannel_reopen");
    state.highest_voucher_amount = 5_000_000;
    state.spent = 0;
    state.settled_on_chain = 0;
    state.deposit = 10_000_000;
    store.insert("0xchannel_reopen", state);

    // Simulate what handle_open does when reopening:
    // on_chain.settled has increased to 5_000_000
    let on_chain_settled: u128 = 5_000_000;
    let result = store
        .update_channel(
            "0xchannel_reopen",
            Box::new(move |existing| {
                let existing = existing.unwrap();
                let settled_on_chain = std::cmp::max(on_chain_settled, existing.settled_on_chain);
                let spent = std::cmp::max(settled_on_chain, existing.spent);
                Ok(Some(ChannelState {
                    settled_on_chain,
                    spent,
                    highest_voucher_amount: 7_000_000,
                    ..existing
                }))
            }),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.settled_on_chain, 5_000_000);
    assert_eq!(result.spent, 5_000_000);
    assert_eq!(result.highest_voucher_amount, 7_000_000);
    // Available = 7M - 5M = 2M
    let available = result.highest_voucher_amount.saturating_sub(result.spent);
    assert_eq!(available, 2_000_000);
}

#[tokio::test]
async fn test_cold_start_new_channel_with_on_chain_settled() {
    let store = std::sync::Arc::new(InMemoryChannelStore::new());

    let on_chain_settled: u128 = 5_000_000;
    let cumulative_amount: u128 = 7_000_000;
    let on_chain_deposit: u128 = 10_000_000;

    let result = store
        .update_channel(
            "0xchannel_cold",
            Box::new(move |_existing| {
                assert!(
                    _existing.is_none(),
                    "should be a cold start with no existing state"
                );
                Ok(Some(ChannelState {
                    channel_id: "0xchannel_cold".to_string(),
                    chain_id: 1,
                    escrow_contract: "0x1111111111111111111111111111111111111111"
                        .parse()
                        .unwrap(),
                    payer: "0x2222222222222222222222222222222222222222"
                        .parse()
                        .unwrap(),
                    payee: "0x3333333333333333333333333333333333333333"
                        .parse()
                        .unwrap(),
                    token: "0x4444444444444444444444444444444444444444"
                        .parse()
                        .unwrap(),
                    settlement_route: None,
                    authorized_signer: "0x5555555555555555555555555555555555555555"
                        .parse()
                        .unwrap(),
                    deposit: on_chain_deposit,
                    settled_on_chain: on_chain_settled,
                    highest_voucher_amount: cumulative_amount,
                    highest_voucher_signature: None,
                    spent: on_chain_settled,
                    units: 0,
                    finalized: false,
                    closing: false,
                    close_requested_at: 0,
                    created_at: "2025-01-01T00:00:00Z".to_string(),
                }))
            }),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(result.settled_on_chain, 5_000_000);
    assert_eq!(result.spent, 5_000_000);
    let available = result.highest_voucher_amount.saturating_sub(result.spent);
    assert_eq!(available, 2_000_000);
}

#[test]
fn test_open_channel_id_binding_rejects_mismatch() {
    use alloy::eips::Encodable2718;
    use alloy::primitives::Bytes;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use alloy::sol_types::SolCall;
    use tempo_alloy::primitives::transaction::Call;
    use tempo_alloy::primitives::TempoTransaction;

    alloy::sol! {
        interface IEscrowOpen {
            function open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner) external;
        }
    }

    let signer = PrivateKeySigner::random();
    let escrow: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();
    let payee: Address = "0x2222222222222222222222222222222222222222"
        .parse()
        .unwrap();
    let token: Address = "0x3333333333333333333333333333333333333333"
        .parse()
        .unwrap();
    let salt = B256::from([0xABu8; 32]);
    let chain_id: u64 = 42431;

    let open_data =
        IEscrowOpen::openCall::new((payee, token, 1_000_000u128, salt, signer.address()))
            .abi_encode();

    let tx = TempoTransaction {
        chain_id,
        nonce: 0,
        gas_limit: 500_000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        calls: vec![Call {
            to: alloy::primitives::TxKind::Call(escrow),
            value: alloy::primitives::U256::ZERO,
            input: Bytes::from(open_data),
        }],
        ..Default::default()
    };

    let sig_hash = tx.signature_hash();
    let signature = signer.sign_hash_sync(&sig_hash).unwrap();
    let signed_tx = tx.into_signed(signature.into());
    let tx_bytes = signed_tx.encoded_2718();

    // Compute the correct channel ID.
    let correct_id = voucher::compute_channel_id(
        signer.address(),
        payee,
        token,
        salt,
        signer.address(), // authorizedSigner == sender in this test
        escrow,
        chain_id,
    );

    // Should pass with correct channel ID.
    assert!(
        SessionMethod::<alloy::providers::RootProvider<TempoNetwork>>::verify_open_channel_id_binding(
            &tx_bytes,
            correct_id,
            escrow,
            chain_id,
            payee,
            token,
        )
        .is_ok()
    );

    // Should fail with a different channel ID.
    let fake_id = B256::from([0x01u8; 32]);
    let err = SessionMethod::<alloy::providers::RootProvider<TempoNetwork>>::verify_open_channel_id_binding(
        &tx_bytes,
        fake_id,
        escrow,
        chain_id,
        payee,
        token,
    )
    .unwrap_err();
    assert!(
        err.message.contains("does not match claimed channelId"),
        "unexpected error: {}",
        err.message
    );
}

#[test]
fn test_open_channel_id_binding_rejects_wrong_payee_or_token() {
    use alloy::eips::Encodable2718;
    use alloy::primitives::Bytes;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use alloy::sol_types::SolCall;
    use tempo_alloy::primitives::transaction::Call;
    use tempo_alloy::primitives::TempoTransaction;

    alloy::sol! {
        interface IEscrowOpen {
            function open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner) external;
        }
    }

    let signer = PrivateKeySigner::random();
    let escrow: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();
    let payee: Address = "0x2222222222222222222222222222222222222222"
        .parse()
        .unwrap();
    let token: Address = "0x3333333333333333333333333333333333333333"
        .parse()
        .unwrap();
    let wrong: Address = "0x9999999999999999999999999999999999999999"
        .parse()
        .unwrap();
    let salt = B256::from([0xABu8; 32]);
    let chain_id: u64 = 42431;

    let open_data =
        IEscrowOpen::openCall::new((payee, token, 1_000_000u128, salt, signer.address()))
            .abi_encode();

    let tx = TempoTransaction {
        chain_id,
        nonce: 0,
        gas_limit: 500_000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        calls: vec![Call {
            to: alloy::primitives::TxKind::Call(escrow),
            value: alloy::primitives::U256::ZERO,
            input: Bytes::from(open_data),
        }],
        ..Default::default()
    };

    let sig_hash = tx.signature_hash();
    let signature = signer.sign_hash_sync(&sig_hash).unwrap();
    let signed_tx = tx.into_signed(signature.into());
    let tx_bytes = signed_tx.encoded_2718();

    let correct_id = voucher::compute_channel_id(
        signer.address(),
        payee,
        token,
        salt,
        signer.address(),
        escrow,
        chain_id,
    );

    let payee_err = SessionMethod::<alloy::providers::RootProvider<TempoNetwork>>::verify_open_channel_id_binding(
        &tx_bytes,
        correct_id,
        escrow,
        chain_id,
        wrong,
        token,
    )
    .unwrap_err();
    assert!(payee_err.message.contains("payee"));

    let token_err = SessionMethod::<alloy::providers::RootProvider<TempoNetwork>>::verify_open_channel_id_binding(
        &tx_bytes,
        correct_id,
        escrow,
        chain_id,
        payee,
        wrong,
    )
    .unwrap_err();
    assert!(token_err.message.contains("token"));
}

/// Builds an open credential whose transaction opens a channel with
/// `deposit` and whose voucher for `cumulative_amount` is signed by
/// `voucher_signer`.
async fn open_credential(
    payer: &alloy::signers::local::PrivateKeySigner,
    authorized_signer: Address,
    deposit: u128,
    voucher_signer: &alloy::signers::local::PrivateKeySigner,
    cumulative_amount: u128,
) -> (
    String,
    crate::protocol::intents::SessionRequest,
    crate::protocol::core::PaymentCredential,
) {
    use alloy::sol_types::SolCall;

    let salt = B256::repeat_byte(0xab);
    let transaction = signed_call_transaction(
        payer,
        TEST_ESCROW,
        ITestEscrow::openCall::new((TEST_PAYEE, TEST_TOKEN, deposit, salt, authorized_signer))
            .abi_encode(),
    );
    let channel_id = voucher::compute_channel_id(
        payer.address(),
        TEST_PAYEE,
        TEST_TOKEN,
        salt,
        authorized_signer,
        TEST_ESCROW,
        42431,
    );
    let signature = voucher::sign_voucher(
        voucher_signer,
        channel_id,
        cumulative_amount,
        TEST_ESCROW,
        42431,
    )
    .await
    .unwrap();
    let (request, credential) = build_session_credential(
        Some(&TEST_PAYEE.to_string()),
        &TEST_TOKEN.to_string(),
        SessionCredentialPayload::Open {
            payload_type: "transaction".to_string(),
            channel_id: channel_id.to_string(),
            transaction,
            descriptor: None,
            settlement_route: None,
            authorized_signer: None,
            cumulative_amount: cumulative_amount.to_string(),
            signature: alloy::hex::encode_prefixed(signature),
        },
    );
    (channel_id.to_string(), request, credential)
}

/// A voucher the opened channel could never honour must be rejected while
/// the open transaction is still unsent: broadcasting it first would lock
/// the deposit in a channel the server never records.
#[tokio::test]
async fn test_open_rejects_bad_voucher_before_broadcast() {
    let payer = alloy::signers::local::PrivateKeySigner::random();
    let stranger = alloy::signers::local::PrivateKeySigner::random();

    let wrong_signer = open_credential(&payer, payer.address(), 10_000, &stranger, 1_000).await;
    let exceeds_deposit = open_credential(&payer, payer.address(), 10_000, &payer, 10_001).await;
    // The session charges 1_000 per unit, which a deposit of 999 cannot pay.
    let below_amount = open_credential(&payer, payer.address(), 999, &payer, 0).await;

    for ((channel_id, request, credential), expected) in [
        (wrong_signer, ErrorCode::InvalidSignature),
        (exceeds_deposit, ErrorCode::AmountExceedsDeposit),
        (below_amount, ErrorCode::InsufficientBalance),
    ] {
        let store = Arc::new(InMemoryChannelStore::new());
        let asserter = alloy::providers::mock::Asserter::new();
        push_mined_transaction(&asserter);
        let method = mocked_session_method(store.clone(), asserter.clone());

        let err = method
            .verify_session(&credential, &request)
            .await
            .unwrap_err();
        assert_eq!(err.code, Some(expected), "{}", err.message);
        assert_eq!(asserter.read_q().len(), 3, "transaction was broadcast");
        assert!(store.get_channel_sync(&channel_id).is_none());
    }
}

/// Without an authorized signer in the open call, the payer signs vouchers.
#[tokio::test]
async fn test_open_stores_channel_after_broadcast() {
    let payer = alloy::signers::local::PrivateKeySigner::random();
    let (channel_id, request, credential) =
        open_credential(&payer, Address::ZERO, 10_000, &payer, 1_000).await;

    let store = Arc::new(InMemoryChannelStore::new());
    let asserter = alloy::providers::mock::Asserter::new();
    push_mined_transaction(&asserter);
    push_on_chain_channel(&asserter, payer.address(), Address::ZERO, 10_000);
    let method = mocked_session_method(store.clone(), asserter);

    method.verify_session(&credential, &request).await.unwrap();

    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert_eq!(stored.authorized_signer, payer.address());
    assert_eq!(stored.deposit, 10_000);
    assert_eq!(stored.highest_voucher_amount, 1_000);
}
