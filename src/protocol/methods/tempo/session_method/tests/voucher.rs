use super::*;
use crate::protocol::methods::tempo::voucher;

#[tokio::test]
async fn test_stale_voucher_with_garbage_signature_rejected() {
    use alloy::signers::local::PrivateKeySigner;

    let signer = PrivateKeySigner::random();
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id = format!("0x{}", "ab".repeat(32));

    // Set up channel with a known highest_voucher_amount and valid signature
    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    state.highest_voucher_signature = Some(vec![0xAA; 65]);
    state.deposit = 100_000;
    store.insert(&channel_id, state.clone());

    let method = test_session_method(store);

    // Submit a stale voucher (cumulative_amount=0 <= highest=1000) with garbage signature.
    // This should be REJECTED because the signature is invalid.
    let garbage_sig = format!("0x{}", "ff".repeat(65));
    let result = method
        .verify_and_accept_voucher(
            &channel_id,
            &state,
            0,            // cumulative_amount <= highest_voucher_amount
            &garbage_sig, // garbage signature
            state.escrow_contract,
            42431,
            0,       // min_delta
            100_000, // deposit
            0,       // settled
            false,   // not finalized
            0,       // no close request
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidSignature));
}

#[tokio::test]
async fn test_stale_voucher_same_amount_different_signature_rejected() {
    use crate::protocol::methods::tempo::voucher::sign_voucher;
    use alloy::signers::local::PrivateKeySigner;

    let signer = PrivateKeySigner::random();
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id_hex = format!("0x{}", "ab".repeat(32));
    let channel_id_b256 = channel_id_hex.parse::<alloy::primitives::B256>().unwrap();
    let escrow: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();

    // Sign a real voucher for amount=1000
    let real_sig = sign_voucher(&signer, channel_id_b256, 1000u128, escrow, 42431)
        .await
        .unwrap();

    let mut state = test_channel_state(&channel_id_hex);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1000;
    state.highest_voucher_signature = Some(real_sig.to_vec());
    state.deposit = 100_000;
    store.insert(&channel_id_hex, state.clone());

    let method = test_session_method(store);

    // Submit same amount but forged signature — should be rejected
    let forged_sig = format!("0x{}", "cd".repeat(65));
    let result = method
        .verify_and_accept_voucher(
            &channel_id_hex,
            &state,
            1000,        // same amount as highest
            &forged_sig, // different signature
            escrow,
            42431,
            0,
            100_000,
            0,
            false,
            0,
        )
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Some(ErrorCode::InvalidSignature));
}

#[tokio::test]
async fn test_exact_replay_of_highest_voucher_rejected() {
    use crate::protocol::methods::tempo::voucher::sign_voucher;
    use alloy::signers::local::PrivateKeySigner;

    let signer = PrivateKeySigner::random();
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id_hex = format!("0x{}", "ab".repeat(32));
    let channel_id_b256 = channel_id_hex.parse::<alloy::primitives::B256>().unwrap();
    let escrow: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();

    let real_sig = sign_voucher(&signer, channel_id_b256, 1000u128, escrow, 42431)
        .await
        .unwrap();
    let sig_hex = format!("0x{}", alloy::primitives::hex::encode(&real_sig));

    let mut state = test_channel_state(&channel_id_hex);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1000;
    state.highest_voucher_signature = Some(real_sig.to_vec());
    state.deposit = 100_000;
    store.insert(&channel_id_hex, state.clone());

    let method = test_session_method(store);

    // Exact replay: same amount and same signature does not add new funds.
    let result = method
        .verify_and_accept_voucher(
            &channel_id_hex,
            &state,
            1000,
            &sig_hex,
            escrow,
            42431,
            0,
            100_000,
            0,
            false,
            0,
        )
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, Some(ErrorCode::DeltaTooSmall));
}

#[tokio::test]
async fn test_concurrent_voucher_acceptance_has_one_winner() {
    use crate::protocol::methods::tempo::voucher::sign_voucher;
    use alloy::signers::local::PrivateKeySigner;

    let signer = PrivateKeySigner::random();
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id = format!("0x{}", "ab".repeat(32));
    let channel_id_b256 = channel_id.parse::<B256>().unwrap();
    let escrow: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();
    let signature = sign_voucher(&signer, channel_id_b256, 2_000, escrow, 42431)
        .await
        .unwrap();
    let signature_bytes = signature.to_vec();
    let signature = alloy::hex::encode_prefixed(signature);

    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    state.deposit = 10_000;
    store.insert(&channel_id, state.clone());

    let method = test_session_method(store.clone());
    let verify = || {
        method.verify_and_accept_voucher(
            &channel_id,
            &state,
            2_000,
            &signature,
            escrow,
            42431,
            0,
            10_000,
            0,
            false,
            0,
        )
    };
    let (first, second) = tokio::join!(verify(), verify());

    assert_eq!(
        [first.is_ok(), second.is_ok()]
            .into_iter()
            .filter(|accepted| *accepted)
            .count(),
        1
    );
    let error = first.err().or_else(|| second.err()).unwrap();
    assert_eq!(error.code, Some(ErrorCode::DeltaTooSmall));

    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert_eq!(stored.highest_voucher_amount, 2_000);
    assert_eq!(stored.highest_voucher_signature, Some(signature_bytes));
}

#[tokio::test]
async fn test_concurrent_vouchers_recheck_minimum_delta_atomically() {
    use crate::protocol::methods::tempo::voucher::sign_voucher;
    use alloy::signers::local::PrivateKeySigner;

    let signer = PrivateKeySigner::random();
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id = format!("0x{}", "ab".repeat(32));
    let channel_id_b256 = channel_id.parse::<B256>().unwrap();
    let escrow: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();
    let lower_signature = sign_voucher(&signer, channel_id_b256, 2_000, escrow, 42431)
        .await
        .unwrap();
    let higher_signature = sign_voucher(&signer, channel_id_b256, 2_500, escrow, 42431)
        .await
        .unwrap();
    let lower_signature = alloy::hex::encode_prefixed(lower_signature);
    let higher_signature = alloy::hex::encode_prefixed(higher_signature);

    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    state.deposit = 10_000;
    store.insert(&channel_id, state.clone());

    let method = test_session_method(store.clone());
    let lower = method.verify_and_accept_voucher(
        &channel_id,
        &state,
        2_000,
        &lower_signature,
        escrow,
        42431,
        1_000,
        10_000,
        0,
        false,
        0,
    );
    let higher = method.verify_and_accept_voucher(
        &channel_id,
        &state,
        2_500,
        &higher_signature,
        escrow,
        42431,
        1_000,
        10_000,
        0,
        false,
        0,
    );
    let (lower, higher) = tokio::join!(lower, higher);

    assert!(lower.is_ok());
    assert_eq!(higher.unwrap_err().code, Some(ErrorCode::DeltaTooSmall));
    assert_eq!(
        store
            .get_channel_sync(&channel_id)
            .unwrap()
            .highest_voucher_amount,
        2_000
    );
}

#[tokio::test]
async fn test_accept_voucher_preserves_concurrent_deposit_update() {
    use crate::protocol::methods::tempo::voucher::sign_voucher;
    use alloy::signers::local::PrivateKeySigner;

    let signer = PrivateKeySigner::random();
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id_hex = format!("0x{}", "ab".repeat(32));
    let channel_id_b256 = channel_id_hex.parse::<alloy::primitives::B256>().unwrap();
    let escrow: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();

    let sig = sign_voucher(&signer, channel_id_b256, 2_000u128, escrow, 42431)
        .await
        .unwrap();
    let sig_hex = format!("0x{}", alloy::primitives::hex::encode(&sig));

    let mut stale_state = test_channel_state(&channel_id_hex);
    stale_state.authorized_signer = signer.address();
    stale_state.highest_voucher_amount = 1_000;
    stale_state.deposit = 10_000;

    let mut current_state = stale_state.clone();
    current_state.deposit = 20_000;
    store.insert(&channel_id_hex, current_state);

    let method = test_session_method(store.clone());
    method
        .verify_and_accept_voucher(
            &channel_id_hex,
            &stale_state,
            2_000,
            &sig_hex,
            escrow,
            42431,
            0,
            stale_state.deposit,
            0,
            false,
            0,
        )
        .await
        .unwrap();

    let updated = store.get_channel(&channel_id_hex).await.unwrap().unwrap();
    assert_eq!(updated.highest_voucher_amount, 2_000);
    assert_eq!(updated.deposit, 20_000);
}

#[tokio::test]
async fn test_stale_voucher_with_forged_keychain_envelope_rejected() {
    use alloy::signers::local::PrivateKeySigner;

    let signer = PrivateKeySigner::random();
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id = format!("0x{}", "ab".repeat(32));

    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    state.highest_voucher_signature = Some(vec![0xAA; 65]);
    state.deposit = 100_000;
    store.insert(&channel_id, state.clone());

    let method = test_session_method(store);

    // Forge a keychain envelope: 0x03 + authorized_signer address + garbage inner sig.
    // This previously would have passed verify_voucher because it only checked the
    // embedded address against expected_signer without verifying the inner signature.
    let mut forged_envelope = vec![0x03u8];
    forged_envelope.extend_from_slice(signer.address().as_slice());
    forged_envelope.extend_from_slice(&[0xBB; 65]);
    let forged_sig = alloy::hex::encode_prefixed(&forged_envelope);

    let result = method
        .verify_and_accept_voucher(
            &channel_id,
            &state,
            500, // stale: below highest_voucher_amount of 1000
            &forged_sig,
            state.escrow_contract,
            42431,
            0,
            100_000,
            0,
            false,
            0,
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(
        err.code,
        Some(crate::protocol::traits::ErrorCode::InvalidSignature)
    );
}

#[tokio::test]
async fn test_voucher_signature_must_be_canonical() {
    use crate::protocol::methods::tempo::voucher::sign_voucher;
    use alloy::primitives::{Signature, U256};
    use alloy::signers::local::PrivateKeySigner;

    let signer = PrivateKeySigner::random();
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id = format!("0x{}", "ab".repeat(32));
    let channel_id_b256 = channel_id.parse::<B256>().unwrap();
    let escrow: Address = "0x5555555555555555555555555555555555555555"
        .parse()
        .unwrap();
    let signature = sign_voucher(&signer, channel_id_b256, 2_000, escrow, 42431)
        .await
        .unwrap()
        .to_vec();
    let parsed = Signature::from_raw(&signature).unwrap();

    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    state.deposit = 10_000;
    store.insert(&channel_id, state.clone());

    let method = test_session_method(store.clone());
    let submit = |signature: Vec<u8>| {
        let signature = alloy::hex::encode_prefixed(signature);
        let (method, channel_id, state) = (&method, &channel_id, &state);
        async move {
            method
                .verify_and_accept_voucher(
                    channel_id, state, 2_000, &signature, escrow, 42431, 0, 10_000, 0, false, 0,
                )
                .await
        }
    };

    let order = U256::from_str_radix(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )
    .unwrap();
    let high_s = Signature::new(parsed.r(), order - parsed.s(), !parsed.v());
    let with_trailer = [signature.as_slice(), &[0x77; 32]].concat();
    for rejected in [high_s.as_bytes().to_vec(), with_trailer] {
        let err = submit(rejected).await.unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::InvalidSignature));
    }
    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert_eq!(stored.highest_voucher_amount, 1_000);

    // An EIP-2098 compact signature is accepted and stored in the 65-byte form.
    submit(parsed.as_erc2098().to_vec()).await.unwrap();
    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert_eq!(stored.highest_voucher_amount, 2_000);
    assert_eq!(stored.highest_voucher_signature, Some(signature));
}

/// A voucher referencing a channel opened for a different payee must
/// be rejected to prevent cross-session channel reuse.
#[tokio::test]
async fn test_voucher_rejects_channel_with_wrong_payee() {
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id = format!("0x{}", "ab".repeat(32));

    // Store a channel whose payee is 0x2222...
    let mut state = test_channel_state(&channel_id);
    state.highest_voucher_amount = 500;
    state.deposit = 100_000;
    store.insert(&channel_id, state);

    let method = test_session_method(store);

    // Challenge expects recipient 0x9999... (different from stored 0x2222...)
    let (request, credential) = build_session_credential(
        Some("0x9999999999999999999999999999999999999999"),
        "0x3333333333333333333333333333333333333333", // matches stored token
        SessionCredentialPayload::Voucher {
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

/// A voucher referencing a channel opened for a different
/// token/currency must be rejected to prevent cross-session channel reuse.
#[tokio::test]
async fn test_voucher_rejects_channel_with_wrong_token() {
    let store = Arc::new(InMemoryChannelStore::new());
    let channel_id = format!("0x{}", "ab".repeat(32));

    // Store a channel whose token is 0x3333...
    let mut state = test_channel_state(&channel_id);
    state.highest_voucher_amount = 500;
    state.deposit = 100_000;
    store.insert(&channel_id, state);

    let method = test_session_method(store);

    // Challenge expects currency 0x9999... (different from stored 0x3333...)
    let (request, credential) = build_session_credential(
        Some("0x2222222222222222222222222222222222222222"), // matches stored payee
        "0x9999999999999999999999999999999999999999",       // wrong token
        SessionCredentialPayload::Voucher {
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
        err.message.contains("token"),
        "expected token mismatch error, got: {}",
        err.message
    );
}

/// Channel IDs are hex, so a credential may spell one in any case. It must
/// resolve to the channel that is stored under the lowercase ID.
#[tokio::test]
async fn test_voucher_accepts_mixed_case_channel_id() {
    use alloy::providers::{mock::Asserter, ProviderBuilder};
    use alloy::sol_types::SolValue;

    /// Store that looks channels up by the exact key it is given.
    struct ExactKeyStore(InMemoryChannelStore);

    impl ChannelStore for ExactKeyStore {
        fn get_channel(
            &self,
            channel_id: &str,
        ) -> std::pin::Pin<
            Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
        > {
            let result = self.0.channels.lock().unwrap().get(channel_id).cloned();
            Box::pin(async move { Ok(result) })
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
            let mut channels = self.0.channels.lock().unwrap();
            let result = updater(channels.get(channel_id).cloned());
            if let Ok(Some(state)) = &result {
                channels.insert(channel_id.to_string(), state.clone());
            }
            Box::pin(async move { result })
        }
    }

    let signer = alloy::signers::local::PrivateKeySigner::random();
    let lower = format!("0x{}", "ab".repeat(32));
    let upper = format!("0x{}", "AB".repeat(32));
    let mut state = test_channel_state(&lower);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    let store = Arc::new(ExactKeyStore(InMemoryChannelStore::new()));
    store.0.insert(&lower, state.clone());

    let asserter = Asserter::new();
    asserter.push_success(&Bytes::from(
        (
            false,
            0u64,
            state.payer,
            state.payee,
            state.token,
            state.authorized_signer,
            state.deposit,
            0u128,
        )
            .abi_encode_params(),
    ));
    let method = SessionMethod::new(
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_mocked_client(asserter),
        store.clone(),
        SessionMethodConfig {
            escrow_contract: state.escrow_contract,
            chain_id: state.chain_id,
            min_voucher_delta: 0,
        },
    );

    let signature = voucher::sign_voucher(
        &signer,
        lower.parse().unwrap(),
        2_000,
        state.escrow_contract,
        state.chain_id,
    )
    .await
    .unwrap();
    let (request, credential) = build_session_credential(
        Some("0x2222222222222222222222222222222222222222"),
        "0x3333333333333333333333333333333333333333",
        SessionCredentialPayload::Voucher {
            channel_id: upper,
            descriptor: None,
            settlement_route: None,
            cumulative_amount: "2000".to_string(),
            signature: alloy::hex::encode_prefixed(signature),
        },
    );

    let receipt = method.verify_session(&credential, &request).await.unwrap();
    assert_eq!(receipt.reference, lower);
    let channels = store.0.channels.lock().unwrap();
    assert_eq!(channels.len(), 1);
    assert_eq!(channels[&lower].highest_voucher_amount, 2_000);
}

/// A voucher receipt reports the channel's balance and carries no
/// transaction hash.
#[tokio::test]
async fn test_voucher_returns_session_receipt() {
    use alloy::sol_types::SolValue;

    let signer = alloy::signers::local::PrivateKeySigner::random();
    let channel_id = format!("0x{}", "ab".repeat(32));
    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    state.spent = 400;
    state.units = 4;
    let store = Arc::new(InMemoryChannelStore::new());
    store.insert(&channel_id, state.clone());

    let asserter = alloy::providers::mock::Asserter::new();
    asserter.push_success(&Bytes::from(
        (
            false,
            0u64,
            state.payer,
            state.payee,
            state.token,
            state.authorized_signer,
            state.deposit,
            0u128,
        )
            .abi_encode_params(),
    ));
    let method = mocked_session_method(store, asserter);

    let signature = voucher::sign_voucher(
        &signer,
        channel_id.parse().unwrap(),
        2_000,
        state.escrow_contract,
        state.chain_id,
    )
    .await
    .unwrap();
    let (request, credential) = build_session_credential(
        Some("0x2222222222222222222222222222222222222222"),
        "0x3333333333333333333333333333333333333333",
        SessionCredentialPayload::Voucher {
            channel_id: channel_id.clone(),
            descriptor: None,
            settlement_route: None,
            cumulative_amount: "2000".to_string(),
            signature: alloy::hex::encode_prefixed(signature),
        },
    );

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
            "acceptedCumulative": "2000",
            "spent": "400",
            "units": 4,
        })
    );
}

/// Amounts are decimal digits only. `u128::from_str` would also read a
/// leading `+`, so the same voucher could be spelled in two ways.
#[tokio::test]
async fn test_voucher_rejects_signed_amount() {
    let signer = alloy::signers::local::PrivateKeySigner::random();
    let channel_id = format!("0x{}", "ab".repeat(32));
    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    state.highest_voucher_amount = 1_000;
    let store = Arc::new(InMemoryChannelStore::new());
    store.insert(&channel_id, state.clone());

    let asserter = alloy::providers::mock::Asserter::new();
    push_on_chain_channel(
        &asserter,
        state.payer,
        state.authorized_signer,
        state.deposit,
    );
    let method = mocked_session_method(store.clone(), asserter);

    let signature = voucher::sign_voucher(
        &signer,
        channel_id.parse().unwrap(),
        2_000,
        state.escrow_contract,
        state.chain_id,
    )
    .await
    .unwrap();
    let (request, credential) = build_session_credential(
        Some("0x2222222222222222222222222222222222222222"),
        "0x3333333333333333333333333333333333333333",
        SessionCredentialPayload::Voucher {
            channel_id: channel_id.clone(),
            descriptor: None,
            settlement_route: None,
            cumulative_amount: "+2000".to_string(),
            signature: alloy::hex::encode_prefixed(signature),
        },
    );

    let err = method
        .verify_session(&credential, &request)
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidPayload));
    assert_eq!(err.message, "invalid cumulativeAmount");
    assert_eq!(
        store
            .get_channel_sync(&channel_id)
            .unwrap()
            .highest_voucher_amount,
        1_000
    );
}

/// Builds a voucher credential for `amount` on a stored channel whose
/// vouchers `signer` signs.
async fn voucher_credential(
    signer: &alloy::signers::local::PrivateKeySigner,
    state: &ChannelState,
    amount: u128,
) -> (
    crate::protocol::intents::SessionRequest,
    crate::protocol::core::PaymentCredential,
) {
    let signature = voucher::sign_voucher(
        signer,
        state.channel_id.parse().unwrap(),
        amount,
        state.escrow_contract,
        state.chain_id,
    )
    .await
    .unwrap();
    build_session_credential(
        Some(&TEST_PAYEE.to_string()),
        &TEST_TOKEN.to_string(),
        SessionCredentialPayload::Voucher {
            channel_id: state.channel_id.clone(),
            descriptor: None,
            settlement_route: None,
            cumulative_amount: amount.to_string(),
            signature: alloy::hex::encode_prefixed(signature),
        },
    )
}

/// A node that lags behind a top-up reports the old deposit. The deposit
/// only grows while a channel is open, so the recorded one stays.
#[tokio::test]
async fn test_voucher_keeps_deposit_when_chain_read_is_stale() {
    let signer = alloy::signers::local::PrivateKeySigner::random();
    let channel_id = format!("0x{}", "ab".repeat(32));
    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    let store = Arc::new(InMemoryChannelStore::new());
    store.insert(&channel_id, state.clone());

    let asserter = alloy::providers::mock::Asserter::new();
    push_on_chain_channel(
        &asserter,
        state.payer,
        state.authorized_signer,
        state.deposit - 50_000,
    );
    let method = mocked_session_method(store.clone(), asserter);

    let (request, credential) = voucher_credential(&signer, &state, state.deposit).await;
    method.verify_session(&credential, &request).await.unwrap();

    let stored = store.get_channel_sync(&channel_id).unwrap();
    assert_eq!(stored.deposit, state.deposit);
    assert_eq!(stored.highest_voucher_amount, state.deposit);
}

/// A close that finalizes the channel while a voucher awaits the chain
/// must not be undone by that voucher's older on-chain snapshot.
#[tokio::test]
async fn test_voucher_does_not_reopen_finalized_channel() {
    let signer = alloy::signers::local::PrivateKeySigner::random();
    let channel_id = format!("0x{}", "ab".repeat(32));
    let mut state = test_channel_state(&channel_id);
    state.authorized_signer = signer.address();
    let store = Arc::new(ChangeAfterRead::new(|state| ChannelState {
        finalized: true,
        ..state
    }));
    store.inner.insert(&channel_id, state.clone());

    let asserter = alloy::providers::mock::Asserter::new();
    push_on_chain_channel(
        &asserter,
        state.payer,
        state.authorized_signer,
        state.deposit,
    );
    let method = mocked_session_method(store.clone(), asserter);

    let (request, credential) = voucher_credential(&signer, &state, 2_000).await;
    let err = method
        .verify_session(&credential, &request)
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::ChannelClosed));

    let stored = store.inner.get_channel_sync(&channel_id).unwrap();
    assert!(stored.finalized);
    assert_eq!(stored.highest_voucher_amount, 0);
}
