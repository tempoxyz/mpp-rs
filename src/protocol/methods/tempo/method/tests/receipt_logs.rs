use super::*;

#[test]
fn test_event_topics() {
    // Verify event topic constants match keccak256 of event signatures
    // Transfer(address,address,uint256)
    assert_eq!(
        TRANSFER_EVENT_TOPIC,
        alloy::primitives::b256!(
            "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        )
    );

    // TransferWithMemo(address,address,uint256,bytes32)
    assert_eq!(
        TRANSFER_WITH_MEMO_EVENT_TOPIC,
        alloy::primitives::b256!(
            "57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0"
        )
    );
}

#[test]
fn test_match_receipt_transfer_logs_prefers_memo_logs() {
    let currency = Address::repeat_byte(0x20);
    let sender = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let logs = vec![
        make_transfer_log(currency, sender, recipient, amount),
        make_transfer_with_memo_log(currency, sender, recipient, amount, memo),
    ];
    let expected = vec![Transfer {
        amount,
        recipient,
        memo: None,
    }];

    let matched =
        match_receipt_transfer_logs(&logs, sender, currency, &expected, None, None).unwrap();

    assert_eq!(matched, vec![MatchedTransferLog::Memo(memo)]);
}

#[test]
fn test_match_receipt_transfer_logs_with_split_preserves_bound_memo() {
    let currency = Address::repeat_byte(0x20);
    let sender = Address::repeat_byte(0x11);
    let primary = Address::repeat_byte(0x33);
    let split = Address::repeat_byte(0x44);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let logs = vec![
        make_transfer_log(currency, sender, split, U256::from(10u64)),
        make_transfer_with_memo_log(currency, sender, primary, U256::from(90u64), memo),
    ];
    let expected = vec![
        Transfer {
            amount: U256::from(90u64),
            recipient: primary,
            memo: None,
        },
        Transfer {
            amount: U256::from(10u64),
            recipient: split,
            memo: None,
        },
    ];

    let matched =
        match_receipt_transfer_logs(&logs, sender, currency, &expected, None, None).unwrap();

    assert_eq!(matched.len(), 2);
    assert!(matched.contains(&MatchedTransferLog::Memo(memo)));
    assert!(matched.contains(&MatchedTransferLog::Transfer));
}

#[test]
fn test_match_receipt_transfer_logs_merges_transfer_with_memo_twin_logs() {
    let currency = Address::repeat_byte(0x20);
    let sender = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(1000u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let transfer = || make_transfer_log(currency, sender, recipient, amount);
    let transfer_with_memo =
        || make_transfer_with_memo_log(currency, sender, recipient, amount, memo);
    let unrelated =
        || serde_json::json!({ "address": format!("{currency:#x}"), "topics": [], "data": "0x" });
    // amount=2000 with a 1000 split to the primary recipient.
    let expected = vec![
        Transfer {
            amount,
            recipient,
            memo: None,
        };
        2
    ];
    let matched = |logs: &[serde_json::Value]| {
        match_receipt_transfer_logs(logs, sender, currency, &expected, None, None)
    };

    // One transferWithMemo call emits both events but pays only once.
    assert!(matched(&[transfer(), transfer_with_memo()]).is_err());
    assert!(matched(&[transfer_with_memo(), transfer()]).is_err());

    assert_eq!(
        matched(&[
            transfer(),
            transfer_with_memo(),
            transfer(),
            transfer_with_memo()
        ])
        .unwrap(),
        vec![MatchedTransferLog::Memo(memo); 2]
    );
    for logs in [
        [transfer(), transfer_with_memo(), transfer()],
        [transfer(), transfer(), transfer_with_memo()],
    ] {
        let matched = matched(&logs).unwrap();
        assert!(matched.contains(&MatchedTransferLog::Memo(memo)));
        assert!(matched.contains(&MatchedTransferLog::Transfer));
    }

    // Only adjacent logs are twins.
    assert!(matched(&[transfer(), unrelated(), transfer_with_memo()]).is_ok());
}

/// Only logs with the exact shape of the TIP-20 events count as transfers.
#[test]
fn test_match_receipt_transfer_logs_ignores_malformed_logs() {
    let currency = Address::repeat_byte(0x20);
    let sender = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let expected = vec![Transfer {
        amount,
        recipient,
        memo: None,
    }];
    let matched = |log: serde_json::Value| {
        match_receipt_transfer_logs(&[log], sender, currency, &expected, None, None)
    };
    let transfer = || make_transfer_log(currency, sender, recipient, amount);
    let transfer_with_memo =
        || make_transfer_with_memo_log(currency, sender, recipient, amount, memo);

    assert!(matched(transfer()).is_ok());
    assert!(matched(transfer_with_memo()).is_ok());

    // `Transfer` with a third indexed topic, as ERC-721 emits it.
    let mut extra_topic = transfer();
    extra_topic["topics"]
        .as_array_mut()
        .unwrap()
        .push(address_topic(recipient).into());
    assert!(matched(extra_topic).is_err());

    // `Approval(owner, spender, amount)` has the shape of `Transfer`.
    let mut approval = transfer();
    approval["topics"][0] = alloy::primitives::keccak256("Approval(address,address,uint256)")
        .to_string()
        .into();
    assert!(matched(approval).is_err());

    let mut short_amount = transfer();
    short_amount["data"] = "0x64".into();
    assert!(matched(short_amount).is_err());

    let mut missing_memo_topic = transfer_with_memo();
    missing_memo_topic["topics"].as_array_mut().unwrap().pop();
    assert!(matched(missing_memo_topic).is_err());
}

#[test]
fn test_match_receipt_transfer_logs_accepts_canonical_settlement_sender() {
    let currency = Address::repeat_byte(0x20);
    let payer = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let swapper = super::super::super::machine_token::MACHINE_TOKEN_SWAPPER_MAINNET;
    let logs = vec![make_transfer_with_memo_log(
        currency, recipient, recipient, amount, memo,
    )];
    let expected = vec![Transfer {
        amount,
        recipient,
        memo: Some(memo),
    }];

    let rejected = match_receipt_transfer_logs_with_settlement(
        &logs,
        currency,
        &expected,
        ReceiptSenderPolicy {
            expected_sender: payer,
            source: None,
            validate_sender: None,
            transaction_sender: payer,
            settlement_senders: &[swapper],
        },
    );
    assert!(rejected.is_err());

    let logs = vec![make_transfer_with_memo_log(
        currency, swapper, recipient, amount, memo,
    )];
    let matched = match_receipt_transfer_logs_with_settlement(
        &logs,
        currency,
        &expected,
        ReceiptSenderPolicy {
            expected_sender: payer,
            source: None,
            validate_sender: None,
            transaction_sender: payer,
            settlement_senders: &[swapper],
        },
    )
    .unwrap();
    assert_eq!(matched, vec![MatchedTransferLog::Memo(memo)]);

    let wrong_transaction_sender = Address::repeat_byte(0x44);
    assert!(match_receipt_transfer_logs_with_settlement(
        &logs,
        currency,
        &expected,
        ReceiptSenderPolicy {
            expected_sender: payer,
            source: None,
            validate_sender: None,
            transaction_sender: wrong_transaction_sender,
            settlement_senders: &[swapper],
        },
    )
    .is_err());
}

#[test]
fn test_match_transfer_logs_accepts_source_matching_transfer_sender() {
    let currency = Address::repeat_byte(0x20);
    let source = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let logs = vec![make_transfer_with_memo_log(
        currency, source, recipient, amount, memo,
    )];
    let expected = vec![Transfer {
        amount,
        recipient,
        memo: None,
    }];

    let matched =
        match_receipt_transfer_logs(&logs, source, currency, &expected, None, None).unwrap();
    assert_eq!(matched, vec![MatchedTransferLog::Memo(memo)]);
}

#[test]
fn test_match_transfer_logs_rejects_source_differing_from_transfer_sender() {
    let currency = Address::repeat_byte(0x20);
    let declared_source = Address::repeat_byte(0x99);
    let actual_sender = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let logs = vec![make_transfer_log(
        currency,
        actual_sender,
        recipient,
        amount,
    )];
    let expected = vec![Transfer {
        amount,
        recipient,
        memo: None,
    }];

    let err = match_receipt_transfer_logs(&logs, declared_source, currency, &expected, None, None)
        .unwrap_err();
    assert!(err.to_string().contains("No matching transfer event found"));
}

#[test]
fn test_match_transfer_logs_validate_sender_override_allows_mismatch() {
    let currency = Address::repeat_byte(0x20);
    let declared_source = Address::repeat_byte(0x99);
    let actual_sender = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let source_did = did_pkh(MODERATO_CHAIN_ID, declared_source);
    let logs = vec![make_transfer_log(
        currency,
        actual_sender,
        recipient,
        amount,
    )];
    let expected = vec![Transfer {
        amount,
        recipient,
        memo: None,
    }];

    let cb_did = source_did.clone();
    let cb: Box<ValidateSenderCallback> = Box::new(move |v: SenderValidation| {
        assert_eq!(v.expected_sender, declared_source);
        assert_eq!(v.sender, actual_sender);
        assert_eq!(v.source, Some(cb_did.as_str()));
        true
    });
    let matched = match_receipt_transfer_logs(
        &logs,
        declared_source,
        currency,
        &expected,
        Some(&source_did),
        Some(cb.as_ref()),
    )
    .unwrap();
    assert_eq!(matched, vec![MatchedTransferLog::Transfer]);
}

#[test]
fn test_match_transfer_logs_validate_sender_returning_false_rejects() {
    let currency = Address::repeat_byte(0x20);
    let declared_source = Address::repeat_byte(0x99);
    let actual_sender = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let logs = vec![make_transfer_log(
        currency,
        actual_sender,
        recipient,
        amount,
    )];
    let expected = vec![Transfer {
        amount,
        recipient,
        memo: None,
    }];

    let cb: Box<ValidateSenderCallback> = Box::new(|_v: SenderValidation| false);
    let err = match_receipt_transfer_logs(
        &logs,
        declared_source,
        currency,
        &expected,
        None,
        Some(cb.as_ref()),
    )
    .unwrap_err();
    assert!(err.to_string().contains("No matching transfer event found"));
}

#[test]
fn test_match_transfer_logs_validate_sender_not_called_when_sender_matches() {
    let currency = Address::repeat_byte(0x20);
    let source = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let memo = attribution::encode("challenge-123", "api.example.com", None);
    let logs = vec![make_transfer_with_memo_log(
        currency, source, recipient, amount, memo,
    )];
    let expected = vec![Transfer {
        amount,
        recipient,
        memo: None,
    }];

    // Callback panics if invoked; sender already matches.
    let cb: Box<ValidateSenderCallback> = Box::new(|_v: SenderValidation| {
        panic!("validate_sender must not run when sender already matches")
    });
    let matched =
        match_receipt_transfer_logs(&logs, source, currency, &expected, None, Some(cb.as_ref()))
            .unwrap();
    assert_eq!(matched, vec![MatchedTransferLog::Memo(memo)]);
}

#[test]
fn test_match_transfer_logs_validate_sender_not_called_for_memo_incompatible_logs() {
    let currency = Address::repeat_byte(0x20);
    let declared_source = Address::repeat_byte(0x99);
    let wrong_sender = Address::repeat_byte(0x11);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let wanted_memo = attribution::encode("challenge-123", "api.example.com", None);
    let other_memo = attribution::encode("challenge-999", "api.example.com", None);
    // First log has a wrong sender and a non-matching memo; second matches.
    let logs = vec![
        make_transfer_with_memo_log(currency, wrong_sender, recipient, amount, other_memo),
        make_transfer_with_memo_log(currency, declared_source, recipient, amount, wanted_memo),
    ];
    let expected = vec![Transfer {
        amount,
        recipient,
        memo: Some(wanted_memo),
    }];

    let cb: Box<ValidateSenderCallback> = Box::new(|_v: SenderValidation| {
        panic!("validate_sender must not run for memo-incompatible logs")
    });
    let matched = match_receipt_transfer_logs(
        &logs,
        declared_source,
        currency,
        &expected,
        None,
        Some(cb.as_ref()),
    )
    .unwrap();
    assert_eq!(matched, vec![MatchedTransferLog::Memo(wanted_memo)]);
}

#[test]
fn test_assert_challenge_bound_memo_accepts_bound_memo() {
    let memo = attribution::encode("challenge-123", "api.example.com", None);

    assert!(assert_challenge_bound_memo(
        &[MatchedTransferLog::Memo(memo)],
        "challenge-123",
        "api.example.com",
    )
    .is_ok());
}

#[test]
fn test_assert_challenge_bound_memo_rejects_plain_transfer() {
    let error = assert_challenge_bound_memo(
        &[MatchedTransferLog::Transfer],
        "challenge-123",
        "api.example.com",
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("memo is not bound to this challenge"));
}

#[test]
fn test_assert_challenge_bound_memo_rejects_wrong_challenge() {
    let memo = attribution::encode("challenge-123", "api.example.com", None);

    let error = assert_challenge_bound_memo(
        &[MatchedTransferLog::Memo(memo)],
        "challenge-456",
        "api.example.com",
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("memo is not bound to this challenge"));
}

#[test]
fn test_assert_challenge_bound_memo_rejects_non_mpp_memo() {
    let error = assert_challenge_bound_memo(
        &[MatchedTransferLog::Memo([0x11; 32])],
        "challenge-123",
        "api.example.com",
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("memo is not bound to this challenge"));
}

#[test]
fn test_assert_challenge_bound_memo_rejects_wrong_realm() {
    let memo = attribution::encode("challenge-123", "api.example.com", None);

    let error = assert_challenge_bound_memo(
        &[MatchedTransferLog::Memo(memo)],
        "challenge-123",
        "other.example.com",
    )
    .unwrap_err();

    assert!(error
        .to_string()
        .contains("memo is not bound to this challenge"));
}

#[test]
fn test_assert_challenge_bound_memo_rejects_conflicting_attribution() {
    let bound = MatchedTransferLog::Memo(attribution::encode(
        "challenge-123",
        "api.example.com",
        None,
    ));
    let other_challenge = attribution::encode("challenge-456", "api.example.com", None);
    let other_realm = attribution::encode("challenge-123", "other.example.com", None);

    for conflicting in [other_challenge, other_realm].map(MatchedTransferLog::Memo) {
        for matched in [[bound, conflicting], [conflicting, bound]] {
            let error = assert_challenge_bound_memo(&matched, "challenge-123", "api.example.com")
                .unwrap_err();
            assert!(error
                .to_string()
                .contains("memo is not bound to this challenge"));
        }
    }

    // Plain transfers and non-MPP memos carry no attribution to conflict.
    assert!(assert_challenge_bound_memo(
        &[
            MatchedTransferLog::Memo([0x11; 32]),
            MatchedTransferLog::Transfer,
            bound,
        ],
        "challenge-123",
        "api.example.com",
    )
    .is_ok());
}
