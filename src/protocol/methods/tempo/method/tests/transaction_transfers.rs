use super::*;

#[test]
fn test_transfer_selector() {
    // transfer(address,uint256) = 0xa9059cbb
    assert_eq!(TRANSFER_SELECTOR, [0xa9, 0x05, 0x9c, 0xbb]);
}

#[test]
fn test_transfer_with_memo_selector() {
    // transferWithMemo(address,uint256,bytes32) = 0x95777d59
    assert_eq!(TRANSFER_WITH_MEMO_SELECTOR, [0x95, 0x77, 0x7d, 0x59]);
}

#[test]
fn test_calldata_length_constants() {
    // Verify the expected calldata lengths match ABI encoding
    // transfer(address,uint256): 4 + 32 + 32 = 68
    // transferWithMemo(address,uint256,bytes32): 4 + 32 + 32 + 32 = 100
    const TRANSFER_CALLDATA_LEN: usize = 4 + 32 + 32;
    const TRANSFER_WITH_MEMO_CALLDATA_LEN: usize = 4 + 32 + 32 + 32;

    assert_eq!(TRANSFER_CALLDATA_LEN, 68);
    assert_eq!(TRANSFER_WITH_MEMO_CALLDATA_LEN, 100);
}

#[test]
fn test_selector_parsing_short_input() {
    // Ensure short inputs don't panic - test with various short lengths
    let short_inputs: Vec<&[u8]> = vec![&[], &[0xa9], &[0xa9, 0x05], &[0xa9, 0x05, 0x9c]];

    for input in short_inputs {
        // This mimics the parsing logic - should not panic
        if input.len() >= 4 {
            let _selector: [u8; 4] = input[..4].try_into().unwrap_or([0; 4]);
        }
    }
}

#[test]
fn test_validate_transaction_transfers_rejects_unexpected_fee_payer_calls() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let expected = vec![Transfer {
        amount: U256::from(100u64),
        recipient,
        memo: None,
    }];

    let tx_bytes = encode_signed_tx(
        vec![
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_input(recipient, U256::from(100u64)),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(Address::repeat_byte(0x44)),
                value: U256::ZERO,
                input: Bytes::from(vec![0u8; 4]),
            },
        ],
        MAX_FEE_PAYER_GAS_LIMIT,
    );

    let error = method
        .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
        .unwrap_err();

    assert!(
        error.to_string().contains("disallowed call pattern")
            || error.to_string().contains("no matching payment call")
    );
}

#[test]
fn test_validate_transaction_transfers_accepts_fee_payer_approve_swap_prefix() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let token_in = Address::repeat_byte(0x11);
    let expected = vec![Transfer {
        amount: U256::from(100u64),
        recipient,
        memo: None,
    }];

    let tx_bytes = encode_signed_tx(
        vec![
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(token_in),
                value: U256::ZERO,
                input: make_approve_input(STABLECOIN_DEX_ADDRESS, U256::from(100u64)),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                value: U256::ZERO,
                input: make_swap_input(token_in, currency, 100),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_input(recipient, U256::from(100u64)),
            },
        ],
        MAX_FEE_PAYER_GAS_LIMIT,
    );

    method
        .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
        .unwrap();
}

#[test]
fn test_validate_transaction_transfers_accepts_exact_machine_token_route() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);
    let currency = Address::repeat_byte(0x20);
    let expected = vec![Transfer {
        amount: U256::from(100u64),
        recipient: Address::repeat_byte(0x33),
        memo: Some([0xab; 32]),
    }];
    let route = super::super::super::machine_token::route(CHAIN_ID, currency, &expected).unwrap();
    let tx_bytes = encode_signed_tx(route.calls.to_vec(), MAX_FEE_PAYER_GAS_LIMIT);

    let settlement_sender = method
        .validate_transaction_transfers_with_machine_token(
            &tx_bytes,
            currency,
            &expected,
            CHAIN_ID,
            TransactionValidationOptions {
                require_exact_calls: true,
                machine_token_enabled: true,
                challenge_binding: None,
            },
        )
        .unwrap();
    assert_eq!(settlement_sender, Some(route.settlement_sender));

    assert!(method
        .validate_transaction_transfers_with_machine_token(
            &tx_bytes,
            currency,
            &expected,
            CHAIN_ID,
            TransactionValidationOptions {
                require_exact_calls: true,
                ..Default::default()
            },
        )
        .is_err());
}

#[test]
fn test_validate_transaction_transfers_checks_challenge_bound_memo() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);
    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100u64);
    let bound = attribution::encode("challenge-123", "api.example.com", None);
    let cases = [
        ("matching challenge", Some(bound), true),
        (
            "wrong challenge",
            Some(attribution::encode(
                "challenge-456",
                "api.example.com",
                None,
            )),
            false,
        ),
        (
            "wrong realm",
            Some(attribution::encode(
                "challenge-123",
                "other.example.com",
                None,
            )),
            false,
        ),
        ("non-MPP memo", Some([0xab; 32]), false),
        ("plain transfer", None, false),
    ];

    for require_exact_calls in [false, true] {
        for (name, memo, should_accept) in cases {
            for split in [false, true] {
                for reverse in [false, true] {
                    let mut expected = vec![Transfer {
                        amount,
                        recipient,
                        memo: None,
                    }];
                    let input = match memo {
                        Some(memo) => make_transfer_with_memo_input(recipient, amount, memo),
                        None => make_transfer_input(recipient, amount),
                    };
                    let mut calls = vec![tempo_alloy::primitives::transaction::Call {
                        to: TxKind::Call(currency),
                        value: U256::ZERO,
                        input,
                    }];
                    if split {
                        let split_recipient = Address::repeat_byte(0x44);
                        expected.push(Transfer {
                            amount,
                            recipient: split_recipient,
                            memo: Some([0xcd; 32]),
                        });
                        calls.push(tempo_alloy::primitives::transaction::Call {
                            to: TxKind::Call(currency),
                            value: U256::ZERO,
                            input: make_transfer_with_memo_input(
                                split_recipient,
                                amount,
                                [0xcd; 32],
                            ),
                        });
                    }
                    if reverse {
                        calls.reverse();
                    }
                    let tx_bytes = encode_signed_tx(calls, MAX_FEE_PAYER_GAS_LIMIT);
                    let result = method.validate_transaction_transfers_with_machine_token(
                        &tx_bytes,
                        currency,
                        &expected,
                        CHAIN_ID,
                        TransactionValidationOptions {
                            require_exact_calls,
                            challenge_binding: Some(("challenge-123", "api.example.com")),
                            ..Default::default()
                        },
                    );
                    assert_eq!(result.is_ok(), should_accept,
                        "case: {name}, exact: {require_exact_calls}, split: {split}, reverse: {reverse}");
                    if let Err(error) = result {
                        assert!(
                            error
                                .to_string()
                                .contains("memo is not bound to this challenge"),
                            "case: {name}; unexpected error: {error}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn test_validate_transaction_transfers_rejects_conflicting_attribution() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);
    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let split_recipient = Address::repeat_byte(0x44);
    let amount = U256::from(100u64);
    let realm = "api.example.com";
    // One transaction paying the primary transfer of `challenge-456` and
    // the split of `challenge-123`.
    let calls = vec![
        tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(currency),
            value: U256::ZERO,
            input: make_transfer_with_memo_input(
                recipient,
                amount,
                attribution::encode("challenge-456", realm, None),
            ),
        },
        tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(currency),
            value: U256::ZERO,
            input: make_transfer_with_memo_input(
                split_recipient,
                amount,
                attribution::encode("challenge-123", realm, None),
            ),
        },
    ];
    let primary = Transfer {
        amount,
        recipient,
        memo: None,
    };
    let split = Transfer {
        amount,
        recipient: split_recipient,
        memo: None,
    };

    for reverse in [false, true] {
        let mut calls = calls.clone();
        if reverse {
            calls.reverse();
        }
        let tx_bytes = encode_signed_tx(calls, MAX_FEE_PAYER_GAS_LIMIT);
        let validate = |challenge_id, expected: &[Transfer], require_exact_calls| {
            method.validate_transaction_transfers_with_machine_token(
                &tx_bytes,
                currency,
                expected,
                CHAIN_ID,
                TransactionValidationOptions {
                    require_exact_calls,
                    challenge_binding: Some((challenge_id, realm)),
                    ..Default::default()
                },
            )
        };

        for require_exact_calls in [false, true] {
            let error = validate(
                "challenge-123",
                &[primary.clone(), split.clone()],
                require_exact_calls,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("memo is not bound to this challenge"),
                "unexpected error: {error}"
            );
        }
        // The unmatched split transfer does not affect the other challenge.
        assert!(validate("challenge-456", std::slice::from_ref(&primary), false).is_ok());
    }
}

#[test]
fn test_machine_token_route_checks_challenge_binding() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);
    let currency = Address::repeat_byte(0x20);
    let expected = vec![Transfer {
        amount: U256::from(100),
        recipient: Address::repeat_byte(0x33),
        memo: None,
    }];
    for (memo, should_accept) in [
        (
            attribution::encode("challenge-123", "api.example.com", None),
            true,
        ),
        (
            attribution::encode("challenge-456", "api.example.com", None),
            false,
        ),
        (
            attribution::encode("challenge-123", "other.example.com", None),
            false,
        ),
        ([0xab; 32], false),
    ] {
        let mut actual = expected.clone();
        actual[0].memo = Some(memo);
        let route = super::super::super::machine_token::route(CHAIN_ID, currency, &actual).unwrap();
        let tx_bytes = encode_signed_tx(route.calls.to_vec(), MAX_FEE_PAYER_GAS_LIMIT);
        let result = method.validate_transaction_transfers_with_machine_token(
            &tx_bytes,
            currency,
            &expected,
            CHAIN_ID,
            TransactionValidationOptions {
                require_exact_calls: true,
                machine_token_enabled: true,
                challenge_binding: Some(("challenge-123", "api.example.com")),
            },
        );
        assert_eq!(result.is_ok(), should_accept);
        match result {
            Ok(sender) => assert_eq!(sender, Some(route.settlement_sender)),
            Err(error) => assert!(error
                .to_string()
                .contains("memo is not bound to this challenge")),
        }
    }
}

#[test]
fn test_legacy_primary_memo_does_not_disable_challenge_binding() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);
    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let amount = U256::from(100);
    for (memo, should_accept) in [
        (
            attribution::encode("challenge-123", "api.example.com", None),
            true,
        ),
        ([0xab; 32], false),
    ] {
        let tx_bytes = encode_signed_tx(
            vec![tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_with_memo_input(recipient, amount, memo),
            }],
            MAX_FEE_PAYER_GAS_LIMIT,
        );
        let request = ChargeRequest {
            amount: amount.to_string(),
            currency: format!("{currency:#x}"),
            recipient: Some(format!("{recipient:#x}")),
            method_details: Some(
                serde_json::json!({ "chainId": CHAIN_ID, "memo": alloy::hex::encode_prefixed([0xab; 32]) }),
            ),
            ..Default::default()
        };
        let result = method.validate_transaction_credential(
            &alloy::hex::encode_prefixed(&tx_bytes),
            &request,
            CHAIN_ID,
            "challenge-123",
            "api.example.com",
        );
        assert_eq!(result.is_ok(), should_accept);
    }
}

#[test]
fn test_validate_transaction_transfers_accepts_fee_payer_approve_swap_prefix_with_splits() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    let currency = Address::repeat_byte(0x20);
    let primary_recipient = Address::repeat_byte(0x33);
    let split_recipient = Address::repeat_byte(0x34);
    let token_in = Address::repeat_byte(0x11);
    let expected = vec![
        Transfer {
            amount: U256::from(90u64),
            recipient: primary_recipient,
            memo: None,
        },
        Transfer {
            amount: U256::from(10u64),
            recipient: split_recipient,
            memo: None,
        },
    ];

    let tx_bytes = encode_signed_tx(
        vec![
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(token_in),
                value: U256::ZERO,
                input: make_approve_input(STABLECOIN_DEX_ADDRESS, U256::from(100u64)),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                value: U256::ZERO,
                input: make_swap_input(token_in, currency, 100),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_input(primary_recipient, U256::from(90u64)),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_input(split_recipient, U256::from(10u64)),
            },
        ],
        MAX_FEE_PAYER_GAS_LIMIT,
    );

    method
        .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
        .unwrap();
}

#[test]
fn test_validate_transaction_transfers_rejects_fee_payer_swap_without_approve() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let token_in = Address::repeat_byte(0x11);
    let expected = vec![Transfer {
        amount: U256::from(100u64),
        recipient,
        memo: None,
    }];

    let tx_bytes = encode_signed_tx(
        vec![
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                value: U256::ZERO,
                input: make_swap_input(token_in, currency, 100),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_input(recipient, U256::from(100u64)),
            },
        ],
        MAX_FEE_PAYER_GAS_LIMIT,
    );

    let error = method
        .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
        .unwrap_err();

    assert!(
        error.to_string().contains("disallowed call pattern")
            || error.to_string().contains("no matching payment call")
    );
}

#[test]
fn test_validate_transaction_transfers_rejects_fee_payer_wrong_approve_spender() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let token_in = Address::repeat_byte(0x11);
    let expected = vec![Transfer {
        amount: U256::from(100u64),
        recipient,
        memo: None,
    }];

    let tx_bytes = encode_signed_tx(
        vec![
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(token_in),
                value: U256::ZERO,
                input: make_approve_input(Address::repeat_byte(0x99), U256::from(100u64)),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                value: U256::ZERO,
                input: make_swap_input(token_in, currency, 100),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_input(recipient, U256::from(100u64)),
            },
        ],
        MAX_FEE_PAYER_GAS_LIMIT,
    );

    let error = method
        .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
        .unwrap_err();

    assert!(error.to_string().contains("approve spender is not the DEX"));
}

#[test]
fn test_validate_transaction_transfers_rejects_fee_payer_wrong_approve_target() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let token_in = Address::repeat_byte(0x11);
    let expected = vec![Transfer {
        amount: U256::from(100u64),
        recipient,
        memo: None,
    }];

    let tx_bytes = encode_signed_tx(
        vec![
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(Address::repeat_byte(0x99)),
                value: U256::ZERO,
                input: make_approve_input(STABLECOIN_DEX_ADDRESS, U256::from(100u64)),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                value: U256::ZERO,
                input: make_swap_input(token_in, currency, 100),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_input(recipient, U256::from(100u64)),
            },
        ],
        MAX_FEE_PAYER_GAS_LIMIT,
    );

    let error = method
        .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("approve target is not the swap input token"));
}

#[test]
fn test_validate_transaction_transfers_rejects_fee_payer_wrong_swap_target() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let token_in = Address::repeat_byte(0x11);
    let expected = vec![Transfer {
        amount: U256::from(100u64),
        recipient,
        memo: None,
    }];

    let tx_bytes = encode_signed_tx(
        vec![
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(token_in),
                value: U256::ZERO,
                input: make_approve_input(STABLECOIN_DEX_ADDRESS, U256::from(100u64)),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(Address::repeat_byte(0x98)),
                value: U256::ZERO,
                input: make_swap_input(token_in, currency, 100),
            },
            tempo_alloy::primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_input(recipient, U256::from(100u64)),
            },
        ],
        MAX_FEE_PAYER_GAS_LIMIT,
    );

    let error = method
        .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
        .unwrap_err();

    assert!(error.to_string().contains("swap target is not the DEX"));
}

/// The swap prefix must only acquire the charge: the approval covers
/// exactly the swap input, and the swap buys exactly the payment.
#[test]
fn test_validate_transaction_transfers_rejects_fee_payer_unbound_swap_prefix() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let split_recipient = Address::repeat_byte(0x34);
    let token_in = Address::repeat_byte(0x11);
    let expected = vec![
        Transfer {
            amount: U256::from(90u64),
            recipient,
            memo: None,
        },
        Transfer {
            amount: U256::from(10u64),
            recipient: split_recipient,
            memo: None,
        },
    ];

    let validate = |approve_amount: u64, token_out: Address, amount_out: u128| {
        let tx_bytes = encode_signed_tx(
            vec![
                tempo_alloy::primitives::transaction::Call {
                    to: TxKind::Call(token_in),
                    value: U256::ZERO,
                    input: make_approve_input(STABLECOIN_DEX_ADDRESS, U256::from(approve_amount)),
                },
                tempo_alloy::primitives::transaction::Call {
                    to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                    value: U256::ZERO,
                    input: Bytes::from(
                        IStablecoinDEX::swapExactAmountOutCall {
                            tokenIn: token_in,
                            tokenOut: token_out,
                            amountOut: amount_out,
                            maxAmountIn: 101,
                        }
                        .abi_encode(),
                    ),
                },
                tempo_alloy::primitives::transaction::Call {
                    to: TxKind::Call(currency),
                    value: U256::ZERO,
                    input: make_transfer_input(recipient, U256::from(90u64)),
                },
                tempo_alloy::primitives::transaction::Call {
                    to: TxKind::Call(currency),
                    value: U256::ZERO,
                    input: make_transfer_input(split_recipient, U256::from(10u64)),
                },
            ],
            MAX_FEE_PAYER_GAS_LIMIT,
        );
        method.validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
    };

    validate(101, currency, 100).expect("bound swap prefix is accepted");

    for (approve_amount, token_out, amount_out, expected_error) in [
        (
            u64::MAX,
            currency,
            100,
            "approve amount does not match the swap max input",
        ),
        (
            101,
            Address::repeat_byte(0x21),
            100,
            "swap output token is not the payment currency",
        ),
        (
            101,
            currency,
            1_000,
            "swap output does not match the payment amount",
        ),
        (
            101,
            currency,
            90,
            "swap output does not match the payment amount",
        ),
    ] {
        let error = validate(approve_amount, token_out, amount_out).unwrap_err();
        assert!(
            error.to_string().contains(expected_error),
            "expected `{expected_error}`, got: {error}"
        );
    }
}

#[test]
fn test_validate_transaction_transfers_rejects_fee_payer_gas_limit_above_max() {
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_http("http://127.0.0.1:1".parse().unwrap());
    let method = ChargeMethod::new(provider);

    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let expected = vec![Transfer {
        amount: U256::from(100u64),
        recipient,
        memo: None,
    }];

    let tx_bytes = encode_signed_tx(
        vec![tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(currency),
            value: U256::ZERO,
            input: make_transfer_input(recipient, U256::from(100u64)),
        }],
        MAX_FEE_PAYER_GAS_LIMIT + 1,
    );

    let error = method
        .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
        .unwrap_err();

    assert!(error.to_string().contains("exceeds maximum"));
}

#[test]
fn test_policy_override_adjusts_fee_payer_gas_limit() {
    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let expected = vec![Transfer {
        amount: U256::from(100u64),
        recipient,
        memo: None,
    }];
    let calls = vec![tempo_alloy::primitives::transaction::Call {
        to: TxKind::Call(currency),
        value: U256::ZERO,
        input: make_transfer_input(recipient, U256::from(100u64)),
    }];

    let build_method = || {
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        ChargeMethod::new(provider)
    };

    // Lower ceiling: default (2M) would accept 2.5M, override (500k) rejects.
    let lowered = build_method().with_fee_payer_policy_override(FeePayerPolicyOverride {
        max_gas: Some(500_000),
        ..Default::default()
    });
    let tx_under_default_over_override = encode_signed_tx(calls.clone(), 500_001);
    let error = lowered
        .validate_transaction_transfers(
            &tx_under_default_over_override,
            currency,
            &expected,
            CHAIN_ID,
            true,
        )
        .unwrap_err();
    assert!(error.to_string().contains("exceeds maximum 500000"));

    // Raise ceiling: default (2M) would reject 2.5M, override (3M) accepts.
    let raised = build_method().with_fee_payer_policy_override(FeePayerPolicyOverride {
        max_gas: Some(3_000_000),
        ..Default::default()
    });
    let tx_over_default_under_override = encode_signed_tx(calls, 2_500_000);
    raised
        .validate_transaction_transfers(
            &tx_over_default_under_override,
            currency,
            &expected,
            CHAIN_ID,
            true,
        )
        .expect("override should raise ceiling above default");
}
