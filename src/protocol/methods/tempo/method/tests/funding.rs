use super::*;
use crate::protocol::methods::tempo::method::transaction_credential::{
    funding_currency, signed_transaction_funding_currency,
};
use tempo_alloy::primitives::transaction::Call;

fn call(to: Address, input: Bytes) -> Call {
    Call {
        to: TxKind::Call(to),
        value: U256::ZERO,
        input,
    }
}

fn payment(recipient: Address) -> Vec<Transfer> {
    vec![Transfer {
        amount: U256::from(100u64),
        recipient,
        memo: None,
    }]
}

#[test]
fn test_funding_currency_direct_transfer_is_payment_currency() {
    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let calls = [call(
        currency,
        make_transfer_input(recipient, U256::from(100u64)),
    )];

    assert_eq!(
        funding_currency(&calls, CHAIN_ID, currency, &payment(recipient), false),
        Some(currency)
    );
}

#[test]
fn test_funding_currency_dex_swap_is_input_token() {
    let currency = Address::repeat_byte(0x20);
    let recipient = Address::repeat_byte(0x33);
    let token_in = Address::repeat_byte(0x11);
    let calls = [
        call(
            token_in,
            make_approve_input(STABLECOIN_DEX_ADDRESS, U256::from(100u64)),
        ),
        call(
            STABLECOIN_DEX_ADDRESS,
            make_swap_input(token_in, currency, 100),
        ),
        call(currency, make_transfer_input(recipient, U256::from(100u64))),
    ];

    assert_eq!(
        funding_currency(&calls, CHAIN_ID, currency, &payment(recipient), false),
        Some(token_in)
    );

    // A swap that does not buy the payment currency is not a recognized route.
    let mut unbound = calls.clone();
    unbound[1] = call(
        STABLECOIN_DEX_ADDRESS,
        make_swap_input(token_in, Address::repeat_byte(0x44), 100),
    );
    assert_eq!(
        funding_currency(&unbound, CHAIN_ID, currency, &payment(recipient), false),
        None
    );
}

#[test]
fn test_funding_currency_machine_token_route_is_mach() {
    let currency = Address::repeat_byte(0x20);
    let expected = vec![Transfer {
        amount: U256::from(100u64),
        recipient: Address::repeat_byte(0x33),
        memo: Some([0xab; 32]),
    }];
    let route = super::super::super::machine_token::route(CHAIN_ID, currency, &expected).unwrap();
    let TxKind::Call(mach) = route.calls[0].to else {
        panic!("route approves a token");
    };

    assert_eq!(
        funding_currency(&route.calls, CHAIN_ID, currency, &expected, true),
        Some(mach)
    );
    // Without machine-token funding enabled the route is not recognized.
    assert_eq!(
        funding_currency(&route.calls, CHAIN_ID, currency, &expected, false),
        None
    );
}

#[test]
fn test_funding_currency_unrelated_transfer_is_none() {
    let currency = Address::repeat_byte(0x20);
    let calls = [call(
        currency,
        make_transfer_input(Address::repeat_byte(0x99), U256::from(100u64)),
    )];

    assert_eq!(
        funding_currency(
            &calls,
            CHAIN_ID,
            currency,
            &payment(Address::repeat_byte(0x33)),
            false
        ),
        None
    );
}

#[test]
fn test_signed_transaction_funding_currency_reads_signed_calls() {
    let request = test_charge_request_with_amount("100");
    let currency = request.currency_address().unwrap();
    let recipient: Address = request.recipient.as_deref().unwrap().parse().unwrap();
    let token_in = Address::repeat_byte(0x11);
    let tx_bytes = encode_signed_tx(
        vec![
            call(
                token_in,
                make_approve_input(STABLECOIN_DEX_ADDRESS, U256::from(100u64)),
            ),
            call(
                STABLECOIN_DEX_ADDRESS,
                make_swap_input(token_in, currency, 100),
            ),
            call(currency, make_transfer_input(recipient, U256::from(100u64))),
        ],
        MAX_FEE_PAYER_GAS_LIMIT,
    );

    assert_eq!(
        signed_transaction_funding_currency(
            &hex::encode_prefixed(tx_bytes),
            &request,
            MODERATO_CHAIN_ID
        ),
        Some(token_in)
    );
    assert_eq!(
        signed_transaction_funding_currency("0xzz", &request, MODERATO_CHAIN_ID),
        None
    );
}

#[test]
fn test_receipt_funding_currency_round_trips() {
    let receipt = Receipt::success("tempo", "0xabc");
    assert_eq!(receipt.funding_currency(), None);
    assert!(!serde_json::to_string(&receipt)
        .unwrap()
        .contains("fundingCurrency"));

    let receipt = receipt.with_funding_currency("0x20C0000000000000000000000000000000000000");
    let json = serde_json::to_value(&receipt).unwrap();
    assert_eq!(
        json["fundingCurrency"],
        "0x20C0000000000000000000000000000000000000"
    );
    let parsed: Receipt = serde_json::from_value(json).unwrap();
    assert_eq!(
        parsed.funding_currency(),
        Some("0x20C0000000000000000000000000000000000000")
    );
}
