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

#[test]
fn test_signed_transaction_funding_currency_reads_fee_payer_envelope() {
    let request = test_charge_request_with_amount("100");
    let currency = request.currency_address().unwrap();
    let recipient: Address = request.recipient.as_deref().unwrap().parse().unwrap();
    let token_in = Address::repeat_byte(0x11);
    let mut tx = make_fee_payer_tx(60);
    tx.chain_id = MODERATO_CHAIN_ID;
    tx.calls = vec![
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
    let signer = alloy::signers::local::PrivateKeySigner::random();
    let envelope = sign_and_encode_0x78(tx, &signer);

    assert_eq!(
        signed_transaction_funding_currency(
            &hex::encode_prefixed(envelope),
            &request,
            MODERATO_CHAIN_ID
        ),
        Some(token_in)
    );
}

/// Records how many mocked RPC responses were still queued when the replay
/// key was claimed.
struct ClaimProbeStore {
    inner: crate::store::MemoryStore,
    asserter: alloy::providers::mock::Asserter,
    queued_at_claim: std::sync::Mutex<Option<usize>>,
}

impl crate::store::Store for ClaimProbeStore {
    fn get(
        &self,
        key: &str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Option<serde_json::Value>, crate::store::StoreError>,
                > + Send
                + '_,
        >,
    > {
        self.inner.get(key)
    }

    fn put(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), crate::store::StoreError>> + Send + '_>,
    > {
        self.inner.put(key, value)
    }

    fn delete(
        &self,
        key: &str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), crate::store::StoreError>> + Send + '_>,
    > {
        self.inner.delete(key)
    }

    fn put_if_absent(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<bool, crate::store::StoreError>> + Send + '_>,
    > {
        *self.queued_at_claim.lock().unwrap() = Some(self.asserter.read_q().len());
        self.inner.put_if_absent(key, value)
    }
}

/// The informational funding lookup finishes before the hash is claimed, so
/// a stalled or cancelled lookup cannot strand a reserved payment.
#[tokio::test]
async fn test_verify_hash_funding_lookup_runs_before_replay_claim() {
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
    // eth_getTransactionByHash fails: the payment stays valid, unlabelled.
    asserter.push_failure_msg("transaction lookup unavailable");
    let store = Arc::new(ClaimProbeStore {
        inner: crate::store::MemoryStore::new(),
        asserter: asserter.clone(),
        queued_at_claim: std::sync::Mutex::new(None),
    });
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);
    let method = ChargeMethod::new(provider).with_store(store.clone());
    method.cached_chain_id.set(MODERATO_CHAIN_ID).unwrap();

    let credential = PaymentCredential::new(
        challenge.to_echo(),
        crate::protocol::core::PaymentPayload::hash(format!("{tx_hash:#x}")),
    );
    let receipt = method.verify(&credential, &request).await.unwrap();
    assert_eq!(receipt.funding_currency(), None);
    assert_eq!(*store.queued_at_claim.lock().unwrap(), Some(0));
}
