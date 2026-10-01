use super::*;
use crate::protocol::methods::tempo::session_receipt::SessionReceipt;
use crate::protocol::traits::ErrorCode;
use alloy::primitives::{Bytes, B256};
use std::future::Future;

mod close;
mod open;
mod state;
mod store;
mod top_up;
mod voucher;

fn test_channel_state(channel_id: &str) -> ChannelState {
    ChannelState {
        channel_id: channel_id.to_string(),
        chain_id: 42431,
        escrow_contract: "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap(),
        payer: "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap(),
        payee: "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap(),
        token: "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap(),
        settlement_route: None,
        authorized_signer: "0x4444444444444444444444444444444444444444"
            .parse()
            .unwrap(),
        deposit: 100_000,
        settled_on_chain: 0,
        highest_voucher_amount: 0,
        highest_voucher_signature: None,
        spent: 0,
        units: 0,
        finalized: false,
        closing: false,
        close_requested_at: 0,
        created_at: "2025-01-01T00:00:00Z".to_string(),
    }
}

#[test]
fn test_parse_channel_id_valid() {
    let _id = "0xabababababababababababababababababababababababababababababababab";
    // 32 bytes = 64 hex chars + 0x prefix
    let padded = format!("0x{}", "ab".repeat(32));
    let result = SessionMethod::<()>::parse_channel_id(&padded);
    assert!(result.is_ok());
}

#[test]
fn test_parse_channel_id_invalid() {
    let result = SessionMethod::<()>::parse_channel_id("not-a-hex");
    assert!(result.is_err());
}

#[test]
fn test_parse_signature_valid() {
    let sig_hex = format!("0x{}1b", "01".repeat(64));
    let result = SessionMethod::<()>::parse_signature(&sig_hex);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 65);
}

#[test]
fn test_parse_signature_no_prefix() {
    let sig_hex = format!("{}1b", "01".repeat(64));
    let result = SessionMethod::<()>::parse_signature(&sig_hex);
    assert!(result.is_ok());
}

#[test]
fn test_parse_signature_invalid() {
    let result = SessionMethod::<()>::parse_signature("not-hex!");
    assert!(result.is_err());
}

#[test]
fn test_session_method_config() {
    let config = SessionMethodConfig {
        escrow_contract: "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap(),
        chain_id: 42431,
        min_voucher_delta: 100,
    };
    assert_eq!(config.chain_id, 42431);
    assert_eq!(config.min_voucher_delta, 100);
}

/// The on-chain channel behind `state`, open, with the given deposit and
/// settled amount.
fn on_chain_channel(state: &ChannelState, deposit: u128, settled: u128) -> OnChainChannel {
    OnChainChannel {
        payer: state.payer,
        payee: state.payee,
        token: state.token,
        authorized_signer: state.authorized_signer,
        deposit,
        settled,
        close_requested_at: 0,
        finalized: false,
    }
}

/// Create a SessionMethod with a dummy provider for testing voucher logic
/// (which doesn't touch the provider).
fn test_session_method(
    store: Arc<InMemoryChannelStore>,
) -> SessionMethod<crate::server::TempoProvider> {
    let provider = crate::server::tempo_provider("https://rpc.test.invalid").expect("valid URL");
    let config = SessionMethodConfig {
        escrow_contract: "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap(),
        chain_id: 42431,
        min_voucher_delta: 0,
    };
    SessionMethod::new(provider, store, config)
}

/// Helper to build a SessionRequest, PaymentChallenge, and PaymentCredential
/// for verify_session tests. Uses the given recipient/currency in the
/// challenge and the given payload in the credential.
fn build_session_credential(
    recipient: Option<&str>,
    currency: &str,
    payload: SessionCredentialPayload,
) -> (
    crate::protocol::intents::SessionRequest,
    crate::protocol::core::PaymentCredential,
) {
    use crate::protocol::core::{Base64UrlJson, PaymentChallenge, PaymentCredential};
    use crate::protocol::intents::SessionRequest;

    let request = SessionRequest {
        amount: "1000".to_string(),
        currency: currency.to_string(),
        recipient: recipient.map(|s| s.to_string()),
        method_details: Some(serde_json::json!({
            "escrowContract": "0x5555555555555555555555555555555555555555",
            "chainId": 42431,
        })),
        ..Default::default()
    };
    let challenge = PaymentChallenge::new(
        "test-id",
        "api.example.com",
        METHOD_NAME,
        INTENT_SESSION,
        Base64UrlJson::from_typed(&request).unwrap(),
    );
    let credential = PaymentCredential::new(challenge.to_echo(), payload);
    (request, credential)
}

#[tokio::test]
async fn test_verify_session_rejects_missing_recipient() {
    let store = Arc::new(InMemoryChannelStore::new());
    let method = test_session_method(store);

    let channel_id = format!("0x{}", "ab".repeat(32));
    let (request, credential) = build_session_credential(
        None, // missing recipient
        "0x3333333333333333333333333333333333333333",
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
    assert!(
        err.message.contains("recipient"),
        "expected missing recipient error, got: {}",
        err.message
    );
}

alloy::sol! {
    interface ITestEscrow {
        function open(address payee, address token, uint128 deposit, bytes32 salt, address authorizedSigner) external;
        function topUp(bytes32 channelId, uint256 additionalDeposit) external;
    }
}

const TEST_ESCROW: Address = Address::repeat_byte(0x55);
const TEST_PAYEE: Address = Address::repeat_byte(0x22);
const TEST_TOKEN: Address = Address::repeat_byte(0x33);

/// Signs a Tempo transaction with a single call and returns it hex-encoded.
fn signed_call_transaction(
    signer: &alloy::signers::local::PrivateKeySigner,
    to: Address,
    input: Vec<u8>,
) -> String {
    use alloy::eips::Encodable2718;
    use alloy::signers::SignerSync;
    use tempo_alloy::primitives::transaction::Call;
    use tempo_alloy::primitives::TempoTransaction;

    let tx = TempoTransaction {
        chain_id: 42431,
        gas_limit: 500_000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        calls: vec![Call {
            to: alloy::primitives::TxKind::Call(to),
            value: alloy::primitives::U256::ZERO,
            input: Bytes::from(input),
        }],
        ..Default::default()
    };
    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    alloy::hex::encode_prefixed(tx.into_signed(signature.into()).encoded_2718())
}

/// Queues the RPC responses for a client transaction that is broadcast and
/// mined successfully.
fn push_mined_transaction(asserter: &alloy::providers::mock::Asserter) {
    let tx_hash = B256::repeat_byte(0xcc);
    let receipt = serde_json::json!({
        "transactionHash": tx_hash,
        "transactionIndex": "0x0",
        "blockHash": B256::repeat_byte(0xdd),
        "blockNumber": "0x1",
        "from": Address::repeat_byte(0x11),
        "to": TEST_ESCROW,
        "cumulativeGasUsed": "0x5208",
        "gasUsed": "0x5208",
        "effectiveGasPrice": "0x1",
        "contractAddress": null,
        "logs": [],
        "logsBloom": alloy::primitives::Bloom::ZERO,
        "status": "0x1",
        "type": "0x76",
        "feePayer": Address::repeat_byte(0x11),
    });
    asserter.push_success(&tx_hash); // eth_sendRawTransaction
    asserter.push_success(&receipt); // receipt lookup when registering the watcher
    asserter.push_success(&receipt); // receipt fetch
}

/// Queues the on-chain `getChannel` state of an open channel.
fn push_on_chain_channel(
    asserter: &alloy::providers::mock::Asserter,
    payer: Address,
    authorized_signer: Address,
    deposit: u128,
) {
    use alloy::sol_types::SolValue;

    asserter.push_success(&Bytes::from(
        (
            false,
            0u64,
            payer,
            TEST_PAYEE,
            TEST_TOKEN,
            authorized_signer,
            deposit,
            0u128,
        )
            .abi_encode_params(),
    ));
}

fn mocked_session_method(
    store: Arc<dyn ChannelStore>,
    asserter: alloy::providers::mock::Asserter,
) -> SessionMethod<impl Provider<TempoNetwork> + Clone + 'static> {
    let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
        .connect_mocked_client(asserter);
    SessionMethod::new(
        provider,
        store,
        SessionMethodConfig {
            escrow_contract: "0x5555555555555555555555555555555555555555"
                .parse()
                .unwrap(),
            chain_id: 42431,
            min_voucher_delta: 0,
        },
    )
}

/// Decodes the `Payment-Receipt` header a server would send for `receipt`,
/// checking on the way that it parses as a [`SessionReceipt`].
fn receipt_json(receipt: &Receipt) -> serde_json::Value {
    use crate::protocol::core::types::base64url_decode;

    let header = receipt.to_header().unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&base64url_decode(&header).unwrap()).unwrap();
    let session = SessionReceipt::from_header(&header).unwrap();
    assert_eq!(serde_json::to_value(session).unwrap(), json);
    json
}

/// Store that applies `change` to a channel right after its first read,
/// like another request landing while the handler awaits the chain.
struct ChangeAfterRead {
    inner: InMemoryChannelStore,
    change: fn(ChannelState) -> ChannelState,
    changed: std::sync::atomic::AtomicBool,
}

impl ChangeAfterRead {
    fn new(change: fn(ChannelState) -> ChannelState) -> Self {
        Self {
            inner: InMemoryChannelStore::new(),
            change,
            changed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl ChannelStore for ChangeAfterRead {
    fn get_channel(
        &self,
        channel_id: &str,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    > {
        let snapshot = self.inner.get_channel_sync(channel_id);
        if !self.changed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            if let Some(state) = snapshot.clone() {
                self.inner.insert(channel_id, (self.change)(state));
            }
        }
        Box::pin(async move { Ok(snapshot) })
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
