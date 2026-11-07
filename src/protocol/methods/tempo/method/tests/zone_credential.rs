//! Zone credentials, as mppx's `Charge.zone.test.ts`.

use super::*;
use alloy::consensus::transaction::Recovered;
use tempo_alloy::primitives::TempoTxEnvelope;

use crate::protocol::traits::ErrorCode;

use crate::protocol::methods::tempo::zone::{self, IZonePortal, Withdrawal, Zones};

const ZONE_ID: u32 = 3;
const AMOUNT: u128 = 1_000_000;

fn merchant() -> Address {
    Address::repeat_byte(0x22)
}

fn currency() -> Address {
    "0x20c0000000000000000000000000000000000001"
        .parse()
        .unwrap()
}

fn settlement_hash() -> B256 {
    B256::repeat_byte(0xab)
}

fn tag_a() -> B256 {
    B256::repeat_byte(0xa1)
}

fn tag_b() -> B256 {
    B256::repeat_byte(0xb2)
}

/// One withdrawal of the settlement transaction, by default paying the
/// challenge to the merchant.
#[derive(Clone)]
struct WithdrawalFixture {
    sender_tag: B256,
    memo: [u8; 32],
    to: Address,
    token: Address,
    amount: u128,
    gas_limit: u64,
    callback_success: bool,
    event_address: Address,
    in_calldata: bool,
}

impl WithdrawalFixture {
    fn new(sender_tag: B256, memo: [u8; 32]) -> Self {
        Self {
            sender_tag,
            memo,
            to: merchant(),
            token: currency(),
            amount: AMOUNT,
            gas_limit: 0,
            callback_success: true,
            event_address: zone::portal_address(ZONE_ID),
            in_calldata: true,
        }
    }
}

fn zone_request(details: serde_json::Value) -> ChargeRequest {
    let mut method_details =
        serde_json::json!({ "chainId": MODERATO_CHAIN_ID, "zones": [ZONE_ID] });
    method_details
        .as_object_mut()
        .unwrap()
        .extend(details.as_object().unwrap().clone());
    ChargeRequest {
        amount: AMOUNT.to_string(),
        currency: format!("{:#x}", currency()),
        recipient: Some(format!("{:#x}", merchant())),
        method_details: Some(method_details),
        ..Default::default()
    }
}

fn zone_challenge(id: &str, request: &ChargeRequest) -> PaymentChallenge {
    PaymentChallenge::new(
        id,
        "api.example.com",
        "tempo",
        "charge",
        Base64UrlJson::from_typed(request).unwrap(),
    )
}

fn challenge_memo(challenge: &PaymentChallenge) -> [u8; 32] {
    attribution::encode(&challenge.id, &challenge.realm, None)
}

fn zone_credential(
    challenge: &PaymentChallenge,
    sender_tag: B256,
    zone_id: u32,
) -> PaymentCredential {
    PaymentCredential::new(
        challenge.to_echo(),
        crate::protocol::core::PaymentPayload::zone(
            format!("{:#x}", settlement_hash()),
            format!("{sender_tag:#x}"),
            zone_id,
        ),
    )
}

fn settlement_receipt(withdrawals: &[WithdrawalFixture], success: bool) -> serde_json::Value {
    let logs: Vec<_> = withdrawals
        .iter()
        .enumerate()
        .map(|(index, w)| {
            let data = IZonePortal::WithdrawalProcessed {
                to: w.to,
                senderTag: w.sender_tag,
                token: w.token,
                amount: w.amount,
                callbackSuccess: w.callback_success,
            }
            .encode_log_data();
            serde_json::json!({
                "address": format!("{:#x}", w.event_address),
                "topics": data.topics().iter().map(|topic| format!("{topic:#x}")).collect::<Vec<_>>(),
                "data": format!("{}", data.data),
                "blockHash": format!("{:#x}", settlement_hash()),
                "blockNumber": "0x10",
                "transactionHash": format!("{:#x}", settlement_hash()),
                "transactionIndex": "0x0",
                "logIndex": format!("{index:#x}"),
                "removed": false,
            })
        })
        .collect();
    let sequencer = format!("{:#x}", Address::repeat_byte(0x44));
    serde_json::json!({
        "type": "0x76",
        "status": if success { "0x1" } else { "0x0" },
        "cumulativeGasUsed": "0x1",
        "logs": logs,
        "logsBloom": format!("0x{}", "00".repeat(256)),
        "transactionHash": format!("{:#x}", settlement_hash()),
        "transactionIndex": "0x0",
        "blockHash": format!("{:#x}", settlement_hash()),
        "blockNumber": "0x10",
        "gasUsed": "0x1",
        "effectiveGasPrice": "0x1",
        "from": sequencer,
        "to": format!("{:#x}", zone::portal_address(ZONE_ID)),
        "contractAddress": null,
        "feePayer": sequencer,
        "feeToken": format!("{:#x}", currency()),
    })
}

/// The sequencer's `processWithdrawals` transaction, as `eth_getTransactionByHash` returns it.
fn settlement_transaction(withdrawals: &[WithdrawalFixture]) -> serde_json::Value {
    use alloy::signers::SignerSync;

    let withdrawals = withdrawals
        .iter()
        .filter(|w| w.in_calldata)
        .map(|w| Withdrawal {
            token: w.token,
            senderTag: w.sender_tag,
            to: w.to,
            amount: w.amount,
            memo: w.memo.into(),
            gasLimit: w.gas_limit,
            fallbackNonce: 1,
            callbackData: Bytes::new(),
            encryptedSender: Bytes::new(),
        })
        .collect();
    let tx = tempo_alloy::primitives::TempoTransaction {
        chain_id: MODERATO_CHAIN_ID,
        nonce: 0,
        nonce_key: U256::ZERO,
        gas_limit: 1_000_000,
        max_fee_per_gas: 1,
        max_priority_fee_per_gas: 1,
        fee_token: Some(currency()),
        fee_payer_signature: None,
        valid_before: None,
        valid_after: None,
        calls: vec![tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(zone::portal_address(ZONE_ID)),
            value: U256::ZERO,
            input: IZonePortal::processWithdrawalsCall {
                withdrawals,
                remainingQueue: B256::ZERO,
            }
            .abi_encode()
            .into(),
        }],
        access_list: Default::default(),
        tempo_authorization_list: vec![],
        key_authorization: None,
    };
    let signer = alloy::signers::local::PrivateKeySigner::random();
    let signature: tempo_alloy::primitives::transaction::TempoSignature =
        signer.sign_hash_sync(&tx.signature_hash()).unwrap().into();
    let envelope = TempoTxEnvelope::from(tx.into_signed(signature));
    serde_json::to_value(alloy::rpc::types::Transaction {
        inner: Recovered::new_unchecked(envelope, signer.address()),
        block_hash: Some(settlement_hash()),
        block_number: Some(0x10),
        transaction_index: Some(0),
        effective_gas_price: Some(1),
        block_timestamp: None,
    })
    .unwrap()
}

/// A charge method on a mocked Tempo RPC that answers one verification with
/// the settlement of `withdrawals`.
fn zone_method(
    withdrawals: &[WithdrawalFixture],
    success: bool,
) -> (
    ChargeMethod<impl Provider<tempo_alloy::TempoNetwork> + Clone>,
    alloy::providers::mock::Asserter,
) {
    let asserter = alloy::providers::mock::Asserter::new();
    asserter.push_success(&settlement_receipt(withdrawals, success));
    asserter.push_success(&settlement_transaction(withdrawals));
    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter.clone());
    let method = ChargeMethod::new(provider).with_store(Arc::new(crate::store::MemoryStore::new()));
    method.cached_chain_id.set(MODERATO_CHAIN_ID).unwrap();
    (method, asserter)
}

/// Push another verification's RPC answers.
fn push_settlement(asserter: &alloy::providers::mock::Asserter, withdrawals: &[WithdrawalFixture]) {
    asserter.push_success(&settlement_receipt(withdrawals, true));
    asserter.push_success(&settlement_transaction(withdrawals));
}

#[tokio::test]
async fn test_zone_accepts_settled_withdrawal_bound_to_challenge() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    let (method, _) = zone_method(
        &[WithdrawalFixture::new(tag_a(), challenge_memo(&challenge))],
        true,
    );
    let receipt = method
        .verify(&zone_credential(&challenge, tag_a(), ZONE_ID), &request)
        .await
        .unwrap();
    assert_eq!(receipt.method.as_str(), "tempo");
    assert_eq!(receipt.reference, format!("{:#x}", settlement_hash()));
    assert!(receipt.is_success());
}

#[tokio::test]
async fn test_zone_validate_reports_push_mode_without_claiming() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    let fixture = [WithdrawalFixture::new(tag_a(), challenge_memo(&challenge))];
    let (method, asserter) = zone_method(&fixture, true);
    let credential = zone_credential(&challenge, tag_a(), ZONE_ID);
    let validation = method.validate_local(&credential, &request).await.unwrap();
    assert_eq!(validation.details, serde_json::json!({ "mode": "push" }));
    // Validation claims nothing: the credential still verifies once.
    push_settlement(&asserter, &fixture);
    method.verify(&credential, &request).await.unwrap();
}

#[tokio::test]
async fn test_zone_rejects_replayed_withdrawal() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    let fixture = [WithdrawalFixture::new(tag_a(), challenge_memo(&challenge))];
    let (method, asserter) = zone_method(&fixture, true);
    let credential = zone_credential(&challenge, tag_a(), ZONE_ID);
    method.verify(&credential, &request).await.unwrap();
    push_settlement(&asserter, &fixture);
    let error = method.verify(&credential, &request).await.unwrap_err();
    assert_eq!(error.code, Some(ErrorCode::CredentialReplayed));
    assert!(
        error
            .message
            .contains("Zone withdrawal has already been used"),
        "{error}"
    );
}

#[tokio::test]
async fn test_zone_accepts_two_payments_settled_in_one_transaction() {
    let request = zone_request(serde_json::json!({}));
    let a = zone_challenge("challenge-a", &request);
    let b = zone_challenge("challenge-b", &request);
    let fixture = [
        WithdrawalFixture::new(tag_a(), challenge_memo(&a)),
        WithdrawalFixture::new(tag_b(), challenge_memo(&b)),
    ];
    let (method, asserter) = zone_method(&fixture, true);
    method
        .verify(&zone_credential(&a, tag_a(), ZONE_ID), &request)
        .await
        .unwrap();
    push_settlement(&asserter, &fixture);
    method
        .verify(&zone_credential(&b, tag_b(), ZONE_ID), &request)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_zone_rejects_withdrawal_bound_to_another_challenge() {
    let request = zone_request(serde_json::json!({}));
    let a = zone_challenge("challenge-a", &request);
    let b = zone_challenge("challenge-b", &request);
    let (method, _) = zone_method(&[WithdrawalFixture::new(tag_a(), challenge_memo(&a))], true);
    let error = method
        .verify(&zone_credential(&b, tag_a(), ZONE_ID), &request)
        .await
        .unwrap_err();
    assert_eq!(error.code, Some(ErrorCode::CredentialReplayed));
    assert!(
        error
            .message
            .contains("memo is not bound to this challenge"),
        "{error}"
    );
}

#[tokio::test]
async fn test_zone_rejects_withdrawal_without_mpp_memo() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    let (method, _) = zone_method(&[WithdrawalFixture::new(tag_a(), [0; 32])], true);
    let error = method
        .verify(&zone_credential(&challenge, tag_a(), ZONE_ID), &request)
        .await
        .unwrap_err();
    assert!(
        error
            .message
            .contains("memo is not bound to this challenge"),
        "{error}"
    );
}

#[tokio::test]
async fn test_zone_rejects_mismatched_withdrawals() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    let memo = challenge_memo(&challenge);
    let base = WithdrawalFixture::new(tag_a(), memo);
    let cases = [
        (
            "recipient",
            WithdrawalFixture {
                to: Address::repeat_byte(0x33),
                ..base.clone()
            },
            "Zone withdrawal not found",
        ),
        (
            "amount",
            WithdrawalFixture {
                amount: AMOUNT - 1,
                ..base.clone()
            },
            "Zone withdrawal not found",
        ),
        (
            "currency",
            WithdrawalFixture {
                token: "0x20c0000000000000000000000000000000000002"
                    .parse()
                    .unwrap(),
                ..base.clone()
            },
            "Zone withdrawal not found",
        ),
        (
            "bounced withdrawal",
            WithdrawalFixture {
                callback_success: false,
                ..base.clone()
            },
            "Zone withdrawal bounced",
        ),
        (
            "event from another portal",
            WithdrawalFixture {
                event_address: zone::portal_address(4),
                ..base.clone()
            },
            "not settled",
        ),
        (
            "withdrawal missing from calldata",
            WithdrawalFixture {
                in_calldata: false,
                ..base.clone()
            },
            "Zone withdrawal not found",
        ),
        (
            "callback withdrawal",
            WithdrawalFixture {
                gas_limit: 100_000,
                ..base.clone()
            },
            "Zone withdrawal not found",
        ),
    ];
    for (name, fixture, expected) in cases {
        let (method, _) = zone_method(&[fixture], true);
        let error = method
            .verify(&zone_credential(&challenge, tag_a(), ZONE_ID), &request)
            .await
            .unwrap_err();
        assert!(error.message.contains(expected), "{name}: {error}");
    }
}

#[tokio::test]
async fn test_zone_rejects_reverted_settlement() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    let (method, _) = zone_method(
        &[WithdrawalFixture::new(tag_a(), challenge_memo(&challenge))],
        false,
    );
    let error = method
        .verify(&zone_credential(&challenge, tag_a(), ZONE_ID), &request)
        .await
        .unwrap_err();
    assert_eq!(error.code, Some(ErrorCode::TransactionFailed));
    assert!(
        error.message.contains("settlement transaction reverted"),
        "{error}"
    );
}

/// Rejected before any RPC call: both mocked answers stay queued.
async fn assert_rejected_before_rpc(
    request: &ChargeRequest,
    credential: PaymentCredential,
    expected: &str,
) {
    let (method, asserter) = zone_method(&[], true);
    let error = method.verify(&credential, request).await.unwrap_err();
    assert!(error.message.contains(expected), "{error}");
    assert_eq!(asserter.read_q().len(), 2);
}

#[tokio::test]
async fn test_zone_rejects_zone_the_challenge_does_not_accept() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    assert_rejected_before_rpc(
        &request,
        zone_credential(&challenge, tag_a(), 4),
        "Zone is not accepted for this challenge",
    )
    .await;
}

#[tokio::test]
async fn test_zone_rejects_challenge_without_zones() {
    let mut request = zone_request(serde_json::json!({}));
    request
        .method_details
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("zones");
    let challenge = zone_challenge("challenge-a", &request);
    assert_rejected_before_rpc(
        &request,
        zone_credential(&challenge, tag_a(), ZONE_ID),
        "Zone is not accepted for this challenge",
    )
    .await;
}

#[tokio::test]
async fn test_zone_accepts_any_zone_when_zones_is_true() {
    let request = zone_request(serde_json::json!({ "zones": true }));
    assert_eq!(
        request.tempo_method_details().unwrap().zones,
        Some(Zones::Any)
    );
    let challenge = zone_challenge("challenge-a", &request);
    let (method, _) = zone_method(
        &[WithdrawalFixture::new(tag_a(), challenge_memo(&challenge))],
        true,
    );
    method
        .verify(&zone_credential(&challenge, tag_a(), ZONE_ID), &request)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_zone_checks_portal_of_named_zone_when_zones_is_true() {
    let request = zone_request(serde_json::json!({ "zones": true }));
    let challenge = zone_challenge("challenge-a", &request);
    // The settlement came from Zone 3's portal, not Zone 4's.
    let (method, _) = zone_method(
        &[WithdrawalFixture::new(tag_a(), challenge_memo(&challenge))],
        true,
    );
    let error = method
        .verify(&zone_credential(&challenge, tag_a(), 4), &request)
        .await
        .unwrap_err();
    assert!(
        error.message.contains("Zone withdrawal not settled"),
        "{error}"
    );
}

#[tokio::test]
async fn test_zone_rejects_invalid_zone_ids() {
    let request = zone_request(serde_json::json!({ "zones": true }));
    let challenge = zone_challenge("challenge-a", &request);
    for zone_id in [
        serde_json::json!(0),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!(4_294_967_296u64),
    ] {
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            serde_json::json!({
                "type": "zone",
                "hash": format!("{:#x}", settlement_hash()),
                "senderTag": format!("{:#x}", tag_a()),
                "zoneId": zone_id,
            }),
        );
        let (method, asserter) = zone_method(&[], true);
        let error = method.verify(&credential, &request).await.unwrap_err();
        assert_eq!(
            error.code,
            Some(ErrorCode::InvalidCredential),
            "{zone_id}: {error}"
        );
        assert_eq!(asserter.read_q().len(), 2);
    }
}

#[tokio::test]
async fn test_zone_rejects_credential_without_settlement_hash() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    let credential = PaymentCredential::new(
        challenge.to_echo(),
        serde_json::json!({
            "type": "zone",
            "senderTag": format!("{:#x}", tag_a()),
            "zoneId": ZONE_ID,
        }),
    );
    let (method, asserter) = zone_method(&[], true);
    let error = method.verify(&credential, &request).await.unwrap_err();
    assert_eq!(error.code, Some(ErrorCode::InvalidCredential), "{error}");
    assert_eq!(asserter.read_q().len(), 2);
}

#[tokio::test]
async fn test_zone_rejects_malformed_sender_tag() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    let credential = PaymentCredential::new(
        challenge.to_echo(),
        crate::protocol::core::PaymentPayload::zone(
            format!("{:#x}", settlement_hash()),
            "0x1234",
            ZONE_ID,
        ),
    );
    assert_rejected_before_rpc(&request, credential, "Invalid Zone credential senderTag").await;
}

#[tokio::test]
async fn test_zone_rejects_pull_only_challenges() {
    let request = zone_request(serde_json::json!({ "supportedModes": ["pull"] }));
    let challenge = zone_challenge("challenge-a", &request);
    assert_rejected_before_rpc(
        &request,
        zone_credential(&challenge, tag_a(), ZONE_ID),
        "Zone credentials are not supported for this challenge",
    )
    .await;
}

#[tokio::test]
async fn test_zone_rejects_split_payments() {
    let request = zone_request(serde_json::json!({
        "splits": [{ "amount": "100000", "recipient": format!("{:#x}", Address::repeat_byte(0x33)) }]
    }));
    let challenge = zone_challenge("challenge-a", &request);
    assert_rejected_before_rpc(
        &request,
        zone_credential(&challenge, tag_a(), ZONE_ID),
        "Zone credentials do not support split payments",
    )
    .await;
}

#[tokio::test]
async fn test_zone_rejects_credential_with_source() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    let mut credential = zone_credential(&challenge, tag_a(), ZONE_ID);
    credential.source = Some(format!(
        "did:pkh:eip155:{MODERATO_CHAIN_ID}:{:#x}",
        Address::repeat_byte(0x44)
    ));
    let (method, _) = zone_method(&[], true);
    let error = method
        .validate_local(&credential, &request)
        .await
        .unwrap_err();
    assert!(error.message.contains("must not carry a source"), "{error}");
    assert_eq!(error.code, Some(ErrorCode::InvalidCredential));
    assert_rejected_before_rpc(&request, credential, "must not carry a source").await;
}

#[tokio::test]
async fn test_zone_rejects_credential_in_relay_mode() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    let credential = zone_credential(&challenge, tag_a(), ZONE_ID);
    let (method, _) = zone_method(&[], true);
    let method = method
        .with_relay(crate::protocol::methods::tempo::RelayConfig::new(
            "test-api-key",
        ))
        .unwrap();
    for error in [
        ChargeMethodTrait::validate(&method, &credential, &request)
            .await
            .unwrap_err(),
        ChargeMethodTrait::broadcast(&method, &credential, &request)
            .await
            .unwrap_err(),
        ChargeMethodTrait::verify(&method, &credential, &request)
            .await
            .unwrap_err(),
    ] {
        assert!(
            error.message.contains("not supported with a relay"),
            "{error}"
        );
    }
}

/// A hash credential naming the settlement transaction, answering `challenge`.
fn settlement_hash_credential(challenge: &PaymentChallenge) -> PaymentCredential {
    PaymentCredential::new(
        challenge.to_echo(),
        crate::protocol::core::PaymentPayload::hash(format!("{:#x}", settlement_hash())),
    )
}

fn assert_zone_settlement_hash_rejected(error: VerificationError) {
    assert_eq!(error.code, Some(ErrorCode::InvalidCredential), "{error}");
    assert!(
        error
            .message
            .contains("Zone settlement transactions can't be redeemed as hash credentials"),
        "{error}"
    );
}

#[tokio::test]
async fn test_hash_credential_rejects_zone_settlement() {
    let request = zone_request(serde_json::json!({}));
    let challenge = zone_challenge("challenge-a", &request);
    // Emitted by an address that is no known portal: the event alone refuses it.
    let mut withdrawal = WithdrawalFixture::new(tag_a(), challenge_memo(&challenge));
    withdrawal.event_address = Address::repeat_byte(0x55);
    let fixture = [withdrawal];
    let (method, asserter) = zone_method(&fixture, true);
    let credential = settlement_hash_credential(&challenge);
    assert_zone_settlement_hash_rejected(method.verify(&credential, &request).await.unwrap_err());
    asserter.write_q().clear();
    push_settlement(&asserter, &fixture);
    assert_zone_settlement_hash_rejected(
        method
            .validate_local(&credential, &request)
            .await
            .unwrap_err(),
    );
}

#[tokio::test]
async fn test_zone_batch_still_verifies_after_hash_credential_attempts() {
    let request = zone_request(serde_json::json!({}));
    let a = zone_challenge("challenge-a", &request);
    let b = zone_challenge("challenge-b", &request);
    let fixture = [
        WithdrawalFixture::new(tag_a(), challenge_memo(&a)),
        WithdrawalFixture::new(tag_b(), challenge_memo(&b)),
    ];
    let (method, asserter) = zone_method(&fixture, true);
    method
        .verify(&zone_credential(&a, tag_a(), ZONE_ID), &request)
        .await
        .unwrap();
    // Someone tries to redeem the batch's settlement as a hash credential.
    push_settlement(&asserter, &fixture);
    assert_zone_settlement_hash_rejected(
        method
            .verify(&settlement_hash_credential(&b), &request)
            .await
            .unwrap_err(),
    );
    // The other payer in the batch is still paid for.
    asserter.write_q().clear();
    push_settlement(&asserter, &fixture);
    method
        .verify(&zone_credential(&b, tag_b(), ZONE_ID), &request)
        .await
        .unwrap();
}
