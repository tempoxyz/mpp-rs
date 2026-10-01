use std::num::NonZeroU64;
use std::sync::atomic::{AtomicUsize, Ordering};

use alloy::consensus::transaction::SignerRecoverable;
use alloy::eips::Decodable2718;
use alloy::primitives::{hex, keccak256, Bytes, TxKind, B256, U256};
use alloy::sol_types::SolCall;
use tempo_alloy::contracts::precompiles::{IStablecoinDEX, ITIP20, STABLECOIN_DEX_ADDRESS};

use super::{
    super::{
        network::TempoNetwork as KnownTempoNetwork, DEFAULT_CURRENCY_TESTNET, MODERATO_CHAIN_ID,
        OUSD, PATH_USD, USDC,
    },
    calls::{TRANSFER_SELECTOR, TRANSFER_WITH_MEMO_SELECTOR},
    fee_payer::MAX_FEE_PAYER_GAS_LIMIT,
    hash_credential::parse_hash_credential_source,
    memo::assert_challenge_bound_memo,
    receipt_logs::{
        match_receipt_transfer_logs, match_receipt_transfer_logs_with_settlement,
        MatchedTransferLog, ReceiptSenderPolicy, TRANSFER_EVENT_TOPIC,
        TRANSFER_WITH_MEMO_EVENT_TOPIC,
    },
    transaction_credential::TransactionValidationOptions,
    *,
};
use crate::protocol::core::{Base64UrlJson, PaymentChallenge};
use crate::tempo::attribution;

mod fee_payer;
mod hash_credential;
mod proof_credential;
mod receipt_logs;
mod simulate;
mod transaction_credential;
mod transaction_transfers;
mod verify;

struct AsyncOnlySigner {
    inner: alloy::signers::local::PrivateKeySigner,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl alloy::signers::Signer for AsyncOnlySigner {
    async fn sign_hash(&self, hash: &B256) -> alloy::signers::Result<alloy::primitives::Signature> {
        use alloy::signers::SignerSync;

        tokio::task::yield_now().await;
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.sign_hash_sync(hash)
    }

    fn address(&self) -> Address {
        alloy::signers::Signer::address(&self.inner)
    }

    fn chain_id(&self) -> Option<u64> {
        alloy::signers::Signer::chain_id(&self.inner)
    }

    fn set_chain_id(&mut self, chain_id: Option<u64>) {
        alloy::signers::Signer::set_chain_id(&mut self.inner, chain_id);
    }
}

fn test_charge_request_with_amount(amount: &str) -> ChargeRequest {
    ChargeRequest {
        amount: amount.to_string(),
        currency: "0x20c0000000000000000000000000000000000000".to_string(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
        method_details: Some(serde_json::json!({ "chainId": 42431 })),
        ..Default::default()
    }
}

fn test_proof_challenge(request: &ChargeRequest) -> PaymentChallenge {
    PaymentChallenge::new(
        "proof-challenge-id",
        "api.example.com",
        "tempo",
        "charge",
        Base64UrlJson::from_typed(request).unwrap(),
    )
}

/// Helper: build a valid TempoTransaction for fee payer tests.
fn make_fee_payer_tx(valid_before_secs_from_now: u64) -> tempo_alloy::primitives::TempoTransaction {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    tempo_alloy::primitives::TempoTransaction {
        chain_id: CHAIN_ID,
        nonce: 0,
        nonce_key: U256::MAX,
        gas_limit: 1_000_000,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        fee_token: None,
        fee_payer_signature: Some(alloy::primitives::Signature::new(
            U256::ZERO,
            U256::ZERO,
            false,
        )),
        valid_before: NonZeroU64::new(now + valid_before_secs_from_now),
        valid_after: None,
        calls: vec![tempo_alloy::primitives::transaction::Call {
            to: TxKind::Call(Address::repeat_byte(0x20)),
            value: U256::ZERO,
            input: Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]), // transfer selector
        }],
        access_list: Default::default(),
        tempo_authorization_list: vec![],
        key_authorization: None,
    }
}

fn make_transfer_input(recipient: Address, amount: U256) -> Bytes {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&TRANSFER_SELECTOR);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(recipient.as_slice());

    let mut amount_bytes = [0u8; 32];
    amount.to_be_bytes::<32>().clone_into(&mut amount_bytes);
    data.extend_from_slice(&amount_bytes);
    Bytes::from(data)
}

fn make_transfer_with_memo_input(recipient: Address, amount: U256, memo: [u8; 32]) -> Bytes {
    Bytes::from(
        ITIP20::transferWithMemoCall {
            to: recipient,
            amount,
            memo: memo.into(),
        }
        .abi_encode(),
    )
}

fn make_approve_input(spender: Address, amount: U256) -> Bytes {
    Bytes::from(ITIP20::approveCall { spender, amount }.abi_encode())
}

fn make_swap_input(token_in: Address, token_out: Address, amount_out: u128) -> Bytes {
    Bytes::from(
        IStablecoinDEX::swapExactAmountOutCall {
            tokenIn: token_in,
            tokenOut: token_out,
            amountOut: amount_out,
            maxAmountIn: amount_out,
        }
        .abi_encode(),
    )
}

fn encode_signed_tx(
    calls: Vec<tempo_alloy::primitives::transaction::Call>,
    gas_limit: u64,
) -> Vec<u8> {
    use alloy::eips::Encodable2718;
    use alloy::signers::SignerSync;

    let signer = alloy::signers::local::PrivateKeySigner::random();
    let tx = tempo_alloy::primitives::TempoTransaction {
        chain_id: CHAIN_ID,
        nonce: 0,
        nonce_key: U256::MAX,
        gas_limit,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        fee_token: Some(Address::repeat_byte(0x20)),
        fee_payer_signature: None,
        valid_before: None,
        valid_after: None,
        calls,
        access_list: Default::default(),
        tempo_authorization_list: vec![],
        key_authorization: None,
    };

    let signature: tempo_alloy::primitives::transaction::TempoSignature =
        signer.sign_hash_sync(&tx.signature_hash()).unwrap().into();

    tx.into_signed(signature).encoded_2718()
}

fn address_topic(address: Address) -> String {
    format!("0x{:0>64}", hex::encode(address.as_slice()))
}

fn amount_data(amount: U256) -> String {
    let mut amount_bytes = [0u8; 32];
    amount.to_be_bytes::<32>().clone_into(&mut amount_bytes);
    hex::encode(amount_bytes)
}

fn make_transfer_log(
    currency: Address,
    from: Address,
    to: Address,
    amount: U256,
) -> serde_json::Value {
    serde_json::json!({
        "address": format!("{:#x}", currency),
        "topics": [
            format!("{:#x}", TRANSFER_EVENT_TOPIC),
            address_topic(from),
            address_topic(to),
        ],
        "data": format!("0x{}", amount_data(amount)),
    })
}

fn make_transfer_with_memo_log(
    currency: Address,
    from: Address,
    to: Address,
    amount: U256,
    memo: [u8; 32],
) -> serde_json::Value {
    serde_json::json!({
        "address": format!("{:#x}", currency),
        "topics": [
            format!("{:#x}", TRANSFER_WITH_MEMO_EVENT_TOPIC),
            address_topic(from),
            address_topic(to),
            format!("0x{}", hex::encode(memo)),
        ],
        "data": format!("0x{}", amount_data(amount)),
    })
}

fn did_pkh(chain_id: u64, address: Address) -> String {
    format!("did:pkh:eip155:{chain_id}:{address}")
}

/// Helper: sign a tx and encode as a 0x78 fee payer envelope.
fn sign_and_encode_0x78(
    tx: tempo_alloy::primitives::TempoTransaction,
    signer: &alloy::signers::local::PrivateKeySigner,
) -> Vec<u8> {
    use super::super::{FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID};
    use alloy::signers::SignerSync;

    let sig_hash = tx.signature_hash();
    let sig = signer.sign_hash_sync(&sig_hash).unwrap();
    let signature: tempo_alloy::primitives::transaction::TempoSignature = sig.into();
    let encoded =
        FeePayerEnvelope78::from_signing_tx(tx, signer.address(), signature).encoded_envelope();
    assert_eq!(encoded[0], TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID);
    encoded
}
