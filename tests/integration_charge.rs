//! Integration tests for the MPP charge flow with a live Tempo blockchain.
//!
//! These tests require a running Tempo localnet and are gated behind the
//! `integration` feature flag. They match the mppx test style: live blockchain
//! node + live HTTP server + real on-chain settlement.
//!
//! # Running
//!
//! ```bash
//! # Start a Tempo localnet first (e.g., via prool/Docker), then:
//! TEMPO_RPC_URL=http://localhost:8545 cargo test --features integration --test integration_charge
//! ```

#![cfg(feature = "integration")]

use std::sync::Arc;

use alloy::eips::Encodable2718;
use alloy::network::ReceiptResponse;
use alloy::primitives::{address, Address, Bytes, TxKind, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::SolCall;
use axum::{routing::get, Json, Router};
use mpp::client::{Fetch, PaymentProvider, TempoProvider};
use mpp::server::axum::{ChargeChallenger, ChargeConfig, MppCharge, WithReceipt};
use mpp::server::{tempo, Mpp, TempoConfig};
use reqwest::Client;
use tempo_alloy::contracts::precompiles::tip20::ITIP20;
use tempo_alloy::contracts::precompiles::ITIPFeeAMM;
use tempo_alloy::TempoNetwork;
use tempo_primitives::transaction::Call;
use tempo_primitives::TempoTransaction;
use tokio::sync::Mutex;

/// Well-known dev private key (account[0] of test mnemonic).
const DEV_PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// PathUSD token address.
const PATH_USD: Address = address!("0x20c0000000000000000000000000000000000000");

/// Fee manager precompile address.
const FEE_MANAGER: Address = address!("0xfeec000000000000000000000000000000000000");

/// Default localnet RPC URL (overridable via `TEMPO_RPC_URL` env var).
const DEFAULT_RPC_URL: &str = "http://localhost:8545";

fn rpc_url() -> String {
    std::env::var("TEMPO_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_string())
}

/// Fetch the chain ID from the RPC.
async fn get_chain_id(rpc: &str) -> u64 {
    let provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap());
    provider
        .get_chain_id()
        .await
        .expect("failed to get chain id")
}

/// Dev signer (account[0]) — pre-funded on localnet.
fn dev_signer() -> PrivateKeySigner {
    DEV_PRIVATE_KEY.parse().unwrap()
}

/// Serialize dev account transactions to avoid nonce conflicts across parallel tests.
static DEV_LOCK: std::sync::LazyLock<Mutex<()>> = std::sync::LazyLock::new(|| Mutex::new(()));

/// One-time setup: ensures AMM fee liquidity is minted.
static SETUP: std::sync::LazyLock<Mutex<bool>> = std::sync::LazyLock::new(|| Mutex::new(false));

/// Send a transaction from the dev account, optionally specifying a fee token.
/// Acquires DEV_LOCK internally to serialize nonce usage.
async fn dev_send_with_fee_token(rpc: &str, calls: Vec<Call>, fee_token: Option<Address>) -> B256 {
    let _dev = DEV_LOCK.lock().await;
    dev_send_with_fee_token_unlocked(rpc, calls, fee_token).await
}

/// Inner send helper — caller must hold DEV_LOCK.
async fn dev_send_with_fee_token_unlocked(
    rpc: &str,
    calls: Vec<Call>,
    fee_token: Option<Address>,
) -> B256 {
    let signer = dev_signer();
    let provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap());

    let nonce = provider
        .get_transaction_count(signer.address())
        .await
        .expect("failed to get nonce");
    let chain_id = provider
        .get_chain_id()
        .await
        .expect("failed to get chain id");
    let gas_price = provider
        .get_gas_price()
        .await
        .expect("failed to get gas price");

    let tx = TempoTransaction {
        chain_id,
        nonce,
        gas_limit: 5_000_000,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price,
        fee_token,
        calls,
        ..Default::default()
    };

    let sig = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let signed = tx.into_signed(sig.into());
    let raw = format!("0x{}", hex::encode(signed.encoded_2718()));

    let tx_hash: B256 = provider
        .raw_request("eth_sendRawTransaction".into(), (raw,))
        .await
        .expect("dev_send failed");

    // Wait for confirmation.
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash).await {
            use alloy::network::ReceiptResponse;
            assert!(receipt.status(), "dev transaction reverted: {tx_hash:#x}");
            return tx_hash;
        }
    }
    panic!("dev transaction not confirmed after 10s: {tx_hash:#x}");
}

/// Send a transaction from the dev account (default fee token).
async fn dev_send(rpc: &str, calls: Vec<Call>) -> B256 {
    dev_send_with_fee_token(rpc, calls, None).await
}

/// Mint AMM fee liquidity for token IDs 1, 2, 3 (matching mppx setup.ts).
///
/// Assumes a fresh localnet — if the chain already has liquidity, repeated
/// mints should still succeed (additive).
async fn setup_liquidity(rpc: &str) {
    let mut done = SETUP.lock().await;
    if *done {
        return;
    }

    // Hold DEV_LOCK once for the entire batch of mints.
    let _dev = DEV_LOCK.lock().await;

    let dev_addr = dev_signer().address();

    // Mint liquidity for fee tokens 1, 2, 3 with pathUSD as validator token.
    // TokenId.toAddress(n) = 0x20c0 + hex(n, 18 bytes), matching mppx setup.ts.
    let fee_tokens: [Address; 3] = [
        address!("0x20c0000000000000000000000000000000000001"),
        address!("0x20c0000000000000000000000000000000000002"),
        address!("0x20c0000000000000000000000000000000000003"),
    ];
    for user_token in fee_tokens {
        let mint_data = ITIPFeeAMM::mintCall::new((
            user_token,
            PATH_USD,
            U256::from(1_000_000_000u64), // 1000 pathUSD
            dev_addr,
        ))
        .abi_encode();

        // Use pathUSD as fee token for the mint tx itself (no AMM needed yet).
        // Use _unlocked variant since we already hold DEV_LOCK.
        dev_send_with_fee_token_unlocked(
            rpc,
            vec![Call {
                to: TxKind::Call(FEE_MANAGER),
                value: U256::ZERO,
                input: Bytes::from(mint_data),
            }],
            Some(PATH_USD),
        )
        .await;
    }

    *done = true;
}

/// Fund an account by transferring pathUSD from the dev account.
async fn fund_account(rpc: &str, to: Address) {
    setup_liquidity(rpc).await;

    let amount = U256::from(10_000_000_000u64); // 10,000 pathUSD
    let transfer_data = ITIP20::transferCall::new((to, amount)).abi_encode();

    dev_send(
        rpc,
        vec![Call {
            to: TxKind::Call(PATH_USD),
            value: U256::ZERO,
            input: Bytes::from(transfer_data),
        }],
    )
    .await;
}

/// Fund an account with an exact amount of pathUSD.
async fn fund_account_amount(rpc: &str, to: Address, amount: U256) {
    setup_liquidity(rpc).await;

    let transfer_data = ITIP20::transferCall::new((to, amount)).abi_encode();

    dev_send(
        rpc,
        vec![Call {
            to: TxKind::Call(PATH_USD),
            value: U256::ZERO,
            input: Bytes::from(transfer_data),
        }],
    )
    .await;
}

// ==================== Fee payer test helpers ====================

/// Encode a 0x78 fee payer envelope for testing (mirrors encode_fee_payer_envelope
/// in provider.rs which is private).
fn encode_fee_payer_envelope_for_test(
    tx: &TempoTransaction,
    sender: Address,
    signature: tempo_primitives::transaction::TempoSignature,
) -> Vec<u8> {
    mpp::protocol::methods::tempo::FeePayerEnvelope78::from_signing_tx(
        tx.clone(),
        sender,
        signature,
    )
    .encoded_envelope()
}

/// Query TIP-20 pathUSD balance for an address.
async fn tip20_balance(provider: &impl Provider<TempoNetwork>, addr: Address) -> U256 {
    let balance_call = ITIP20::balanceOfCall::new((addr,)).abi_encode();
    let result = provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(PATH_USD)
                .input(alloy::rpc::types::TransactionInput::new(Bytes::from(
                    balance_call,
                )))
                .into(),
        )
        .await
        .expect("balanceOf call failed");
    U256::from_be_slice(&result)
}

async fn wait_for_receipt(
    provider: &impl Provider<TempoNetwork>,
    tx_hash: B256,
) -> Result<tempo_alloy::rpc::TempoTransactionReceipt, String> {
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash).await {
            return Ok(receipt);
        }
    }
    Err(format!(
        "transaction receipt not found after 10s: {tx_hash:#x}"
    ))
}

// ==================== ChargeConfig types ====================

struct OneCent;
impl ChargeConfig for OneCent {
    fn amount() -> &'static str {
        "0.01"
    }
}

struct OneDollar;
impl ChargeConfig for OneDollar {
    fn amount() -> &'static str {
        "1.00"
    }
    fn description() -> Option<&'static str> {
        Some("Premium content")
    }
}

struct ZeroDollar;
impl ChargeConfig for ZeroDollar {
    fn amount() -> &'static str {
        "0"
    }
}

// ==================== Server helpers ====================

/// Start an axum server on port 0 and return (url, JoinHandle).
async fn start_server(
    mpp: impl Into<Arc<dyn ChargeChallenger>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let state = mpp.into();

    let app = Router::new()
        .route("/health", get(health))
        .route("/identity", get(identity))
        .route("/paid", get(paid))
        .route("/premium", get(premium))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("server error");
    });

    (url, handle)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn paid(charge: MppCharge<OneCent>) -> WithReceipt<Json<serde_json::Value>> {
    WithReceipt {
        receipt: charge.receipt,
        body: Json(serde_json::json!({ "message": "paid content" })),
    }
}

async fn premium(charge: MppCharge<OneDollar>) -> WithReceipt<Json<serde_json::Value>> {
    WithReceipt {
        receipt: charge.receipt,
        body: Json(serde_json::json!({ "message": "premium content", "tier": "gold" })),
    }
}

async fn identity(charge: MppCharge<ZeroDollar>) -> WithReceipt<Json<serde_json::Value>> {
    WithReceipt {
        receipt: charge.receipt,
        body: Json(serde_json::json!({ "message": "identity verified" })),
    }
}

// ==================== Tests ====================

/// Verify the health endpoint works (no payment required).
#[tokio::test]
async fn test_health_no_payment() {
    let rpc = rpc_url();
    let server_signer = PrivateKeySigner::random();
    fund_account(&rpc, server_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .secret_key("integration-test-secret"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let resp = Client::new()
        .get(format!("{url}/health"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");

    handle.abort();
    let _ = handle.await;
}

/// Hitting a paid endpoint with no Authorization header returns 402 with
/// a proper `WWW-Authenticate: Payment ...` challenge.
#[tokio::test]
async fn test_402_challenge_flow() {
    let rpc = rpc_url();
    let server_signer = PrivateKeySigner::random();
    fund_account(&rpc, server_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .secret_key("integration-test-secret"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 402);
    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("missing WWW-Authenticate header")
        .to_str()
        .unwrap();
    assert!(
        www_auth.starts_with("Payment "),
        "WWW-Authenticate should start with 'Payment '"
    );
    assert!(
        www_auth.contains("method=\"tempo\""),
        "challenge should contain method=tempo"
    );
    assert!(
        www_auth.contains("intent=\"charge\""),
        "challenge should contain intent=charge"
    );

    handle.abort();
    let _ = handle.await;
}

/// Full E2E charge round-trip: client hits server → gets 402 → signs real
/// TIP-20 transfer on-chain → server verifies → returns 200 with receipt.
///
/// This matches the mppx `Mppx.test.ts` "fetch" describe block pattern.
#[tokio::test]
async fn test_e2e_charge_round_trip() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(server_signer)
        .secret_key("e2e-test-secret"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let provider = TempoProvider::new(client_signer, &rpc).expect("failed to create TempoProvider");

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .expect("request with payment failed");

    assert_eq!(resp.status(), 200, "expected 200 after successful payment");

    // Verify Payment-Receipt header is present.
    let receipt_hdr = resp
        .headers()
        .get("payment-receipt")
        .expect("missing Payment-Receipt header")
        .to_str()
        .unwrap();
    let receipt = mpp::parse_receipt(receipt_hdr).expect("failed to parse receipt");
    assert_eq!(receipt.status, mpp::ReceiptStatus::Success);
    assert_eq!(receipt.method.as_str(), "tempo");
    assert!(
        receipt.reference.starts_with("0x"),
        "receipt reference should be a tx hash"
    );

    // Verify the response body.
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "paid content");

    handle.abort();
    let _ = handle.await;
}

/// Zero-amount auth flows should use a signed proof instead of a transaction.
#[tokio::test]
async fn test_zero_amount_identity_flow_uses_proof_credential() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .secret_key("identity-test-secret"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let provider = TempoProvider::new(client_signer, &rpc).expect("failed to create TempoProvider");

    let first = Client::new()
        .get(format!("{url}/identity"))
        .send()
        .await
        .expect("identity request failed");
    assert_eq!(first.status(), 402);

    let www_auth = first
        .headers()
        .get("www-authenticate")
        .expect("missing WWW-Authenticate header")
        .to_str()
        .unwrap();
    let challenge = mpp::parse_www_authenticate(www_auth).expect("failed to parse challenge");

    let credential = provider
        .pay(&challenge)
        .await
        .expect("failed to create proof credential");
    let payload = credential
        .charge_payload()
        .expect("expected charge payload");
    assert!(
        payload.is_proof(),
        "zero-amount flow should use proof payloads"
    );

    let auth_header = mpp::format_authorization(&credential).expect("failed to format credential");
    let response = Client::new()
        .get(format!("{url}/identity"))
        .header("authorization", auth_header)
        .send()
        .await
        .expect("identity auth request failed");

    assert_eq!(response.status(), 200);

    let receipt_hdr = response
        .headers()
        .get("payment-receipt")
        .expect("missing Payment-Receipt header")
        .to_str()
        .unwrap();
    let receipt = mpp::parse_receipt(receipt_hdr).expect("failed to parse receipt");
    assert_eq!(receipt.status, mpp::ReceiptStatus::Success);
    assert_eq!(receipt.reference, challenge.id);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["message"], "identity verified");

    handle.abort();
    let _ = handle.await;
}

/// E2E charge round-trip for a higher amount with description.
#[tokio::test]
async fn test_e2e_premium_charge() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(server_signer)
        .secret_key("premium-test-secret"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let provider = TempoProvider::new(client_signer, &rpc).expect("failed to create TempoProvider");

    let resp = Client::new()
        .get(format!("{url}/premium"))
        .send_with_payment(&provider)
        .await
        .expect("premium request failed");

    assert_eq!(resp.status(), 200);

    let receipt_hdr = resp
        .headers()
        .get("payment-receipt")
        .expect("missing Payment-Receipt header")
        .to_str()
        .unwrap();
    let receipt = mpp::parse_receipt(receipt_hdr).expect("failed to parse receipt");
    assert_eq!(receipt.status, mpp::ReceiptStatus::Success);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "premium content");
    assert_eq!(body["tier"], "gold");

    handle.abort();
    let _ = handle.await;
}

/// Verify that a wrong Authorization scheme (e.g., Bearer) is treated as
/// "no payment" and returns 402 with a challenge.
#[tokio::test]
async fn test_wrong_auth_scheme_returns_402() {
    let rpc = rpc_url();
    let server_signer = PrivateKeySigner::random();
    fund_account(&rpc, server_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .secret_key("wrong-scheme-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .header("authorization", "Bearer some-jwt-token")
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 402);
    assert!(resp.headers().contains_key("www-authenticate"));

    handle.abort();
    let _ = handle.await;
}

/// Sending a malformed `Authorization: Payment <garbage>` credential returns
/// 402 with a fresh challenge (matching mppx's "malformed credential" test).
#[tokio::test]
async fn test_malformed_credential_returns_402() {
    let rpc = rpc_url();
    let server_signer = PrivateKeySigner::random();
    fund_account(&rpc, server_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .secret_key("malformed-cred-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .header("authorization", "Payment !!not-valid-base64!!")
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status(), 402);
    assert!(
        resp.headers().contains_key("www-authenticate"),
        "should return a fresh challenge for retry"
    );

    handle.abort();
    let _ = handle.await;
}

/// Transfer to the wrong recipient on-chain → server rejects the credential
/// and returns 402 (matching mppx's "rejects hash with non-matching Transfer log").
#[tokio::test]
async fn test_wrong_recipient_transfer_rejected() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let wrong_recipient = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .secret_key("wrong-recipient-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    // Step 1: Get the 402 challenge.
    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status(), 402);

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("missing WWW-Authenticate")
        .to_str()
        .unwrap();
    let challenge = mpp::parse_www_authenticate(www_auth).expect("failed to parse challenge");

    // Step 2: Send a real TIP-20 transfer to the WRONG recipient.
    let charge: mpp::ChargeRequest = challenge.request.decode().unwrap();
    let amount: U256 = charge.amount.parse().unwrap();
    let currency: Address = charge.currency.parse().unwrap();

    let transfer_data = ITIP20::transferCall::new((wrong_recipient.address(), amount)).abi_encode();

    let tx_hash = dev_send(
        &rpc,
        vec![Call {
            to: TxKind::Call(currency),
            value: U256::ZERO,
            input: Bytes::from(transfer_data),
        }],
    )
    .await;

    // Step 3: Build a credential with the wrong-recipient tx hash.
    let echo = challenge.to_echo();
    let credential =
        mpp::PaymentCredential::new(echo, mpp::PaymentPayload::hash(format!("{tx_hash:#x}")));
    let auth_header =
        mpp::format_authorization(&credential).expect("failed to format authorization");

    // Step 4: Submit — should be rejected with 402.
    let resp = Client::new()
        .get(format!("{url}/paid"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        402,
        "wrong-recipient transfer should be rejected"
    );

    handle.abort();
    let _ = handle.await;
}

/// Two different clients can independently pay for the same endpoint,
/// each getting their own receipt.
#[tokio::test]
async fn test_multiple_sequential_payments() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_a = PrivateKeySigner::random();
    let client_b = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_a.address()).await;
    fund_account(&rpc, client_b.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(server_signer)
        .secret_key("multi-pay-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    // Client A pays.
    let provider_a = TempoProvider::new(client_a, &rpc).expect("failed to create TempoProvider A");
    let resp_a = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider_a)
        .await
        .expect("client A payment failed");
    assert_eq!(resp_a.status(), 200);

    let receipt_a_hdr = resp_a
        .headers()
        .get("payment-receipt")
        .expect("missing receipt A")
        .to_str()
        .unwrap();
    let receipt_a = mpp::parse_receipt(receipt_a_hdr).expect("failed to parse receipt A");
    assert_eq!(receipt_a.status, mpp::ReceiptStatus::Success);

    // Client B pays.
    let provider_b = TempoProvider::new(client_b, &rpc).expect("failed to create TempoProvider B");
    let resp_b = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider_b)
        .await
        .expect("client B payment failed");
    assert_eq!(resp_b.status(), 200);

    let receipt_b_hdr = resp_b
        .headers()
        .get("payment-receipt")
        .expect("missing receipt B")
        .to_str()
        .unwrap();
    let receipt_b = mpp::parse_receipt(receipt_b_hdr).expect("failed to parse receipt B");
    assert_eq!(receipt_b.status, mpp::ReceiptStatus::Success);

    // Receipts should reference different transactions.
    assert_ne!(
        receipt_a.reference, receipt_b.reference,
        "each payment should produce a unique tx reference"
    );

    handle.abort();
    let _ = handle.await;
}

/// Verify client balance decreases after a successful payment.
#[tokio::test]
async fn test_client_balance_decreases_after_payment() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    let provider_http =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap());

    // Check balance before payment.
    let balance_call = ITIP20::balanceOfCall::new((client_signer.address(),)).abi_encode();
    let balance_before: U256 = {
        let result = provider_http
            .call(
                alloy::rpc::types::TransactionRequest::default()
                    .to(PATH_USD)
                    .input(alloy::rpc::types::TransactionInput::new(Bytes::from(
                        balance_call.clone(),
                    )))
                    .into(),
            )
            .await
            .expect("balanceOf call failed");
        U256::from_be_slice(&result)
    };

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(server_signer)
        .secret_key("balance-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    // Pay $0.01 (10_000 base units with 6 decimals).
    let provider =
        TempoProvider::new(client_signer.clone(), &rpc).expect("failed to create TempoProvider");
    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .expect("payment failed");
    assert_eq!(resp.status(), 200);

    // Check balance after payment.
    let balance_after: U256 = {
        let result = provider_http
            .call(
                alloy::rpc::types::TransactionRequest::default()
                    .to(PATH_USD)
                    .input(alloy::rpc::types::TransactionInput::new(Bytes::from(
                        balance_call,
                    )))
                    .into(),
            )
            .await
            .expect("balanceOf call failed");
        U256::from_be_slice(&result)
    };

    let charge_amount = U256::from(10_000u64); // $0.01 with 6 decimals
    let actual_decrease = balance_before - balance_after;
    assert!(
        actual_decrease >= charge_amount,
        "client balance should decrease by at least the charge amount ({charge_amount}), but decreased by {actual_decrease}"
    );

    handle.abort();
    let _ = handle.await;
}

// ==================== Fee payer vs non-fee-payer tests ====================

/// E2E round-trip WITHOUT fee payer: client signs a standard 0x76 transaction
/// and broadcasts it directly. Server verifies on-chain.
#[tokio::test]
async fn test_e2e_charge_without_fee_payer() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    let client_addr = client_signer.address();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    // Server configured WITHOUT fee_payer
    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .secret_key("no-fee-payer-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let provider = TempoProvider::new(client_signer, &rpc).expect("failed to create TempoProvider");

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .expect("non-fee-payer payment failed");

    assert_eq!(
        resp.status(),
        200,
        "expected 200 after successful non-fee-payer payment"
    );

    let receipt_hdr = resp
        .headers()
        .get("payment-receipt")
        .expect("missing Payment-Receipt header")
        .to_str()
        .unwrap();
    let receipt = mpp::parse_receipt(receipt_hdr).expect("failed to parse receipt");
    assert_eq!(receipt.status, mpp::ReceiptStatus::Success);
    assert_eq!(receipt.method.as_str(), "tempo");
    assert!(receipt.reference.starts_with("0x"));

    // Assert on-chain receipt reports sender as fee payer (no sponsorship).
    let provider_http =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap());
    let tx_hash: B256 = receipt
        .reference
        .parse()
        .expect("receipt reference should be B256");
    let chain_receipt = wait_for_receipt(&provider_http, tx_hash)
        .await
        .expect("receipt not found");
    assert_eq!(chain_receipt.from(), client_addr);
    assert_eq!(
        chain_receipt.fee_payer, client_addr,
        "without fee sponsorship, fee_payer should equal sender"
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "paid content");

    handle.abort();
    let _ = handle.await;
}

/// E2E round-trip WITH fee payer: client signs a 0x78 fee payer envelope,
/// server co-signs and broadcasts as 0x76.
#[tokio::test]
async fn test_e2e_charge_with_fee_payer() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    let fee_payer_addr = server_signer.address();
    let client_addr = client_signer.address();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", fee_payer_addr),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(server_signer)
        .secret_key("fee-payer-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let provider = TempoProvider::new(client_signer, &rpc).expect("failed to create TempoProvider");

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .expect("fee-payer payment failed");

    assert_eq!(
        resp.status(),
        200,
        "expected 200 after successful fee-payer payment"
    );

    let receipt_hdr = resp
        .headers()
        .get("payment-receipt")
        .expect("missing Payment-Receipt header")
        .to_str()
        .unwrap();
    let receipt = mpp::parse_receipt(receipt_hdr).expect("failed to parse receipt");
    assert_eq!(receipt.status, mpp::ReceiptStatus::Success);
    assert_eq!(receipt.method.as_str(), "tempo");
    assert!(receipt.reference.starts_with("0x"));

    // Assert on-chain receipt reports fee_payer as the sponsor (server), not the sender.
    let provider_http =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap());
    let tx_hash: B256 = receipt
        .reference
        .parse()
        .expect("receipt reference should be B256");
    let chain_receipt = wait_for_receipt(&provider_http, tx_hash)
        .await
        .expect("receipt not found");

    assert_eq!(chain_receipt.from(), client_addr);
    assert_eq!(
        chain_receipt.fee_payer, fee_payer_addr,
        "with fee sponsorship, fee_payer should be the configured sponsor"
    );
    assert_ne!(
        chain_receipt.fee_payer,
        chain_receipt.from(),
        "with sponsorship, fee_payer must differ from sender"
    );
    assert_eq!(
        chain_receipt.fee_token,
        Some(PATH_USD),
        "server should choose pathUSD as the fee token on localnet"
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "paid content");

    handle.abort();
    let _ = handle.await;
}

/// Fee payer requested but server has no signer configured → 402.
#[tokio::test]
async fn test_fee_payer_requested_but_no_signer_returns_402() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    // Enable fee_payer in challenges but do NOT set a fee_payer_signer
    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .secret_key("no-signer-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let provider = TempoProvider::new(client_signer, &rpc).expect("failed to create TempoProvider");

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        402,
        "fee payer requested without signer should return 402"
    );
    assert!(
        resp.headers().contains_key("www-authenticate"),
        "should return a fresh challenge for retry"
    );

    handle.abort();
    let _ = handle.await;
}

/// Fee payer with malicious 0x78 envelope (wrong recipient) → server rejects with 402.
/// The server co-signs (it can't avoid it) but validate_transaction catches the
/// wrong recipient before broadcasting.
#[tokio::test]
async fn test_fee_payer_wrong_recipient_rejected() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();
    let wrong_recipient = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(server_signer.clone())
        .secret_key("wrong-recipient-fp-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    // Step 1: Get a 402 challenge.
    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status(), 402);

    let www_auth = resp
        .headers()
        .get("www-authenticate")
        .expect("missing WWW-Authenticate")
        .to_str()
        .unwrap();
    let challenge = mpp::parse_www_authenticate(www_auth).expect("failed to parse challenge");

    // Step 2: Build a 0x78 fee payer envelope that sends to the WRONG recipient.
    let charge: mpp::ChargeRequest = challenge.request.decode().unwrap();
    let amount: U256 = charge.amount.parse().unwrap();
    let currency: Address = charge.currency.parse().unwrap();

    // Build transferWithMemo to wrong_recipient instead of server_signer
    let transfer_data = ITIP20::transferCall::new((wrong_recipient.address(), amount)).abi_encode();

    let provider_http =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap());
    let gas_price = provider_http
        .get_gas_price()
        .await
        .expect("failed to get gas price");

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let tx = TempoTransaction {
        chain_id,
        nonce: 0,
        nonce_key: U256::MAX,
        gas_limit: 1_000_000,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price,
        fee_token: None,
        fee_payer_signature: Some(alloy::primitives::Signature::new(
            U256::ZERO,
            U256::ZERO,
            false,
        )),
        valid_before: Some(now + 25),
        valid_after: None,
        calls: vec![Call {
            to: TxKind::Call(currency),
            value: U256::ZERO,
            input: Bytes::from(transfer_data),
        }],
        ..Default::default()
    };

    // Sign and encode as 0x78 envelope
    let sig_hash = tx.signature_hash();
    let sig = client_signer.sign_hash_sync(&sig_hash).unwrap();

    let tx_bytes = encode_fee_payer_envelope_for_test(&tx, client_signer.address(), sig.into());
    let signed_tx_hex = format!("0x{}", hex::encode(&tx_bytes));

    // Step 3: Build a credential with the malicious envelope.
    let echo = challenge.to_echo();
    let credential = mpp::PaymentCredential::with_source(
        echo,
        format!("did:pkh:eip155:{}:{}", chain_id, client_signer.address()),
        mpp::PaymentPayload::transaction(signed_tx_hex),
    );
    let auth_header =
        mpp::format_authorization(&credential).expect("failed to format authorization");

    // Step 4: Submit — should be rejected with 402.
    let resp = Client::new()
        .get(format!("{url}/paid"))
        .header("authorization", &auth_header)
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        402,
        "wrong-recipient fee payer envelope should be rejected"
    );

    handle.abort();
    let _ = handle.await;
}

/// Verify that with fee payer enabled, the client's pathUSD balance decreases
/// (payment amount) while the fee payer's native/pathUSD balance is used for gas.
#[tokio::test]
async fn test_fee_payer_balance_accounting() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    let provider_http =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap());

    // Record balances before payment.
    let client_balance_before = tip20_balance(&provider_http, client_signer.address()).await;
    let server_balance_before = tip20_balance(&provider_http, server_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(server_signer.clone())
        .secret_key("balance-accounting-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let provider =
        TempoProvider::new(client_signer.clone(), &rpc).expect("failed to create TempoProvider");

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .expect("fee-payer payment failed");
    assert_eq!(resp.status(), 200);

    // Assert on-chain receipt shows sponsorship.
    let receipt_hdr = resp
        .headers()
        .get("payment-receipt")
        .expect("missing Payment-Receipt header")
        .to_str()
        .unwrap();
    let receipt = mpp::parse_receipt(receipt_hdr).expect("failed to parse receipt");
    let tx_hash: B256 = receipt
        .reference
        .parse()
        .expect("receipt reference should be B256");
    let chain_receipt = wait_for_receipt(&provider_http, tx_hash)
        .await
        .expect("receipt not found");
    assert_eq!(chain_receipt.from(), client_signer.address());
    assert_eq!(chain_receipt.fee_payer, server_signer.address());

    // Record balances after payment.
    let client_balance_after = tip20_balance(&provider_http, client_signer.address()).await;
    let server_balance_after = tip20_balance(&provider_http, server_signer.address()).await;

    let charge_amount = U256::from(10_000u64); // $0.01 with 6 decimals

    // Client's pathUSD should decrease by at least the charge amount.
    let client_decrease = client_balance_before - client_balance_after;
    assert!(
        client_decrease >= charge_amount,
        "client pathUSD should decrease by at least {charge_amount}, but decreased by {client_decrease}"
    );

    // Server is both recipient and fee payer. Its net change is:
    //   +charge_amount (received payment) - gas_cost (paid gas in pathUSD)
    // So the server's balance should increase, but by less than charge_amount.
    let server_increase = server_balance_after - server_balance_before;
    assert!(
        !server_increase.is_zero(),
        "server pathUSD should increase (received payment minus gas), but didn't change"
    );

    // In fee payer mode, the fee payer (server) pays gas. The client's decrease
    // should be exactly the charge amount — no gas cost for the client.
    // Allow a small tolerance in case of rounding.
    assert_eq!(
        client_decrease, charge_amount,
        "in fee payer mode, client should only pay the charge amount (no gas), \
         but client balance decreased by {client_decrease} instead of {charge_amount}"
    );

    handle.abort();
    let _ = handle.await;
}

/// Regression: without fee sponsorship, a client that only has `amount` pathUSD should
/// fail to pay (because it also needs gas). With fee sponsorship enabled, the same
/// client should succeed (client only pays `amount`; sponsor pays gas).
#[tokio::test]
async fn test_fee_payer_allows_client_without_gas_buffer() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    let fee_payer_addr = server_signer.address();
    let client_addr = client_signer.address();

    // Sponsor has plenty of funds.
    fund_account(&rpc, fee_payer_addr).await;

    // Client has ONLY the charge amount.
    let charge_amount = U256::from(10_000u64); // $0.01 with 6 decimals
    fund_account_amount(&rpc, client_addr, charge_amount).await;

    let provider_http =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap());

    // Sanity check: balance starts exactly at charge_amount.
    let client_balance_before = tip20_balance(&provider_http, client_addr).await;
    assert_eq!(client_balance_before, charge_amount);

    // --- Case 1: NO fee payer → should fail with insufficient funds for gas.
    let mpp_no_fp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", fee_payer_addr),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .secret_key("no-fp-no-buffer"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp_no_fp) as Arc<dyn ChargeChallenger>).await;
    let provider = TempoProvider::new(client_signer.clone(), &rpc).expect("TempoProvider");

    let result = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await;

    // Without fee sponsorship the client has no gas buffer, so either:
    //   (a) gas estimation reverts client-side → Err, or
    //   (b) the payment tx goes through but the transfer fails/reverts and the
    //       server responds 402 again → Ok(402).
    // Both outcomes are acceptable; the key invariant is that the client's
    // balance does NOT decrease (no successful payment was made).
    let payment_failed = match &result {
        Err(_) => true,
        Ok(resp) => resp.status() == reqwest::StatusCode::PAYMENT_REQUIRED,
    };
    assert!(
        payment_failed,
        "expected payment failure without fee payer, got: {:?}",
        result,
    );

    // The charge amount should NOT have been transferred. Gas may be consumed if the
    // tx was submitted and reverted (gas is paid in TIP-20 for AA txs), but the
    // full charge (10,000) must not have been deducted.
    let client_balance_after_failed = tip20_balance(&provider_http, client_addr).await;
    let consumed = charge_amount - client_balance_after_failed;
    assert!(
        consumed < charge_amount,
        "full charge was deducted despite payment failure: consumed={consumed}",
    );

    handle.abort();
    let _ = handle.await;

    // Re-fund the client: Case 1 may have consumed gas (TIP-20), leaving the
    // balance below the charge amount.
    let shortfall = charge_amount.saturating_sub(tip20_balance(&provider_http, client_addr).await);
    if shortfall > U256::ZERO {
        fund_account_amount(&rpc, client_addr, shortfall).await;
    }

    // --- Case 2: Fee payer enabled → should succeed.
    let mpp_fp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", fee_payer_addr),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(server_signer)
        .secret_key("fp-no-buffer"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp_fp) as Arc<dyn ChargeChallenger>).await;

    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .expect("fee payer payment should succeed");
    assert_eq!(resp.status(), 200);

    let receipt_hdr = resp
        .headers()
        .get("payment-receipt")
        .expect("missing Payment-Receipt header")
        .to_str()
        .unwrap();
    let receipt = mpp::parse_receipt(receipt_hdr).expect("failed to parse receipt");
    let tx_hash: B256 = receipt
        .reference
        .parse()
        .expect("receipt reference should be B256");
    let chain_receipt = wait_for_receipt(&provider_http, tx_hash)
        .await
        .expect("receipt not found");
    assert_eq!(chain_receipt.from(), client_addr);
    assert_eq!(chain_receipt.fee_payer, fee_payer_addr);

    // Client should have paid exactly `charge_amount` and nothing else.
    let client_balance_after = tip20_balance(&provider_http, client_addr).await;
    assert_eq!(client_balance_after, U256::ZERO);

    handle.abort();
    let _ = handle.await;
}

/// Fee-payer-enabled server handles premium ($1) charges correctly.
#[tokio::test]
async fn test_e2e_fee_payer_premium_charge() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(server_signer)
        .secret_key("fee-payer-premium-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let provider = TempoProvider::new(client_signer, &rpc).expect("failed to create TempoProvider");

    let resp = Client::new()
        .get(format!("{url}/premium"))
        .send_with_payment(&provider)
        .await
        .expect("fee-payer premium payment failed");

    assert_eq!(resp.status(), 200);

    let receipt_hdr = resp
        .headers()
        .get("payment-receipt")
        .expect("missing Payment-Receipt header")
        .to_str()
        .unwrap();
    let receipt = mpp::parse_receipt(receipt_hdr).expect("failed to parse receipt");
    assert_eq!(receipt.status, mpp::ReceiptStatus::Success);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["message"], "premium content");
    assert_eq!(body["tier"], "gold");

    handle.abort();
    let _ = handle.await;
}
