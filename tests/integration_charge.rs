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
use alloy::primitives::{address, Address, Bytes, TxKind, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::SignerSync;
use alloy::sol_types::SolCall;
use alloy_signer_local::PrivateKeySigner;
use axum::{routing::get, Json, Router};
use mpp::client::{Fetch, TempoProvider};
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

/// Read a TIP-20 balance for PATH_USD.
async fn tip20_balance<P: Provider<TempoNetwork>>(provider: &P, address: Address) -> U256 {
    let balance_call = ITIP20::balanceOfCall::new((address,)).abi_encode();
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

// ==================== Server helpers ====================

/// Start an axum server on port 0 and return (url, JoinHandle).
async fn start_server(
    mpp: impl Into<Arc<dyn ChargeChallenger>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let state = mpp.into();

    let app = Router::new()
        .route("/health", get(health))
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
    let balance_before = tip20_balance(&provider_http, client_signer.address()).await;

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
    let balance_after = tip20_balance(&provider_http, client_signer.address()).await;

    let charge_amount = U256::from(10_000u64); // $0.01 with 6 decimals
    let actual_decrease = balance_before - balance_after;
    assert!(
        actual_decrease >= charge_amount,
        "client balance should decrease by at least the charge amount ({charge_amount}), but decreased by {actual_decrease}"
    );

    handle.abort();
    let _ = handle.await;
}

/// Fee payer sponsorship should charge the fee payer for gas while the client
/// only transfers the payment amount.
#[tokio::test]
async fn test_fee_payer_sponsorship_charges_fee_payer() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    let provider_http =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap());

    let client_before = tip20_balance(&provider_http, client_signer.address()).await;
    let fee_payer_before = tip20_balance(&provider_http, server_signer.address()).await;

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(server_signer)
        .secret_key("fee-payer-balance-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let provider =
        TempoProvider::new(client_signer.clone(), &rpc).expect("failed to create TempoProvider");
    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .expect("payment failed");
    assert_eq!(resp.status(), 200);

    let client_after = tip20_balance(&provider_http, client_signer.address()).await;
    let fee_payer_after = tip20_balance(&provider_http, server_signer.address()).await;

    let charge_amount = U256::from(10_000u64);
    assert_eq!(client_before - client_after, charge_amount);
    assert!(
        fee_payer_after < fee_payer_before,
        "fee payer balance should decrease to cover gas"
    );

    handle.abort();
    let _ = handle.await;
}

/// Without sponsorship, the client should pay the charge amount plus gas.
#[tokio::test]
async fn test_non_fee_payer_pays_gas() {
    let rpc = rpc_url();
    let chain_id = get_chain_id(&rpc).await;

    let server_signer = PrivateKeySigner::random();
    let client_signer = PrivateKeySigner::random();

    fund_account(&rpc, server_signer.address()).await;
    fund_account(&rpc, client_signer.address()).await;

    let provider_http =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap());

    let client_before = tip20_balance(&provider_http, client_signer.address()).await;
    let gas_price = provider_http
        .get_gas_price()
        .await
        .expect("failed to get gas price");

    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{}", server_signer.address()),
        })
        .rpc_url(&rpc)
        .chain_id(chain_id)
        .secret_key("non-fee-payer-balance-test"),
    )
    .expect("failed to create Mpp");

    let (url, handle) = start_server(Arc::new(mpp) as Arc<dyn ChargeChallenger>).await;

    let provider =
        TempoProvider::new(client_signer.clone(), &rpc).expect("failed to create TempoProvider");
    let resp = Client::new()
        .get(format!("{url}/paid"))
        .send_with_payment(&provider)
        .await
        .expect("payment failed");
    assert_eq!(resp.status(), 200);

    let client_after = tip20_balance(&provider_http, client_signer.address()).await;
    let charge_amount = U256::from(10_000u64);
    let delta = client_before - client_after;

    if gas_price > U256::ZERO {
        assert!(
            delta > charge_amount,
            "client should pay gas without sponsorship"
        );
    } else {
        assert_eq!(delta, charge_amount);
    }

    handle.abort();
    let _ = handle.await;
}
