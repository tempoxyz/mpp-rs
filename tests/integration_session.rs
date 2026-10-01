//! Integration tests for the MPP session flow with a live Tempo blockchain.
//!
//! A `TempoSessionProvider` pays a server built from `Mpp` and
//! `TempoSessionMethod` over HTTP, with every transaction settled on a Tempo
//! localnet. The localnet has no session escrow, so each test deploys the
//! `TempoStreamChannel` contract first.
//!
//! # Running
//!
//! ```bash
//! TEMPO_RPC_URL=http://localhost:8545 cargo test --features integration --test integration_session
//! ```

#![cfg(feature = "integration")]

use std::sync::Arc;

use alloy::eips::Encodable2718;
use alloy::network::ReceiptResponse;
use alloy::primitives::{address, Address, Bytes, TxKind, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy::sol_types::{SolCall, SolEvent};
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use mpp::client::{Fetch, TempoSessionProvider};
use mpp::protocol::methods::tempo::{ChannelState, SessionCredentialPayload};
use mpp::server::sse::{self, parse_event, ServeOptions, SseEvent};
use mpp::server::{
    tempo, tempo_provider, Mpp, SessionChallengeOptions, SessionChannelStore, SessionMethodConfig,
    SessionVerifyResult, TempoChargeMethod, TempoConfig, TempoProvider, TempoSessionMethod,
};
use mpp::{
    format_authorization, parse_authorization, parse_receipt, parse_www_authenticate,
    PaymentCredential,
};
use reqwest::Client;
use tempo_alloy::contracts::precompiles::tip20::ITIP20;
use tempo_alloy::primitives::transaction::Call;
use tempo_alloy::primitives::TempoTransaction;
use tempo_alloy::TempoNetwork;
use tokio::sync::Mutex;

/// Well-known dev private key (account[0] of test mnemonic).
const DEV_PRIVATE_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

/// PathUSD token address.
const PATH_USD: Address = address!("0x20c0000000000000000000000000000000000000");

/// HMAC secret for test servers (the SDK requires at least 32 bytes).
const TEST_SECRET: &str = "test-secret-key-at-least-32-bytes";

/// Default localnet RPC URL (overridable via `TEMPO_RPC_URL` env var).
const DEFAULT_RPC_URL: &str = "http://localhost:8545";

/// Creation bytecode of the `TempoStreamChannel` escrow: the `bytecode` field
/// of `test/fixtures/TempoStreamChannel.json` in wevm/mppx at commit b09a35a,
/// the artifact mppx deploys in its own session tests.
const ESCROW_CREATION_CODE: &str = include_str!("fixtures/TempoStreamChannel.hex");

/// Price of one streamed value in base units.
const TICK_COST: u128 = 100;

alloy::sol! {
    interface IEscrow {
        struct Channel {
            bool finalized;
            uint64 closeRequestedAt;
            address payer;
            address payee;
            address token;
            address authorizedSigner;
            uint128 deposit;
            uint128 settled;
        }

        function getChannel(bytes32 channelId) external view returns (Channel memory);
        function topUp(bytes32 channelId, uint256 additionalDeposit) external;
    }
}

fn rpc_url() -> String {
    std::env::var("TEMPO_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_string())
}

fn rpc_provider(rpc: &str) -> impl Provider<TempoNetwork> {
    ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc.parse().unwrap())
}

/// Serialize dev account transactions to avoid nonce conflicts across parallel tests.
static DEV_LOCK: std::sync::LazyLock<Mutex<()>> = std::sync::LazyLock::new(|| Mutex::new(()));

/// Send a transaction from the pre-funded dev account and return its receipt.
async fn dev_send(rpc: &str, calls: Vec<Call>) -> tempo_alloy::rpc::TempoTransactionReceipt {
    let _dev = DEV_LOCK.lock().await;
    let signer: PrivateKeySigner = DEV_PRIVATE_KEY.parse().unwrap();
    let provider = rpc_provider(rpc);

    let gas_price = provider.get_gas_price().await.unwrap();
    let tx = TempoTransaction {
        chain_id: provider.get_chain_id().await.unwrap(),
        nonce: provider
            .get_transaction_count(signer.address())
            .await
            .unwrap(),
        gas_limit: 10_000_000,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price,
        calls,
        ..Default::default()
    };
    let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let raw = Bytes::from(tx.into_signed(signature.into()).encoded_2718());

    let tx_hash: B256 = provider
        .raw_request("eth_sendRawTransaction".into(), (raw,))
        .await
        .expect("dev transaction rejected");
    let receipt = wait_for_receipt(&provider, tx_hash).await;
    assert!(receipt.status(), "dev transaction reverted: {tx_hash:#x}");
    receipt
}

async fn wait_for_receipt(
    provider: &impl Provider<TempoNetwork>,
    tx_hash: B256,
) -> tempo_alloy::rpc::TempoTransactionReceipt {
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash).await {
            return receipt;
        }
    }
    panic!("transaction not confirmed after 10s: {tx_hash:#x}");
}

/// Deploy the session escrow contract and return its address.
async fn deploy_escrow(rpc: &str) -> Address {
    let code = hex::decode(ESCROW_CREATION_CODE.trim().trim_start_matches("0x")).unwrap();
    let receipt = dev_send(
        rpc,
        vec![Call {
            to: TxKind::Create,
            value: U256::ZERO,
            input: Bytes::from(code),
        }],
    )
    .await;
    receipt
        .contract_address()
        .expect("escrow deployment has no contract address")
}

/// Fund an account with 10,000 pathUSD from the dev account.
async fn fund_account(rpc: &str, to: Address) {
    let amount = U256::from(10_000_000_000u64);
    dev_send(
        rpc,
        vec![Call {
            to: TxKind::Call(PATH_USD),
            value: U256::ZERO,
            input: Bytes::from(ITIP20::transferCall::new((to, amount)).abi_encode()),
        }],
    )
    .await;
}

async fn tip20_balance(provider: &impl Provider<TempoNetwork>, addr: Address) -> U256 {
    let call = ITIP20::balanceOfCall::new((addr,)).abi_encode();
    let result = provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(PATH_USD)
                .input(alloy::rpc::types::TransactionInput::new(Bytes::from(call)))
                .into(),
        )
        .await
        .expect("balanceOf call failed");
    U256::from_be_slice(&result)
}

async fn on_chain_channel(
    provider: &impl Provider<TempoNetwork>,
    escrow: Address,
    channel_id: B256,
) -> IEscrow::Channel {
    let call = IEscrow::getChannelCall::new((channel_id,)).abi_encode();
    let result = provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(escrow)
                .input(alloy::rpc::types::TransactionInput::new(Bytes::from(call)))
                .into(),
        )
        .await
        .expect("getChannel call failed");
    IEscrow::getChannelCall::abi_decode_returns(&result).unwrap()
}

/// The pathUSD the escrow paid out in `receipt`, as `(recipient, amount)`.
fn escrow_payouts(
    receipt: &tempo_alloy::rpc::TempoTransactionReceipt,
    escrow: Address,
) -> Vec<(Address, U256)> {
    receipt
        .logs()
        .iter()
        .filter(|log| log.address() == PATH_USD)
        .filter_map(|log| ITIP20::Transfer::decode_log_data(log.data()).ok())
        .filter(|transfer| transfer.from == escrow)
        .map(|transfer| (transfer.to, transfer.amount))
        .collect()
}

// ==================== Server ====================

type SessionMpp = Mpp<TempoChargeMethod<TempoProvider>, TempoSessionMethod<TempoProvider>>;

struct AppState {
    payment: SessionMpp,
    store: Arc<SessionChannelStore>,
    /// Values each stream delivers.
    values: usize,
    /// Deposit suggested for a new channel, in base units.
    suggested_deposit: u128,
}

/// A server whose `/stream` route sells `values` streamed values for
/// `TICK_COST` each through a session on `escrow`.
async fn start_server(
    rpc: &str,
    escrow: Address,
    payee: PrivateKeySigner,
    values: usize,
    suggested_deposit: u128,
) -> (String, Arc<AppState>) {
    let chain_id = rpc_provider(rpc).get_chain_id().await.unwrap();
    let store = Arc::new(SessionChannelStore::new());
    let session_method = TempoSessionMethod::new(
        tempo_provider(rpc).unwrap(),
        store.clone(),
        SessionMethodConfig {
            escrow_contract: escrow,
            chain_id,
            min_voucher_delta: 0,
        },
    )
    .with_close_signer(payee.clone());
    let payment = Mpp::create(
        tempo(TempoConfig {
            recipient: &format!("{:#x}", payee.address()),
        })
        .rpc_url(rpc)
        .chain_id(chain_id)
        .secret_key(TEST_SECRET),
    )
    .expect("failed to create Mpp")
    .with_session_method(session_method);

    let state = Arc::new(AppState {
        payment,
        store,
        values,
        suggested_deposit,
    });
    let app = Router::new()
        .route("/stream", get(stream).post(manage))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/stream", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, state)
}

/// Verify the session credential of a request, or answer it with a challenge
/// (no credential) or the reason it was rejected.
#[allow(clippy::result_large_err)]
async fn verify(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(PaymentCredential, SessionVerifyResult), Response> {
    let credential = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_authorization(value).ok());
    let Some(credential) = credential else {
        let challenge = state
            .payment
            .session_challenge_with_details(
                &TICK_COST.to_string(),
                &format!("{PATH_USD:#x}"),
                state.payment.recipient().unwrap(),
                SessionChallengeOptions {
                    unit_type: Some("value"),
                    suggested_deposit: Some(&state.suggested_deposit.to_string()),
                    ..Default::default()
                },
            )
            .unwrap();
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            [(header::WWW_AUTHENTICATE, challenge.to_header().unwrap())],
        )
            .into_response());
    };
    match state.payment.verify_session(&credential).await {
        Ok(verified) => Ok((credential, verified)),
        Err(error) => Err((StatusCode::BAD_REQUEST, error.to_string()).into_response()),
    }
}

/// Answer a credential that does not ask for content with its receipt.
fn receipt_response(verified: SessionVerifyResult) -> Response {
    let receipt = HeaderValue::from_str(&verified.receipt.to_header().unwrap()).unwrap();
    (
        [(header::HeaderName::from_static("payment-receipt"), receipt)],
        axum::Json(verified.management_response.unwrap_or_default()),
    )
        .into_response()
}

/// `GET /stream`: the content request. A voucher starts the metered stream.
async fn stream(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let (credential, verified) = match verify(&state, &headers).await {
        Ok(verified) => verified,
        Err(response) => return response,
    };
    // An open is answered directly; the client asks again with a voucher.
    if verified.management_response.is_some() {
        return receipt_response(verified);
    }

    let values = (0..state.values).map(|index| format!("value-{index}"));
    let events = sse::serve(ServeOptions {
        store: state.store.clone(),
        channel_id: verified.receipt.reference.clone(),
        challenge_id: credential.challenge.id.clone(),
        tick_cost: TICK_COST,
        generate: futures_util::stream::iter(values),
        poll_interval_ms: 50,
        min_voucher_delta: 0,
    });
    let body = Body::from_stream(futures_util::StreamExt::map(events, |event| {
        Ok::<_, std::convert::Infallible>(event)
    }));
    ([(header::CONTENT_TYPE, "text/event-stream")], body).into_response()
}

/// `POST /stream`: vouchers, top-ups and the close of a running session.
/// None of them asks for content, so a voucher must not start a stream here:
/// it would compete with the stream that asked for it.
async fn manage(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match verify(&state, &headers).await {
        Ok((_, verified)) => receipt_response(verified),
        Err(response) => response,
    }
}

// ==================== Client ====================

/// What a client saw on one metered stream.
#[derive(Debug, Default)]
struct Streamed {
    values: Vec<String>,
    need_vouchers: usize,
    /// `spent` and `units` of the final receipt.
    receipt: Option<(String, Option<u64>)>,
}

/// Read a metered stream to its end, answering every need-voucher event.
async fn read_stream(
    client: &Client,
    provider: &TempoSessionProvider,
    url: &str,
    mut response: reqwest::Response,
) -> Streamed {
    let mut streamed = Streamed::default();
    let mut buffer = String::new();
    while let Some(chunk) = response.chunk().await.expect("stream failed") {
        buffer.push_str(std::str::from_utf8(&chunk).unwrap());
        while let Some(end) = buffer.find("\n\n") {
            let event: String = buffer.drain(..end + 2).collect();
            match parse_event(&event) {
                Some(SseEvent::Message(value)) => streamed.values.push(value),
                Some(SseEvent::PaymentNeedVoucher(event)) => {
                    streamed.need_vouchers += 1;
                    provider
                        .send_voucher(
                            client,
                            url,
                            &event.channel_id,
                            event.required_cumulative.parse().unwrap(),
                        )
                        .await
                        .expect("voucher rejected");
                }
                Some(SseEvent::PaymentReceipt(receipt)) => {
                    streamed.receipt = Some((receipt.spent, receipt.units));
                }
                None => panic!("unparsable event: {event:?}"),
            }
        }
    }
    streamed
}

// ==================== Tests ====================

/// A funded payer and payee, an escrow, and a server selling `values` values
/// per stream.
struct Fixture {
    rpc: String,
    escrow: Address,
    payee: PrivateKeySigner,
    payer: PrivateKeySigner,
    url: String,
    server: Arc<AppState>,
    provider: TempoSessionProvider,
    client: Client,
}

impl Fixture {
    async fn new(values: usize, suggested_deposit: u128) -> Self {
        let rpc = rpc_url();
        let escrow = deploy_escrow(&rpc).await;
        let payee = PrivateKeySigner::random();
        let payer = PrivateKeySigner::random();
        fund_account(&rpc, payee.address()).await;
        fund_account(&rpc, payer.address()).await;

        let (url, server) =
            start_server(&rpc, escrow, payee.clone(), values, suggested_deposit).await;
        let provider = TempoSessionProvider::new(payer.clone(), &rpc)
            .unwrap()
            .with_escrow_contract(escrow);
        Self {
            rpc,
            escrow,
            payee,
            payer,
            url,
            server,
            provider,
            client: Client::new(),
        }
    }

    /// Open the channel with the first request and return its id.
    async fn open(&self) -> B256 {
        let opened = self
            .client
            .get(&self.url)
            .send_with_payment(&self.provider)
            .await
            .expect("open failed");
        assert_eq!(opened.status(), 200);
        let receipt = parse_receipt(opened.headers()["payment-receipt"].to_str().unwrap()).unwrap();
        let channels = self.provider.channels();
        let channel_id = channels
            .values()
            .next()
            .expect("no channel tracked")
            .channel_id;
        assert_eq!(receipt.reference, channel_id.to_string());
        channel_id
    }

    /// Pay for a stream with a voucher and read it to its end.
    async fn stream(&self) -> Streamed {
        let response = self
            .client
            .get(&self.url)
            .send_with_payment(&self.provider)
            .await
            .expect("stream request failed");
        assert_eq!(response.status(), 200);
        // A stream that waits for a voucher it never gets would hang the test.
        let stream = read_stream(&self.client, &self.provider, &self.url, response);
        tokio::time::timeout(std::time::Duration::from_secs(30), stream)
            .await
            .expect("stream did not end")
    }

    /// Close the channel and return the receipt of the settlement transaction.
    async fn close(&self) -> tempo_alloy::rpc::TempoTransactionReceipt {
        let receipt = self
            .provider
            .close(&self.client, &self.url)
            .await
            .expect("close failed")
            .expect("close returned no receipt");
        let receipt = serde_json::to_value(&receipt).unwrap();
        let tx_hash: B256 = receipt["txHash"]
            .as_str()
            .expect("close receipt has no transaction hash")
            .parse()
            .unwrap();
        let settlement = rpc_provider(&self.rpc)
            .get_transaction_receipt(tx_hash)
            .await
            .unwrap()
            .expect("close transaction not found");
        assert!(settlement.status());
        settlement
    }

    fn stored(&self, channel_id: B256) -> ChannelState {
        self.server
            .store
            .get_channel_sync(&channel_id.to_string())
            .expect("server does not know the channel")
    }
}

/// Open a channel, stream past the amount the first voucher covers, and
/// close: every value is paid for by a voucher, and the close settles exactly
/// what was delivered and refunds the rest of the deposit.
#[tokio::test]
async fn test_e2e_session_stream_and_close() {
    const VALUES: usize = 5;
    const DEPOSIT: u128 = 600;
    let spent = VALUES as u128 * TICK_COST;

    let fixture = Fixture::new(VALUES, DEPOSIT).await;
    let chain = rpc_provider(&fixture.rpc);

    let channel_id = fixture.open().await;
    let on_chain = on_chain_channel(&chain, fixture.escrow, channel_id).await;
    assert_eq!(on_chain.payer, fixture.payer.address());
    assert_eq!(on_chain.payee, fixture.payee.address());
    assert_eq!(on_chain.token, PATH_USD);
    assert_eq!(on_chain.deposit, DEPOSIT);
    assert_eq!(on_chain.settled, 0);

    let streamed = fixture.stream().await;
    let expected: Vec<String> = (0..VALUES).map(|index| format!("value-{index}")).collect();
    assert_eq!(streamed.values, expected);
    assert!(
        streamed.need_vouchers > 0,
        "the stream never asked for a voucher"
    );
    assert_eq!(
        streamed.receipt,
        Some((spent.to_string(), Some(VALUES as u64)))
    );

    // Nothing is settled until the close.
    let stored = fixture.stored(channel_id);
    assert_eq!(stored.spent, spent);
    assert_eq!(stored.highest_voucher_amount, spent);
    assert!(!stored.finalized);
    assert_eq!(
        tip20_balance(&chain, fixture.escrow).await,
        U256::from(DEPOSIT)
    );

    let settlement = fixture.close().await;
    let mut payouts = escrow_payouts(&settlement, fixture.escrow);
    payouts.sort();
    let mut expected = vec![
        (fixture.payee.address(), U256::from(spent)),
        (fixture.payer.address(), U256::from(DEPOSIT - spent)),
    ];
    expected.sort();
    assert_eq!(payouts, expected);
    assert_eq!(tip20_balance(&chain, fixture.escrow).await, U256::ZERO);
    assert!(fixture.stored(channel_id).finalized);
}

/// A top-up raises the deposit on-chain and in the server's record, and the
/// server then accepts a voucher above the old deposit.
///
/// The session client only tops up TIP-1034 channels, so the `topUp`
/// credential for this escrow channel is built by hand.
#[tokio::test]
async fn test_e2e_session_top_up() {
    const VALUES: usize = 3;
    const DEPOSIT: u128 = 300;
    const TOP_UP: u128 = 200;
    let spent = VALUES as u128 * TICK_COST;

    let fixture = Fixture::new(VALUES, DEPOSIT).await;
    let chain = rpc_provider(&fixture.rpc);
    let chain_id = chain.get_chain_id().await.unwrap();

    let channel_id = fixture.open().await;
    let streamed = fixture.stream().await;
    assert_eq!(streamed.values.len(), VALUES);
    assert_eq!(fixture.stored(channel_id).spent, DEPOSIT);

    // The deposit is used up. Answer a fresh challenge with a top-up.
    let unpaid = fixture.client.post(&fixture.url).send().await.unwrap();
    assert_eq!(unpaid.status(), 402);
    let challenge =
        parse_www_authenticate(unpaid.headers()["www-authenticate"].to_str().unwrap()).unwrap();

    let gas_price = chain.get_gas_price().await.unwrap();
    let call = |to: Address, input: Vec<u8>| Call {
        to: TxKind::Call(to),
        value: U256::ZERO,
        input: Bytes::from(input),
    };
    let tx = TempoTransaction {
        chain_id,
        nonce: chain
            .get_transaction_count(fixture.payer.address())
            .await
            .unwrap(),
        gas_limit: 2_000_000,
        max_fee_per_gas: gas_price,
        max_priority_fee_per_gas: gas_price,
        fee_token: Some(PATH_USD),
        calls: vec![
            call(
                PATH_USD,
                ITIP20::approveCall::new((fixture.escrow, U256::from(TOP_UP))).abi_encode(),
            ),
            call(
                fixture.escrow,
                IEscrow::topUpCall::new((channel_id, U256::from(TOP_UP))).abi_encode(),
            ),
        ],
        ..Default::default()
    };
    let signature = fixture.payer.sign_hash_sync(&tx.signature_hash()).unwrap();
    let transaction = tx.into_signed(signature.into()).encoded_2718();
    let credential = PaymentCredential::with_source(
        challenge.to_echo(),
        PaymentCredential::evm_did(chain_id, &fixture.payer.address().to_string()),
        SessionCredentialPayload::TopUp {
            payload_type: "transaction".to_string(),
            channel_id: channel_id.to_string(),
            transaction: alloy::hex::encode_prefixed(transaction),
            descriptor: None,
            settlement_route: None,
            additional_deposit: TOP_UP.to_string(),
        },
    );
    let topped_up = fixture
        .client
        .post(&fixture.url)
        .header("authorization", format_authorization(&credential).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(
        topped_up.status(),
        200,
        "{}",
        topped_up.text().await.unwrap()
    );

    let on_chain = on_chain_channel(&chain, fixture.escrow, channel_id).await;
    assert_eq!(on_chain.deposit, DEPOSIT + TOP_UP);
    assert_eq!(fixture.stored(channel_id).deposit, DEPOSIT + TOP_UP);

    // A voucher above the old deposit is accepted now. The client learns the
    // new deposit from the server, as it would from a need-voucher event.
    let voucher = fixture
        .provider
        .voucher_credential_with_top_up(
            &fixture.client,
            &fixture.url,
            reqwest::header::HeaderMap::new(),
            &channel_id.to_string(),
            DEPOSIT + TICK_COST,
            DEPOSIT + TOP_UP,
        )
        .await
        .expect("voucher above the old deposit");
    let accepted = fixture
        .client
        .post(&fixture.url)
        .header("authorization", format_authorization(&voucher).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(accepted.status(), 200, "{}", accepted.text().await.unwrap());
    assert_eq!(
        fixture.stored(channel_id).highest_voucher_amount,
        DEPOSIT + TICK_COST
    );

    // The client closes at the amount it authorized, so the close settles the
    // last voucher although nothing was delivered for it, and refunds the rest
    // of both deposits.
    let settlement = fixture.close().await;
    let mut payouts = escrow_payouts(&settlement, fixture.escrow);
    payouts.sort();
    let mut expected = vec![
        (fixture.payee.address(), U256::from(spent + TICK_COST)),
        (
            fixture.payer.address(),
            U256::from(DEPOSIT + TOP_UP - spent - TICK_COST),
        ),
    ];
    expected.sort();
    assert_eq!(payouts, expected);
    assert_eq!(tip20_balance(&chain, fixture.escrow).await, U256::ZERO);
}
