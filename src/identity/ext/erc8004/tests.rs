use std::sync::Arc;

use alloy::primitives::{address, Address, Bytes, FixedBytes, U256};
use alloy::providers::mock::Asserter;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol_types::SolCall;
use http_types::{HeaderMap, HeaderValue, Method, Uri};
use serde_json::json;

use super::constants::{IDENTITY_REGISTRY, TYPE};
use super::server::{create, Config, Erc8004, IIdentityRegistry, IERC1271};
use super::*;
use crate::identity::{
    IdentityRequest, PaymentCheck, PaymentCheckInput, Rejection, RejectionStatus, Verification,
    Verifier,
};
use crate::protocol::core::{Base64UrlJson, PaymentChallenge, PaymentCredential, PaymentPayload};
use crate::store::MemoryStore;

const ORIGIN: &str = "https://api.example";
const URL: &str = "https://api.example/haiku?q=1";
const CONTRACT_WALLET: Address = address!("0x3333333333333333333333333333333333333333");

fn agent_key() -> PrivateKeySigner {
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
        .parse()
        .unwrap()
}

fn other_key() -> PrivateKeySigner {
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
        .parse()
        .unwrap()
}

/// A stand-in for the registry's chain: answers `eth_call`s in order.
fn registry() -> Asserter {
    Asserter::new()
}

fn wallet(asserter: &Asserter, wallet: Address) {
    asserter.push_success(&Bytes::from(
        IIdentityRegistry::getAgentWalletCall::abi_encode_returns(&wallet),
    ));
}

fn setup(asserter: &Asserter, config: impl FnOnce(Config) -> Config) -> Erc8004 {
    let provider = ProviderBuilder::new()
        .connect_mocked_client(asserter.clone())
        .erased();
    create(config(
        Config::new(ORIGIN)
            .provider(provider)
            .store(Arc::new(MemoryStore::new())),
    ))
    .unwrap()
}

fn id(agent_id: u64) -> String {
    AgentRef {
        chain_id: 4217,
        registry: IDENTITY_REGISTRY,
        agent_id: U256::from(agent_id),
    }
    .format()
}

fn request(headers: &[(&str, String)]) -> IdentityRequest {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            http_types::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    IdentityRequest::new(Method::GET, Uri::from_static("/haiku?q=1"), map)
}

/// Signs a request to `URL` with the client prover and returns it as the server sees it.
#[cfg(feature = "client")]
async fn signed(signer: PrivateKeySigner, agent_id: u64) -> IdentityRequest {
    use crate::identity::client::{ProveContext, Prover, Scope};

    let prover = client::prover(client::ProverConfig::new(
        signer,
        U256::from(agent_id),
        Scope::origins([ORIGIN]),
    ));
    let context = ProveContext {
        created: now(),
        nonce: format!("nonce-{}", now()),
        challenge: None,
    };
    let mut outbound = reqwest::Request::new(reqwest::Method::GET, URL.parse().unwrap());
    prover.prove(&mut outbound, &context).await.unwrap();
    assert!(outbound.headers()["agent-signature"].is_sensitive());
    let headers: Vec<(&str, String)> = ["agent-id", "agent-signature"]
        .into_iter()
        .map(|name| (name, outbound.headers()[name].to_str().unwrap().to_owned()))
        .collect();
    request(&headers)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn rejected<T: std::fmt::Debug>(outcome: Verification<T>) -> Rejection {
    match outcome {
        Verification::Rejected(rejection) => rejection,
        Verification::Valid(value) => panic!("expected a rejection, got {value:?}"),
    }
}

fn credential(intent: &str, payload: serde_json::Value, payer: Address) -> PaymentCredential {
    let challenge = PaymentChallenge::new(
        "challenge-1",
        "api.example",
        "tempo",
        intent,
        Base64UrlJson::from_value(&json!({"amount": "1"})).unwrap(),
    );
    let mut credential = PaymentCredential::new(challenge.to_echo(), payload);
    credential.source = Some(format!("did:pkh:eip155:4217:{payer}"));
    credential
}

async fn check(
    agents: &Erc8004,
    request: &IdentityRequest,
    credential: &PaymentCredential,
) -> Verification<Agent> {
    agents
        .payment_check
        .verify(PaymentCheckInput {
            request,
            challenge: &credential.challenge,
            credential: Some(credential),
        })
        .await
}

#[test]
fn formats_and_parses_agent_ids() {
    let agent = AgentRef::parse(&id(42)).unwrap();
    assert_eq!(agent.agent_id, U256::from(42));
    assert_eq!(agent.registry, IDENTITY_REGISTRY);
    assert_eq!(
        id(42),
        "eip155:4217:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432:42"
    );
    let lower = "eip155:4217:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42";
    assert_eq!(AgentRef::parse(lower).unwrap().format(), id(42));
    for malformed in [
        "",
        "eip155:4217:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432",
        "eip155:4217:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42:1",
        "eip155:4217:0x8004:42",
        "eip155:x:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42",
        "cosmos:4217:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:42",
        "eip155:4217:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432:-1",
    ] {
        assert!(AgentRef::parse(malformed).is_none(), "{malformed}");
    }
    assert_eq!(
        message(&id(1), "GET", URL, 10, "n"),
        format!("mppx:erc8004\n{}\nGET {URL}\n10\nn", id(1))
    );
}

#[test]
fn marks_the_agent_headers_as_bearer_identity_headers() {
    assert!(crate::identity::headers::REQUEST.contains(&"agent-id"));
    assert!(crate::identity::headers::REQUEST.contains(&"agent-signature"));
    assert_eq!(agents_requirement(), TYPE);
}

fn agents_requirement() -> String {
    let agents = setup(&registry(), |config| config);
    agents.payment_check.requires()[0].kind.clone()
}

#[test]
fn needs_a_provider_off_tempo_mainnet() {
    assert!(create(Config::new(ORIGIN).chain_id(1)).is_err());
    assert!(create(
        Config::new(ORIGIN)
            .chain_id(1)
            .rpc_url("http://localhost:8545")
    )
    .is_ok());
    assert!(create(Config::new("not a url")).is_err());
}

#[tokio::test]
async fn rejects_a_request_without_an_agent() {
    let agents = setup(&registry(), |config| config);
    let rejection = rejected(agents.verifier.verify(&request(&[])).await);
    assert_eq!(rejection.status, RejectionStatus::Missing);
}

#[tokio::test]
async fn rejects_an_agent_in_another_registry() {
    let agents = setup(&registry(), |config| config);
    let foreign = format!("eip155:1:{IDENTITY_REGISTRY}:1");
    let rejection = rejected(
        agents
            .verifier
            .verify(&request(&[("agent-id", foreign)]))
            .await,
    );
    assert_eq!(rejection.status, RejectionStatus::Invalid);
    assert!(rejection.reason.contains("Identity Registry"));
}

#[cfg(feature = "client")]
mod signed {
    use super::*;

    #[tokio::test]
    async fn an_agent_signs_with_its_registered_wallet() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        wallet(&asserter, agent_key().address());
        let request = signed(agent_key(), 1).await;
        let agent = agents.verifier.verify(&request).await;
        assert_eq!(
            agent,
            Verification::Valid(Agent {
                id: id(1),
                agent_id: U256::from(1),
                wallet: agent_key().address(),
            })
        );
        // The payment check shares the request's lookup and signature check.
        let credential = credential(
            "charge",
            serde_json::to_value(PaymentPayload::transaction("0x76")).unwrap(),
            agent_key().address(),
        );
        assert!(check(&agents, &request, &credential).await.is_valid());
    }

    #[tokio::test]
    async fn rejects_a_signature_from_a_key_other_than_the_wallet() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        wallet(&asserter, agent_key().address());
        asserter.push_failure_msg("execution reverted");
        let rejection = rejected(agents.verifier.verify(&signed(other_key(), 1).await).await);
        assert_eq!(rejection.status, RejectionStatus::Invalid);
        assert_eq!(
            rejection.reason,
            "The agent's wallet did not sign the request."
        );
    }

    #[tokio::test]
    async fn rejects_a_signature_for_another_request() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        wallet(&asserter, agent_key().address());
        asserter.push_failure_msg("execution reverted");
        let signed = signed(agent_key(), 1).await;
        let moved = IdentityRequest::new(
            Method::POST,
            Uri::from_static("/haiku?q=1"),
            signed.headers().clone(),
        );
        let rejection = rejected(agents.verifier.verify(&moved).await);
        assert_eq!(
            rejection.reason,
            "The agent's wallet did not sign the request."
        );
    }

    #[tokio::test]
    async fn rejects_a_payment_from_an_account_other_than_the_wallet() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        wallet(&asserter, agent_key().address());
        let credential = credential(
            "charge",
            serde_json::to_value(PaymentPayload::transaction("0x76")).unwrap(),
            other_key().address(),
        );
        let rejection = rejected(check(&agents, &signed(agent_key(), 1).await, &credential).await);
        assert_eq!(rejection.status, RejectionStatus::Forbidden);
        assert_eq!(
            rejection.reason,
            "The payment is not from the agent's wallet."
        );
    }

    #[tokio::test]
    async fn rejects_an_agent_without_a_wallet() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        wallet(&asserter, Address::ZERO);
        let rejection = rejected(agents.verifier.verify(&signed(agent_key(), 2).await).await);
        assert_eq!(rejection.status, RejectionStatus::Forbidden);
    }

    #[tokio::test]
    async fn accepts_an_erc1271_wallet_that_approves_the_signature() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        wallet(&asserter, CONTRACT_WALLET);
        asserter.push_success(&Bytes::from(
            IERC1271::isValidSignatureCall::abi_encode_returns(&FixedBytes([
                0x16, 0x26, 0xba, 0x7e,
            ])),
        ));
        let agent = agents.verifier.verify(&signed(agent_key(), 3).await).await;
        match agent {
            Verification::Valid(agent) => assert_eq!(agent.wallet, CONTRACT_WALLET),
            other => panic!("expected a valid agent, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_a_replayed_signature() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        wallet(&asserter, agent_key().address());
        wallet(&asserter, agent_key().address());
        let first = signed(agent_key(), 1).await;
        assert!(agents.verifier.verify(&first).await.is_valid());
        let replay = request(&[
            ("agent-id", first.header("agent-id").unwrap().to_owned()),
            (
                "agent-signature",
                first.header("agent-signature").unwrap().to_owned(),
            ),
        ]);
        let rejection = rejected(agents.verifier.verify(&replay).await);
        assert_eq!(rejection.status, RejectionStatus::Invalid);
        assert!(rejection.reason.contains("already used"));
    }

    #[tokio::test]
    async fn rejects_an_expired_signature() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        wallet(&asserter, agent_key().address());
        let stale = format!("{}.n.0x00", now() - 400);
        let request = request(&[("agent-id", id(1)), ("agent-signature", stale)]);
        let rejection = rejected(agents.verifier.verify(&request).await);
        assert_eq!(rejection.reason, "The agent signature has expired.");
    }

    #[tokio::test]
    async fn answers_unavailable_when_the_registry_is_down() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        asserter.push_failure_msg("down");
        let rejection = rejected(agents.verifier.verify(&signed(agent_key(), 1).await).await);
        assert_eq!(rejection.status, RejectionStatus::Unavailable);
    }

    #[tokio::test]
    async fn answers_unavailable_when_the_erc1271_call_fails_to_reach_the_chain() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        wallet(&asserter, CONTRACT_WALLET);
        // Nothing queued for `isValidSignature`: the mock fails as a transport error.
        let rejection = rejected(agents.verifier.verify(&signed(agent_key(), 3).await).await);
        assert_eq!(rejection.status, RejectionStatus::Unavailable);
    }

    #[tokio::test]
    async fn rejects_when_the_erc1271_call_reverts() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config);
        wallet(&asserter, CONTRACT_WALLET);
        asserter.push_failure_msg("execution reverted");
        let rejection = rejected(agents.verifier.verify(&signed(agent_key(), 3).await).await);
        assert_eq!(rejection.status, RejectionStatus::Invalid);
    }

    #[tokio::test(start_paused = true)]
    async fn answers_unavailable_when_the_registry_stalls() {
        let provider = ProviderBuilder::new()
            .connect_client(alloy::rpc::client::RpcClient::new(Stalled, true))
            .erased();
        let agents = create(Config::new(ORIGIN).provider(provider)).unwrap();
        let rejection = rejected(agents.verifier.verify(&signed(agent_key(), 1).await).await);
        assert_eq!(rejection.status, RejectionStatus::Unavailable);
    }

    /// A transport whose calls never answer.
    #[derive(Clone)]
    struct Stalled;

    impl tower::Service<alloy_json_rpc::RequestPacket> for Stalled {
        type Response = alloy_json_rpc::ResponsePacket;
        type Error = alloy::transports::TransportError;
        type Future = alloy::transports::TransportFut<'static>;

        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, _: alloy_json_rpc::RequestPacket) -> Self::Future {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn allow_decides_by_agent() {
        let asserter = registry();
        let agents = setup(&asserter, |config| {
            config.allow(|agent| agent.agent_id != U256::from(1))
        });
        wallet(&asserter, agent_key().address());
        let rejection = rejected(agents.verifier.verify(&signed(agent_key(), 1).await).await);
        assert_eq!(rejection.status, RejectionStatus::Forbidden);
    }

    #[tokio::test]
    async fn rejects_an_erc1271_return_that_is_not_the_encoded_magic() {
        let magic = [0x16, 0x26, 0xba, 0x7e];
        // Echoed calldata starts with the same four bytes as the magic value.
        let echoed = IERC1271::isValidSignatureCall {
            hash: FixedBytes([7; 32]),
            signature: Bytes::from(vec![1; 65]),
        }
        .abi_encode();
        let mut dirty = [0u8; 32];
        dirty[..4].copy_from_slice(&magic);
        dirty[31] = 1;
        for output in [echoed, dirty.to_vec(), magic.to_vec()] {
            let asserter = registry();
            let agents = setup(&asserter, |config| config);
            wallet(&asserter, CONTRACT_WALLET);
            asserter.push_success(&Bytes::from(output));
            let rejection = rejected(agents.verifier.verify(&signed(agent_key(), 3).await).await);
            assert_eq!(
                rejection.reason,
                "The agent's wallet did not sign the request."
            );
        }
    }

    #[tokio::test]
    async fn a_denied_agent_claims_no_nonce() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let open = Arc::new(AtomicBool::new(false));
        let gate = open.clone();
        let asserter = registry();
        let agents = setup(&asserter, move |config| {
            config.allow(move |_| gate.load(Ordering::SeqCst))
        });
        wallet(&asserter, agent_key().address());
        wallet(&asserter, agent_key().address());
        let first = signed(agent_key(), 1).await;
        let rejection = rejected(agents.verifier.verify(&first).await);
        assert_eq!(rejection.status, RejectionStatus::Forbidden);
        open.store(true, Ordering::SeqCst);
        let again = request(&[
            ("agent-id", first.header("agent-id").unwrap().to_owned()),
            (
                "agent-signature",
                first.header("agent-signature").unwrap().to_owned(),
            ),
        ]);
        assert!(agents.verifier.verify(&again).await.is_valid());
    }

    #[tokio::test]
    async fn a_signed_payment_runs_allow_after_the_signature() {
        let asserter = registry();
        let agents = setup(&asserter, |config| config.allow(|_| false));
        wallet(&asserter, agent_key().address());
        let credential = credential(
            "charge",
            serde_json::to_value(PaymentPayload::transaction("0x76")).unwrap(),
            agent_key().address(),
        );
        let rejection = rejected(check(&agents, &signed(agent_key(), 1).await, &credential).await);
        assert_eq!(rejection.status, RejectionStatus::Forbidden);
        assert_eq!(rejection.reason, "This agent may not call this API.");
    }
}

#[tokio::test]
async fn the_payment_proves_the_agent_without_allow() {
    let asserter = registry();
    let agents = setup(&asserter, |config| config);
    let payer = agent_key().address();
    wallet(&asserter, payer);
    let request = request(&[("agent-id", id(1))]);
    let credential = credential(
        "charge",
        serde_json::to_value(PaymentPayload::transaction("0x76")).unwrap(),
        payer,
    );
    assert!(check(&agents, &request, &credential).await.is_valid());
}

#[tokio::test]
async fn needs_the_signature_before_allow_or_when_required() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let payer = agent_key().address();
    let asked = Arc::new(AtomicBool::new(false));
    let seen = asked.clone();
    let with_allow = move |config: Config| {
        let seen = seen.clone();
        config.allow(move |_| {
            seen.store(true, Ordering::SeqCst);
            true
        })
    };
    let required = |config: Config| config.require_signature();
    let configs: [Box<dyn FnOnce(Config) -> Config>; 2] =
        [Box::new(with_allow), Box::new(required)];
    for config in configs {
        let asserter = registry();
        let agents = setup(&asserter, config);
        wallet(&asserter, payer);
        let request = request(&[("agent-id", id(1))]);
        let credential = credential(
            "charge",
            serde_json::to_value(PaymentPayload::transaction("0x76")).unwrap(),
            payer,
        );
        let rejection = rejected(check(&agents, &request, &credential).await);
        assert_eq!(rejection.status, RejectionStatus::Invalid);
        assert_eq!(
            rejection.reason,
            "The agent signature is missing or malformed."
        );
    }
    assert!(
        !asked.load(Ordering::SeqCst),
        "allow ran without a signature"
    );
}

#[tokio::test]
async fn rejects_an_oversized_signature_header() {
    let asserter = registry();
    let agents = setup(&asserter, |config| config);
    wallet(&asserter, agent_key().address());
    let header = format!("{}.n.0x{}", now(), "ab".repeat(16 * 1024));
    let request = request(&[("agent-id", id(1)), ("agent-signature", header)]);
    let rejection = rejected(agents.verifier.verify(&request).await);
    assert_eq!(
        rejection.reason,
        "The agent signature is missing or malformed."
    );
}

#[test]
fn keeps_rpc_credentials_out_of_debug_and_errors() {
    let config = Config::new(ORIGIN).rpc_url("https://user:key@rpc.example:8545/v1/key?apikey=key");
    let debug = format!("{config:?}");
    assert!(debug.contains("https://rpc.example:8545"), "{debug}");
    assert!(!debug.contains("key"), "{debug}");
    let error = create(Config::new(ORIGIN).rpc_url("not a url key")).unwrap_err();
    assert!(!error.to_string().contains("key"));
}

#[tokio::test]
async fn needs_the_signature_when_the_payment_does_not_bind_its_source() {
    let asserter = registry();
    let agents = setup(&asserter, |config| config);
    let payer = agent_key().address();
    let cases = [
        ("session", json!({"type": "topUp"})),
        ("charge", json!({"type": "hash"})),
        ("charge", json!({"type": "zone"})),
        ("charge", json!({})),
    ];
    for (intent, payload) in cases {
        wallet(&asserter, payer);
        let request = request(&[("agent-id", id(1))]);
        let credential = credential(intent, payload, payer);
        let rejection = rejected(check(&agents, &request, &credential).await);
        assert_eq!(rejection.status, RejectionStatus::Invalid, "{intent}");
    }
}

#[tokio::test]
async fn needs_the_signature_without_a_credential() {
    let asserter = registry();
    let agents = setup(&asserter, |config| config);
    wallet(&asserter, agent_key().address());
    let request = request(&[("agent-id", id(1))]);
    let challenge = credential("charge", json!({}), agent_key().address()).challenge;
    let rejection = rejected(
        agents
            .payment_check
            .verify(PaymentCheckInput {
                request: &request,
                challenge: &challenge,
                credential: None,
            })
            .await,
    );
    assert_eq!(rejection.status, RejectionStatus::Invalid);
}

#[test]
fn signs_the_configured_origin_not_the_host() {
    let mut headers = HeaderMap::new();
    headers.insert("host", HeaderValue::from_static("other.example"));
    let request = IdentityRequest::new(
        Method::GET,
        Uri::from_static("https://other.example/haiku?q=1"),
        headers,
    );
    assert_eq!(server::target(ORIGIN, &request), URL);
    let bare = IdentityRequest::new(Method::GET, Uri::from_static("/"), HeaderMap::new());
    assert_eq!(server::target(ORIGIN, &bare), "https://api.example/");
}

#[cfg(feature = "client")]
mod bounded {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn a_spent_signature_is_rejected_before_allow() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let asserter = registry();
        let agents = setup(&asserter, move |config| {
            config.allow(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                true
            })
        });
        wallet(&asserter, agent_key().address());
        wallet(&asserter, agent_key().address());
        let first = signed(agent_key(), 1).await;
        assert!(agents.verifier.verify(&first).await.is_valid());
        let replay = request(&[
            ("agent-id", first.header("agent-id").unwrap().to_owned()),
            (
                "agent-signature",
                first.header("agent-signature").unwrap().to_owned(),
            ),
        ]);
        let rejection = rejected(agents.verifier.verify(&replay).await);
        assert_eq!(rejection.status, RejectionStatus::Invalid);
        assert!(rejection.reason.contains("already used"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_prover_signs_only_in_scope() {
        use crate::identity::client::{ProveContext, Prover, Scope};

        let prover = client::prover(client::ProverConfig::new(
            agent_key(),
            U256::from(1),
            Scope::origins([ORIGIN]),
        ));
        let context = ProveContext {
            created: now(),
            nonce: "nonce".to_owned(),
            challenge: None,
        };
        let mut outbound = reqwest::Request::new(
            reqwest::Method::GET,
            "https://other.example/haiku".parse().unwrap(),
        );
        assert!(prover.prove(&mut outbound, &context).await.is_err());
        assert!(outbound.headers().get("agent-id").is_none());
        assert!(outbound.headers().get("agent-signature").is_none());
    }

    /// A transport that records each request and answers with the next result.
    #[derive(Clone)]
    struct Recorder {
        sent: Arc<Mutex<Vec<serde_json::Value>>>,
        results: Arc<Mutex<Vec<Bytes>>>,
    }

    impl tower::Service<alloy_json_rpc::RequestPacket> for Recorder {
        type Response = alloy_json_rpc::ResponsePacket;
        type Error = alloy::transports::TransportError;
        type Future = alloy::transports::TransportFut<'static>;

        fn poll_ready(
            &mut self,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn call(&mut self, packet: alloy_json_rpc::RequestPacket) -> Self::Future {
            let request = serde_json::to_value(&packet).unwrap();
            let result = self.results.lock().unwrap().remove(0);
            let response = json!({"jsonrpc": "2.0", "id": request["id"], "result": result});
            self.sent.lock().unwrap().push(request);
            Box::pin(std::future::ready(Ok(
                serde_json::from_value(response).unwrap()
            )))
        }
    }

    #[tokio::test]
    async fn the_erc1271_call_is_capped_and_reads_the_latest_block() {
        let recorder = Recorder {
            sent: Arc::default(),
            results: Arc::new(Mutex::new(vec![
                Bytes::from(IIdentityRegistry::getAgentWalletCall::abi_encode_returns(
                    &CONTRACT_WALLET,
                )),
                Bytes::from(IERC1271::isValidSignatureCall::abi_encode_returns(
                    &FixedBytes([0x16, 0x26, 0xba, 0x7e]),
                )),
            ])),
        };
        let provider = ProviderBuilder::new()
            .connect_client(alloy::rpc::client::RpcClient::new(recorder.clone(), true))
            .erased();
        let agents = create(Config::new(ORIGIN).provider(provider)).unwrap();
        assert!(agents
            .verifier
            .verify(&signed(agent_key(), 3).await)
            .await
            .is_valid());
        let sent = recorder.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        for call in sent.iter() {
            assert_eq!(call["method"], "eth_call");
            assert_eq!(call["params"][1], "latest", "{call}");
        }
        assert_eq!(sent[1]["params"][0]["gas"], "0xf4240");
        assert!(sent[0]["params"][0].get("gas").is_none());
    }

    /// Serves one HTTP response per connection and counts the connections.
    async fn serve(
        response: impl Fn(serde_json::Value) -> String + Send + Sync + 'static,
    ) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                let body = loop {
                    let read = socket.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break serde_json::Value::Null;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&buffer).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        if body.len() >= length {
                            break serde_json::from_str(body).unwrap_or_default();
                        }
                    }
                };
                let _ = socket.write_all(response(body).as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        (url, hits)
    }

    fn ok(body: String) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn wallet_reply(request: &serde_json::Value, padding: usize) -> String {
        let result = Bytes::from(IIdentityRegistry::getAgentWalletCall::abi_encode_returns(
            &agent_key().address(),
        ));
        json!({
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": result,
            "padding": "0".repeat(padding),
        })
        .to_string()
    }

    async fn verify_at(url: &str) -> Verification<Agent> {
        let agents = create(Config::new(ORIGIN).rpc_url(url)).unwrap();
        agents.verifier.verify(&signed(agent_key(), 1).await).await
    }

    #[tokio::test]
    async fn the_default_provider_reads_the_configured_endpoint() {
        let (url, _) = serve(|request| ok(wallet_reply(&request, 0))).await;
        assert!(verify_at(&url).await.is_valid());
    }

    #[tokio::test]
    async fn the_default_provider_follows_no_redirect() {
        let (target, hits) = serve(|request| ok(wallet_reply(&request, 0))).await;
        let (url, _) = serve(move |_| {
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {target}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
        })
        .await;
        let rejection = rejected(verify_at(&url).await);
        assert_eq!(rejection.status, RejectionStatus::Unavailable);
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn the_default_provider_refuses_an_oversized_reply() {
        let (url, _) = serve(|request| ok(wallet_reply(&request, 70 * 1024))).await;
        let rejection = rejected(verify_at(&url).await);
        assert_eq!(rejection.status, RejectionStatus::Unavailable);
    }
}
