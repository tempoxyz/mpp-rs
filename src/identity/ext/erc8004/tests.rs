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
    async fn allow_decides_by_agent() {
        let asserter = registry();
        let agents = setup(&asserter, |config| {
            config.allow(|agent| agent.agent_id != U256::from(1))
        });
        wallet(&asserter, agent_key().address());
        let rejection = rejected(agents.verifier.verify(&signed(agent_key(), 1).await).await);
        assert_eq!(rejection.status, RejectionStatus::Forbidden);
    }
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
