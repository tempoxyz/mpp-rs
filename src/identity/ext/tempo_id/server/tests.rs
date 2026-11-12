use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use http_types::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use rsa::traits::PublicKeyParts;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::identity::{IdentityContext, RouteIdentity};
use crate::protocol::core::{Base64UrlJson, PaymentChallenge, PaymentCredential, PaymentPayload};
use crate::store::MemoryStore;

const CLIENT_ID: &str = "app_test";
const PAYER: &str = "0x1111111111111111111111111111111111111111";
const OTHER: &str = "0x2222222222222222222222222222222222222222";
const URL: &str = "https://api.example/haiku";

/// A deterministic RNG for the test RSA key: SHA-256 over a counter.
struct TestRng(u64);

impl rsa::rand_core::TryRng for TestRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(32) {
            self.0 += 1;
            let block = Sha256::digest(self.0.to_le_bytes());
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        Ok(())
    }
}

impl rsa::rand_core::TryCryptoRng for TestRng {}

fn signing_key() -> &'static rsa::PrivateKey {
    static KEY: OnceLock<rsa::PrivateKey> = OnceLock::new();
    KEY.get_or_init(|| rsa::PrivateKey::new(&mut TestRng(7), 1024).expect("test RSA key"))
}

/// A local Tempo ID issuer serving its key set, counting fetches.
struct Issuer {
    url: String,
    fetches: Arc<AtomicUsize>,
}

async fn issuer() -> Issuer {
    let public = signing_key().to_public_key();
    let jwks = json!({ "keys": [{
        "kty": "RSA",
        "kid": "key-1",
        "n": URL_SAFE_NO_PAD.encode(public.n_bytes()),
        "e": URL_SAFE_NO_PAD.encode(public.e_bytes()),
    }]})
    .to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let fetches = Arc::new(AtomicUsize::new(0));
    let counter = fetches.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                jwks.len(),
                jwks
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    Issuer { url, fetches }
}

fn sign(header: Value, claims: Value) -> String {
    let input = format!("{}.{}", jwt::encode(&header), jwt::encode(&claims));
    let hashed = rsa::sha2::Sha256::digest(input.as_bytes());
    let signature = signing_key()
        .sign(rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(), &hashed)
        .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn now() -> i64 {
    super::now()
}

fn access_claims(issuer: &Issuer) -> Value {
    let mut compliance = serde_json::Map::new();
    compliance.insert(PAYER.to_lowercase(), json!("clear"));
    compliance.insert(OTHER.to_owned(), json!("blocked"));
    json!({
        "iss": issuer.url,
        "aud": issuer.url,
        "sub": "user_1",
        "client_id": CLIENT_ID,
        "exp": now() + 600,
        "access_keys": [
            { "chain_id": 4217, "account": PAYER },
            { "chain_id": 42431, "account": OTHER },
        ],
        "compliance": compliance,
    })
}

fn access_token(claims: &Value) -> String {
    sign(
        json!({ "alg": "RS256", "typ": "at+jwt", "kid": "key-1" }),
        claims.clone(),
    )
}

fn server_for(issuer: &Issuer) -> TempoId {
    create(
        Config::new(CLIENT_ID)
            .issuer(issuer.url.clone())
            .origin("https://api.example"),
    )
}

fn request(headers: &[(&str, String)]) -> IdentityRequest {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            http_types::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    IdentityRequest::new(Method::GET, Uri::from_static(URL), map)
}

fn bearer(token: &str) -> IdentityRequest {
    request(&[("authorization", format!("Bearer {token}"))])
}

fn rejected<T: std::fmt::Debug>(outcome: Verification<T>) -> Rejection {
    match outcome {
        Verification::Rejected(rejection) => rejection,
        Verification::Valid(value) => panic!("expected a rejection, got {value:?}"),
    }
}

fn credential(method: &str, source: Option<String>) -> PaymentCredential {
    let challenge = PaymentChallenge::new(
        "challenge-1",
        "api.example",
        method,
        "charge",
        Base64UrlJson::from_value(&json!({"amount": "1"})).unwrap(),
    );
    let mut credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xabc"));
    credential.source = source;
    credential
}

async fn check(
    tempo_id: &TempoId,
    request: &IdentityRequest,
    credential: &PaymentCredential,
) -> Verification<Payer> {
    tempo_id
        .payment_check
        .verify(PaymentCheckInput {
            request,
            challenge: &credential.challenge,
            credential: Some(credential),
        })
        .await
}

#[tokio::test]
async fn missing_token_asks_to_sign_in() {
    let issuer = issuer().await;
    let tempo_id = server_for(&issuer);
    let rejection = rejected(tempo_id.verifier.verify(&request(&[])).await);
    assert_eq!(rejection.status, RejectionStatus::Missing);
    assert_eq!(rejection.reason, "Sign in with Tempo ID.");
    assert_eq!(
        rejection.headers.get(WWW_AUTHENTICATE).unwrap(),
        r#"DPoP algs="ES256", Bearer"#
    );
    let basic = request(&[("authorization", "Basic abc".to_owned())]);
    assert_eq!(
        rejected(tempo_id.verifier.verify(&basic).await).status,
        RejectionStatus::Missing
    );
}

#[tokio::test]
async fn valid_bearer_token_names_the_caller() {
    let issuer = issuer().await;
    let tempo_id = server_for(&issuer);
    let token = access_token(&access_claims(&issuer));
    let Verification::Valid(caller) = tempo_id.verifier.verify(&bearer(&token)).await else {
        panic!("expected a valid caller");
    };
    assert_eq!(caller.user_id, "user_1");
    assert_eq!(caller.client_id, CLIENT_ID);
    // Only the configured chain's access keys count.
    assert_eq!(caller.accounts, vec![PAYER.parse::<Address>().unwrap()]);
    assert_eq!(
        caller.compliance.get(&PAYER.parse::<Address>().unwrap()),
        Some(&ComplianceState::Clear)
    );
    assert_eq!(
        caller.compliance.get(&OTHER.parse::<Address>().unwrap()),
        Some(&ComplianceState::Blocked)
    );
    assert_eq!(caller.email, None);
    assert!(tempo_id.verifier.reads_authorization());
}

#[tokio::test]
async fn rejects_tokens_tempo_id_did_not_issue_for_this_api() {
    let issuer = issuer().await;
    let tempo_id = server_for(&issuer);
    let base = access_claims(&issuer);
    let with = |key: &str, value: Value| {
        let mut claims = base.clone();
        claims[key] = value;
        access_token(&claims)
    };
    let cases = [
        (
            with("aud", json!("https://other.example")),
            RejectionStatus::Invalid,
            "The access token is for another API.",
        ),
        (
            with("aud", json!([issuer.url, "https://other.example"])),
            RejectionStatus::Invalid,
            "The access token is for another API.",
        ),
        (
            with("iss", json!("https://evil.example")),
            RejectionStatus::Invalid,
            "The access token is not from Tempo ID.",
        ),
        (
            with("exp", json!(now() - 120)),
            RejectionStatus::Invalid,
            "The access token has expired.",
        ),
        (
            with("client_id", json!("app_other")),
            RejectionStatus::Forbidden,
            "This app may not call this API.",
        ),
        (
            sign(
                json!({ "alg": "RS256", "typ": "JWT", "kid": "key-1" }),
                base.clone(),
            ),
            RejectionStatus::Invalid,
            "The token is not a Tempo ID access token.",
        ),
        (
            sign(
                json!({ "alg": "RS256", "typ": "at+jwt", "kid": "unknown" }),
                base.clone(),
            ),
            RejectionStatus::Invalid,
            "The access token signature is invalid.",
        ),
        (
            sign(
                json!({ "alg": "HS256", "typ": "at+jwt", "kid": "key-1" }),
                base.clone(),
            ),
            RejectionStatus::Invalid,
            "The access token signature is invalid.",
        ),
        (
            "not-a-jwt".to_owned(),
            RejectionStatus::Invalid,
            "The token is not a Tempo ID access token.",
        ),
    ];
    for (token, status, reason) in cases {
        let rejection = rejected(tempo_id.verifier.verify(&bearer(&token)).await);
        assert_eq!(
            (rejection.status, rejection.reason.as_str()),
            (status, reason)
        );
    }

    // A tampered payload breaks the signature.
    let token = access_token(&base);
    let mut parts: Vec<&str> = token.split('.').collect();
    let mut tampered = base.clone();
    tampered["sub"] = json!("user_2");
    let payload = jwt::encode(&tampered);
    parts[1] = &payload;
    let rejection = rejected(tempo_id.verifier.verify(&bearer(&parts.join("."))).await);
    assert_eq!(rejection.reason, "The access token signature is invalid.");
}

#[tokio::test]
async fn unreachable_keys_are_unavailable() {
    let tempo_id = create(Config::new(CLIENT_ID).issuer("http://127.0.0.1:9"));
    let token = sign(
        json!({ "alg": "RS256", "typ": "at+jwt", "kid": "key-1" }),
        json!({ "iss": "http://127.0.0.1:9", "sub": "user_1" }),
    );
    let rejection = rejected(tempo_id.verifier.verify(&bearer(&token)).await);
    assert_eq!(rejection.status, RejectionStatus::Unavailable);
    assert_eq!(rejection.status.code(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn failed_key_fetch_cools_down_before_any_key_set_loads() {
    // An issuer that answers every key-set request with a 500.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let fetches = Arc::new(AtomicUsize::new(0));
    let counter = fetches.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buffer = [0u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                .await;
        }
    });
    let tempo_id = create(Config::new(CLIENT_ID).issuer(&url));
    let token = sign(
        json!({ "alg": "RS256", "typ": "at+jwt", "kid": "key-1" }),
        json!({ "iss": url, "sub": "user_1" }),
    );
    for _ in 0..3 {
        let rejection = rejected(tempo_id.verifier.verify(&bearer(&token)).await);
        assert_eq!(rejection.status, RejectionStatus::Unavailable);
    }
    // Within 30 seconds of the failed fetch, requests answer 503 without refetching.
    assert_eq!(fetches.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn key_set_without_keys_counts_as_a_failed_fetch() {
    // An issuer whose key set has no keys.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buffer = [0u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let body = r#"{"keys":[]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    let tempo_id = create(Config::new(CLIENT_ID).issuer(&url));
    let token = sign(
        json!({ "alg": "RS256", "typ": "at+jwt", "kid": "key-1" }),
        json!({ "iss": url, "sub": "user_1" }),
    );
    let rejection = rejected(tempo_id.verifier.verify(&bearer(&token)).await);
    assert_eq!(rejection.status, RejectionStatus::Unavailable);
}

#[tokio::test]
async fn keys_are_cached() {
    let issuer = issuer().await;
    let tempo_id = server_for(&issuer);
    let token = access_token(&access_claims(&issuer));
    for _ in 0..3 {
        assert!(tempo_id.verifier.verify(&bearer(&token)).await.is_valid());
    }
    assert_eq!(issuer.fetches.load(Ordering::SeqCst), 1);
    // An unknown key ID within 30 seconds of the last fetch does not refetch.
    let unknown = sign(
        json!({ "alg": "RS256", "typ": "at+jwt", "kid": "rotated" }),
        access_claims(&issuer),
    );
    assert!(!tempo_id.verifier.verify(&bearer(&unknown)).await.is_valid());
    assert_eq!(issuer.fetches.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn id_token_adds_the_email() {
    let issuer = issuer().await;
    let tempo_id = server_for(&issuer);
    let token = access_token(&access_claims(&issuer));
    let id_token = |claims: Value| sign(json!({ "alg": "RS256", "kid": "key-1" }), claims);
    let id_claims = json!({
        "iss": issuer.url, "aud": CLIENT_ID, "sub": "user_1",
        "exp": now() + 600, "email": "Ada@Example.com", "email_verified": true,
    });
    let with_id = |id: String| {
        request(&[
            ("authorization", format!("Bearer {token}")),
            (ID_TOKEN_HEADER, id),
        ])
    };

    let Verification::Valid(caller) = tempo_id
        .verifier
        .verify(&with_id(id_token(id_claims.clone())))
        .await
    else {
        panic!("expected a valid caller");
    };
    assert_eq!(caller.email.as_deref(), Some("ada@example.com"));
    assert_eq!(caller.email_verified, Some(true));

    // An expired ID token names no email.
    let mut expired = id_claims.clone();
    expired["exp"] = json!(now() - 600);
    let Verification::Valid(caller) = tempo_id.verifier.verify(&with_id(id_token(expired))).await
    else {
        panic!("expected a valid caller");
    };
    assert_eq!(caller.email, None);

    // Another user's ID token is refused.
    let mut other = id_claims.clone();
    other["sub"] = json!("user_2");
    let rejection = rejected(tempo_id.verifier.verify(&with_id(id_token(other))).await);
    assert_eq!(rejection.reason, "The ID token is for another user or app.");
    let rejection = rejected(
        tempo_id
            .verifier
            .verify(&with_id("garbage".to_owned()))
            .await,
    );
    assert_eq!(rejection.reason, "The ID token is malformed.");
}

#[tokio::test]
async fn allow_decides_on_the_verified_user() {
    let issuer = issuer().await;
    let tempo_id = create(
        Config::new(CLIENT_ID)
            .issuer(issuer.url.clone())
            .allow(|user| {
                user.email
                    .as_deref()
                    .is_some_and(|email| email.ends_with("@example.com"))
            }),
    );
    let token = access_token(&access_claims(&issuer));
    let rejection = rejected(tempo_id.verifier.verify(&bearer(&token)).await);
    assert_eq!(rejection.status, RejectionStatus::Forbidden);
    assert_eq!(rejection.reason, "This user may not call this API.");
}

#[tokio::test]
async fn payment_check_requires_a_granted_cleared_tempo_account() {
    let issuer = issuer().await;
    let tempo_id = server_for(&issuer);
    assert_eq!(
        tempo_id.payment_check.requires(),
        &[Requirement::new("tempo-id").with_issuer(issuer.url.clone())]
    );
    let mut claims = access_claims(&issuer);
    claims["tempo_accounts"] = json!([OTHER]);
    let token = access_token(&claims);
    let did = |chain: u64, address: &str| Some(format!("did:pkh:eip155:{chain}:{address}"));

    let paid = credential("tempo", did(4217, PAYER));
    let Verification::Valid(payer) = check(&tempo_id, &bearer(&token), &paid).await else {
        panic!("expected a valid payer");
    };
    assert_eq!(payer.account, Some(PAYER.parse().unwrap()));
    assert_eq!(payer.user_id, "user_1");

    let cases = [
        (
            credential("stripe", did(4217, PAYER)),
            RejectionStatus::Forbidden,
            "Pay with the tempo method.".to_owned(),
        ),
        (
            credential("tempo", did(42431, PAYER)),
            RejectionStatus::Invalid,
            "The payment must name its source account on chain 4217.".to_owned(),
        ),
        (
            credential("tempo", None),
            RejectionStatus::Invalid,
            "The payment must name its source account on chain 4217.".to_owned(),
        ),
        (
            credential(
                "tempo",
                did(4217, "0x3333333333333333333333333333333333333333"),
            ),
            RejectionStatus::Forbidden,
            "The paying account is not one this user granted to the app.".to_owned(),
        ),
        // Granted through tempo_accounts, but screened as blocked.
        (
            credential("tempo", did(4217, OTHER)),
            RejectionStatus::Forbidden,
            "The paying account is not cleared to pay.".to_owned(),
        ),
    ];
    for (credential, status, reason) in cases {
        let rejection = rejected(check(&tempo_id, &bearer(&token), &credential).await);
        assert_eq!((rejection.status, rejection.reason), (status, reason));
    }
}

#[cfg(feature = "client")]
mod dpop {
    use super::*;
    use crate::identity::ext::tempo_id::client::proof;
    use crate::identity::ext::tempo_id::DpopKey;

    pub(super) fn dpop_key() -> DpopKey {
        DpopKey::new(p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap())
    }

    pub(super) fn bound_token(issuer: &Issuer, key: &DpopKey) -> String {
        let mut claims = access_claims(issuer);
        claims["cnf"] = json!({ "jkt": key.thumbprint() });
        access_token(&claims)
    }

    fn dpop_request(token: &str, proof: String) -> IdentityRequest {
        request(&[("authorization", format!("DPoP {token}")), ("dpop", proof)])
    }

    pub(super) fn proof_for(
        key: &DpopKey,
        token: &str,
        method: reqwest::Method,
        url: &str,
    ) -> String {
        proof(
            key,
            token,
            &reqwest::Request::new(method, url.parse().unwrap()),
        )
    }

    #[tokio::test]
    async fn dpop_bound_token_needs_a_fresh_proof_of_its_key() {
        let issuer = issuer().await;
        let store = Arc::new(MemoryStore::new());
        let tempo_id = create(
            Config::new(CLIENT_ID)
                .issuer(issuer.url.clone())
                .origin("https://api.example")
                .store(store),
        );
        let key = dpop_key();
        let token = bound_token(&issuer, &key);

        let proof = proof_for(
            &key,
            &token,
            reqwest::Method::GET,
            "https://api.example/haiku?q=1",
        );
        assert!(tempo_id
            .verifier
            .verify(&dpop_request(&token, proof.clone()))
            .await
            .is_valid());

        // The store accepts each proof once.
        let rejection = rejected(tempo_id.verifier.verify(&dpop_request(&token, proof)).await);
        assert_eq!(rejection.reason, "The DPoP proof was already used.");

        let cases = [
            (
                proof_for(&key, &token, reqwest::Method::POST, URL),
                "The DPoP proof is for another request.",
            ),
            (
                proof_for(
                    &key,
                    &token,
                    reqwest::Method::GET,
                    "https://other.example/haiku",
                ),
                "The DPoP proof is for another request.",
            ),
            (
                proof_for(&key, "another-token", reqwest::Method::GET, URL),
                "The DPoP proof is for another token.",
            ),
            (
                proof_for(
                    &DpopKey::new(p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap()),
                    &token,
                    reqwest::Method::GET,
                    URL,
                ),
                "The DPoP proof key does not bind the token.",
            ),
            ("garbage".to_owned(), "The DPoP proof is malformed."),
        ];
        for (proof, reason) in cases {
            let rejection = rejected(tempo_id.verifier.verify(&dpop_request(&token, proof)).await);
            assert_eq!(rejection.reason, reason);
        }

        // A DPoP-bound token sent as Bearer, and a Bearer token sent as DPoP, are refused.
        let rejection = rejected(tempo_id.verifier.verify(&bearer(&token)).await);
        assert_eq!(
            rejection.reason,
            "The access token scheme does not match its binding."
        );
        let plain = access_token(&access_claims(&issuer));
        let proof = proof_for(&key, &plain, reqwest::Method::GET, URL);
        let rejection = rejected(tempo_id.verifier.verify(&dpop_request(&plain, proof)).await);
        assert_eq!(
            rejection.reason,
            "The access token scheme does not match its binding."
        );
    }

    #[tokio::test]
    async fn verifier_and_payment_check_spend_one_proof_per_request() {
        let issuer = issuer().await;
        let store = Arc::new(MemoryStore::new());
        let tempo_id = create(
            Config::new(CLIENT_ID)
                .issuer(issuer.url.clone())
                .origin("https://api.example")
                .store(store),
        );
        let key = dpop_key();
        let token = bound_token(&issuer, &key);
        let proof = proof_for(&key, &token, reqwest::Method::GET, URL);

        let route = RouteIdentity::new()
            .verifier(&tempo_id.verifier)
            .payment(&tempo_id.payment_check);
        let context = IdentityContext::new(dpop_request(&token, proof));
        let call = route.verify_request(&context).await.unwrap();
        let paid = credential("tempo", Some(format!("did:pkh:eip155:4217:{PAYER}")));
        let results = call.accept(&paid).await.unwrap();
        assert_eq!(results.get(&tempo_id.verifier).unwrap().user_id, "user_1");
        assert_eq!(
            results.payment(&tempo_id.payment_check).unwrap().account,
            Some(PAYER.parse().unwrap())
        );
    }

    #[tokio::test]
    async fn prover_sends_dpop_or_bearer_tokens() {
        use crate::identity::client::{ProveContext, Prover, Scope};
        use crate::identity::ext::tempo_id::client::{prover, ProverConfig};

        let context = ProveContext {
            created: 0,
            nonce: "n".into(),
            challenge: None,
        };
        let bearer = prover(
            ProverConfig::new(Scope::origins(["https://api.example"]), || async {
                Ok("token-1".to_owned())
            })
            .id_token(|| async { Some("id-1".to_owned()) }),
        );
        let mut request = reqwest::Request::new(reqwest::Method::GET, URL.parse().unwrap());
        bearer.prove(&mut request, &context).await.unwrap();
        assert_eq!(request.headers()["authorization"], "Bearer token-1");
        assert_eq!(request.headers()["tempo-id-token"], "id-1");
        assert!(!request.headers().contains_key("dpop"));
        assert!(bearer.scope().contains(&URL.parse().unwrap()));
        assert!(!bearer
            .scope()
            .contains(&"https://other.example/".parse().unwrap()));
        assert_eq!(bearer.headers(), &["dpop", "tempo-id-token"]);

        let key = dpop_key();
        let dpop = prover(
            ProverConfig::new(Scope::Any, || async { Ok("token-2".to_owned()) }).dpop(key.clone()),
        );
        let mut request = reqwest::Request::new(reqwest::Method::GET, URL.parse().unwrap());
        dpop.prove(&mut request, &context).await.unwrap();
        assert_eq!(request.headers()["authorization"], "DPoP token-2");
        let proof = jwt::decode(request.headers()["dpop"].to_str().unwrap()).unwrap();
        assert_eq!(proof.header["typ"], "dpop+jwt");
        assert_eq!(proof.claims["htm"], "GET");
        assert_eq!(proof.claims["htu"], URL);
        assert_eq!(proof.claims["ath"], jwt::sha256("token-2"));

        // A paid attempt whose Credential is in Authorization fails instead of
        // losing the Credential.
        let mut request = reqwest::Request::new(reqwest::Method::GET, URL.parse().unwrap());
        request.headers_mut().insert(
            "authorization",
            "Payment eyJjaGFsbGVuZ2UiOnt9fQ".parse().unwrap(),
        );
        assert!(dpop.prove(&mut request, &context).await.is_err());

        // A Challenge whose Credential goes in Authorization is refused before paying.
        use crate::identity::client::{PrepareContext, ResponseParts};
        let challenge = |header: Option<&str>| {
            let mut challenge = crate::protocol::core::PaymentChallenge::new(
                "id",
                "realm",
                "tempo",
                "charge",
                crate::protocol::core::Base64UrlJson::from_value(&json!({})).unwrap(),
            );
            challenge.header = header.map(str::to_owned);
            PrepareContext {
                challenge,
                requirements: Vec::new(),
            }
        };
        let parts = ResponseParts {
            status: http_types::StatusCode::PAYMENT_REQUIRED,
            headers: http_types::HeaderMap::new(),
            url: URL.parse().unwrap(),
        };
        assert!(dpop.prepare(&parts, &challenge(None)).await.is_err());
        assert!(dpop
            .prepare(&parts, &challenge(Some("Payment-Authorization")))
            .await
            .is_ok());
        assert!(request.headers()["authorization"]
            .to_str()
            .unwrap()
            .starts_with("Payment "));
    }
}

#[cfg(feature = "client")]
#[tokio::test]
async fn dpop_without_an_origin_is_a_server_error() {
    let issuer = issuer().await;
    let tempo_id = create(Config::new(CLIENT_ID).issuer(issuer.url.clone()));
    let key = dpop::dpop_key();
    let token = dpop::bound_token(&issuer, &key);
    let proof = dpop::proof_for(&key, &token, reqwest::Method::GET, URL);
    let mut headers = HeaderMap::new();
    headers.insert("authorization", format!("DPoP {token}").parse().unwrap());
    headers.insert("dpop", proof.parse().unwrap());
    headers.insert("host", "api.example".parse().unwrap());
    let request = IdentityRequest::new(Method::GET, "/haiku".parse().unwrap(), headers);
    let rejection = rejected(tempo_id.verifier.verify(&request).await);
    assert_eq!(rejection.status, RejectionStatus::Unavailable);
}

#[test]
fn htu_never_trusts_the_host_header() {
    let mut headers = http_types::HeaderMap::new();
    headers.insert("host", "other.example".parse().unwrap());
    let request = IdentityRequest::new(http_types::Method::GET, "/haiku".parse().unwrap(), headers);
    assert_eq!(htu(None, &request), None);
    // An absolute-form target names the client's choice of origin too.
    let absolute = IdentityRequest::new(
        http_types::Method::GET,
        "https://other.example/haiku".parse().unwrap(),
        http_types::HeaderMap::new(),
    );
    assert_eq!(htu(None, &absolute), None);
    assert_eq!(
        htu(Some("https://api.example"), &absolute).as_deref(),
        Some("https://api.example/haiku")
    );
    assert_eq!(
        htu(Some("https://api.example"), &request).as_deref(),
        Some("https://api.example/haiku")
    );
}

#[test]
fn htu_keeps_the_host_for_scheme_relative_paths() {
    let request = IdentityRequest::new(
        http_types::Method::GET,
        "//evil.example/x?q=1".parse().unwrap(),
        http_types::HeaderMap::new(),
    );
    assert_eq!(
        htu(Some("https://api.example"), &request).as_deref(),
        Some("https://api.example//evil.example/x")
    );
}

#[test]
fn payment_check_needs_requires_auth() {
    let issuer = "https://id.example";
    let tempo_id = create(Config::new(CLIENT_ID).issuer(issuer));
    assert!(crate::identity::RouteIdentity::new()
        .payment(&tempo_id.payment_check)
        .reads_authorization());
}
