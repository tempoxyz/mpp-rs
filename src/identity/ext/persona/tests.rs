//! Persona tests against a fake Persona API, as mppx's `Persona.test.ts`.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use axum::body::Bytes;
use axum::http::{HeaderMap as AxumHeaders, Method as AxumMethod, StatusCode, Uri as AxumUri};
use axum::response::{IntoResponse, Response};
use http_types::{HeaderMap, Method, Uri};
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::*;
use crate::identity::requirements;
use crate::identity::{
    IdentityRequest, PaymentCheck, PaymentCheckInput, Rejection, RejectionStatus, Verification,
    Verifier,
};
use crate::protocol::core::{Base64UrlJson, PaymentChallenge, PaymentCredential, PaymentPayload};
use crate::store::{MemoryStore, Store};

const KEY: &str = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// Generous, so a loaded test machine reads as slow, not as a Persona outage.
const SLOW: Duration = Duration::from_secs(60);
const OTHER: &str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";

fn account() -> PrivateKeySigner {
    KEY.parse().unwrap()
}

fn payer() -> String {
    did(&account().address().to_string(), 4217)
}

/// A request the fake API received.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: AxumHeaders,
    body: Option<Value>,
}

impl Seen {
    fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

type Handler = Arc<dyn Fn(&Seen) -> Response + Send + Sync>;

/// Serves `handler` on a local port, recording every request.
async fn serve(handler: Handler) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let app = axum::Router::new().fallback(
        move |method: AxumMethod, uri: AxumUri, headers: AxumHeaders, body: Bytes| {
            let handler = handler.clone();
            let log = log.clone();
            async move {
                let request = Seen {
                    method: method.to_string(),
                    path: uri.path().to_owned(),
                    query: reqwest::Url::parse(&format!("http://fake{uri}"))
                        .unwrap()
                        .query_pairs()
                        .into_owned()
                        .collect(),
                    headers,
                    body: serde_json::from_slice(&body).ok(),
                };
                let response = handler(&request);
                log.lock().unwrap().push(request);
                response
            }
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, seen)
}

fn ok(body: Value) -> Response {
    axum::Json(body).into_response()
}

/// A fake Persona API: lists inquiries as the real endpoint filters them, and starts new ones.
struct Fake {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    inquiries: Arc<Mutex<Vec<Value>>>,
}

impl Fake {
    fn calls(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn persona(&self, api_key: &str) -> Config {
        Config::new(api_key).api_url(self.url.clone()).timeout(SLOW)
    }
}

async fn fake(inquiries: Vec<Value>, status: Option<u16>, page_size: Option<usize>) -> Fake {
    let inquiries = Arc::new(Mutex::new(inquiries));
    let store = inquiries.clone();
    let (url, seen) = serve(Arc::new(move |request: &Seen| {
        if let Some(status) = status {
            return (StatusCode::from_u16(status).unwrap(), "upstream error").into_response();
        }
        let mut inquiries = store.lock().unwrap();
        if request.method == "POST" && request.path == "/api/v1/inquiries" {
            let attributes = &request.body.as_ref().unwrap()["data"]["attributes"];
            let id = format!("inq_{}", inquiries.len() + 1);
            inquiries.push(json!({
                "id": id,
                "attributes": { "status": "created", "reference-id": attributes["reference-id"] },
                "relationships": template(attributes["inquiry-template-id"].as_str().unwrap()),
            }));
            return ok(json!({ "data": { "id": id, "type": "inquiry" } }));
        }
        if request.method == "POST" && request.path.ends_with("/generate-one-time-link") {
            return ok(
                json!({ "meta": { "one-time-link": "https://withpersona.com/verify?code=abc" } }),
            );
        }
        let reference = request.param("filter[reference-id]").unwrap_or_default();
        let statuses: Vec<&str> = request
            .param("filter[status]")
            .unwrap_or_default()
            .split(',')
            .collect();
        let matches: Vec<Value> = inquiries
            .iter()
            .filter(|inquiry| {
                inquiry["attributes"]["reference-id"] == reference
                    && statuses.contains(&inquiry["attributes"]["status"].as_str().unwrap_or(""))
            })
            .cloned()
            .collect();
        let size = page_size.unwrap_or(matches.len().max(1));
        let start: usize = request
            .param("page[after]")
            .map(|after| after.parse().unwrap())
            .unwrap_or(0);
        let end = (start + size).min(matches.len());
        let next = (end < matches.len()).then(|| {
            let mut url = reqwest::Url::parse("http://fake").unwrap();
            url.set_path(&request.path);
            {
                let mut query = url.query_pairs_mut();
                for (key, value) in &request.query {
                    if key != "page[after]" {
                        query.append_pair(key, value);
                    }
                }
                query.append_pair("page[after]", &end.to_string());
            }
            format!("{}?{}", url.path(), url.query().unwrap())
        });
        ok(json!({ "data": matches[start.min(end)..end], "links": { "next": next } }))
    }))
    .await;
    Fake {
        url,
        seen,
        inquiries,
    }
}

fn template(id: &str) -> Value {
    json!({ "inquiry-template": { "data": { "id": id, "type": "inquiry-template" } } })
}

fn now_iso() -> String {
    OffsetDateTime::now_utc().format(&Rfc3339).unwrap()
}

fn approved(id: &str, reference: &str, decisioned_at: &str) -> Value {
    json!({
        "id": id,
        "attributes": { "status": "approved", "reference-id": reference, "decisioned-at": decisioned_at },
    })
}

fn request() -> IdentityRequest {
    IdentityRequest::new(
        Method::GET,
        Uri::from_static("https://api.example/resource"),
        HeaderMap::new(),
    )
}

fn credential(source: Option<&str>) -> PaymentCredential {
    let challenge = PaymentChallenge::new(
        "challenge-1",
        "api.example",
        "test",
        "charge",
        Base64UrlJson::from_value(&json!({"amount": "1"})).unwrap(),
    );
    let mut credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xabc"));
    credential.source = source.map(str::to_owned);
    credential
}

/// Reads the payer from the Credential's source: safe here, where the test trusts it.
fn from_source(input: &PaymentCheckInput<'_>) -> Option<String> {
    input
        .credential
        .and_then(|credential| credential.source.as_deref())
        .map(normalize)
}

async fn pay(check: &PersonaPaymentCheck, source: Option<&str>) -> Verification<VerifiedInquiry> {
    let request = request();
    let credential = credential(source);
    check
        .verify(PaymentCheckInput {
            request: &request,
            challenge: &credential.challenge,
            credential: Some(&credential),
        })
        .await
}

fn rejected(outcome: Verification<VerifiedInquiry>) -> Rejection {
    match outcome {
        Verification::Rejected(rejection) => rejection,
        Verification::Valid(value) => panic!("expected a rejection, got {value:?}"),
    }
}

fn valid(outcome: Verification<VerifiedInquiry>) -> VerifiedInquiry {
    match outcome {
        Verification::Valid(value) => value,
        Verification::Rejected(rejection) => panic!("expected a valid payer, got {rejection}"),
    }
}

fn link(rejection: &Rejection) -> Option<&str> {
    rejection
        .headers
        .get(http_types::header::LINK)
        .map(|value| value.to_str().unwrap())
}

fn proof(message: &str, nonce: &str) -> WalletProof {
    let signature = account().sign_message_sync(message.as_bytes()).unwrap();
    WalletProof {
        address: account().address(),
        chain_id: 4217,
        message: message.to_owned(),
        signature: signature.to_string(),
        nonce: nonce.to_owned(),
    }
}

#[tokio::test]
async fn links_a_wallet_starts_an_inquiry_and_accepts_the_payer_once_approved() {
    let api = fake(vec![], None, None).await;
    let persona = Persona::new(api.persona("persona_key").template_id("itmpl_1")).unwrap();

    let payer = payer();
    let message = format!("Link {payer} to KYC on api.example. Nonce: n-123");
    let reference_id = verify_wallet(&proof(&message, "n-123")).unwrap();
    assert_eq!(reference_id, payer);

    let started = persona
        .start_inquiry(StartInquiry::new(&reference_id))
        .await
        .unwrap();
    assert_eq!(
        started,
        StartedInquiry {
            inquiry_id: "inq_1".into(),
            url: "https://withpersona.com/verify?code=abc".into(),
        }
    );
    let calls = api.calls();
    assert_eq!(
        calls[0].body,
        Some(
            json!({ "data": { "attributes": { "inquiry-template-id": "itmpl_1", "reference-id": payer } } })
        )
    );
    assert_eq!(calls[0].headers["authorization"], "Bearer persona_key");
    assert_eq!(calls[0].headers["persona-version"], "2023-01-05");
    assert_eq!(
        calls[1].path,
        "/api/v1/inquiries/inq_1/generate-one-time-link"
    );

    let kyc = persona.payment_check(
        from_source,
        LookupOptions::new().onboarding("https://api.example/kyc"),
    );
    assert_eq!(
        requirements::serialize(kyc.requires()).unwrap(),
        "kyc;issuer=\"https://api.withpersona.com\""
    );
    let pending = rejected(pay(&kyc, Some(&payer)).await);
    assert_eq!(pending.status, RejectionStatus::Forbidden);
    assert_eq!(pending.status.code().as_u16(), 403);
    assert_eq!(
        link(&pending),
        Some("<https://api.example/kyc>; rel=\"kyc\"")
    );

    api.inquiries.lock().unwrap()[0] = json!({
        "id": "inq_1",
        "attributes": approved("inq_1", &payer, &now_iso())["attributes"],
        "relationships": template("itmpl_1"),
    });
    // The Credential's source checksums the address; the check normalizes it.
    let source = format!("did:pkh:eip155:4217:{}", account().address());
    let value = valid(pay(&kyc, Some(&source)).await);
    assert_eq!(value.inquiry_id, "inq_1");
    assert_eq!(value.reference_id, payer);
    assert_eq!(value.status, InquiryStatus::Approved);
    assert!(value.verified_at.is_some());
    let lookup = api.calls().pop().unwrap();
    assert_eq!(lookup.param("filter[inquiry-template-id]"), Some("itmpl_1"));
    assert_eq!(lookup.param("filter[status]"), Some("approved"));
}

#[tokio::test]
async fn rejects_a_wallet_signature_without_the_nonce_for_another_chain_or_from_another_address() {
    let message = format!("Link {} and {}. Nonce: n-1", payer(), did(OTHER, 4217));
    let base = proof(&message, "n-1");
    let error = |proof: WalletProof| verify_wallet(&proof).unwrap_err().to_string();
    assert!(error(WalletProof {
        nonce: "n-2".into(),
        ..base.clone()
    })
    .contains("nonce"));
    assert!(error(WalletProof {
        nonce: String::new(),
        ..base.clone()
    })
    .contains("nonce"));
    // The signer committed to chain 4217 only.
    assert!(error(WalletProof {
        chain_id: 1,
        ..base.clone()
    })
    .contains("wallet's DID"));
    assert!(error(WalletProof {
        address: OTHER.parse().unwrap(),
        ..base.clone()
    })
    .contains("does not match"));
    assert!(error(WalletProof {
        signature: "0x1234".into(),
        ..base.clone()
    })
    .contains("does not match"));

    let mut chains = Vec::new();
    let reference_id = verify_wallet_with(&base, |proof| {
        chains.push(proof.chain_id);
        async { true }
    })
    .await
    .unwrap();
    assert_eq!(reference_id, payer());
    assert_eq!(chains, vec![4217]);
    let refused = verify_wallet_with(&base, |_| async { false })
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("does not match"));
}

#[tokio::test]
async fn never_follows_a_pagination_link_to_another_origin() {
    let (url, seen) = serve(Arc::new(|_: &Seen| {
        ok(json!({ "data": [], "links": { "next": "https://evil.example/api/v1/inquiries" } }))
    }))
    .await;
    let check = Persona::new(Config::new("k").api_url(url).timeout(SLOW))
        .unwrap()
        .payment_check(from_source, LookupOptions::new());
    // Following it would fail as unavailable; stopping is a plain rejection.
    let rejection = rejected(pay(&check, Some(&payer())).await);
    assert_eq!(rejection.status, RejectionStatus::Forbidden);
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn never_follows_a_protocol_relative_pagination_path_to_another_origin() {
    let origin = Arc::new(Mutex::new(String::new()));
    let base = origin.clone();
    let (url, seen) = serve(Arc::new(move |_: &Seen| {
        ok(json!({ "data": [], "links": { "next": format!("{}//evil.example/x", base.lock().unwrap()) } }))
    }))
    .await;
    *origin.lock().unwrap() = url.clone();
    let check = Persona::new(Config::new("k").api_url(url).timeout(SLOW))
        .unwrap()
        .payment_check(from_source, LookupOptions::new());
    let rejection = rejected(pay(&check, Some(&payer())).await);
    assert_eq!(rejection.status, RejectionStatus::Forbidden);
    {
        let seen = seen.lock().unwrap();
        // It stays on the API origin, reading the path as a path, up to the page limit.
        assert_eq!(seen.len(), constants::MAX_PAGES);
        assert!(seen[1..]
            .iter()
            .all(|request| request.path == "//evil.example/x"));
    }

    // A bare protocol-relative link resolves to another origin and is not followed.
    let (url, seen) = serve(Arc::new(|_: &Seen| {
        ok(json!({ "data": [], "links": { "next": "//evil.example/x" } }))
    }))
    .await;
    let check = Persona::new(Config::new("k").api_url(url).timeout(SLOW))
        .unwrap()
        .payment_check(from_source, LookupOptions::new());
    assert_eq!(
        rejected(pay(&check, Some(&payer())).await).status,
        RejectionStatus::Forbidden
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn rejects_as_missing_or_forbidden_with_the_onboarding_link() {
    let payer = payer();
    let api = fake(
        vec![
            json!({ "id": "inq_1", "attributes": { "status": "declined", "reference-id": payer } }),
        ],
        None,
        None,
    )
    .await;
    let kyc = Persona::new(api.persona("k")).unwrap().payment_check(
        from_source,
        LookupOptions::new().onboarding_fn(|_, reference_id| {
            Some(format!("/kyc?for={}", reference_id.unwrap_or_default()))
        }),
    );

    let declined = rejected(pay(&kyc, Some(&payer)).await);
    assert_eq!(declined.status, RejectionStatus::Forbidden);
    assert_eq!(declined.reason, "The payer has not passed Persona KYC.");
    assert_eq!(
        link(&declined),
        Some(format!("</kyc?for={payer}>; rel=\"kyc\"").as_str())
    );

    let calls = api.calls().len();
    let anonymous = rejected(pay(&kyc, None).await);
    assert_eq!(anonymous.status, RejectionStatus::Missing);
    assert_eq!(anonymous.status.code().as_u16(), 401);
    assert_eq!(anonymous.reason, "Persona KYC requires a payer.");
    assert_eq!(link(&anonymous), Some("</kyc?for=>; rel=\"kyc\""));
    assert_eq!(api.calls().len(), calls);
}

#[tokio::test]
async fn maps_a_persona_api_failure_to_unavailable_without_its_body() {
    let api = fake(vec![], Some(500), None).await;
    let kyc = Persona::new(api.persona("k"))
        .unwrap()
        .payment_check(from_source, LookupOptions::new().onboarding("/kyc"));
    let rejection = rejected(pay(&kyc, Some(&payer())).await);
    assert_eq!(rejection.status, RejectionStatus::Unavailable);
    assert_eq!(rejection.status.code().as_u16(), 503);
    assert_eq!(rejection.reason, "Persona KYC verification is unavailable.");
    assert!(rejection.headers.is_empty());
}

#[tokio::test]
async fn caches_approvals_only() {
    let api = fake(vec![approved("inq_1", &payer(), &now_iso())], None, None).await;
    let kyc = Persona::new(api.persona("k")).unwrap().payment_check(
        from_source,
        LookupOptions::new().cache(Arc::new(MemoryStore::new())),
    );
    valid(pay(&kyc, Some(&payer())).await);
    valid(pay(&kyc, Some(&payer())).await);
    assert_eq!(api.calls().len(), 1);

    let other = did(OTHER, 4217);
    rejected(pay(&kyc, Some(&other)).await);
    rejected(pay(&kyc, Some(&other)).await);
    assert_eq!(api.calls().len(), 3);
}

#[tokio::test]
async fn does_not_share_cached_approvals_across_persona_organizations() {
    let cache: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let approved_api = fake(vec![approved("inq_1", &payer(), &now_iso())], None, None).await;
    let empty_api = fake(vec![], None, None).await;
    let options = LookupOptions::new().cache(cache.clone());
    let a = Persona::new(approved_api.persona("org-a"))
        .unwrap()
        .payment_check(from_source, options.clone());
    // Same origin as org-a's API, different key.
    let b = Persona::new(
        Config::new("org-b")
            .api_url(empty_api.url.clone())
            .timeout(SLOW),
    )
    .unwrap()
    .payment_check(from_source, options);
    valid(pay(&a, Some(&payer())).await);
    assert_eq!(
        rejected(pay(&b, Some(&payer())).await).status,
        RejectionStatus::Forbidden
    );
    assert_eq!(empty_api.calls().len(), 1);
}

#[tokio::test]
async fn applies_each_checks_own_cache_ttl_to_a_shared_cache() {
    let cache: Arc<dyn Store> = Arc::new(MemoryStore::new());
    let api = fake(vec![approved("inq_1", &payer(), &now_iso())], None, None).await;
    let persona = Persona::new(api.persona("k")).unwrap();
    let lenient = persona.payment_check(
        from_source,
        LookupOptions::new()
            .cache(cache.clone())
            .cache_ttl(Duration::from_secs(3600)),
    );
    let strict = persona.payment_check(
        from_source,
        LookupOptions::new().cache(cache).cache_ttl(Duration::ZERO),
    );
    valid(pay(&lenient, Some(&payer())).await);
    api.inquiries.lock().unwrap().clear();
    valid(pay(&lenient, Some(&payer())).await);
    assert_eq!(
        rejected(pay(&strict, Some(&payer())).await).status,
        RejectionStatus::Forbidden
    );
}

#[tokio::test]
async fn applies_max_age_across_pages_and_a_custom_reference_id() {
    let old = (OffsetDateTime::now_utc() - Duration::from_secs(7200))
        .format(&Rfc3339)
        .unwrap();
    let api = fake(
        vec![
            approved("inq_a", "customer-1", &old),
            approved("inq_b", "customer-1", &old),
            approved("inq_c", "customer-1", &now_iso()),
        ],
        None,
        Some(1),
    )
    .await;
    let kyc = Persona::new(api.persona("k")).unwrap().payment_check(
        |_| Some("customer-1".to_owned()),
        LookupOptions::new().max_age(Duration::from_secs(3600)),
    );
    let value = valid(pay(&kyc, Some(&payer())).await);
    assert_eq!(value.inquiry_id, "inq_c");
    assert_eq!(value.reference_id, "customer-1");
    assert_eq!(api.calls().len(), 3);
}

#[tokio::test]
async fn accepts_only_inquiries_from_the_configured_template() {
    let mut other = approved("inq_2", &payer(), &now_iso());
    other["relationships"] = template("itmpl_other");
    let untagged = approved("inq_3", &payer(), &now_iso());
    let listed = json!([other, untagged]);
    let (url, _) = serve(Arc::new(move |_: &Seen| {
        ok(json!({ "data": listed, "links": { "next": null } }))
    }))
    .await;
    let kyc = Persona::new(
        Config::new("k")
            .api_url(url)
            .timeout(SLOW)
            .template_id("itmpl_1"),
    )
    .unwrap()
    .payment_check(from_source, LookupOptions::new());
    assert_eq!(
        rejected(pay(&kyc, Some(&payer())).await).status,
        RejectionStatus::Forbidden
    );

    let mut matching = approved("inq_1", &payer(), &now_iso());
    matching["relationships"] = template("itmpl_1");
    let listed = json!([other, matching]);
    let (url, _) = serve(Arc::new(move |_: &Seen| {
        ok(json!({ "data": listed, "links": { "next": null } }))
    }))
    .await;
    let kyc = Persona::new(
        Config::new("k")
            .api_url(url)
            .timeout(SLOW)
            .template_id("itmpl_1"),
    )
    .unwrap()
    .payment_check(from_source, LookupOptions::new());
    assert_eq!(valid(pay(&kyc, Some(&payer())).await).inquiry_id, "inq_1");
}

#[tokio::test]
async fn ignores_inquiries_the_api_returns_outside_its_filters() {
    let (url, _) = serve(Arc::new(|_: &Seen| {
        ok(json!({ "data": [
            approved("inq_wrong", "someone-else", &now_iso()),
            { "id": "inq_declined", "attributes": { "status": "declined", "reference-id": payer() } },
        ] }))
    }))
    .await;
    let kyc = Persona::new(Config::new("k").api_url(url).timeout(SLOW))
        .unwrap()
        .payment_check(from_source, LookupOptions::new());
    assert_eq!(
        rejected(pay(&kyc, Some(&payer())).await).status,
        RejectionStatus::Forbidden
    );
}

#[tokio::test]
async fn treats_a_malformed_response_as_unavailable() {
    let (url, _) = serve(Arc::new(|_: &Seen| ok(json!({ "data": "nope" })))).await;
    let kyc = Persona::new(Config::new("k").api_url(url).timeout(SLOW))
        .unwrap()
        .payment_check(from_source, LookupOptions::new());
    assert_eq!(
        rejected(pay(&kyc, Some(&payer())).await).status,
        RejectionStatus::Unavailable
    );
}

#[tokio::test]
async fn requires_kyc_before_any_402_with_a_request_stage_verifier() {
    let api = fake(
        vec![approved("inq_1", "customer-1", &now_iso())],
        None,
        None,
    )
    .await;
    let verifier = Persona::new(api.persona("k")).unwrap().verifier(
        |request| request.header("x-customer").map(str::to_owned),
        LookupOptions::new(),
    );
    assert_eq!(
        rejected(verifier.verify(&request()).await).status,
        RejectionStatus::Missing
    );
    let mut headers = HeaderMap::new();
    headers.insert("x-customer", "customer-1".parse().unwrap());
    let customer = IdentityRequest::new(
        Method::GET,
        Uri::from_static("https://api.example/"),
        headers,
    );
    assert_eq!(valid(verifier.verify(&customer).await).inquiry_id, "inq_1");
}

#[test]
fn normalizes_dids_per_chain() {
    assert_eq!(did("0xAbC", 4217), "did:pkh:eip155:4217:0xabc");
    assert_eq!(
        did_in("solana", "mainnet", "So1AnaBase58"),
        "did:pkh:solana:mainnet:So1AnaBase58"
    );
    assert_eq!(normalize("DID:PKH:EIP155:1:0xAB"), "did:pkh:eip155:1:0xab");
    assert_eq!(normalize("customer-1"), "customer-1");
}

#[tokio::test]
async fn treats_a_persona_redirect_as_unavailable_without_following_it() {
    let (url, seen) = serve(Arc::new(|_: &Seen| {
        (StatusCode::FOUND, [("location", "https://evil.example/")]).into_response()
    }))
    .await;
    let kyc = Persona::new(Config::new("k").api_url(url).timeout(SLOW))
        .unwrap()
        .payment_check(from_source, LookupOptions::new());
    assert_eq!(
        rejected(pay(&kyc, Some(&payer())).await).status,
        RejectionStatus::Unavailable
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn rejects_with_unavailable_when_no_status_is_accepted() {
    let api = fake(vec![approved("inq_1", &payer(), &now_iso())], None, None).await;
    let kyc = Persona::new(api.persona("k"))
        .unwrap()
        .payment_check(from_source, LookupOptions::new().statuses([]));
    assert_eq!(
        rejected(pay(&kyc, Some(&payer())).await).status,
        RejectionStatus::Unavailable
    );
    assert!(api.calls().is_empty());
}

#[tokio::test]
async fn validates_its_config() {
    let error = Persona::new(Config::new("")).unwrap_err();
    assert!(error.to_string().contains("api_key"));
    let error = Persona::new(Config::new("k").timeout(Duration::ZERO)).unwrap_err();
    assert!(error.to_string().contains("timeout"));
    let error = Persona::new(Config::new("k").api_url("not a url")).unwrap_err();
    assert!(error.to_string().contains("api_url"));
    let persona = Persona::new(Config::new("k")).unwrap();
    let error = persona
        .start_inquiry(StartInquiry::new("ref"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("template_id"));
    let error = persona
        .start_inquiry(StartInquiry::new(""))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("reference_id"));
    // Debug output never carries the API key.
    assert!(!format!("{:?}", Config::new("secret-key")).contains("secret-key"));
}
