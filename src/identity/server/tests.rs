use std::sync::atomic::{AtomicUsize, Ordering};

use http_types::header::WWW_AUTHENTICATE;

use super::*;
use crate::protocol::core::{Base64UrlJson, PaymentChallenge, PaymentPayload};

fn request(headers: &[(&'static str, &'static str)]) -> IdentityRequest {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(*name, HeaderValue::from_static(value));
    }
    IdentityRequest::new(Method::GET, Uri::from_static("/paid"), map)
}

fn credential(id: &str) -> PaymentCredential {
    let challenge = PaymentChallenge::new(
        id,
        "realm",
        "tempo",
        "charge",
        Base64UrlJson::from_value(&serde_json::json!({"amount": "1"})).unwrap(),
    );
    PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xabc"))
}

/// A verifier that returns a fixed outcome and counts its runs.
struct Fixed {
    outcome: Verification<&'static str>,
    runs: Arc<AtomicUsize>,
}

impl Verifier for Fixed {
    type Value = &'static str;

    fn verify<'a>(
        &'a self,
        _request: &'a IdentityRequest,
    ) -> BoxFuture<'a, Verification<&'static str>> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::ready(self.outcome.clone()))
    }
}

fn fixed(outcome: Verification<&'static str>) -> (Handle<Fixed>, Arc<AtomicUsize>) {
    let runs = Arc::new(AtomicUsize::new(0));
    (
        Handle::new(Fixed {
            outcome,
            runs: runs.clone(),
        }),
        runs,
    )
}

/// A payment check that accepts only the payer `allowed`.
struct PayerCheck {
    requires: Vec<Requirement>,
    runs: Arc<AtomicUsize>,
}

impl PaymentCheck for PayerCheck {
    type Value = String;

    fn requires(&self) -> &[Requirement] {
        &self.requires
    }

    fn verify<'a>(&'a self, input: PaymentCheckInput<'a>) -> BoxFuture<'a, Verification<String>> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        let source = input.credential.and_then(|c| c.source.clone());
        Box::pin(async move {
            match source.as_deref() {
                Some("allowed") => Verification::Valid("allowed".to_owned()),
                _ => Rejection::forbidden("Not this payer.").into(),
            }
        })
    }
}

fn payer_check() -> (Handle<PayerCheck>, Arc<AtomicUsize>) {
    let runs = Arc::new(AtomicUsize::new(0));
    (
        Handle::new(PayerCheck {
            requires: vec![Requirement::new("kyc").with_issuer("https://kyc.example")],
            runs: runs.clone(),
        }),
        runs,
    )
}

#[test]
fn statuses_map_to_fixed_codes() {
    assert_eq!(RejectionStatus::Missing.code(), StatusCode::UNAUTHORIZED);
    assert_eq!(RejectionStatus::Invalid.code(), StatusCode::UNAUTHORIZED);
    assert_eq!(RejectionStatus::Forbidden.code(), StatusCode::FORBIDDEN);
    assert_eq!(
        RejectionStatus::Unavailable.code(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn decide_picks_highest_precedence_and_merges_headers() {
    let decision = decide(&[
        Rejection::missing().with_header(WWW_AUTHENTICATE, HeaderValue::from_static("A")),
        Rejection::invalid("bad").with_header(WWW_AUTHENTICATE, HeaderValue::from_static("B")),
        Rejection::unavailable("down"),
        Rejection::invalid("worse"),
    ]);
    assert_eq!(decision.status, RejectionStatus::Unavailable);
    assert_eq!(decision.reason, "down");
    let values: Vec<_> = decision.headers.get_all(WWW_AUTHENTICATE).iter().collect();
    assert_eq!(values, ["A", "B"]);

    // Ties go to the first outcome.
    let decision = decide(&[Rejection::invalid("first"), Rejection::invalid("second")]);
    assert_eq!(decision.reason, "first");
    assert_eq!(
        decide(&[Rejection::unavailable("down"), Rejection::forbidden("no")]).status,
        RejectionStatus::Forbidden
    );
}

#[tokio::test]
async fn verify_requires_every_verifier() {
    let (a, _) = fixed(Verification::Valid("a"));
    let (b, _) = fixed(Rejection::forbidden("no").into());
    let context = IdentityContext::new(request(&[]));
    let route = RouteIdentity::new().verifier(&a).verifier(&b);
    let rejection = route.verify_request(&context).await.unwrap_err();
    assert_eq!(rejection.stage, RejectionStage::Request);
    assert_eq!(rejection.rejection.status, RejectionStatus::Forbidden);
    assert_eq!(rejection.status_code(), StatusCode::FORBIDDEN);

    let route = RouteIdentity::new().verifier(&a);
    let call = route.verify_request(&context).await.unwrap();
    assert_eq!(call.results().get(&a), Some(&"a"));
    assert_eq!(call.results().get(&b), None);
}

#[tokio::test]
async fn verifiers_run_once_per_context() {
    let (a, runs) = fixed(Verification::Valid("a"));
    let context = IdentityContext::new(request(&[]));
    let route = RouteIdentity::new().verifier(&a).verifier(&a);
    route.verify_request(&context).await.unwrap();
    route.verify_request(&context).await.unwrap();
    assert_eq!(runs.load(Ordering::SeqCst), 1);

    // A new request runs it again.
    let other = IdentityContext::new(request(&[]));
    route.verify_request(&other).await.unwrap();
    assert_eq!(runs.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn any_of_accepts_the_first_valid_member_and_runs_every_member() {
    let (missing, missing_runs) = fixed(Verification::Rejected(Rejection::missing()));
    let (first, _) = fixed(Verification::Valid("first"));
    let (second, second_runs) = fixed(Verification::Valid("second"));
    let either = any_of([(&missing).into(), (&first).into(), (&second).into()]);
    let context = IdentityContext::new(request(&[]));
    let call = RouteIdentity::new()
        .verifier(&either)
        .verify_request(&context)
        .await
        .unwrap();
    let results = call.results();
    assert_eq!(results.get(&either), Some(&AnyOfMatch { index: 1 }));
    assert_eq!(results.get(&first), Some(&"first"));
    // Only the matched member's value is recorded.
    assert_eq!(results.get(&second), None);
    assert_eq!(missing_runs.load(Ordering::SeqCst), 1);
    assert_eq!(second_runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn nested_any_of_records_the_leaf_value() {
    let (missing, _) = fixed(Verification::Rejected(Rejection::missing()));
    let (leaf, _) = fixed(Verification::Valid("leaf"));
    let inner = any_of([(&missing).into(), (&leaf).into()]);
    let outer = any_of([(&missing).into(), (&inner).into()]);
    let context = IdentityContext::new(request(&[]));
    let results = RouteIdentity::new()
        .verifier(&outer)
        .verify_request(&context)
        .await
        .unwrap()
        .results();
    assert_eq!(results.get(&outer), Some(&AnyOfMatch { index: 1 }));
    assert_eq!(results.get(&inner), Some(&AnyOfMatch { index: 1 }));
    assert_eq!(results.get(&leaf), Some(&"leaf"));
}

#[tokio::test]
async fn any_of_groups_attestation_requirements_as_alternatives() {
    let required = |value: &'static str| {
        Verification::Rejected(Rejection::missing().with_header(
            HeaderName::from_static("identity-attestation-required"),
            HeaderValue::from_static(value),
        ))
    };
    let (a, _) = fixed(required(r#"email;issuer="https://a.example""#));
    let (b, _) = fixed(required(r#"email;issuer="https://b.example""#));
    let either = any_of([(&a).into(), (&b).into()]);
    let context = IdentityContext::new(request(&[]));
    let rejection = RouteIdentity::new()
        .verifier(&either)
        .verify_request(&context)
        .await
        .unwrap_err()
        .rejection;
    assert_eq!(rejection.status, RejectionStatus::Missing);
    assert_eq!(
        rejection.reason,
        "None of the accepted identity proofs was presented."
    );
    let values: Vec<_> = rejection
        .headers
        .get_all("identity-attestation-required")
        .iter()
        .collect();
    assert_eq!(
        values,
        [r#"(email;issuer="https://a.example" email;issuer="https://b.example")"#]
    );

    // Direct use (outside a context) combines the same way.
    let outcome = either.verify(&request(&[])).await;
    assert!(matches!(outcome, Verification::Rejected(r) if r.status == RejectionStatus::Missing));
}

#[test]
#[should_panic(expected = "at least two")]
fn any_of_needs_two_members() {
    let (a, _) = fixed(Verification::Valid("a"));
    let _ = any_of([(&a).into()]);
}

#[tokio::test]
async fn from_fn_maps_lookups_to_outcomes() {
    let challenge = HeaderMap::from_iter([(WWW_AUTHENTICATE, HeaderValue::from_static("ApiKey"))]);
    let customer = from_fn_with_challenge(challenge, |request: &IdentityRequest| {
        let key = request.header("x-api-key").map(str::to_owned);
        async move {
            match key.as_deref() {
                None => Ok(None),
                Some("good") => Ok(Some("customer-1".to_owned())),
                Some(_) => Err(Rejection::forbidden("Unknown API key.")),
            }
        }
    });

    match customer.verify(&request(&[])).await {
        Verification::Rejected(rejection) => {
            assert_eq!(rejection.status, RejectionStatus::Missing);
            assert_eq!(rejection.headers.get(WWW_AUTHENTICATE).unwrap(), "ApiKey");
        }
        Verification::Valid(_) => panic!("expected missing"),
    }
    match customer.verify(&request(&[("x-api-key", "bad")])).await {
        Verification::Rejected(rejection) => {
            assert_eq!(rejection.status, RejectionStatus::Forbidden);
            assert_eq!(rejection.reason, "Unknown API key.");
            assert_eq!(rejection.headers.get(WWW_AUTHENTICATE).unwrap(), "ApiKey");
        }
        Verification::Valid(_) => panic!("expected forbidden"),
    }
    assert_eq!(
        customer.verify(&request(&[("x-api-key", "good")])).await,
        Verification::Valid("customer-1".to_owned())
    );
}

#[tokio::test]
async fn payment_check_gates_and_accepts_with_one_run() {
    let (check, runs) = payer_check();
    let route = RouteIdentity::new().payment(&check);
    assert_eq!(
        route.required_header().unwrap(),
        r#"kyc;issuer="https://kyc.example""#
    );
    let context = IdentityContext::new(request(&[]));
    let mut unpaid = route.verify_request(&context).await.unwrap();
    assert_eq!(
        unpaid.challenge().unwrap(),
        r#"kyc;issuer="https://kyc.example""#
    );
    let call = route.verify_request(&context).await.unwrap();

    let mut paid = credential("challenge-1");
    paid.source = Some("allowed".to_owned());
    let gate = call.payment_gate().unwrap();
    assert!(gate.admit(&paid).await);
    let results = call.clone().accept(&paid).await.unwrap();
    assert_eq!(results.payment(&check).map(String::as_str), Some("allowed"));
    // The gate and accept share one memoized run.
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn rejected_payment_check_rejects_the_paid_retry() {
    let (check, _) = payer_check();
    let route = RouteIdentity::new().payment(&check);
    let context = IdentityContext::new(request(&[]));
    let call = route.verify_request(&context).await.unwrap();
    let paid = credential("challenge-1");
    assert!(!call.payment_gate().unwrap().admit(&paid).await);
    let rejection = call.accept(&paid).await.unwrap_err();
    assert_eq!(rejection.stage, RejectionStage::Payment);
    assert_eq!(rejection.status_code(), StatusCode::FORBIDDEN);

    let response = rejection.into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    assert_eq!(response.body(), "Not this payer.");
}

#[test]
#[should_panic(expected = "invalid identity payment check")]
fn payment_check_requirements_must_serialize() {
    let check = Handle::new(PayerCheck {
        requires: vec![Requirement::new("not a token")],
        runs: Arc::new(AtomicUsize::new(0)),
    });
    let _ = RouteIdentity::new().payment(&check);
}

#[test]
fn transitions_follow_the_state_machine() {
    let valid = || Outcome::Valid(Values::new());
    let rejected = || Outcome::Rejected(Rejection::forbidden("no"));

    let state = transition(State::Request, Event::Verified(valid())).unwrap();
    assert_eq!(state.phase(), "identified");
    let state = transition(State::Request, Event::Verified(rejected())).unwrap();
    assert!(matches!(state, State::Rejected(r) if r.stage == RejectionStage::Request));

    let identified = || transition(State::Request, Event::Verified(valid())).unwrap();
    let paying = transition(identified(), Event::Pay { paid: true }).unwrap();
    assert_eq!(paying.phase(), "payment");
    let accepted = transition(paying.clone(), Event::Checked(valid())).unwrap();
    assert_eq!(accepted.phase(), "accepted");
    let refused = transition(paying, Event::Checked(rejected())).unwrap();
    assert!(matches!(refused, State::Rejected(r) if r.stage == RejectionStage::Payment));

    // Without a Credential, a refusal only means not authorized.
    let unpaid = transition(identified(), Event::Pay { paid: false }).unwrap();
    assert_eq!(
        transition(unpaid, Event::Checked(rejected()))
            .unwrap()
            .phase(),
        "identified"
    );

    assert_eq!(
        transition(accepted, Event::Challenge).unwrap().phase(),
        "challenged"
    );
    assert_eq!(
        transition(identified(), Event::Challenge).unwrap().phase(),
        "challenged"
    );

    // Illegal events are refused.
    assert!(transition(State::Request, Event::Pay { paid: true }).is_err());
    assert!(transition(identified(), Event::Verified(valid())).is_err());
    assert!(transition(State::Request, Event::Challenge).is_err());
}

#[tokio::test]
async fn memoize_runs_once_per_request_and_key() {
    let request = request(&[]);
    let key = MemoKey::new();
    let runs = AtomicUsize::new(0);
    for _ in 0..3 {
        let value = request
            .memoize(&key, async {
                runs.fetch_add(1, Ordering::SeqCst);
                7u32
            })
            .await;
        assert_eq!(value, 7);
    }
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    let other = MemoKey::new();
    assert_eq!(request.memoize(&other, async { 8u32 }).await, 8);
}

#[tokio::test]
async fn concurrent_memoize_shares_one_computation() {
    let request = request(&[]);
    let key = MemoKey::new();
    let runs = AtomicUsize::new(0);
    let compute = || async {
        // Suspend mid-computation, so the other call starts before a value is stored.
        tokio::task::yield_now().await;
        runs.fetch_add(1, Ordering::SeqCst)
    };
    let (first, second) = tokio::join!(
        request.memoize(&key, compute()),
        request.memoize(&key, compute())
    );
    assert_eq!((first, second), (0, 0));
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn reads_authorization_propagates_through_any_of() {
    struct Bearer;
    impl Verifier for Bearer {
        type Value = ();
        fn reads_authorization(&self) -> bool {
            true
        }
        fn verify<'a>(&'a self, _request: &'a IdentityRequest) -> BoxFuture<'a, Verification<()>> {
            Box::pin(std::future::ready(Verification::Valid(())))
        }
    }
    let (plain, _) = fixed(Verification::Valid("a"));
    let bearer = Handle::new(Bearer);
    assert!(!RouteIdentity::new().verifier(&plain).reads_authorization());
    let either = any_of([(&plain).into(), (&bearer).into()]);
    assert!(RouteIdentity::new().verifier(&either).reads_authorization());
}
