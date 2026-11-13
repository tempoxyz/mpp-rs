//! The Axum extractors with a route identity.

use std::sync::atomic::{AtomicUsize, Ordering};

use http_body_util::BodyExt;

use super::*;
use crate::identity::{
    from_fn, BoxFuture, Handle, IdentityRequest, PaymentCheck, PaymentCheckInput, Rejection,
    Requirement, RouteIdentity, Verification,
};
use crate::protocol::core::headers::format_authorization;
use crate::protocol::core::{Base64UrlJson, PaymentCredential, PaymentPayload};

#[derive(Debug)]
struct OneCent;
impl ChargeConfig for OneCent {
    fn amount() -> &'static str {
        "0.01"
    }
}

/// Accepts every credential, counting verifications.
struct CountingChallenger {
    verified: Arc<AtomicUsize>,
    header: &'static str,
}

impl ChargeChallenger for CountingChallenger {
    fn challenge(
        &self,
        amount: &str,
        _options: ChallengeOptions,
    ) -> Result<PaymentChallenge, String> {
        Ok(PaymentChallenge::new(
            "mock-id",
            "mock-realm",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": amount})).unwrap(),
        ))
    }

    fn verify_payment(
        &self,
        _credential_str: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        let verified = self.verified.clone();
        Box::pin(async move {
            // Counted when polled: settlement happens here, not when the future is created.
            verified.fetch_add(1, Ordering::SeqCst);
            Ok(Receipt {
                status: crate::protocol::core::ReceiptStatus::Success,
                method: crate::protocol::core::MethodName::new("tempo"),
                timestamp: "2025-01-01T00:00:00Z".into(),
                reference: "0xabc".into(),
                external_id: None,
                subscription_id: None,
                funding_currency: None,
                extensions: serde_json::Map::new(),
            })
        })
    }

    fn verify_payment_for_amount_and_scope(
        &self,
        credential_str: &str,
        amount: &str,
        _mppx_scope: Option<serde_json::Value>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        self.verify_payment_for_amount(credential_str, amount)
    }

    fn credential_header(&self) -> &str {
        self.header
    }
}

/// Accepts only payments whose source is `did:allowed`.
struct SourceCheck {
    requires: Vec<Requirement>,
}

impl PaymentCheck for SourceCheck {
    type Value = String;

    fn requires(&self) -> &[Requirement] {
        &self.requires
    }

    fn verify<'a>(&'a self, input: PaymentCheckInput<'a>) -> BoxFuture<'a, Verification<String>> {
        let source = input
            .credential
            .and_then(|credential| credential.source.clone());
        Box::pin(async move {
            match source.as_deref() {
                Some("did:allowed") => Verification::Valid("did:allowed".to_owned()),
                _ => Rejection::forbidden("This payer may not call this API.").into(),
            }
        })
    }
}

fn api_key() -> Handle<impl crate::identity::Verifier<Value = String>> {
    from_fn(|request: &IdentityRequest| {
        let key = request.header("x-api-key").map(str::to_owned);
        async move {
            match key.as_deref() {
                None => Ok(None),
                Some("good") => Ok(Some("customer-1".to_owned())),
                Some(_) => Err(Rejection::forbidden("Unknown API key.")),
            }
        }
    })
}

fn source_check() -> Handle<SourceCheck> {
    Handle::new(SourceCheck {
        requires: vec![Requirement::new("kyc").with_issuer("https://kyc.example")],
    })
}

fn credential(header: &'static str, source: Option<&str>) -> String {
    let challenger = CountingChallenger {
        verified: Arc::default(),
        header,
    };
    let challenge = challenger
        .challenge("0.01", ChallengeOptions::default())
        .unwrap();
    let mut credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xabc"));
    credential.source = source.map(str::to_owned);
    format_authorization(&credential).unwrap()
}

async fn extract(
    identity: Option<RouteIdentity>,
    header: &'static str,
    headers: &[(&'static str, String)],
) -> (Result<MppCharge<OneCent>, MppChargeRejection>, usize) {
    let verified = Arc::new(AtomicUsize::new(0));
    let challenger: Arc<dyn ChargeChallenger> = Arc::new(CountingChallenger {
        verified: verified.clone(),
        header,
    });
    let mut builder = http_types::Request::builder().uri("https://api.example/paid");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let (mut parts, ()) = builder.body(()).unwrap().into_parts();
    if let Some(identity) = identity {
        parts.extensions.insert(identity);
    }
    let result = MppCharge::<OneCent>::from_request_parts(&mut parts, &challenger).await;
    (result, verified.load(Ordering::SeqCst))
}

#[tokio::test]
async fn request_verifier_rejects_before_any_402() {
    let identity = RouteIdentity::new().verifier(api_key());
    let (result, verified) = extract(Some(identity.clone()), "Authorization", &[]).await;
    let response = result.unwrap_err().into_response();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get(WWW_AUTHENTICATE_HEADER).is_none());
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(verified, 0);

    let (result, _) = extract(
        Some(identity),
        "Authorization",
        &[("x-api-key", "bad".into())],
    )
    .await;
    let response = result.unwrap_err().into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"Unknown API key.");
}

#[tokio::test]
async fn verifiers_see_the_uri_before_router_nesting() {
    // Rejects with the path it saw, so the response shows it.
    let path = from_fn(|request: &IdentityRequest| {
        let path = request.uri().path().to_owned();
        async move { Err::<Option<()>, _>(Rejection::forbidden(path)) }
    });
    let challenger: Arc<dyn ChargeChallenger> = Arc::new(CountingChallenger {
        verified: Arc::default(),
        header: "Authorization",
    });
    let (mut parts, ()) = http_types::Request::builder()
        .uri("/paid")
        .body(())
        .unwrap()
        .into_parts();
    parts
        .extensions
        .insert(axum::extract::OriginalUri("/api/paid".parse().unwrap()));
    parts.extensions.insert(RouteIdentity::new().verifier(path));
    let result = MppCharge::<OneCent>::from_request_parts(&mut parts, &challenger).await;
    let body = result
        .unwrap_err()
        .into_response()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&body[..], b"/api/paid");
}

#[tokio::test]
async fn verified_identity_reaches_the_handler() {
    let key = api_key();
    let identity = RouteIdentity::new().verifier(&key);
    let (result, _) = extract(
        Some(identity.clone()),
        "Authorization",
        &[("x-api-key", "good".into())],
    )
    .await;
    // Identified, unpaid: a 402.
    assert_eq!(
        result.unwrap_err().into_response().status(),
        StatusCode::PAYMENT_REQUIRED
    );

    let (result, verified) = extract(
        Some(identity),
        "Authorization",
        &[
            ("x-api-key", "good".into()),
            ("authorization", credential("Authorization", None)),
        ],
    )
    .await;
    let charge = result.unwrap();
    assert_eq!(
        charge.identity.get(&key).map(String::as_str),
        Some("customer-1")
    );
    assert_eq!(verified, 1);
}

#[tokio::test]
async fn every_402_lists_the_payment_check_requirements() {
    let identity = RouteIdentity::new().payment(source_check());
    let (result, _) = extract(Some(identity), "Authorization", &[]).await;
    let response = result.unwrap_err().into_response();
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(
        response.headers()["identity-required"],
        r#"kyc;issuer="https://kyc.example""#
    );
    assert!(response.headers().get(WWW_AUTHENTICATE_HEADER).is_some());

    // Without a route identity, no header.
    let (result, _) = extract(None, "Authorization", &[]).await;
    let response = result.unwrap_err().into_response();
    assert!(response.headers().get("identity-required").is_none());
}

#[tokio::test]
async fn payment_check_refuses_before_settlement_without_a_fresh_402() {
    let check = source_check();
    let identity = RouteIdentity::new().payment(&check);
    let (result, verified) = extract(
        Some(identity.clone()),
        "Authorization",
        &[(
            "authorization",
            credential("Authorization", Some("did:other")),
        )],
    )
    .await;
    let response = result.unwrap_err().into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response.headers().get(WWW_AUTHENTICATE_HEADER).is_none());
    assert_eq!(verified, 0, "a refused payer's credential must not settle");

    let (result, verified) = extract(
        Some(identity),
        "Authorization",
        &[(
            "authorization",
            credential("Authorization", Some("did:allowed")),
        )],
    )
    .await;
    let charge = result.unwrap();
    assert_eq!(
        charge.identity.payment(&check).map(String::as_str),
        Some("did:allowed")
    );
    assert_eq!(verified, 1);
}

#[tokio::test]
async fn authorization_verifiers_need_requires_auth() {
    struct Bearer;
    impl crate::identity::Verifier for Bearer {
        type Value = ();
        fn reads_authorization(&self) -> bool {
            true
        }
        fn verify<'a>(&'a self, _request: &'a IdentityRequest) -> BoxFuture<'a, Verification<()>> {
            Box::pin(std::future::ready(Verification::Valid(())))
        }
    }
    let identity = RouteIdentity::new().verifier(Handle::new(Bearer));
    let (result, _) = extract(Some(identity.clone()), "Authorization", &[]).await;
    assert!(matches!(
        result.unwrap_err(),
        MppChargeRejection::InternalError(_)
    ));

    // With Payment-Authorization, the bearer verifier passes and the route asks for payment.
    let (result, _) = extract(Some(identity), "Payment-Authorization", &[]).await;
    assert_eq!(
        result.unwrap_err().into_response().status(),
        StatusCode::PAYMENT_REQUIRED
    );
}
