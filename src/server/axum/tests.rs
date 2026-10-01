use super::*;
use crate::protocol::core::Base64UrlJson;

fn test_challenge() -> PaymentChallenge {
    PaymentChallenge::new(
        "test-id",
        "test-realm",
        "tempo",
        "charge",
        Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
    )
}

struct MockChallenger {
    accept: bool,
}

impl ChargeChallenger for MockChallenger {
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
        let accept = self.accept;
        Box::pin(async move {
            if accept {
                Ok(Receipt {
                    status: crate::protocol::core::ReceiptStatus::Success,
                    method: crate::protocol::core::MethodName::new("tempo"),
                    timestamp: "2025-01-01T00:00:00Z".into(),
                    reference: "0xabc".into(),
                    external_id: None,
                    subscription_id: None,
                    extensions: serde_json::Map::new(),
                })
            } else {
                Err("payment rejected".into())
            }
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
}

struct BodyAwareChallenger {
    seen_challenge_body: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    seen_verify_body: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
}

impl ChargeChallenger for BodyAwareChallenger {
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

    fn challenge_with_body(
        &self,
        amount: &str,
        options: ChallengeOptions,
        body: &[u8],
    ) -> Result<PaymentChallenge, String> {
        *self.seen_challenge_body.lock().unwrap() = Some(body.to_vec());
        let mut challenge = self.challenge(amount, options)?;
        challenge.digest = Some(crate::body_digest::compute(body));
        Ok(challenge)
    }

    fn verify_payment(
        &self,
        _credential_str: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        Box::pin(std::future::ready(Err(
            "legacy verifier should not be called".into(),
        )))
    }

    fn verify_payment_for_amount_with_body(
        &self,
        _credential_str: &str,
        _amount: &str,
        body: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        *self.seen_verify_body.lock().unwrap() = Some(body.to_vec());
        Box::pin(std::future::ready(Ok(Receipt {
            status: crate::protocol::core::ReceiptStatus::Success,
            method: crate::protocol::core::MethodName::new("tempo"),
            timestamp: "2025-01-01T00:00:00Z".into(),
            reference: "0xbody-aware".into(),
            external_id: None,
            subscription_id: None,
            extensions: serde_json::Map::new(),
        })))
    }

    fn verify_payment_for_amount_scope_and_body(
        &self,
        credential_str: &str,
        amount: &str,
        _mppx_scope: Option<serde_json::Value>,
        body: &[u8],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>> {
        self.verify_payment_for_amount_with_body(credential_str, amount, body)
    }
}

#[derive(Debug)]
struct OneCent;
impl ChargeConfig for OneCent {
    fn amount() -> &'static str {
        "0.01"
    }
}

#[test]
fn test_payment_required_into_response() {
    let resp = PaymentRequired(test_challenge()).into_response();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
}

#[test]
fn test_unformattable_challenge_returns_500_without_challenge() {
    let mut challenge = test_challenge();
    challenge.realm = "a\nb".to_string();
    let resp = PaymentRequired(challenge).into_response();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
}

#[test]
fn test_payment_required_has_json_content_type() {
    let resp = PaymentRequired(test_challenge()).into_response();
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/json"
    );
}

#[test]
fn test_rejection_challenge_returns_402_with_header() {
    let rejection = MppChargeRejection::Challenge(PaymentRequired(test_challenge()));
    let resp = rejection.into_response();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
}

#[test]
fn test_rejection_verification_failed_returns_402_with_header() {
    let rejection = MppChargeRejection::VerificationFailed(PaymentRequired(test_challenge()));
    let resp = rejection.into_response();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
}

#[test]
fn test_rejection_internal_error() {
    let rejection = MppChargeRejection::InternalError("oops".into());
    let resp = rejection.into_response();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
}

#[test]
fn test_custom_amount() {
    struct FiveDollars;
    impl ChargeConfig for FiveDollars {
        fn amount() -> &'static str {
            "5.00"
        }
    }
    assert_eq!(FiveDollars::amount(), "5.00");
}

#[test]
fn test_config_defaults() {
    assert_eq!(OneCent::description(), None);
}

#[test]
fn test_config_overrides() {
    struct Premium;
    impl ChargeConfig for Premium {
        fn amount() -> &'static str {
            "10.00"
        }
        fn description() -> Option<&'static str> {
            Some("Premium access")
        }
    }
    assert_eq!(Premium::amount(), "10.00");
    assert_eq!(Premium::description(), Some("Premium access"));
}

#[test]
fn test_with_receipt_attaches_header() {
    use crate::protocol::core::{MethodName, ReceiptStatus};

    let receipt = Receipt {
        status: ReceiptStatus::Success,
        method: MethodName::new("tempo"),
        timestamp: "2025-01-01T00:00:00Z".into(),
        reference: "0xabc".into(),
        external_id: None,
        subscription_id: None,
        extensions: serde_json::Map::new(),
    };

    let resp = WithReceipt {
        receipt,
        body: "ok",
    }
    .into_response();

    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().contains_key(PAYMENT_RECEIPT_HEADER));
    // Per spec, receipt responses must be Cache-Control: private.
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "private"
    );
}

#[test]
fn test_with_receipt_does_not_attach_header_to_error_response() {
    use crate::protocol::core::{MethodName, ReceiptStatus};

    for status in [
        StatusCode::FOUND,
        StatusCode::FORBIDDEN,
        StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        let receipt = Receipt {
            status: ReceiptStatus::Success,
            method: MethodName::new("tempo"),
            timestamp: "2025-01-01T00:00:00Z".into(),
            reference: "0xabc".into(),
            external_id: None,
            subscription_id: None,
            extensions: serde_json::Map::new(),
        };
        let resp = WithReceipt {
            receipt,
            body: (status, "error"),
        }
        .into_response();

        assert_eq!(resp.status(), status);
        assert!(!resp.headers().contains_key(PAYMENT_RECEIPT_HEADER));
        assert!(!resp.headers().contains_key(header::CACHE_CONTROL));
    }
}

#[test]
fn test_with_receipt_preserves_existing_cache_control() {
    use crate::protocol::core::{MethodName, ReceiptStatus};

    let receipt = Receipt {
        status: ReceiptStatus::Success,
        method: MethodName::new("tempo"),
        timestamp: "2025-01-01T00:00:00Z".into(),
        reference: "0xabc".into(),
        external_id: None,
        subscription_id: None,
        extensions: serde_json::Map::new(),
    };
    let mut body = "ok".into_response();
    body.headers_mut()
        .append(header::CACHE_CONTROL, HeaderValue::from_static("public"));
    body.headers_mut().append(
        header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=60"),
    );

    let resp = WithReceipt { receipt, body }.into_response();

    assert!(resp.headers().contains_key(PAYMENT_RECEIPT_HEADER));
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "public, max-age=60, private"
    );
}

#[test]
fn test_mock_challenger_generates_challenge() {
    let challenger = MockChallenger { accept: true };
    let challenge = challenger
        .challenge("0.50", ChallengeOptions::default())
        .unwrap();
    assert_eq!(challenge.id, "mock-id");
}

#[tokio::test]
async fn test_mock_challenger_verify_accept() {
    let challenger = MockChallenger { accept: true };
    let result = challenger.verify_payment("Payment eyJ...").await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap().reference, "0xabc");
}

#[tokio::test]
async fn test_mock_challenger_verify_reject() {
    let challenger = MockChallenger { accept: false };
    let result = challenger.verify_payment("Payment eyJ...").await;
    assert!(result.is_err());
}

async fn run_extractor<C: ChargeConfig>(
    challenger: impl ChargeChallenger,
    auth_header: Option<&str>,
) -> Result<MppCharge<C>, MppChargeRejection> {
    run_extractor_with_uri::<C>(challenger, auth_header, "/test").await
}

async fn run_extractor_with_uri<C: ChargeConfig>(
    challenger: impl ChargeChallenger,
    auth_header: Option<&str>,
    uri: &str,
) -> Result<MppCharge<C>, MppChargeRejection> {
    let state: Arc<dyn ChargeChallenger> = Arc::new(challenger);
    let mut builder = http_types::Request::builder().uri(uri);
    if let Some(auth) = auth_header {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    let req = builder.body(()).unwrap();
    let (mut parts, _body) = req.into_parts();
    MppCharge::<C>::from_request_parts(&mut parts, &state).await
}

#[tokio::test]
async fn test_extractor_binds_axum_matched_route_scope() {
    use axum::routing::get;
    use tower::ServiceExt;

    #[derive(Clone)]
    struct ScopeCaptureChallenger {
        seen_scope: Arc<std::sync::Mutex<Option<serde_json::Value>>>,
    }

    impl ChargeChallenger for ScopeCaptureChallenger {
        fn challenge(
            &self,
            amount: &str,
            options: ChallengeOptions,
        ) -> Result<PaymentChallenge, String> {
            *self.seen_scope.lock().unwrap() = options.mppx_scope;
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
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            Box::pin(std::future::ready(Err("unused".into())))
        }
    }

    async fn paid(_charge: MppCharge<OneCent>) -> &'static str {
        "paid"
    }

    let seen_scope = Arc::new(std::sync::Mutex::new(None));
    let state: Arc<dyn ChargeChallenger> = Arc::new(ScopeCaptureChallenger {
        seen_scope: seen_scope.clone(),
    });
    let app = axum::Router::new()
        .route("/paid/{id}", get(paid))
        .with_state(state);

    let response = app
        .oneshot(
            http_types::Request::builder()
                .uri("/paid/one?view=full")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(
        seen_scope.lock().unwrap().as_ref(),
        Some(&serde_json::json!({
            "route": "/paid/{id}",
            "resource": "/paid/one",
            "query": "view=full",
        }))
    );
}

async fn run_body_extractor<C: ChargeConfig>(
    challenger: impl ChargeChallenger,
    auth_header: Option<&str>,
    body: &'static str,
) -> Result<MppChargeWithBody<C>, MppChargeRejection> {
    let state: Arc<dyn ChargeChallenger> = Arc::new(challenger);
    let mut builder = Request::builder().uri("/test");
    if let Some(auth) = auth_header {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    let req = builder.body(axum_core::body::Body::from(body)).unwrap();
    MppChargeWithBody::<C>::from_request(req, &state).await
}

#[tokio::test]
async fn test_extractor_no_auth_returns_challenge() {
    let result = run_extractor::<OneCent>(MockChallenger { accept: true }, None).await;
    let err = result.unwrap_err();
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
}

#[tokio::test]
async fn test_extractor_valid_payment_returns_receipt() {
    let result = run_extractor::<OneCent>(
        MockChallenger { accept: true },
        Some("Payment eyJmYWtlIjp0cnVlfQ"),
    )
    .await;
    let charge = result.unwrap();
    assert_eq!(charge.receipt.reference, "0xabc");
}

#[tokio::test]
async fn test_extractor_fails_closed_when_challenger_does_not_verify_scope() {
    struct LegacyChallenger;

    impl ChargeChallenger for LegacyChallenger {
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
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            Box::pin(std::future::ready(Ok(Receipt {
                status: crate::protocol::core::ReceiptStatus::Success,
                method: crate::protocol::core::MethodName::new("tempo"),
                timestamp: "2025-01-01T00:00:00Z".into(),
                reference: "0xlegacy".into(),
                external_id: None,
                subscription_id: None,
                extensions: serde_json::Map::new(),
            })))
        }
    }

    let result =
        run_extractor::<OneCent>(LegacyChallenger, Some("Payment eyJmYWtlIjp0cnVlfQ")).await;

    let err = result.unwrap_err();
    assert!(matches!(err, MppChargeRejection::Problem(_)));
}

#[tokio::test]
async fn test_extractor_invalid_payment_returns_challenge_for_retry() {
    let result = run_extractor::<OneCent>(
        MockChallenger { accept: false },
        Some("Payment eyJmYWtlIjp0cnVlfQ"),
    )
    .await;
    let err = result.unwrap_err();
    assert!(matches!(err, MppChargeRejection::Problem(_)));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    assert!(resp.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    assert_eq!(
        resp.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/problem+json"
    );
}

#[tokio::test]
async fn test_extractor_wrong_scheme_returns_challenge() {
    let result =
        run_extractor::<OneCent>(MockChallenger { accept: true }, Some("Bearer some-token")).await;
    let err = result.unwrap_err();
    assert!(matches!(err, MppChargeRejection::Challenge(_)));
}

#[tokio::test]
async fn test_extractor_custom_amount() {
    #[derive(Debug)]
    struct TenCents;
    impl ChargeConfig for TenCents {
        fn amount() -> &'static str {
            "0.10"
        }
    }

    let result = run_extractor::<TenCents>(MockChallenger { accept: true }, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_extractor_challenge_failure_returns_internal_error() {
    struct FailingChallenger;
    impl ChargeChallenger for FailingChallenger {
        fn challenge(
            &self,
            _amount: &str,
            _options: ChallengeOptions,
        ) -> Result<PaymentChallenge, String> {
            Err("config error".into())
        }
        fn verify_payment(
            &self,
            _credential_str: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            Box::pin(std::future::ready(Err("unused".into())))
        }
    }

    let state: Arc<dyn ChargeChallenger> = Arc::new(FailingChallenger);
    let req = http_types::Request::builder()
        .uri("/test")
        .body(())
        .unwrap();
    let (mut parts, _body) = req.into_parts();
    let result = MppCharge::<OneCent>::from_request_parts(&mut parts, &state).await;
    let err = result.unwrap_err();
    assert!(matches!(err, MppChargeRejection::InternalError(_)));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_extractor_malformed_payment_credential_returns_verification_failed() {
    let result = run_extractor::<OneCent>(
        MockChallenger { accept: false },
        Some("Payment !!not-base64!!"),
    )
    .await;
    let err = result.unwrap_err();
    assert!(matches!(err, MppChargeRejection::Problem(_)));
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
}

#[tokio::test]
async fn test_body_extractor_challenge_binds_request_body() {
    let seen_challenge_body = Arc::new(std::sync::Mutex::new(None));
    let seen_verify_body = Arc::new(std::sync::Mutex::new(None));
    let result = run_body_extractor::<OneCent>(
        BodyAwareChallenger {
            seen_challenge_body: seen_challenge_body.clone(),
            seen_verify_body,
        },
        None,
        r#"{"query":"paid"}"#,
    )
    .await;

    let err = result.unwrap_err();
    let challenge = match err {
        MppChargeRejection::Challenge(PaymentRequired(challenge)) => challenge,
        other => panic!("expected challenge rejection, got {other:?}"),
    };
    assert_eq!(
        challenge.digest.as_deref(),
        Some(crate::body_digest::compute(br#"{"query":"paid"}"#).as_str())
    );
    assert_eq!(
        seen_challenge_body.lock().unwrap().as_deref(),
        Some(br#"{"query":"paid"}"#.as_slice())
    );
}

#[tokio::test]
async fn test_body_extractor_verifies_and_preserves_request_body() {
    let seen_challenge_body = Arc::new(std::sync::Mutex::new(None));
    let seen_verify_body = Arc::new(std::sync::Mutex::new(None));
    let result = run_body_extractor::<OneCent>(
        BodyAwareChallenger {
            seen_challenge_body,
            seen_verify_body: seen_verify_body.clone(),
        },
        Some("Payment eyJmYWtlIjp0cnVlfQ"),
        r#"{"query":"paid"}"#,
    )
    .await;

    let charge = result.unwrap();
    assert_eq!(charge.receipt.reference, "0xbody-aware");
    assert_eq!(charge.body.as_ref(), br#"{"query":"paid"}"#);
    assert_eq!(
        seen_verify_body.lock().unwrap().as_deref(),
        Some(br#"{"query":"paid"}"#.as_slice())
    );
}

async fn post_to_body_extractor(body: axum_core::body::Body) -> StatusCode {
    use axum::routing::post;
    use tower::ServiceExt;

    async fn paid(_charge: MppChargeWithBody<OneCent>) {}

    let state: Arc<dyn ChargeChallenger> = Arc::new(MockChallenger { accept: true });
    let app = axum::Router::new()
        .route("/paid", post(paid))
        .layer(axum_core::extract::DefaultBodyLimit::max(1024))
        .with_state(state);

    let req = Request::builder()
        .method("POST")
        .uri("/paid")
        .body(body)
        .unwrap();
    app.oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn test_body_extractor_respects_default_body_limit() {
    use futures_util::StreamExt;

    let chunks = futures_util::stream::iter(0..).map(|i| {
        assert!(i < 4, "body read past the limit");
        Ok::<_, std::convert::Infallible>(Bytes::from_static(&[0; 512]))
    });
    let status = post_to_body_extractor(axum_core::body::Body::from_stream(chunks)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_body_extractor_body_read_error_returns_400() {
    let chunks = futures_util::stream::iter([Err::<Bytes, _>(std::io::Error::other("reset"))]);
    let status = post_to_body_extractor(axum_core::body::Body::from_stream(chunks)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_extractor_uses_route_aware_verification_path() {
    struct RouteAwareChallenger {
        seen_amount: Arc<std::sync::Mutex<Option<String>>>,
    }

    impl ChargeChallenger for RouteAwareChallenger {
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
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            Box::pin(std::future::ready(Err(
                "legacy verifier should not be called".into(),
            )))
        }

        fn verify_payment_for_amount(
            &self,
            _credential_str: &str,
            amount: &str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            *self.seen_amount.lock().unwrap() = Some(amount.to_string());
            Box::pin(std::future::ready(Ok(Receipt {
                status: crate::protocol::core::ReceiptStatus::Success,
                method: crate::protocol::core::MethodName::new("tempo"),
                timestamp: "2025-01-01T00:00:00Z".into(),
                reference: "0xroute-aware".into(),
                external_id: None,
                subscription_id: None,
                extensions: serde_json::Map::new(),
            })))
        }

        fn verify_payment_for_amount_and_scope(
            &self,
            credential_str: &str,
            amount: &str,
            _mppx_scope: Option<serde_json::Value>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Receipt, String>> + Send>>
        {
            self.verify_payment_for_amount(credential_str, amount)
        }
    }

    let seen_amount = Arc::new(std::sync::Mutex::new(None));
    let result = run_extractor::<OneCent>(
        RouteAwareChallenger {
            seen_amount: seen_amount.clone(),
        },
        Some("Payment eyJmYWtlIjp0cnVlfQ"),
    )
    .await;

    let charge = result.unwrap();
    assert_eq!(charge.receipt.reference, "0xroute-aware");
    assert_eq!(seen_amount.lock().unwrap().as_deref(), Some("0.01"));
}

// Framework route-replay conformance: exercise the real extractor
// (`MppCharge<C>`) and per-route amount selection against the production
// binding logic, matching the two-price axum-extractor example.
#[cfg(feature = "tempo")]
mod route_replay {
    use super::*;
    use crate::protocol::core::headers::format_authorization;
    use crate::protocol::core::{PaymentCredential, PaymentPayload};
    use crate::protocol::intents::ChargeRequest;
    use crate::protocol::traits::VerificationError;
    use crate::server::{ChargeMethod, Mpp};
    use std::future::Future;

    #[derive(Debug)]
    struct OneDollar;
    impl ChargeConfig for OneDollar {
        fn amount() -> &'static str {
            "1.00"
        }
    }

    // Chain-free charge method so verification never needs RPC.
    #[derive(Clone)]
    struct SuccessMethod;

    #[allow(clippy::manual_async_fn)]
    impl ChargeMethod for SuccessMethod {
        fn method(&self) -> &str {
            "tempo"
        }
        fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &ChargeRequest,
        ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
            async { Ok(Receipt::success("tempo", "0xtxhash")) }
        }
    }

    // Faithful challenger delegating to the production binding logic.
    #[derive(Clone)]
    struct RealBindingChallenger {
        mpp: Mpp<SuccessMethod>,
    }

    impl RealBindingChallenger {
        fn new() -> Self {
            Self {
                mpp: Mpp::new_with_config(
                    SuccessMethod,
                    "MPP Payment",
                    "test-secret-key-at-least-32-bytes",
                    "0x20c0000000000000000000000000000000000000",
                    "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                ),
            }
        }
    }

    impl ChargeChallenger for RealBindingChallenger {
        fn challenge(
            &self,
            amount: &str,
            options: ChallengeOptions,
        ) -> Result<PaymentChallenge, String> {
            self.mpp
                .charge_with_options(
                    amount,
                    crate::server::ChargeOptions {
                        description: options.description,
                        mppx_scope: options.mppx_scope.as_ref(),
                        ..Default::default()
                    },
                )
                .map(|mut offers| offers.remove(0))
                .map_err(|e| e.to_string())
        }

        fn verify_payment(
            &self,
            credential_str: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>> {
            let credential = match parse_authorization(credential_str) {
                Ok(c) => c,
                Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
            };
            let mpp = self.mpp.clone();
            Box::pin(async move {
                mpp.broadcast_credential(&credential)
                    .await
                    .map_err(|e| e.to_string())
            })
        }

        fn verify_payment_for_amount(
            &self,
            credential_str: &str,
            amount: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>> {
            let credential = match parse_authorization(credential_str) {
                Ok(c) => c,
                Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
            };
            let expected = match self
                .mpp
                .charge(amount)
                .map(|mut offers| offers.remove(0))
                .and_then(|c| c.request.decode())
            {
                Ok(req) => req,
                Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
            };
            let mpp = self.mpp.clone();
            Box::pin(async move {
                mpp.verify_credential_with_expected_request(&credential, &expected)
                    .await
                    .map_err(|e| e.to_string())
            })
        }

        fn verify_payment_for_amount_and_scope(
            &self,
            credential_str: &str,
            amount: &str,
            mppx_scope: Option<serde_json::Value>,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>> {
            let credential = match parse_authorization(credential_str) {
                Ok(c) => c,
                Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
            };
            let expected = match self
                .mpp
                .charge_with_options(
                    amount,
                    crate::server::ChargeOptions {
                        mppx_scope: mppx_scope.as_ref(),
                        ..Default::default()
                    },
                )
                .map(|mut offers| offers.remove(0))
                .and_then(|c| c.request.decode())
            {
                Ok(req) => req,
                Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
            };
            let mpp = self.mpp.clone();
            Box::pin(async move {
                mpp.verify_credential_with_expected_request(&credential, &expected)
                    .await
                    .map_err(|e| e.to_string())
            })
        }
    }

    // Mint an `Authorization: Payment …` string for the given route amount.
    fn scope_for_uri(uri: &str) -> serde_json::Value {
        let req = http_types::Request::builder().uri(uri).body(()).unwrap();
        let (parts, _body) = req.into_parts();
        mppx_scope_from_parts(&parts).unwrap()
    }

    fn mint_credential(challenger: &RealBindingChallenger, amount: &str) -> String {
        mint_scoped_credential(challenger, amount, "/test")
    }

    fn mint_scoped_credential(
        challenger: &RealBindingChallenger,
        amount: &str,
        uri: &str,
    ) -> String {
        let challenge = challenger
            .challenge(
                amount,
                ChallengeOptions {
                    mppx_scope: Some(scope_for_uri(uri)),
                    ..Default::default()
                },
            )
            .unwrap();
        let credential =
            PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
        format_authorization(&credential).unwrap()
    }

    #[tokio::test]
    async fn test_extractor_accepts_credential_on_matching_route() {
        let challenger = RealBindingChallenger::new();
        let auth = mint_credential(&challenger, OneCent::amount());

        let charge = run_extractor::<OneCent>(challenger, Some(&auth))
            .await
            .expect("credential minted for the route must verify");
        assert_eq!(charge.receipt.reference, "0xtxhash");
    }

    #[tokio::test]
    async fn test_extractor_rejects_cross_route_credential_replay() {
        let challenger = RealBindingChallenger::new();
        // Mint for the cheap route, replay on the expensive route.
        let auth = mint_credential(&challenger, OneCent::amount());

        let err = run_extractor::<OneDollar>(challenger, Some(&auth))
            .await
            .expect_err("cross-route replay must be rejected");
        assert!(matches!(err, MppChargeRejection::Problem(_)));
        assert_eq!(err.into_response().status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn test_extractor_selects_per_route_amount() {
        let challenger = RealBindingChallenger::new();
        // A credential minted at $1.00 is accepted by the premium route...
        let auth = mint_credential(&challenger, OneDollar::amount());
        assert!(run_extractor::<OneDollar>(challenger.clone(), Some(&auth))
            .await
            .is_ok());
        // ...but rejected by the cheap route, proving the extractor passes
        // each route's own `ChargeConfig::amount()` to verification.
        let err = run_extractor::<OneCent>(challenger, Some(&auth))
            .await
            .expect_err("premium credential must not satisfy the cheap route");
        assert!(matches!(err, MppChargeRejection::Problem(_)));
    }

    #[tokio::test]
    async fn test_extractor_rejects_cross_resource_credential_replay() {
        let challenger = RealBindingChallenger::new();
        let auth = mint_scoped_credential(&challenger, OneCent::amount(), "/paid/one?view=full");

        let err = run_extractor_with_uri::<OneCent>(challenger, Some(&auth), "/paid/two?view=full")
            .await
            .expect_err("same-price cross-resource replay must be rejected");
        assert!(matches!(err, MppChargeRejection::Problem(_)));
        assert_eq!(err.into_response().status(), StatusCode::PAYMENT_REQUIRED);
    }
}

#[cfg(feature = "tempo")]
mod currency_offers {
    use super::*;
    use crate::protocol::core::headers::{format_authorization, parse_www_authenticate_all};
    use crate::protocol::core::{PaymentCredential, PaymentPayload};
    use crate::protocol::intents::ChargeRequest;
    use crate::protocol::methods::tempo::{CHAIN_ID, OUSD, PATH_USD, USDC};
    use crate::protocol::traits::VerificationError;
    use crate::server::{tempo, ChargeMethod, Mpp, TempoConfig};
    use std::future::Future;

    const RECIPIENT: &str = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2";

    #[derive(Clone)]
    struct SuccessMethod;

    #[allow(clippy::manual_async_fn)]
    impl ChargeMethod for SuccessMethod {
        fn method(&self) -> &str {
            "tempo"
        }
        fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &ChargeRequest,
        ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
            async { Ok(Receipt::success("tempo", "0xtxhash")) }
        }
    }

    /// RPC-free challenger mirroring the Tempo `ChargeChallenger` binding.
    #[derive(Clone)]
    struct OffersChallenger {
        mpp: Mpp<SuccessMethod>,
    }

    impl OffersChallenger {
        fn new(currencies: &[&str]) -> Self {
            Self {
                mpp: Mpp::new_with_config(
                    SuccessMethod,
                    "MPP Payment",
                    "test-secret-key-at-least-32-bytes",
                    "",
                    RECIPIENT,
                )
                .with_currencies(currencies.iter().map(|c| c.to_string()).collect()),
            }
        }

        fn options(options: &ChallengeOptions) -> crate::server::ChargeOptions<'_> {
            crate::server::ChargeOptions {
                description: options.description,
                mppx_scope: options.mppx_scope.as_ref(),
                ..Default::default()
            }
        }
    }

    impl ChargeChallenger for OffersChallenger {
        fn challenge(
            &self,
            amount: &str,
            options: ChallengeOptions,
        ) -> Result<PaymentChallenge, String> {
            self.mpp
                .charge_with_options(amount, Self::options(&options))
                .map(|mut offers| offers.remove(0))
                .map_err(|e| e.to_string())
        }

        fn verify_payment(
            &self,
            credential_str: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>> {
            self.verify_payment_for_amount_and_scope(credential_str, "0.01", None)
        }

        fn verify_payment_for_amount_and_scope(
            &self,
            credential_str: &str,
            amount: &str,
            mppx_scope: Option<serde_json::Value>,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>> {
            let credential = match parse_authorization(credential_str) {
                Ok(c) => c,
                Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
            };
            // Same as the Tempo binding: expected request from the preferred offer.
            let options = ChallengeOptions {
                mppx_scope,
                ..Default::default()
            };
            let expected = match self
                .mpp
                .charge_with_options(amount, Self::options(&options))
                .map(|mut offers| offers.remove(0))
                .and_then(|c| c.request.decode::<ChargeRequest>())
            {
                Ok(req) => req,
                Err(e) => return Box::pin(std::future::ready(Err(e.to_string()))),
            };
            let mpp = self.mpp.clone();
            Box::pin(async move {
                mpp.verify_credential_with_expected_request(&credential, &expected)
                    .await
                    .map_err(|e| e.to_string())
            })
        }

        fn challenges(
            &self,
            amount: &str,
            options: ChallengeOptions,
        ) -> Result<Vec<PaymentChallenge>, String> {
            self.mpp
                .charge_with_options(amount, Self::options(&options))
                .map_err(|e| e.to_string())
        }
    }

    fn currencies_of(challenges: &[PaymentChallenge]) -> Vec<String> {
        challenges
            .iter()
            .map(|c| c.request.decode::<ChargeRequest>().unwrap().currency)
            .collect()
    }

    fn response_offers(rejection: MppChargeRejection) -> Vec<PaymentChallenge> {
        let resp = rejection.into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let values: Vec<&str> = resp
            .headers()
            .get_all(WWW_AUTHENTICATE_HEADER)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        let challenges: Vec<PaymentChallenge> = parse_www_authenticate_all(values.clone())
            .into_iter()
            .map(|r| r.unwrap())
            .collect();
        // One header per offer.
        assert_eq!(values.len(), challenges.len());
        challenges
    }

    fn scoped_auth(challenger: &OffersChallenger, currency: &str) -> String {
        let req = http_types::Request::builder()
            .uri("/test")
            .body(())
            .unwrap();
        let (parts, _body) = req.into_parts();
        let challenges = challenger
            .challenges(
                OneCent::amount(),
                ChallengeOptions {
                    mppx_scope: mppx_scope_from_parts(&parts),
                    ..Default::default()
                },
            )
            .unwrap();
        let challenge = challenges
            .iter()
            .find(|c| c.request.decode::<ChargeRequest>().unwrap().currency == currency)
            .unwrap();
        let credential =
            PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
        format_authorization(&credential).unwrap()
    }

    #[tokio::test]
    async fn test_extractor_returns_every_offer_in_order() {
        let err = run_extractor::<OneCent>(OffersChallenger::new(&[OUSD, USDC]), None)
            .await
            .unwrap_err();
        assert!(matches!(err, MppChargeRejection::Offers(_)));
        let offers = response_offers(err);
        assert_eq!(currencies_of(&offers), [OUSD, USDC]);
        assert!(offers
            .iter()
            .all(|c| c.verify("test-secret-key-at-least-32-bytes")));
    }

    #[tokio::test]
    async fn test_extractor_single_offer_keeps_challenge_variant() {
        let err = run_extractor::<OneCent>(OffersChallenger::new(&[PATH_USD]), None)
            .await
            .unwrap_err();
        let MppChargeRejection::Challenge(PaymentRequired(challenge)) = err else {
            panic!("single offer should use the Challenge variant: {err:?}");
        };
        assert_eq!(currencies_of(&[challenge]), [PATH_USD]);
    }

    #[tokio::test]
    async fn test_extractor_accepts_credential_for_each_offer() {
        let challenger = OffersChallenger::new(&[OUSD, USDC]);
        for currency in [OUSD, USDC] {
            let auth = scoped_auth(&challenger, currency);
            let charge = run_extractor::<OneCent>(challenger.clone(), Some(&auth))
                .await
                .unwrap_or_else(|err| panic!("{currency} credential rejected: {err:?}"));
            assert_eq!(charge.receipt.reference, "0xtxhash");
        }
    }

    #[tokio::test]
    async fn test_extractor_rejects_non_offered_currency_with_all_offers() {
        // Credential minted by a server that offered pathUSD, replayed against
        // a server (same secret/realm) that only accepts OUSD and USDC.e.
        let auth = scoped_auth(&OffersChallenger::new(&[PATH_USD]), PATH_USD);
        let err = run_extractor::<OneCent>(OffersChallenger::new(&[OUSD, USDC]), Some(&auth))
            .await
            .unwrap_err();
        assert!(matches!(err, MppChargeRejection::Problem(_)));
        assert_eq!(currencies_of(&response_offers(err)), [OUSD, USDC]);
    }

    #[tokio::test]
    async fn test_tempo_challenger_reports_typed_problems() {
        let mpp = Mpp::create(
            tempo(TempoConfig {
                recipient: RECIPIENT,
            })
            .rpc_url("http://127.0.0.1:1")
            .chain_id(CHAIN_ID)
            .secret_key("test-secret-key-at-least-32-bytes"),
        )
        .unwrap();
        let unpaid = run_extractor::<OneCent>(mpp.clone(), None)
            .await
            .unwrap_err();
        let offer = response_offers(unpaid).remove(0);
        let authorization = |challenge: &PaymentChallenge| {
            let credential =
                PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
            format_authorization(&credential).unwrap()
        };
        let rejected = |rejection| match rejection {
            MppChargeRejection::Problem(rejected) => rejected,
            other => panic!("unexpected rejection: {other:?}"),
        };

        let mut forged = offer.clone();
        forged.id = "forged".to_string();
        let err = run_extractor::<OneCent>(mpp.clone(), Some(&authorization(&forged)))
            .await
            .unwrap_err();
        let problem = rejected(err);
        assert!(problem.problem.problem_type.ends_with("/invalid-challenge"));
        assert_eq!(currencies_of(&problem.offers), [OUSD, USDC]);

        // The chain ID lookup hits an unreachable RPC.
        let err = run_extractor::<OneCent>(mpp, Some(&authorization(&offer)))
            .await
            .unwrap_err();
        let problem = rejected(err);
        assert_eq!(problem.problem.status, 500);
        assert!(problem.offers.is_empty());
    }

    #[tokio::test]
    async fn test_tempo_challenger_offers_mainnet_defaults() {
        let mpp = Mpp::create(
            tempo(TempoConfig {
                recipient: RECIPIENT,
            })
            .chain_id(CHAIN_ID)
            .secret_key("test-secret-key-at-least-32-bytes"),
        )
        .unwrap();
        let challenger: Arc<dyn ChargeChallenger> = Arc::new(mpp);

        let offers = challenger
            .challenges("0.01", ChallengeOptions::default())
            .unwrap();
        assert_eq!(currencies_of(&offers), [OUSD, USDC]);
        let single = challenger
            .challenge("0.01", ChallengeOptions::default())
            .unwrap();
        assert_eq!(currencies_of(&[single]), [OUSD]);

        let body_offers = challenger
            .challenges_with_body("0.01", ChallengeOptions::default(), b"{}")
            .unwrap();
        assert_eq!(currencies_of(&body_offers), [OUSD, USDC]);
        let digest = crate::body_digest::compute(b"{}");
        assert!(body_offers
            .iter()
            .all(|c| c.digest.as_deref() == Some(digest.as_str())));

        let err = run_extractor::<OneCent>(ArcChallenger(challenger.clone()), None)
            .await
            .unwrap_err();
        assert_eq!(currencies_of(&response_offers(err)), [OUSD, USDC]);

        let err = run_body_extractor::<OneCent>(ArcChallenger(challenger), None, "{}")
            .await
            .unwrap_err();
        assert!(matches!(err, MppChargeRejection::Offers(_)));
        let offers = response_offers(err);
        assert_eq!(currencies_of(&offers), [OUSD, USDC]);
        assert!(offers
            .iter()
            .all(|c| c.digest.as_deref() == Some(digest.as_str())));
    }

    #[test]
    fn test_payment_offers_response_headers() {
        let challenger = OffersChallenger::new(&[OUSD, USDC]);
        let offers = challenger
            .challenges("0.01", ChallengeOptions::default())
            .unwrap();
        let resp = PaymentOffers(offers).into_response();
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            resp.headers()
                .get_all(WWW_AUTHENTICATE_HEADER)
                .iter()
                .count(),
            2
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    /// Forwards to a shared challenger so tests can reuse one `Arc`.
    struct ArcChallenger(Arc<dyn ChargeChallenger>);

    impl ChargeChallenger for ArcChallenger {
        fn challenge(
            &self,
            amount: &str,
            options: ChallengeOptions,
        ) -> Result<PaymentChallenge, String> {
            self.0.challenge(amount, options)
        }

        fn verify_payment(
            &self,
            credential_str: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Receipt, String>> + Send>> {
            self.0.verify_payment(credential_str)
        }

        fn challenges(
            &self,
            amount: &str,
            options: ChallengeOptions,
        ) -> Result<Vec<PaymentChallenge>, String> {
            self.0.challenges(amount, options)
        }

        fn challenges_with_body(
            &self,
            amount: &str,
            options: ChallengeOptions,
            body: &[u8],
        ) -> Result<Vec<PaymentChallenge>, String> {
            self.0.challenges_with_body(amount, options, body)
        }
    }
}
