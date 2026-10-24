use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use tower_layer::Layer;
use tower_service::Service;

#[derive(Clone, Copy)]
enum Failure {
    Expired,
    Malformed,
    Gone,
    Unsupported,
    Internal,
}

impl Failure {
    fn error(self) -> MppError {
        match self {
            Self::Expired => MppError::PaymentExpired(Some("expired credential".into())),
            Self::Malformed => MppError::MalformedCredential(Some("invalid encoding".into())),
            Self::Gone => MppError::ChannelNotFound(Some("unknown channel".into())),
            Self::Unsupported => MppError::UnsupportedPaymentMethod("test".into()),
            Self::Internal => MppError::Internal("private database connection string".into()),
        }
    }
}

#[derive(Clone, Copy, Default)]
enum ChallengeMode {
    #[default]
    Valid,
    Error,
    InvalidHeader,
    Partial,
}

#[derive(Clone, Default)]
struct Verifier {
    failure: Option<Failure>,
    mode: ChallengeMode,
    two_offers: bool,
    challenges: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
    verified: Arc<Mutex<Vec<Option<Vec<u8>>>>>,
}

impl Verifier {
    fn issue(&self, body: Option<&[u8]>) -> Result<String, String> {
        let mut challenges = self.challenges.lock().unwrap();
        let id = format!("fresh-{}", challenges.len());
        challenges.push(body.map(<[u8]>::to_vec));
        match self.mode {
            ChallengeMode::Error => Err("private challenge-generation failure".into()),
            ChallengeMode::InvalidHeader => Ok("Payment id=\"invalid\nheader\"".into()),
            ChallengeMode::Partial => Ok("Payment id=\"custom\"".into()),
            ChallengeMode::Valid => {
                let challenge = crate::protocol::core::PaymentChallenge::new(
                    id,
                    "test-realm",
                    "test",
                    "charge",
                    crate::protocol::core::Base64UrlJson::from_value(&serde_json::json!({
                        "amount": "1", "currency": "usd"
                    }))
                    .unwrap(),
                );
                let mut offers = vec![challenge.clone()];
                if self.two_offers {
                    let mut alternative = challenge;
                    alternative.id = "alternative".into();
                    alternative.method = "other".into();
                    offers.push(alternative);
                }
                crate::protocol::core::format_www_authenticate_many(&offers)
                    .map(|values| values.join(", "))
                    .map_err(|error| error.to_string())
            }
        }
    }
}

impl PaymentVerifier for Verifier {
    fn challenge(&self) -> Result<String, String> {
        self.issue(None)
    }

    fn challenge_with_body(&self, body: &[u8]) -> Result<String, String> {
        self.issue(Some(body))
    }

    fn verify(&self, _: &str) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
        Box::pin(async { Err("use the typed verification hook".into()) })
    }

    fn verify_credential(
        &self,
        _: &str,
        body: Option<&[u8]>,
    ) -> Pin<Box<dyn Future<Output = Result<String, MppError>> + Send>> {
        self.verified.lock().unwrap().push(body.map(<[u8]>::to_vec));
        let failure = self.failure;
        Box::pin(async move {
            match failure {
                Some(failure) => Err(failure.error()),
                None => Ok("mock-receipt".into()),
            }
        })
    }
}

#[derive(Clone)]
struct Application {
    status: StatusCode,
    calls: Arc<AtomicUsize>,
}

impl Application {
    fn new(status: StatusCode) -> Self {
        Self {
            status,
            calls: Arc::default(),
        }
    }
}

impl<B> Service<Request<B>> for Application {
    type Response = Response<Vec<u8>>;
    type Error = std::convert::Infallible;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Request<B>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(Response::builder()
            .status(self.status)
            .header(header::CONTENT_TYPE, "text/plain")
            .header(header::CACHE_CONTROL, "max-age=60")
            .body(b"application response".to_vec())
            .unwrap()))
    }
}

async fn respond(
    body_aware: bool,
    problem_details: bool,
    verifier: Verifier,
    authorization: bool,
    application: Application,
) -> Response<Vec<u8>> {
    let mut request = Request::builder().uri("/paid");
    if authorization {
        request = request.header(header::AUTHORIZATION, "Payment mock-credential");
    }
    let request = request
        .body(http_body_util::Full::new(Bytes::from_static(b"payload")))
        .unwrap();
    if body_aware {
        let layer = PaymentBodyLayer::new(verifier);
        if problem_details {
            layer
                .with_problem_details(|json: Bytes| json.to_vec())
                .layer(application)
                .call(request)
                .await
                .unwrap()
        } else {
            layer.layer(application).call(request).await.unwrap()
        }
    } else {
        let layer = PaymentLayer::new(verifier);
        if problem_details {
            layer
                .with_problem_details(|json: Bytes| json.to_vec())
                .layer(application)
                .call(request)
                .await
                .unwrap()
        } else {
            layer.layer(application).call(request).await.unwrap()
        }
    }
}

fn problem(response: &Response<Vec<u8>>) -> PaymentErrorDetails {
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/problem+json"
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(!response.headers().contains_key(PAYMENT_RECEIPT_HEADER));
    let problem: PaymentErrorDetails = serde_json::from_slice(response.body()).unwrap();
    assert_eq!(problem.status, response.status().as_u16());
    problem
}

#[tokio::test]
async fn typed_rejections_preserve_status_challenge_and_body_binding() {
    for body_aware in [false, true] {
        for failure in [
            Failure::Expired,
            Failure::Malformed,
            Failure::Gone,
            Failure::Unsupported,
            Failure::Internal,
        ] {
            let verifier = Verifier {
                failure: Some(failure),
                ..Verifier::default()
            };
            let application = Application::new(StatusCode::OK);
            let response = respond(
                body_aware,
                true,
                verifier.clone(),
                true,
                application.clone(),
            )
            .await;
            let actual = problem(&response);
            let expected = failure.error().to_problem_details(None);
            assert_eq!(actual.problem_type, expected.problem_type);
            assert_eq!(actual.title, expected.title);
            assert_eq!(actual.detail, expected.detail);
            assert_eq!(actual.hint, expected.hint);
            assert_eq!(application.calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                *verifier.verified.lock().unwrap(),
                [body_aware.then(|| b"payload".to_vec())]
            );
            if matches!(failure, Failure::Internal) {
                assert!(!response.headers().contains_key(WWW_AUTHENTICATE_HEADER));
                assert!(verifier.challenges.lock().unwrap().is_empty());
                assert!(!actual.detail.contains("private database"));
                assert!(actual.challenge_id.is_none());
            } else {
                let challenges = crate::protocol::core::parse_www_authenticate_all([response
                    .headers()[WWW_AUTHENTICATE_HEADER]
                    .to_str()
                    .unwrap()]);
                assert_eq!(challenges[0].as_ref().unwrap().id, "fresh-0");
                assert_eq!(actual.challenge_id.as_deref(), Some("fresh-0"));
                assert_eq!(
                    *verifier.challenges.lock().unwrap(),
                    [body_aware.then(|| b"payload".to_vec())]
                );
            }
        }
    }
}

#[tokio::test]
async fn missing_credentials_return_payment_required_problem() {
    for body_aware in [false, true] {
        let verifier = Verifier::default();
        let response = respond(
            body_aware,
            true,
            verifier.clone(),
            false,
            Application::new(StatusCode::OK),
        )
        .await;
        let actual = problem(&response);
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(actual.problem_type.ends_with("/payment-required"));
        assert!(actual.hint.is_some());
        assert_eq!(actual.challenge_id.as_deref(), Some("fresh-0"));
        assert!(verifier.verified.lock().unwrap().is_empty());
    }
}

/// Implements only the untyped `verify` hooks, like `PaymentLayer::from_fns`.
#[derive(Clone, Default)]
struct UntypedVerifier(Verifier);

impl PaymentVerifier for UntypedVerifier {
    fn challenge(&self) -> Result<String, String> {
        self.0.challenge()
    }

    fn challenge_with_body(&self, body: &[u8]) -> Result<String, String> {
        self.0.challenge_with_body(body)
    }

    fn verify(&self, _: &str) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send>> {
        Box::pin(async { Err("private database connection string".into()) })
    }
}

#[tokio::test]
async fn untyped_verifier_errors_are_not_exposed() {
    for body_aware in [false, true] {
        let request = Request::builder()
            .uri("/paid")
            .header(header::AUTHORIZATION, "Payment mock-credential")
            .body(http_body_util::Full::new(Bytes::from_static(b"payload")))
            .unwrap();
        let body = |json: Bytes| json.to_vec();
        let application = Application::new(StatusCode::OK);
        let response = if body_aware {
            PaymentBodyLayer::new(UntypedVerifier::default())
                .with_problem_details(body)
                .layer(application.clone())
                .call(request)
                .await
                .unwrap()
        } else {
            PaymentLayer::new(UntypedVerifier::default())
                .with_problem_details(body)
                .layer(application.clone())
                .call(request)
                .await
                .unwrap()
        };
        let actual = problem(&response);
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert!(response.headers().contains_key(WWW_AUTHENTICATE_HEADER));
        assert!(actual.problem_type.ends_with("/verification-failed"));
        assert_eq!(actual.detail, "Payment verification failed.");
        assert_eq!(application.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn challenge_failures_return_generic_500_without_challenge() {
    for body_aware in [false, true] {
        for authorization in [false, true] {
            for mode in [ChallengeMode::Error, ChallengeMode::InvalidHeader] {
                let verifier = Verifier {
                    failure: Some(Failure::Expired),
                    mode,
                    ..Verifier::default()
                };
                let response = respond(
                    body_aware,
                    true,
                    verifier,
                    authorization,
                    Application::new(StatusCode::OK),
                )
                .await;
                let actual = problem(&response);
                assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
                assert!(actual.problem_type.ends_with("/internal-payment-error"));
                assert!(!actual.detail.contains("private"));
                assert!(!response.headers().contains_key(WWW_AUTHENTICATE_HEADER));
                assert!(actual.challenge_id.is_none());
            }
        }
    }
}

#[tokio::test]
async fn default_layers_keep_empty_bodies_and_existing_types() {
    let _: PaymentLayer<Verifier> = PaymentLayer::new(Verifier::default());
    let _: PaymentBodyLayer<Verifier> = PaymentBodyLayer::new(Verifier::default());
    for body_aware in [false, true] {
        for failure in [Failure::Expired, Failure::Internal] {
            for authorization in [false, true] {
                let response = respond(
                    body_aware,
                    false,
                    Verifier {
                        failure: Some(failure),
                        ..Verifier::default()
                    },
                    authorization,
                    Application::new(StatusCode::OK),
                )
                .await;
                assert!(response.body().is_empty());
                assert!(!response.headers().contains_key(header::CONTENT_TYPE));
                assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            }
        }
    }
}

#[tokio::test]
async fn application_responses_are_preserved_including_errors() {
    for body_aware in [false, true] {
        for status in [
            StatusCode::OK,
            StatusCode::FORBIDDEN,
            StatusCode::INTERNAL_SERVER_ERROR,
        ] {
            let application = Application::new(status);
            let response = respond(
                body_aware,
                true,
                Verifier::default(),
                true,
                application.clone(),
            )
            .await;
            assert_eq!(response.status(), status);
            assert_eq!(response.body(), b"application response");
            assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
            assert_eq!(application.calls.load(Ordering::SeqCst), 1);
            if status.is_success() {
                assert_eq!(response.headers()[PAYMENT_RECEIPT_HEADER], "mock-receipt");
                assert_eq!(
                    response.headers()[header::CACHE_CONTROL],
                    "max-age=60, private"
                );
            } else {
                assert!(!response.headers().contains_key(PAYMENT_RECEIPT_HEADER));
                assert_eq!(response.headers()[header::CACHE_CONTROL], "max-age=60");
            }
        }
    }
}

#[tokio::test]
async fn request_body_failures_are_reported_without_verification() {
    let verifier = Verifier::default();
    let mut service = PaymentBodyLayer::new(verifier.clone())
        .max_body_bytes(2)
        .with_problem_details(|json: Bytes| json.to_vec())
        .layer(Application::new(StatusCode::OK));
    let response = service
        .call(Request::new(http_body_util::Full::new(Bytes::from_static(
            b"too large",
        ))))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(problem(&response).title, "Payload Too Large");
    assert!(!response.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    let body =
        http_body_util::StreamBody::new(futures_util::stream::iter([Err::<
            http_body::Frame<Bytes>,
            _,
        >("body read failed")]));
    let response = service.call(Request::new(body)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(problem(&response).title, "Bad Request");
    assert!(!response.headers().contains_key(WWW_AUTHENTICATE_HEADER));
    assert!(verifier.challenges.lock().unwrap().is_empty());
    assert!(verifier.verified.lock().unwrap().is_empty());
}

#[tokio::test]
async fn request_body_read_errors_do_not_expose_backend_diagnostics() {
    const PRIVATE_DETAIL: &str =
        "decoder failed at /srv/private/body-store.dat; backend_token=not-a-real-token";

    for problem_details in [false, true] {
        for authorization in [false, true] {
            let verifier = Verifier::default();
            let application = Application::new(StatusCode::OK);
            let body = http_body_util::StreamBody::new(futures_util::stream::iter([Err::<
                http_body::Frame<Bytes>,
                _,
            >(
                std::io::Error::other(PRIVATE_DETAIL),
            )]));
            let mut request = Request::builder();
            if authorization {
                request = request.header(header::AUTHORIZATION, "Payment mock-credential");
            }
            let request = request.body(body).unwrap();
            let layer = PaymentBodyLayer::new(verifier.clone());
            let response = if problem_details {
                layer
                    .with_problem_details(|json: Bytes| json.to_vec())
                    .layer(application.clone())
                    .call(request)
                    .await
                    .unwrap()
            } else {
                layer
                    .layer(application.clone())
                    .call(request)
                    .await
                    .unwrap()
            };

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(!response.headers().contains_key(WWW_AUTHENTICATE_HEADER));
            assert!(!response.headers().contains_key(PAYMENT_RECEIPT_HEADER));
            if problem_details {
                let actual = problem(&response);
                assert_eq!(actual.problem_type, "about:blank");
                assert_eq!(actual.title, "Bad Request");
                assert_eq!(actual.detail, "Failed to read request body");
                assert!(actual.challenge_id.is_none());
            } else {
                assert!(response.body().is_empty());
                assert!(!response.headers().contains_key(header::CONTENT_TYPE));
            }
            let response_text = std::str::from_utf8(response.body()).unwrap();
            assert!(!response_text.contains("/srv/private/"));
            assert!(!response_text.contains("backend_token"));
            assert!(!response_text.contains(PRIVATE_DETAIL));
            assert!(verifier.challenges.lock().unwrap().is_empty());
            assert!(verifier.verified.lock().unwrap().is_empty());
            assert_eq!(application.calls.load(Ordering::SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn clones_share_a_callback_that_does_not_implement_clone() {
    let calls = Mutex::new(0);
    let layer = PaymentLayer::new(Verifier::default()).with_problem_details(move |json: Bytes| {
        *calls.lock().unwrap() += 1;
        json.to_vec()
    });
    let mut service = layer
        .clone()
        .layer(Application::new(StatusCode::OK))
        .clone();
    let response = service.call(Request::new(())).await.unwrap();
    assert_eq!(problem(&response).status, 402);
}

#[tokio::test]
async fn multiple_offers_and_custom_challenge_headers_are_preserved() {
    for body_aware in [false, true] {
        let response = respond(
            body_aware,
            true,
            Verifier {
                two_offers: true,
                ..Verifier::default()
            },
            false,
            Application::new(StatusCode::OK),
        )
        .await;
        let actual = problem(&response);
        let offers = crate::protocol::core::parse_www_authenticate_all([response.headers()
            [WWW_AUTHENTICATE_HEADER]
            .to_str()
            .unwrap()]);
        assert_eq!(offers.len(), 2);
        assert_eq!(offers[0].as_ref().unwrap().id, "fresh-0");
        assert_eq!(offers[1].as_ref().unwrap().id, "alternative");
        assert_eq!(actual.challenge_id.as_deref(), Some("fresh-0"));

        let response = respond(
            body_aware,
            true,
            Verifier {
                mode: ChallengeMode::Partial,
                ..Verifier::default()
            },
            false,
            Application::new(StatusCode::OK),
        )
        .await;
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            response.headers()[WWW_AUTHENTICATE_HEADER],
            "Payment id=\"custom\""
        );
        assert!(problem(&response).challenge_id.is_none());
    }
}

#[tokio::test]
async fn readiness_and_application_errors_keep_their_original_type() {
    #[derive(Clone)]
    struct FailingService(bool);

    impl<B> Service<Request<B>> for FailingService {
        type Response = Response<Vec<u8>>;
        type Error = &'static str;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.0 {
                Poll::Ready(Err("not ready"))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn call(&mut self, _: Request<B>) -> Self::Future {
            std::future::ready(Err("application failure"))
        }
    }

    async fn check<S>(mut service: S, ready_error: bool)
    where
        S: Service<
            Request<http_body_util::Full<Bytes>>,
            Response = Response<Vec<u8>>,
            Error = &'static str,
        >,
    {
        let ready = service.poll_ready(&mut Context::from_waker(std::task::Waker::noop()));
        if ready_error {
            assert_eq!(ready, Poll::Ready(Err("not ready")));
        } else {
            assert_eq!(ready, Poll::Ready(Ok(())));
            let request = Request::builder()
                .header(header::AUTHORIZATION, "Payment mock-credential")
                .body(http_body_util::Full::new(Bytes::new()))
                .unwrap();
            assert_eq!(
                service.call(request).await.unwrap_err(),
                "application failure"
            );
        }
    }

    for ready_error in [false, true] {
        check(
            PaymentLayer::new(Verifier::default())
                .with_problem_details(|json: Bytes| json.to_vec())
                .layer(FailingService(ready_error)),
            ready_error,
        )
        .await;
        check(
            PaymentBodyLayer::new(Verifier::default())
                .with_problem_details(|json: Bytes| json.to_vec())
                .layer(FailingService(ready_error)),
            ready_error,
        )
        .await;
    }
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn axum_body_factory_works_with_a_router() {
    use tower::ServiceExt;
    let app = axum::Router::new()
        .route("/paid", axum::routing::get(|| async { "paid content" }))
        .layer(PaymentLayer::new(Verifier::default()).with_problem_details(axum::body::Body::from));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/paid")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/problem+json"
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let actual: PaymentErrorDetails = serde_json::from_slice(&body).unwrap();
    assert!(actual.problem_type.ends_with("/payment-required"));
}
