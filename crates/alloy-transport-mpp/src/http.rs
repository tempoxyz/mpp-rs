//! Alloy HTTP JSON-RPC transport with automatic MPP payments.

use std::{fmt, sync::Arc, task};

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::{TransportError, TransportErrorKind, TransportFut, TransportResult};
use mpp::client::{Fetch, HttpError, PaymentProvider};
use reqwest::{header::HeaderMap, Url};
use tokio::sync::Semaphore;
use tower_service::Service;

/// An Alloy HTTP transport that pays MPP challenges before replaying JSON-RPC requests.
///
/// The canonical MPP client flow owns challenge selection, credential creation,
/// payment retries, and provider commit/rollback. This adapter only translates
/// between Alloy JSON-RPC packets and `reqwest` requests.
#[derive(Clone)]
pub struct MppHttpTransport<P> {
    client: reqwest::Client,
    url: Url,
    provider: P,
    headers: Option<Arc<HeaderMap>>,
    request_limit: Option<(usize, Arc<Semaphore>)>,
}

impl<P> MppHttpTransport<P> {
    /// Create an MPP transport with a default HTTP client.
    ///
    /// This installs the crate-selected Rustls crypto provider before building
    /// the client.
    pub fn with_default_client(url: Url, provider: P) -> Result<Self, reqwest::Error> {
        install_default_crypto_provider();
        reqwest::Client::builder()
            .build()
            .map(|client| Self::new(client, url, provider))
    }

    /// Create an MPP transport for `url` using `provider`.
    pub const fn new(client: reqwest::Client, url: Url, provider: P) -> Self {
        Self {
            client,
            url,
            provider,
            headers: None,
            request_limit: None,
        }
    }

    /// Set headers to include in JSON-RPC and payment management requests.
    ///
    /// Per-request JSON-RPC headers override headers with the same name.
    pub fn with_headers(mut self, headers: HeaderMap) -> Self {
        self.headers = Some(Arc::new(headers));
        self
    }

    /// Bound concurrent HTTP payment flows.
    ///
    /// This is useful for consumers such as fork databases that can fan out a
    /// large number of paid reads at once. The initial request remains
    /// unbounded; the permit is acquired only after a 402 challenge and covers
    /// payment plus authenticated replay. A limit of zero restores the default
    /// unbounded behavior.
    pub fn with_max_concurrent_requests(mut self, limit: usize) -> Self {
        self.request_limit = (limit != 0).then(|| (limit, Arc::new(Semaphore::new(limit))));
        self
    }

    /// Return the underlying HTTP client.
    pub const fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Return the paid JSON-RPC endpoint.
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Return the payment provider.
    pub const fn payment_provider(&self) -> &P {
        &self.provider
    }
}

impl<P> fmt::Debug for MppHttpTransport<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MppHttpTransport")
            .field("url", &redact_url(&self.url))
            .field(
                "max_concurrent_requests",
                &self.request_limit.as_ref().map(|(limit, _)| limit),
            )
            .finish_non_exhaustive()
    }
}

impl<P> MppHttpTransport<P>
where
    P: PaymentProvider,
{
    async fn request(self, packet: RequestPacket) -> TransportResult<ResponsePacket> {
        let body = serde_json::to_vec(&packet).map_err(TransportErrorKind::custom)?;
        let mut headers = self.headers.as_deref().cloned().unwrap_or_default();
        headers.extend(packet.headers());
        let origin = redact_url(&self.url);
        let request = self
            .client
            .post(self.url.clone())
            .headers(headers)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        let response = match self.request_limit {
            Some((_, limit)) => {
                let mut initial = request.try_clone().ok_or_else(|| {
                    TransportErrorKind::custom_str("MPP HTTP request is not cloneable")
                })?;
                let has_accept_payment = initial
                    .try_clone()
                    .and_then(|request| request.build().ok())
                    .is_some_and(|request| {
                        request.headers().contains_key(
                            mpp::protocol::core::accept_payment::ACCEPT_PAYMENT_HEADER,
                        )
                    });
                if !has_accept_payment {
                    if let Some(header) = self.provider.accept_payment_header() {
                        initial = initial.header(
                            mpp::protocol::core::accept_payment::ACCEPT_PAYMENT_HEADER,
                            header,
                        );
                    }
                }
                let response = initial.send().await.map_err(|source| {
                    TransportErrorKind::custom(MppHttpRequestError {
                        origin: origin.clone(),
                        source: source.into(),
                    })
                })?;
                if response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
                    response
                } else {
                    let _permit = limit.acquire_owned().await.map_err(|_| {
                        TransportErrorKind::custom_str(
                            "MPP HTTP concurrency limiter is unavailable",
                        )
                    })?;
                    request
                        .send_with_payment_from_response(&self.provider, response)
                        .await
                        .map_err(|source| {
                            TransportErrorKind::custom(MppHttpRequestError {
                                origin: origin.clone(),
                                source,
                            })
                        })?
                }
            }
            None => request
                .send_with_payment(&self.provider)
                .await
                .map_err(|source| {
                    TransportErrorKind::custom(MppHttpRequestError {
                        origin: origin.clone(),
                        source,
                    })
                })?,
        };
        decode_response(response).await
    }
}

#[derive(Debug, thiserror::Error)]
#[error("MPP HTTP request to {origin} failed")]
struct MppHttpRequestError {
    origin: String,
    #[source]
    source: HttpError,
}

impl<P> Service<RequestPacket> for MppHttpTransport<P>
where
    P: PaymentProvider + 'static,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> {
        task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, packet: RequestPacket) -> Self::Future {
        Box::pin(self.clone().request(packet))
    }
}

async fn decode_response(response: reqwest::Response) -> TransportResult<ResponsePacket> {
    let status = response.status();
    let diagnostics = format_http_diagnostics(response.headers());
    let body = response.bytes().await.map_err(TransportErrorKind::custom)?;
    if !status.is_success() {
        return Err(TransportErrorKind::http_error(
            status.as_u16(),
            format!("{}{diagnostics}", String::from_utf8_lossy(&body)),
        ));
    }
    serde_json::from_slice(&body)
        .map_err(|error| TransportError::deser_err(error, String::from_utf8_lossy(&body)))
}

fn format_http_diagnostics(headers: &reqwest::header::HeaderMap) -> String {
    const DIAGNOSTIC_HEADERS: &[&str] = &["x-request-id", "cf-ray", "server", "report-to", "nel"];

    let pairs = DIAGNOSTIC_HEADERS
        .iter()
        .filter_map(|name| {
            headers
                .get(*name)
                .and_then(|value| value.to_str().ok().map(|value| format!("{name}: {value}")))
        })
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        String::new()
    } else {
        format!("\n\nHTTP diagnostics:\n{}", pairs.join("\n"))
    }
}

fn redact_url(url: &Url) -> String {
    let mut redacted = url.clone();
    let _ = redacted.set_username("");
    let _ = redacted.set_password(None);
    redacted.set_query(None);
    redacted.to_string()
}

fn install_default_crypto_provider() {
    #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        #[cfg(feature = "aws-lc-rs")]
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        let provider = rustls::crypto::ring::default_provider();
        let _ = rustls::crypto::CryptoProvider::install_default(provider);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use alloy_json_rpc::{Id, Request, RequestMeta};
    use axum::{
        extract::State,
        http::{HeaderName, HeaderValue, StatusCode as AxumStatusCode},
        response::IntoResponse,
        routing::post,
        Router,
    };
    use mpp::{
        client::{PaymentContext, PaymentProvider},
        format_www_authenticate, parse_authorization,
        protocol::core::{
            Base64UrlJson, IntentName, MethodName, PaymentChallenge, PaymentCredential,
        },
        MppError,
    };

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct MockProvider {
        commits: Arc<AtomicUsize>,
        rollbacks: Arc<AtomicUsize>,
    }

    impl PaymentProvider for MockProvider {
        fn supports(&self, method: &str, intent: &str) -> bool {
            method == "tempo" && intent == "charge"
        }

        fn pay(
            &self,
            challenge: &PaymentChallenge,
        ) -> impl Future<Output = Result<PaymentCredential, MppError>> + Send {
            let credential = PaymentCredential::with_source(
                challenge.to_echo(),
                "test-source".to_owned(),
                serde_json::json!({"tx": "0xsigned"}),
            );
            async move { Ok(credential) }
        }

        async fn commit_payment(
            &self,
            _challenge: &PaymentChallenge,
            _credential: &PaymentCredential,
        ) -> Result<(), MppError> {
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn rollback_payment(
            &self,
            _challenge: &PaymentChallenge,
            _credential: &PaymentCredential,
        ) -> Result<(), MppError> {
            self.rollbacks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn challenge() -> PaymentChallenge {
        PaymentChallenge {
            id: "rpc-charge".to_owned(),
            realm: "rpc.example".to_owned(),
            method: MethodName::new("tempo"),
            intent: IntentName::new("charge"),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x0000000000000000000000000000000000000001",
                "methodDetails": {"chainId": 42431}
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
            header: None,
        }
    }

    fn request() -> RequestPacket {
        RequestPacket::Single(
            Request {
                meta: RequestMeta::new("eth_blockNumber".into(), Id::Number(1)),
                params: serde_json::Value::Array(Vec::new()),
            }
            .serialize()
            .unwrap(),
        )
    }

    async fn server(app: Router) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (url, task)
    }

    fn client() -> reqwest::Client {
        install_default_crypto_provider();
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    #[tokio::test]
    async fn passes_through_free_json_rpc() {
        let app = Router::new().route(
            "/",
            post(|| async {
                axum::Json(serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": "0x2a"
                }))
            }),
        );
        let (url, task) = server(app).await;
        let provider = MockProvider::default();
        let mut transport = MppHttpTransport::new(client(), url, provider.clone());

        let response = transport.call(request()).await.unwrap();
        assert!(matches!(response, ResponsePacket::Single(response) if response.is_success()));
        assert_eq!(provider.commits.load(Ordering::SeqCst), 0);
        assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn pays_and_replays_json_rpc() {
        #[derive(Clone)]
        struct AppState {
            challenge: String,
        }

        let app = Router::new()
            .route(
                "/",
                post(
                    |State(state): State<AppState>,
                     request: axum::http::Request<axum::body::Body>| async move {
                        if let Some(authorization) = request.headers().get("authorization") {
                            let credential =
                                parse_authorization(authorization.to_str().unwrap()).unwrap();
                            assert_eq!(credential.challenge.id, "rpc-charge");
                            (
                                AxumStatusCode::OK,
                                axum::Json(serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "result": "0x2a"
                                })),
                            )
                                .into_response()
                        } else {
                            (
                                AxumStatusCode::PAYMENT_REQUIRED,
                                [("www-authenticate", state.challenge)],
                                "payment required",
                            )
                                .into_response()
                        }
                    },
                ),
            )
            .with_state(AppState {
                challenge: format_www_authenticate(&challenge()).unwrap(),
            });
        let (url, task) = server(app).await;
        let provider = MockProvider::default();
        let mut transport = MppHttpTransport::new(client(), url, provider.clone());

        let response = transport.call(request()).await.unwrap();
        assert!(matches!(response, ResponsePacket::Single(response) if response.is_success()));
        assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
        assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[tokio::test]
    async fn preserves_transport_headers_for_management_requests() {
        #[derive(Clone)]
        struct ManagementProvider {
            client: reqwest::Client,
        }

        impl PaymentProvider for ManagementProvider {
            fn supports(&self, method: &str, intent: &str) -> bool {
                method == "tempo" && intent == "charge"
            }

            fn pay(
                &self,
                challenge: &PaymentChallenge,
            ) -> impl Future<Output = Result<PaymentCredential, MppError>> + Send {
                let credential = PaymentCredential::with_source(
                    challenge.to_echo(),
                    "test-source".to_owned(),
                    serde_json::json!({"tx": "0xsigned"}),
                );
                async move { Ok(credential) }
            }

            async fn pay_with_context(
                &self,
                challenge: &PaymentChallenge,
                context: PaymentContext,
            ) -> Result<PaymentCredential, MppError> {
                let response = self
                    .client
                    .post(context.url)
                    .headers(context.headers)
                    .header("x-mpp-management", "top-up")
                    .send()
                    .await
                    .map_err(|error| MppError::InvalidConfig(error.to_string()))?;
                if !response.status().is_success() {
                    return Err(MppError::InvalidConfig(format!(
                        "management request returned {}",
                        response.status()
                    )));
                }
                self.pay(challenge).await
            }
        }

        #[derive(Clone)]
        struct AppState {
            challenge: String,
            management_requests: Arc<AtomicUsize>,
        }

        let state = AppState {
            challenge: format_www_authenticate(&challenge()).unwrap(),
            management_requests: Arc::new(AtomicUsize::new(0)),
        };
        let observed = state.clone();
        let app = Router::new()
            .route(
                "/",
                post(
                    |State(state): State<AppState>,
                     request: axum::http::Request<axum::body::Body>| async move {
                        if request.headers().get("x-api-key")
                            != Some(&HeaderValue::from_static("test-key"))
                        {
                            return AxumStatusCode::UNAUTHORIZED.into_response();
                        }
                        if request.headers().contains_key("x-mpp-management") {
                            state.management_requests.fetch_add(1, Ordering::SeqCst);
                            return AxumStatusCode::NO_CONTENT.into_response();
                        }
                        if request.headers().contains_key("authorization") {
                            (
                                AxumStatusCode::OK,
                                axum::Json(serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "result": "0x2a"
                                })),
                            )
                                .into_response()
                        } else {
                            (
                                AxumStatusCode::PAYMENT_REQUIRED,
                                [("www-authenticate", state.challenge)],
                                "payment required",
                            )
                                .into_response()
                        }
                    },
                ),
            )
            .with_state(state);
        let (url, task) = server(app).await;
        let provider = ManagementProvider { client: client() };
        let headers = HeaderMap::from_iter([(
            HeaderName::from_static("x-api-key"),
            HeaderValue::from_static("test-key"),
        )]);
        let mut transport = MppHttpTransport::new(client(), url, provider).with_headers(headers);

        transport.call(request()).await.unwrap();

        assert_eq!(observed.management_requests.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn rolls_back_rejected_payment() {
        #[derive(Clone)]
        struct AppState {
            challenge: String,
        }

        let app = Router::new()
            .route(
                "/",
                post(
                    |State(state): State<AppState>,
                     request: axum::http::Request<axum::body::Body>| async move {
                        let message = if request.headers().contains_key("authorization") {
                            "payment rejected"
                        } else {
                            "payment required"
                        };
                        (
                            AxumStatusCode::PAYMENT_REQUIRED,
                            [("www-authenticate", state.challenge)],
                            message,
                        )
                    },
                ),
            )
            .with_state(AppState {
                challenge: format_www_authenticate(&challenge()).unwrap(),
            });
        let (url, task) = server(app).await;
        let provider = MockProvider::default();
        let mut transport = MppHttpTransport::new(client(), url, provider.clone());

        let error = transport.call(request()).await.unwrap_err();
        assert!(error.to_string().contains("402"));
        assert_eq!(provider.commits.load(Ordering::SeqCst), 0);
        assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn preserves_whitelisted_http_diagnostics() {
        let app = Router::new().route(
            "/",
            post(|| async {
                (
                    AxumStatusCode::UNAUTHORIZED,
                    [
                        (
                            HeaderName::from_static("x-request-id"),
                            HeaderValue::from_static("request-123"),
                        ),
                        (
                            HeaderName::from_static("authorization"),
                            HeaderValue::from_static("secret"),
                        ),
                    ],
                    "denied",
                )
            }),
        );
        let (url, task) = server(app).await;
        let mut transport = MppHttpTransport::new(client(), url, MockProvider::default());

        let error = transport.call(request()).await.unwrap_err().to_string();
        assert!(error.contains("denied"));
        assert!(error.contains("x-request-id: request-123"));
        assert!(!error.contains("secret"));

        task.abort();
    }

    #[tokio::test]
    async fn request_errors_redact_url_credentials_and_query() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let url = format!("http://user:password@{address}/rpc?api_key=query-secret")
            .parse()
            .unwrap();
        let mut transport = MppHttpTransport::new(client(), url, MockProvider::default());

        let error = transport.call(request()).await.unwrap_err();
        let report = format!("{error}\n{error:?}");
        assert!(!report.contains("password"), "password leaked: {report}");
        assert!(
            !report.contains("query-secret"),
            "query secret leaked: {report}"
        );
        assert!(!report.contains("api_key"), "query key leaked: {report}");
        assert!(
            report.contains(&format!("http://{address}/rpc")),
            "missing safe origin: {report}"
        );
    }

    #[tokio::test]
    async fn leaves_free_requests_unbounded() {
        #[derive(Clone, Default)]
        struct AppState {
            active: Arc<AtomicUsize>,
            maximum: Arc<AtomicUsize>,
        }

        let state = AppState::default();
        let observed = state.clone();
        let app = Router::new()
            .route(
                "/",
                post(|State(state): State<AppState>| async move {
                    let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
                    state.maximum.fetch_max(active, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    state.active.fetch_sub(1, Ordering::SeqCst);
                    axum::Json(serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": "0x2a"
                    }))
                }),
            )
            .with_state(state);
        let (url, task) = server(app).await;
        let transport = MppHttpTransport::new(client(), url, MockProvider::default())
            .with_max_concurrent_requests(2);

        let requests = (0..8).map(|_| {
            let mut transport = transport.clone();
            tokio::spawn(async move { transport.call(request()).await.unwrap() })
        });
        for result in futures::future::join_all(requests).await {
            result.unwrap();
        }

        assert!(
            observed.maximum.load(Ordering::SeqCst) > 2,
            "free requests were incorrectly throttled by the paid-flow limit"
        );
        task.abort();
    }

    #[tokio::test]
    async fn bounds_only_paid_request_flows() {
        #[derive(Clone)]
        struct AppState {
            challenge: String,
            active: Arc<AtomicUsize>,
            maximum: Arc<AtomicUsize>,
        }

        let state = AppState {
            challenge: format_www_authenticate(&challenge()).unwrap(),
            active: Arc::new(AtomicUsize::new(0)),
            maximum: Arc::new(AtomicUsize::new(0)),
        };
        let observed = state.clone();
        let app = Router::new()
            .route(
                "/",
                post(
                    |State(state): State<AppState>,
                     request: axum::http::Request<axum::body::Body>| async move {
                        if request.headers().contains_key("authorization") {
                            let active = state.active.fetch_add(1, Ordering::SeqCst) + 1;
                            state.maximum.fetch_max(active, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(25)).await;
                            state.active.fetch_sub(1, Ordering::SeqCst);
                            (
                                AxumStatusCode::OK,
                                axum::Json(serde_json::json!({
                                    "jsonrpc": "2.0",
                                    "id": 1,
                                    "result": "0x2a"
                                })),
                            )
                                .into_response()
                        } else {
                            (
                                AxumStatusCode::PAYMENT_REQUIRED,
                                [("www-authenticate", state.challenge)],
                                "payment required",
                            )
                                .into_response()
                        }
                    },
                ),
            )
            .with_state(state);
        let (url, task) = server(app).await;
        let transport = MppHttpTransport::new(client(), url, MockProvider::default())
            .with_max_concurrent_requests(2);

        let requests = (0..8).map(|_| {
            let mut transport = transport.clone();
            tokio::spawn(async move { transport.call(request()).await.unwrap() })
        });
        for result in futures::future::join_all(requests).await {
            result.unwrap();
        }

        assert_eq!(observed.maximum.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[test]
    fn debug_redacts_credentials_and_query() {
        let transport = MppHttpTransport::new(
            client(),
            "https://user:password@example.com/rpc?token=secret"
                .parse()
                .unwrap(),
            MockProvider::default(),
        );
        let debug = format!("{transport:?}");
        assert!(!debug.contains("password"));
        assert!(!debug.contains("secret"));
        assert!(debug.contains("https://example.com/rpc"));
    }
}
