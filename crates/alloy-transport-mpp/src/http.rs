//! Alloy HTTP JSON-RPC transport with automatic MPP payments.

use std::{fmt, task};

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::{TransportError, TransportErrorKind, TransportFut, TransportResult};
use mpp::client::{Fetch, PaymentProvider};
use reqwest::Url;
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
        }
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
            .finish_non_exhaustive()
    }
}

impl<P> MppHttpTransport<P>
where
    P: PaymentProvider,
{
    async fn request(self, packet: RequestPacket) -> TransportResult<ResponsePacket> {
        let body = serde_json::to_vec(&packet).map_err(TransportErrorKind::custom)?;
        let headers = packet.headers();
        let response = self
            .client
            .post(self.url)
            .headers(headers)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send_with_payment(&self.provider)
            .await
            .map_err(TransportErrorKind::custom)?;
        decode_response(response).await
    }
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
    let body = response.bytes().await.map_err(TransportErrorKind::custom)?;
    if !status.is_success() {
        return Err(TransportErrorKind::http_error(
            status.as_u16(),
            String::from_utf8_lossy(&body).into_owned(),
        ));
    }
    serde_json::from_slice(&body)
        .map_err(|error| TransportError::deser_err(error, String::from_utf8_lossy(&body)))
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
    };

    use alloy_json_rpc::{Id, Request, RequestMeta};
    use axum::{
        extract::State, http::StatusCode as AxumStatusCode, response::IntoResponse, routing::post,
        Router,
    };
    use mpp::{
        client::PaymentProvider,
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
