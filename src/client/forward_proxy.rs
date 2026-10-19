//! A local forward proxy that pays for `402 Payment Required` responses.
//!
//! [`ForwardProxy`] lets programs that know nothing about MPP, such as `curl`,
//! pay for MPP services. Point them at the proxy with the variables from
//! [`ForwardProxy::environment`]: the proxy then terminates TLS for the origins
//! its [`AcceptPaymentPolicy`] allows, with certificates from its own
//! certificate authority, pays any `402` challenge with the provider for that
//! origin, retries the request and streams the response back. Every other host
//! passes through an untouched `CONNECT` tunnel.

use std::{
    collections::HashMap,
    convert::Infallible,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Empty, Full};
use hyper::{
    body::Incoming,
    header::{
        HeaderName, HeaderValue, CONNECTION, CONTENT_TYPE, HOST, PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
    },
    http::uri::Authority,
    server::conn::http1,
    service::service_fn,
    upgrade::Upgraded,
    HeaderMap, Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use reqwest::Url;
use subtle::ConstantTimeEq;
use tokio_rustls::{
    rustls::{
        crypto::CryptoProvider,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
        ServerConfig,
    },
    TlsAcceptor,
};

use super::{
    send_with_exchange, AcceptPaymentPolicy, ClientEvent, ClientEvents, FlowError,
    PaymentFailedContext, PaymentProvider, DEFAULT_MAX_PAYMENT_RETRIES,
};
use crate::error::{MppError, ResultExt};

type Body = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

type Providers<P> = Box<dyn Fn(&Url) -> Result<P, String> + Send + Sync>;

/// Headers that describe one connection rather than the request (RFC 9110
/// section 7.6.1), plus the legacy `Proxy-Connection`.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// A local HTTP forward proxy that pays for `402 Payment Required` responses.
///
/// [`bind`](Self::bind) takes a loopback port, generates a certificate authority
/// that lives only in this process and writes it, with the system's trusted
/// roots, to a PEM bundle. Give child processes [`environment`](Self::environment)
/// and start the proxy with [`spawn`](Self::spawn).
///
/// Clients authenticate with a random token carried in the proxy URL, so other
/// local users cannot spend through the proxy.
pub struct ForwardProxy<P> {
    listener: std::net::TcpListener,
    address: SocketAddr,
    token: String,
    certificates: PathBuf,
    authority: CertificateAuthority,
    providers: Providers<P>,
    events: ClientEvents,
    bypass: Vec<String>,
}

impl<P: PaymentProvider + 'static> ForwardProxy<P> {
    /// Bind a proxy on a free loopback port that pays with the provider
    /// `providers` returns for each origin. Each origin's provider is created
    /// once, on its first request.
    ///
    /// A rustls [`CryptoProvider`] must be installed as the process default.
    pub fn bind<E: std::fmt::Display>(
        providers: impl Fn(&Url) -> Result<P, E> + Send + Sync + 'static,
    ) -> Result<Self, MppError> {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        let (authority, root) = CertificateAuthority::generate()?;
        let native = rustls_native_certs::load_native_certs();
        if native.certs.is_empty() {
            return Err(MppError::InvalidConfig(format!(
                "no trusted root certificates to bundle with the proxy's: {:?}",
                native.errors
            )));
        }
        let bundle: String = std::iter::once(&root)
            .chain(&native.certs)
            .map(|certificate| pem(certificate))
            .collect();
        let certificates =
            std::env::temp_dir().join(format!("mpp-forward-proxy-{}.pem", std::process::id()));
        std::fs::write(&certificates, bundle)?;
        Ok(Self {
            listener,
            address,
            token: uuid::Uuid::new_v4().simple().to_string(),
            certificates,
            authority,
            providers: Box::new(move |url| providers(url).map_err(|error| error.to_string())),
            events: ClientEvents::default(),
            bypass: Vec::new(),
        })
    }

    /// Hosts that clients reach directly instead of through the proxy, such as
    /// endpoints the process already pays for itself.
    #[must_use]
    pub fn bypass(mut self, hosts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.bypass.extend(hosts.into_iter().map(Into::into));
        self
    }

    /// Payment lifecycle events for every request the proxy pays.
    #[must_use]
    pub fn events(mut self, events: ClientEvents) -> Self {
        self.events = events;
        self
    }

    /// The loopback address the proxy listens on.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The PEM bundle of the proxy's certificate authority and the system's
    /// trusted roots.
    pub fn certificates(&self) -> &Path {
        &self.certificates
    }

    /// Environment variables that route a process's HTTP clients through the
    /// proxy and make them trust its certificates: the `HTTP_PROXY` and
    /// `HTTPS_PROXY` family, `NO_PROXY` extended with loopback and the bypassed
    /// hosts, `NODE_USE_ENV_PROXY` for Node.js's built-in clients, and
    /// `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE` and
    /// `NODE_EXTRA_CA_CERTS` pointing at [`certificates`](Self::certificates).
    pub fn environment(&self) -> Vec<(&'static str, String)> {
        let proxy = format!("http://mpp:{}@{}", self.token, self.address);
        let mut bypass: Vec<String> = ["NO_PROXY", "no_proxy"]
            .into_iter()
            .filter_map(|name| std::env::var(name).ok())
            .flat_map(|hosts| {
                hosts
                    .split(',')
                    .map(|host| host.trim().to_owned())
                    .collect::<Vec<_>>()
            })
            .chain(["localhost", "127.0.0.1", "::1"].map(String::from))
            .chain(self.bypass.iter().cloned())
            .filter(|host| !host.is_empty())
            .collect();
        bypass.sort();
        bypass.dedup();
        let bypass = bypass.join(",");
        let certificates = self.certificates.display().to_string();
        vec![
            ("HTTP_PROXY", proxy.clone()),
            ("HTTPS_PROXY", proxy.clone()),
            ("http_proxy", proxy.clone()),
            ("https_proxy", proxy),
            ("NO_PROXY", bypass.clone()),
            ("no_proxy", bypass),
            ("NODE_USE_ENV_PROXY", "1".to_owned()),
            ("SSL_CERT_FILE", certificates.clone()),
            ("CURL_CA_BUNDLE", certificates.clone()),
            ("REQUESTS_CA_BUNDLE", certificates.clone()),
            ("NODE_EXTRA_CA_CERTS", certificates),
        ]
    }

    /// Serve the proxy on a dedicated thread with its own Tokio runtime.
    ///
    /// Connections queue until `policy` resolves; it decides which origins the
    /// proxy intercepts and pays, for example
    /// [`AcceptPaymentPolicy::Origins`] with the services from
    /// [`directory::service_urls`](super::directory::service_urls).
    pub fn spawn(
        self,
        policy: impl Future<Output = AcceptPaymentPolicy> + Send + 'static,
    ) -> Result<(), MppError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        self.listener.set_nonblocking(true)?;
        let listener = {
            let _runtime = runtime.enter();
            tokio::net::TcpListener::from_std(self.listener)?
        };
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .build()
            .mpp_http("failed to build the proxy's HTTP client")?;
        let authorization = HeaderValue::from_str(&format!(
            "Basic {}",
            STANDARD.encode(format!("mpp:{}", self.token))
        ))
        .mpp_config("invalid proxy credentials")?;
        let (authority, providers, events) = (self.authority, self.providers, self.events);
        std::thread::Builder::new()
            .name("mpp-forward-proxy".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let proxy = Arc::new(Proxy {
                        client,
                        policy: policy.await,
                        events,
                        authorization,
                        authority,
                        providers,
                        paying: Mutex::default(),
                    });
                    loop {
                        let Ok((stream, _)) = listener.accept().await else {
                            continue;
                        };
                        let proxy = proxy.clone();
                        tokio::spawn(async move {
                            let service = service_fn(move |request| {
                                let proxy = proxy.clone();
                                async move { Ok::<_, Infallible>(proxy.handle(request).await) }
                            });
                            let _ = http1::Builder::new()
                                .serve_connection(TokioIo::new(stream), service)
                                .with_upgrades()
                                .await;
                        });
                    }
                })
            })?;
        Ok(())
    }
}

struct Proxy<P> {
    client: reqwest::Client,
    policy: AcceptPaymentPolicy,
    events: ClientEvents,
    authorization: HeaderValue,
    authority: CertificateAuthority,
    providers: Providers<P>,
    paying: Mutex<HashMap<String, P>>,
}

impl<P: PaymentProvider + 'static> Proxy<P> {
    async fn handle(self: Arc<Self>, mut request: Request<Incoming>) -> Response<Body> {
        let authorized = request
            .headers()
            .get(PROXY_AUTHORIZATION)
            .is_some_and(|value| bool::from(value.as_bytes().ct_eq(self.authorization.as_bytes())));
        if !authorized {
            let mut response = respond(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "proxy authentication required",
            );
            response.headers_mut().insert(
                PROXY_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"mpp\""),
            );
            return response;
        }
        if request.method() != Method::CONNECT {
            return match Url::parse(&request.uri().to_string()) {
                Ok(url) if url.scheme() == "http" => self.forward(request, url).await,
                _ => respond(
                    StatusCode::BAD_REQUEST,
                    "expected CONNECT or an absolute http:// URL",
                ),
            };
        }
        let Some(authority) = request.uri().authority().cloned() else {
            return respond(StatusCode::BAD_REQUEST, "CONNECT needs host:port");
        };
        let upgrade = hyper::upgrade::on(&mut request);
        let intercept =
            Url::parse(&format!("https://{authority}/")).is_ok_and(|url| self.policy.allows(&url));
        if intercept {
            tokio::spawn(async move {
                if let Ok(upgraded) = upgrade.await {
                    self.intercept(upgraded, authority).await;
                }
            });
            return Response::new(empty());
        }
        match tokio::net::TcpStream::connect(authority.as_str()).await {
            Ok(mut server) => {
                tokio::spawn(async move {
                    if let Ok(upgraded) = upgrade.await {
                        let _ =
                            tokio::io::copy_bidirectional(&mut TokioIo::new(upgraded), &mut server)
                                .await;
                    }
                });
                Response::new(empty())
            }
            Err(error) => respond(StatusCode::BAD_GATEWAY, &format!("{authority}: {error}")),
        }
    }

    async fn intercept(self: Arc<Self>, upgraded: Upgraded, authority: Authority) {
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let Ok(config) = self.authority.server_config(host) else {
            return;
        };
        let Ok(stream) = TlsAcceptor::from(config)
            .accept(TokioIo::new(upgraded))
            .await
        else {
            return;
        };
        let service = service_fn(move |request: Request<Incoming>| {
            let proxy = self.clone();
            let url = request
                .uri()
                .path_and_query()
                .map_or("/", |path| path.as_str())
                .to_owned();
            let url = Url::parse(&format!("https://{authority}{url}"));
            async move {
                Ok::<_, Infallible>(match url {
                    Ok(url) => proxy.forward(request, url).await,
                    Err(error) => respond(StatusCode::BAD_REQUEST, &error.to_string()),
                })
            }
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    }

    async fn forward(&self, request: Request<Incoming>, url: Url) -> Response<Body> {
        match self.pay(request, url).await {
            Ok(response) => response,
            Err((status, message)) => respond(status, &message),
        }
    }

    async fn pay(
        &self,
        request: Request<Incoming>,
        url: Url,
    ) -> Result<Response<Body>, (StatusCode, String)> {
        let (mut parts, body) = request.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()))?
            .to_bytes();
        strip_hop_by_hop(&mut parts.headers);
        parts.headers.remove(HOST);
        let mut forwarded = reqwest::Request::new(parts.method, url.clone());
        *forwarded.headers_mut() = parts.headers;
        *forwarded.body_mut() = Some(body.into());
        let provider = match self.policy.allows(&url) {
            true => Some(
                self.provider(&url)
                    .map_err(|error| (StatusCode::BAD_GATEWAY, error))?,
            ),
            false => None,
        };
        let response = if let Some(provider) = &provider {
            send_with_exchange(
                &mut self.client.clone(),
                forwarded,
                provider,
                &self.policy,
                &self.events,
                DEFAULT_MAX_PAYMENT_RETRIES,
            )
            .await
            .map_err(|error| match error {
                FlowError::Payment(error) => (
                    StatusCode::PAYMENT_REQUIRED,
                    format!("MPP payment failed: {error}"),
                ),
                FlowError::Send(error) => (StatusCode::BAD_GATEWAY, error.to_string()),
            })?
        } else {
            self.client
                .execute(forwarded)
                .await
                .map_err(|error| (StatusCode::BAD_GATEWAY, error.to_string()))?
        };
        let stream = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("text/event-stream"));
        let mut response = Response::<reqwest::Body>::from(response);
        strip_hop_by_hop(response.headers_mut());
        *response.version_mut() = parts.version;
        Ok(match provider.filter(|_| stream) {
            Some(provider) => response.map(|body| self.answer_events(body, provider, url)),
            None => response.map(|body| body.map_err(Into::into).boxed_unsync()),
        })
    }

    /// Passes a paid event stream through unchanged while the provider answers
    /// its payment events, such as an mppx session's `payment-need-voucher`.
    fn answer_events(&self, body: reqwest::Body, provider: P, url: Url) -> Body {
        let (client, events) = (self.client.clone(), self.events.clone());
        let mut stream = ServerSentEvents::default();
        body.map_frame(move |frame| {
            for (name, data) in frame
                .data_ref()
                .map(|data| stream.push(data))
                .unwrap_or_default()
            {
                let Some(work) = provider.stream_event(&client, url.as_str(), &name, &data) else {
                    continue;
                };
                let events = events.clone();
                tokio::spawn(async move {
                    if let Err(error) = work.await {
                        events
                            .emit(ClientEvent::PaymentFailed(PaymentFailedContext::new(
                                None,
                                error.to_string(),
                            )))
                            .await;
                    }
                });
            }
            frame
        })
        .map_err(Into::into)
        .boxed_unsync()
    }

    fn provider(&self, url: &Url) -> Result<P, String> {
        let origin = url.origin().ascii_serialization();
        let mut paying = self.paying.lock().unwrap();
        if let Some(provider) = paying.get(&origin) {
            return Ok(provider.clone());
        }
        let provider = (self.providers)(url)?;
        paying.insert(origin, provider.clone());
        Ok(provider)
    }
}

struct CertificateAuthority {
    issuer: Issuer<'static, KeyPair>,
    key: KeyPair,
    crypto: Arc<CryptoProvider>,
    configs: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl CertificateAuthority {
    fn generate() -> Result<(Self, CertificateDer<'static>), MppError> {
        let crypto = CryptoProvider::get_default().cloned().ok_or_else(|| {
            MppError::InvalidConfig(
                "install a default rustls CryptoProvider before binding a ForwardProxy".into(),
            )
        })?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "MPP forward proxy");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().mpp_config("failed to generate the proxy CA key")?;
        let root = params
            .self_signed(&key)
            .mpp_config("failed to sign the proxy CA")?
            .der()
            .clone();
        Ok((
            Self {
                issuer: Issuer::new(params, key),
                key: KeyPair::generate().mpp_config("failed to generate the proxy key")?,
                crypto,
                configs: Mutex::default(),
            },
            root,
        ))
    }

    fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, MppError> {
        let mut configs = self.configs.lock().unwrap();
        if let Some(config) = configs.get(host) {
            return Ok(config.clone());
        }
        let mut params =
            CertificateParams::new(vec![host.to_owned()]).mpp_config("invalid intercepted host")?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let certificate = params
            .signed_by(&self.key, &self.issuer)
            .mpp_config("failed to sign a proxy certificate")?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(self.crypto.clone())
            .with_safe_default_protocol_versions()
            .mpp_config("unsupported TLS versions")?
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], key)
            .mpp_config("invalid proxy certificate")?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        configs.insert(host.to_owned(), config.clone());
        Ok(config)
    }
}

/// Named events parsed from a `text/event-stream` body as it arrives.
#[derive(Default)]
struct ServerSentEvents {
    buffer: Vec<u8>,
    name: Option<String>,
    data: Vec<String>,
}

impl ServerSentEvents {
    fn push(&mut self, chunk: &[u8]) -> Vec<(String, String)> {
        self.buffer.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=end).collect();
            let line = String::from_utf8_lossy(&line);
            let line = line.trim_end_matches(['\n', '\r']);
            let field = |prefix: &str| {
                line.strip_prefix(prefix)
                    .map(|value| value.strip_prefix(' ').unwrap_or(value).to_owned())
            };
            if line.is_empty() {
                let data = std::mem::take(&mut self.data).join("\n");
                events.extend(self.name.take().map(|name| (name, data)));
            } else if let Some(name) = field("event:") {
                self.name = Some(name);
            } else if let Some(data) = field("data:") {
                self.data.push(data);
            }
        }
        events
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let nominated: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// PEM-encode a certificate with 64-character lines (RFC 7468 section 2).
fn pem(certificate: &CertificateDer<'_>) -> String {
    let encoded = STANDARD.encode(certificate);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----");
    for (index, character) in encoded.chars().enumerate() {
        if index % 64 == 0 {
            pem.push('\n');
        }
        pem.push(character);
    }
    pem.push_str("\n-----END CERTIFICATE-----\n");
    pem
}

fn respond(status: StatusCode, message: &str) -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::from(format!("{message}\n")))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response
}

fn empty() -> Body {
    Empty::new().map_err(|never| match never {}).boxed_unsync()
}
