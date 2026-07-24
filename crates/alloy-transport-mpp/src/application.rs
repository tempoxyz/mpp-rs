//! Canonical MPP WebSocket transport for arbitrary application messages.
//!
//! This is the protocol-neutral layer beneath Alloy JSON-RPC and other
//! persistent WebSocket consumers. It performs the HTTP 402 probe, creates the
//! initial credential, authorizes the upgraded socket in-band, and services
//! session voucher requests while exposing only application payloads.

use std::{fmt, future::Future, pin::Pin, sync::Arc, time::Duration};

use futures::{SinkExt, StreamExt};
use http::{HeaderMap, HeaderName, HeaderValue};
use mpp::{
    client::{PaymentContext, PaymentProvider},
    format_authorization, MppError, PaymentChallenge, PaymentCredential,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, watch};
use tokio::time::timeout;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{self, client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};
use url::Url;

use crate::{CloseProvider, CloseRequest, VoucherProvider, VoucherRequest};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_EVENTS_CAPACITY: usize = 64;
const CHALLENGE_REFRESH_WINDOW: TimeDuration = TimeDuration::seconds(5);

/// Errors produced by the canonical paid WebSocket transport.
#[derive(Debug, thiserror::Error)]
pub enum MppWsError {
    /// The endpoint URL is not a valid WebSocket URL.
    #[error("invalid MPP WebSocket URL")]
    InvalidUrl(#[source] url::ParseError),
    /// The HTTP payment probe failed.
    #[error("MPP HTTP payment probe failed")]
    Probe(#[source] reqwest::Error),
    /// The probe did not return a payment challenge.
    #[error("MPP payment probe returned HTTP {status} instead of 402")]
    ProbeStatus { status: u16 },
    /// No challenge offered by the server is supported by the provider.
    #[error("MPP server offered no supported payment challenge")]
    UnsupportedChallenge,
    /// A challenge or credential could not be parsed or created.
    #[error("MPP payment failed")]
    Payment(#[from] MppError),
    /// A configured request header is invalid.
    #[error("invalid MPP WebSocket request header")]
    InvalidHeader(#[from] http::Error),
    /// The WebSocket handshake or frame exchange failed.
    #[error("MPP WebSocket failed")]
    WebSocket(#[from] tungstenite::Error),
    /// The payment handshake exceeded its deadline.
    #[error("MPP WebSocket payment handshake timed out")]
    HandshakeTimeout,
    /// The server sent a malformed protocol frame.
    #[error("malformed MPP WebSocket frame: {0}")]
    MalformedFrame(#[from] serde_json::Error),
    /// The server rejected the payment flow.
    #[error("MPP server returned payment error {status}: {message}")]
    PaymentError { status: u16, message: String },
    /// The server closed before the requested application payload arrived.
    #[error("MPP WebSocket closed")]
    Closed,
}

/// Significant canonical MPP events hidden from the application stream.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum MppApplicationEvent {
    /// The HTTP probe selected this challenge.
    Challenge(PaymentChallenge),
    /// The initial credential was sent in-band.
    CredentialSent,
    /// The server requested a larger cumulative voucher.
    NeedVoucher(VoucherRequest),
    /// A follow-up voucher was sent in-band.
    VoucherSent,
    /// The final signed session close credential was sent in-band.
    CloseCredentialSent,
    /// The server accepted a credential or voucher.
    Receipt(Value),
    /// The session is ready to be closed and settled.
    CloseReady(Value),
}

/// Observation handle for a canonical paid application socket.
#[derive(Debug)]
pub struct MppApplicationHandle {
    /// Latest accepted session receipt.
    pub receipt: watch::Receiver<Option<Value>>,
    /// Lossy stream of payment lifecycle events.
    pub events: broadcast::Receiver<MppApplicationEvent>,
}

/// Builder for a canonical paid WebSocket carrying arbitrary text messages.
#[derive(Clone)]
pub struct MppApplicationWsConnect<P, V> {
    url: String,
    headers: HeaderMap,
    payment_provider: P,
    voucher_provider: V,
    handshake_timeout: Duration,
    receipt_tx: watch::Sender<Option<Value>>,
    events_tx: broadcast::Sender<MppApplicationEvent>,
}

impl<P: fmt::Debug, V: fmt::Debug> fmt::Debug for MppApplicationWsConnect<P, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MppApplicationWsConnect")
            .field("url", &redact_url(&self.url))
            .field("headers", &"<redacted>")
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

impl<P, V> MppApplicationWsConnect<P, V> {
    /// Creates a connector backed by the supplied payment and voucher providers.
    pub fn new(url: impl Into<String>, payment_provider: P, voucher_provider: V) -> Self {
        let (receipt_tx, _) = watch::channel(None);
        let (events_tx, _) = broadcast::channel(DEFAULT_EVENTS_CAPACITY);
        Self {
            url: url.into(),
            headers: HeaderMap::new(),
            payment_provider,
            voucher_provider,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            receipt_tx,
            events_tx,
        }
    }

    /// Adds a header to the WebSocket upgrade request.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }

    /// Sets the deadline for the probe, credential creation, and initial receipt.
    pub const fn with_handshake_timeout(mut self, value: Duration) -> Self {
        self.handshake_timeout = value;
        self
    }

    /// Returns an observation handle that remains valid for this connector.
    pub fn mpp_handle(&self) -> MppApplicationHandle {
        MppApplicationHandle {
            receipt: self.receipt_tx.subscribe(),
            events: self.events_tx.subscribe(),
        }
    }
}

impl<P, V> MppApplicationWsConnect<P, V>
where
    P: PaymentProvider + 'static,
    V: VoucherProvider,
{
    /// Opens and authorizes a canonical MPP WebSocket.
    pub async fn connect(&self) -> Result<MppApplicationWs<V>, MppWsError> {
        timeout(self.handshake_timeout, self.connect_inner())
            .await
            .map_err(|_| MppWsError::HandshakeTimeout)?
    }

    async fn connect_inner(&self) -> Result<MppApplicationWs<V>, MppWsError> {
        install_default_crypto_provider();
        let probe_url = probe_url(&self.url)?;
        let mut probe_headers = self.headers.clone();
        if let Some(accept) = self.payment_provider.accept_payment_header() {
            probe_headers.insert(
                HeaderName::from_static("accept-payment"),
                accept.parse().map_err(|error| {
                    MppError::InvalidConfig(format!("invalid Accept-Payment header: {error}"))
                })?,
            );
        }
        let http_client = reqwest::Client::new();
        let challenge = probe_challenge(
            &http_client,
            &probe_url,
            &probe_headers,
            &self.payment_provider,
        )
        .await?;
        let payment_context = PaymentContext {
            url: probe_url.clone(),
            headers: probe_headers.clone(),
        };
        let challenge = self
            .payment_provider
            .prepare_application_websocket_challenge(&challenge, payment_context.clone())
            .await?;
        let _ = self
            .events_tx
            .send(MppApplicationEvent::Challenge(challenge.clone()));
        let credential = self
            .payment_provider
            .pay_with_context(&challenge, payment_context)
            .await?;

        let mut request = self.url.as_str().into_client_request()?;
        request.headers_mut().extend(self.headers.clone());
        let (mut socket, _) = connect_async_with_config(request, None, false).await?;
        send_authorization(&mut socket, &credential).await?;
        let _ = self.events_tx.send(MppApplicationEvent::CredentialSent);

        let mut client = MppApplicationWs {
            socket,
            challenge,
            challenge_refresher: Arc::new(PaymentProbe {
                client: http_client,
                provider: self.payment_provider.clone(),
                url: probe_url,
                headers: probe_headers,
            }),
            voucher_provider: self.voucher_provider.clone(),
            receipt_tx: self.receipt_tx.clone(),
            events_tx: self.events_tx.clone(),
        };
        client.wait_for_receipt().await?;
        Ok(client)
    }
}

/// An authorized canonical MPP WebSocket carrying arbitrary text messages.
pub struct MppApplicationWs<V> {
    socket: Socket,
    challenge: PaymentChallenge,
    challenge_refresher: Arc<dyn ChallengeRefresher>,
    voucher_provider: V,
    receipt_tx: watch::Sender<Option<Value>>,
    events_tx: broadcast::Sender<MppApplicationEvent>,
}

impl<V: VoucherProvider> MppApplicationWs<V> {
    /// Sends one application text payload inside an MPP message envelope.
    pub async fn send(&mut self, data: impl Into<String>) -> Result<(), MppWsError> {
        let frame = ClientFrame::Message { data: data.into() };
        self.socket
            .send(Message::Text(serde_json::to_string(&frame)?.into()))
            .await?;
        Ok(())
    }

    /// Returns the next application text payload, servicing payment frames in-band.
    pub async fn next(&mut self) -> Result<String, MppWsError> {
        loop {
            match self.next_frame().await? {
                ServerFrame::Message { data } => return Ok(data),
                ServerFrame::NeedVoucher { data } => {
                    let _ = self
                        .events_tx
                        .send(MppApplicationEvent::NeedVoucher(data.clone()));
                    self.refresh_challenge_if_expiring(&data.channel_id).await?;
                    let voucher = self
                        .voucher_provider
                        .next_voucher_for_challenge(&self.challenge, &data)
                        .await?;
                    send_authorization(&mut self.socket, &voucher).await?;
                    let _ = self.events_tx.send(MppApplicationEvent::VoucherSent);
                }
                ServerFrame::Receipt { data } => self.accept_receipt(data, false),
                ServerFrame::CloseReady { data } => {
                    self.accept_receipt(data, true);
                    return Err(MppWsError::Closed);
                }
                ServerFrame::Error { status, message } => {
                    return Err(MppWsError::PaymentError { status, message });
                }
            }
        }
    }

    /// Closes only the application WebSocket, leaving the payment session open.
    ///
    /// Use this when an application transport is shutting down but its channel
    /// should remain reusable by a later connection. To settle and refund the
    /// channel instead, use [`Self::close`].
    pub async fn disconnect(mut self) -> Result<(), MppWsError> {
        self.socket.close(None).await?;
        Ok(())
    }

    /// Requests a final session receipt and channel settlement handshake.
    pub async fn close(mut self) -> Result<Value, MppWsError>
    where
        V: CloseProvider,
    {
        let frame = ClientFrame::CloseRequest;
        self.socket
            .send(Message::Text(serde_json::to_string(&frame)?.into()))
            .await?;
        let mut close_credential_sent = false;
        loop {
            match self.next_frame().await? {
                ServerFrame::CloseReady { data } => {
                    self.accept_receipt(data.clone(), true);
                    let request = close_request(&data)?;
                    let credential = self
                        .voucher_provider
                        .close_credential_for_challenge(&self.challenge, &request)
                        .await?;
                    send_authorization(&mut self.socket, &credential).await?;
                    let _ = self
                        .events_tx
                        .send(MppApplicationEvent::CloseCredentialSent);
                    close_credential_sent = true;
                }
                ServerFrame::Receipt { data } => {
                    self.accept_receipt(data.clone(), false);
                    if close_credential_sent {
                        self.socket.close(None).await?;
                        return Ok(data);
                    }
                }
                ServerFrame::NeedVoucher { data } => {
                    self.refresh_challenge_if_expiring(&data.channel_id).await?;
                    let voucher = self
                        .voucher_provider
                        .next_voucher_for_challenge(&self.challenge, &data)
                        .await?;
                    send_authorization(&mut self.socket, &voucher).await?;
                }
                ServerFrame::Error { status, message } => {
                    return Err(MppWsError::PaymentError { status, message });
                }
                ServerFrame::Message { .. } => {}
            }
        }
    }

    async fn wait_for_receipt(&mut self) -> Result<(), MppWsError> {
        match self.next_frame().await? {
            ServerFrame::Receipt { data } => {
                self.accept_receipt(data, false);
                Ok(())
            }
            ServerFrame::Error { status, message } => {
                Err(MppWsError::PaymentError { status, message })
            }
            ServerFrame::NeedVoucher { .. }
            | ServerFrame::Message { .. }
            | ServerFrame::CloseReady { .. } => Err(MppWsError::PaymentError {
                status: 400,
                message: "unexpected frame before initial payment receipt".to_owned(),
            }),
        }
    }

    async fn next_frame(&mut self) -> Result<ServerFrame, MppWsError> {
        loop {
            match self.socket.next().await {
                Some(Ok(Message::Text(text))) => return Ok(serde_json::from_str(&text)?),
                Some(Ok(Message::Ping(payload))) => {
                    self.socket.send(Message::Pong(payload)).await?;
                }
                Some(Ok(Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => return Err(MppWsError::Closed),
                Some(Ok(Message::Binary(_))) => {
                    return Err(MppWsError::PaymentError {
                        status: 400,
                        message: "binary MPP frames are not supported".to_owned(),
                    });
                }
                Some(Err(error)) => return Err(error.into()),
            }
        }
    }

    async fn refresh_challenge_if_expiring(&mut self, channel_id: &str) -> Result<(), MppWsError> {
        if !challenge_needs_refresh(&self.challenge) {
            return Ok(());
        }
        self.challenge = self.challenge_refresher.refresh(channel_id).await?;
        let _ = self
            .events_tx
            .send(MppApplicationEvent::Challenge(self.challenge.clone()));
        Ok(())
    }

    fn accept_receipt(&self, receipt: Value, close_ready: bool) {
        let _ = self.receipt_tx.send(Some(receipt.clone()));
        let event = if close_ready {
            MppApplicationEvent::CloseReady(receipt)
        } else {
            MppApplicationEvent::Receipt(receipt)
        };
        let _ = self.events_tx.send(event);
    }
}

trait ChallengeRefresher: Send + Sync {
    fn refresh<'a>(
        &'a self,
        channel_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<PaymentChallenge, MppWsError>> + Send + 'a>>;
}

struct PaymentProbe<P> {
    client: reqwest::Client,
    provider: P,
    url: Url,
    headers: HeaderMap,
}

impl<P: PaymentProvider> ChallengeRefresher for PaymentProbe<P> {
    fn refresh<'a>(
        &'a self,
        channel_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<PaymentChallenge, MppWsError>> + Send + 'a>> {
        Box::pin(async move {
            let mut headers = self.headers.clone();
            headers.insert(
                HeaderName::from_static("payment-session"),
                channel_id.parse().map_err(|error| {
                    MppError::InvalidConfig(format!(
                        "invalid Payment-Session channel ID header: {error}"
                    ))
                })?,
            );
            probe_challenge(&self.client, &self.url, &headers, &self.provider).await
        })
    }
}

async fn probe_challenge<P: PaymentProvider>(
    client: &reqwest::Client,
    url: &Url,
    headers: &HeaderMap,
    provider: &P,
) -> Result<PaymentChallenge, MppWsError> {
    let response = client
        .get(url.clone())
        .headers(headers.clone())
        .send()
        .await
        .map_err(MppWsError::Probe)?;
    if response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
        return Err(MppWsError::ProbeStatus {
            status: response.status().as_u16(),
        });
    }
    PaymentChallenge::from_headers(
        response
            .headers()
            .get_all(reqwest::header::WWW_AUTHENTICATE)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    )
    .into_iter()
    .filter_map(Result::ok)
    .find(|challenge| provider.supports(challenge.method.as_str(), challenge.intent.as_str()))
    .ok_or(MppWsError::UnsupportedChallenge)
}

fn challenge_needs_refresh(challenge: &PaymentChallenge) -> bool {
    challenge
        .expires
        .as_deref()
        .and_then(|expires| OffsetDateTime::parse(expires, &Rfc3339).ok())
        .is_some_and(|expires| expires <= OffsetDateTime::now_utc() + CHALLENGE_REFRESH_WINDOW)
}

fn close_request(receipt: &Value) -> Result<CloseRequest, MppWsError> {
    let required = |name: &str| {
        receipt
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| MppWsError::PaymentError {
                status: 400,
                message: format!("close-ready receipt is missing {name}"),
            })
    };
    Ok(CloseRequest {
        channel_id: required("channelId")?,
        cumulative_amount: required("spent")?,
    })
}

#[derive(Serialize)]
#[serde(tag = "mpp")]
enum ClientFrame {
    #[serde(rename = "authorization")]
    Authorization { authorization: String },
    #[serde(rename = "message")]
    Message { data: String },
    #[serde(rename = "payment-close-request")]
    CloseRequest,
}

#[derive(Deserialize)]
#[serde(tag = "mpp")]
enum ServerFrame {
    #[serde(rename = "message")]
    Message { data: String },
    #[serde(rename = "payment-need-voucher")]
    NeedVoucher { data: VoucherRequest },
    #[serde(rename = "payment-receipt")]
    Receipt { data: Value },
    #[serde(rename = "payment-close-ready")]
    CloseReady { data: Value },
    #[serde(rename = "payment-error")]
    Error { status: u16, message: String },
}

async fn send_authorization(
    socket: &mut Socket,
    credential: &PaymentCredential,
) -> Result<(), MppWsError> {
    let frame = ClientFrame::Authorization {
        authorization: format_authorization(credential)?,
    };
    socket
        .send(Message::Text(serde_json::to_string(&frame)?.into()))
        .await?;
    Ok(())
}

fn probe_url(raw: &str) -> Result<Url, MppWsError> {
    let mut url = Url::parse(raw).map_err(MppWsError::InvalidUrl)?;
    let scheme = match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        _ => {
            return Err(MppWsError::InvalidUrl(
                url::ParseError::RelativeUrlWithoutBase,
            ))
        }
    };
    url.set_scheme(scheme)
        .map_err(|()| MppWsError::InvalidUrl(url::ParseError::RelativeUrlWithoutBase))?;
    Ok(url)
}

fn redact_url(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "<invalid>".to_owned();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.to_string()
}

fn install_default_crypto_provider() {
    #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        #[cfg(feature = "aws-lc-rs")]
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        #[cfg(all(feature = "ring", not(feature = "aws-lc-rs")))]
        let provider = rustls::crypto::ring::default_provider();
        #[cfg(any(feature = "aws-lc-rs", feature = "ring"))]
        let _ = rustls::crypto::CryptoProvider::install_default(provider);
    }
}
