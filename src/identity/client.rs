//! Client-side identity: provers that add identity proofs to outbound
//! requests, as mppx's `Identity.Client`.

use std::fmt;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Request, Response, StatusCode, Url};

use super::{requirements, BoxFuture, Requirement};
use crate::client::flow::Exchange;
use crate::client::HttpError;
use crate::error::MppError;
use crate::protocol::core::headers::{extract_payment_scheme, parse_authorization};
use crate::protocol::core::{ChallengeEcho, PaymentChallenge};

/// Origins a prover may run for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Any origin.
    Any,
    /// Only these origins, matched exactly, such as `https://shop.example`.
    Origins(Vec<String>),
}

impl Scope {
    /// Only `origins`, such as `["https://shop.example"]`. Each is normalized
    /// to its ASCII serialization; one that is not a URL never matches.
    pub fn origins<I, S>(origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::Origins(
            origins
                .into_iter()
                .filter_map(|origin| Url::parse(origin.as_ref()).ok())
                .map(|url| url.origin().ascii_serialization())
                .collect(),
        )
    }

    /// Whether a request to `url` is in scope.
    pub fn contains(&self, url: &Url) -> bool {
        match self {
            Self::Any => true,
            Self::Origins(origins) => {
                let origin = url.origin().ascii_serialization();
                origins.contains(&origin)
            }
        }
    }
}

/// Values shared by every prover contributing to one HTTP attempt. Every
/// retry gets a new context, so single-use nonces are never replayed.
#[derive(Debug, Clone)]
pub struct ProveContext {
    /// Unix timestamp, in seconds, at which the attempt was created (RFC 9421 `created`).
    pub created: u64,
    /// Base64url-encoded random value identifying the attempt (RFC 9421 `nonce`).
    pub nonce: String,
    /// On a paid attempt, the Challenge being answered, so a proof can bind to its `id`.
    pub challenge: Option<ChallengeEcho>,
}

impl ProveContext {
    fn create(challenge: Option<ChallengeEcho>) -> Self {
        Self {
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or_default(),
            nonce: URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()),
            challenge,
        }
    }
}

/// Passed to [`Prover::prepare`] for a 402 before the payment retry.
#[derive(Debug, Clone)]
pub struct PrepareContext {
    /// The Challenge the client selected; [`Prover::prove`] receives the same
    /// Challenge on the paid retry.
    pub challenge: PaymentChallenge,
    /// The identities the 402's `Identity-Required` header lists.
    pub requirements: Vec<Requirement>,
}

/// The status, headers and URL of a response a prover inspects.
///
/// mppx hands provers the whole response; here they get its head, so the
/// body stays with the caller.
#[derive(Debug, Clone)]
pub struct ResponseParts {
    /// The response status.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// The final URL of the response.
    pub url: Url,
}

impl ResponseParts {
    fn of(response: &Response) -> Self {
        Self {
            status: response.status(),
            headers: response.headers().clone(),
            url: response.url().clone(),
        }
    }
}

/// Passed to [`Prover::retry`] with a rejected response.
#[derive(Debug, Clone, Copy)]
pub struct RetryContext<'a> {
    /// The request that got the response, as sent: proved by every in-scope prover.
    pub request: &'a Request,
}

/// A prover that could not prove a request.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ProverError(String);

impl ProverError {
    /// A prover failure with `message`. Never include tokens or keys.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// Adds one identity protocol to outbound requests on the client, as mppx's `Prover`.
pub trait Prover: Send + Sync {
    /// Origins the prover may run for.
    fn scope(&self) -> &Scope;

    /// Extra sensitive request headers the prover writes, lowercased, such as
    /// a proof header. Like [`headers::REQUEST`](super::headers::REQUEST),
    /// they must never reach another origin.
    fn headers(&self) -> &[&'static str] {
        &[]
    }

    /// Adds the protocol's identity material to `request`.
    fn prove<'a>(
        &'a self,
        request: &'a mut Request,
        context: &'a ProveContext,
    ) -> BoxFuture<'a, Result<(), ProverError>>;

    /// Prepares a proof from a 402 before the payment retry, such as for the
    /// identities it requires.
    fn prepare<'a>(
        &'a self,
        response: &'a ResponseParts,
        context: &'a PrepareContext,
    ) -> BoxFuture<'a, Result<(), ProverError>> {
        let _ = (response, context);
        Box::pin(std::future::ready(Ok(())))
    }

    /// Inspects a rejected (non-402) response to an unpaid attempt and decides
    /// whether to resend the request once.
    ///
    /// Return headers to resend with: they are set on the request before
    /// every in-scope prover proves it again. Payment credential headers are
    /// ignored. Return `None` not to resend. A paid attempt is asked only
    /// after a 401 with no receipt, and resent with the same Payment
    /// credential while its Challenge has not expired: servers check other
    /// authentication before verifying a Payment credential, so a 401 means
    /// nothing settled.
    fn retry<'a>(
        &'a self,
        response: &'a ResponseParts,
        context: RetryContext<'a>,
    ) -> BoxFuture<'a, Option<HeaderMap>> {
        let _ = (response, context);
        Box::pin(std::future::ready(None))
    }
}

/// Payment credential headers a prover's retry headers may never set, lowercased.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "payment-authorization",
    "payment-signature",
    "x-payment",
];

/// x402 credential headers; a request carrying one is a paid attempt.
const X402_CREDENTIAL_HEADERS: &[&str] = &["payment-signature", "x-payment"];

/// Response headers that report a settled payment (MPP receipt, x402
/// settlement response).
const SETTLEMENT_HEADERS: &[&str] = &["payment-receipt", "payment-response", "x-payment-response"];

/// The most of a rejected paid attempt's body kept while it is resent.
const MAX_FALLBACK_BYTES: usize = 64 * 1024;

/// How long reading a rejected paid attempt's body may take.
const FALLBACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Provers applied to every attempt of a request, as mppx's `Identity.Client.from`.
///
/// Provers run in list order on every attempt, sharing one attempt context.
/// List request signers last so their signatures cover headers added by
/// earlier provers.
#[derive(Clone)]
pub struct IdentityClient {
    provers: Arc<Vec<Arc<dyn Prover>>>,
}

impl fmt::Debug for IdentityClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityClient")
            .field("provers", &self.provers.len())
            .finish()
    }
}

/// An identity client configured with no provers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("identity client must configure at least one prover")]
pub struct NoProvers;

impl IdentityClient {
    /// A client applying `provers`, in order. Fails with none, as mppx does.
    pub fn new(provers: Vec<Arc<dyn Prover>>) -> Result<Self, NoProvers> {
        if provers.is_empty() {
            return Err(NoProvers);
        }
        Ok(Self {
            provers: Arc::new(provers),
        })
    }

    /// Extra sensitive request headers the provers declare, lowercased and deduplicated.
    pub fn headers(&self) -> Vec<&'static str> {
        let mut headers: Vec<&'static str> = Vec::new();
        for name in self.provers.iter().flat_map(|prover| prover.headers()) {
            if !headers.contains(name) {
                headers.push(name);
            }
        }
        headers
    }

    fn in_scope(&self, url: &Url) -> Vec<Arc<dyn Prover>> {
        self.provers
            .iter()
            .filter(|prover| prover.scope().contains(url))
            .cloned()
            .collect()
    }

    /// Lets in-scope provers prepare proofs for a 402 before the payment
    /// retry, with the selected Challenge and the 402's requirements.
    pub(crate) async fn prepare(
        &self,
        response: &Response,
        challenge: &PaymentChallenge,
    ) -> Result<(), HttpError> {
        let parts = ResponseParts::of(response);
        let context = PrepareContext {
            challenge: challenge.clone(),
            // A list may be split across several field lines.
            requirements: requirements::parse(
                Some(
                    response
                        .headers()
                        .get_all(requirements::HEADER)
                        .iter()
                        .filter_map(|value| value.to_str().ok())
                        .collect::<Vec<_>>()
                        .join(", "),
                )
                .as_deref()
                .filter(|value| !value.is_empty()),
            ),
        };
        for prover in self.in_scope(response.url()) {
            prover
                .prepare(&parts, &context)
                .await
                .map_err(prover_failed)?;
        }
        Ok(())
    }
}

/// An attempt that was not sent although nothing stopped it; never happens.
fn unsent_resend() -> HttpError {
    HttpError::Payment(MppError::Internal(
        "identity attempt was not sent".to_owned(),
    ))
}

fn prover_failed(error: ProverError) -> HttpError {
    HttpError::Payment(MppError::Internal(format!(
        "identity prover failed: {error}"
    )))
}

/// The Challenge of a Payment credential in `headers`, if any.
fn credential_challenge(headers: &HeaderMap) -> Option<ChallengeEcho> {
    headers.values().find_map(|value| {
        let value = value.to_str().ok()?;
        parse_authorization(extract_payment_scheme(value)?)
            .ok()
            .map(|credential| credential.challenge)
    })
}

/// Whether a request is a paid attempt: it carries a Payment or x402 credential.
/// Its credential may already have settled, so replaying it could pay again.
fn is_paid(request: &Request) -> bool {
    X402_CREDENTIAL_HEADERS
        .iter()
        .any(|name| request.headers().contains_key(*name))
        || request.headers().values().any(|value| {
            value
                .to_str()
                .ok()
                .and_then(extract_payment_scheme)
                .is_some()
        })
}

/// The Challenge a paid attempt may be resent for: the Challenge of the
/// Payment credential the request carries. A request carrying an x402
/// credential header is never resent.
fn resendable_challenge(request: &Request) -> Option<ChallengeEcho> {
    if X402_CREDENTIAL_HEADERS
        .iter()
        .any(|name| request.headers().contains_key(*name))
    {
        return None;
    }
    credential_challenge(request.headers())
}

/// Whether a Challenge has an `expires` still in the future.
fn is_unexpired(challenge: &ChallengeEcho) -> bool {
    challenge
        .expires
        .as_deref()
        .and_then(|expires| {
            time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
                .ok()
        })
        .is_some_and(|expires| expires > time::OffsetDateTime::now_utc())
}

/// Whether a paid attempt's response may be resent: a 401, which never
/// follows settlement, carrying no receipt or other settlement header, while
/// the credential's Challenge has not expired. A 403 can follow a settled
/// payment, so it is never resent.
fn can_resend_paid(response: &Response, challenge: &ChallengeEcho) -> bool {
    response.status() == StatusCode::UNAUTHORIZED
        && !SETTLEMENT_HEADERS
            .iter()
            .any(|name| response.headers().contains_key(*name))
        && is_unexpired(challenge)
}

/// Reads a rejected response into a copy, within a size and time bound, and
/// releases its connection. A body larger than 64 KiB, or still arriving
/// after 2 seconds, is cut off to what arrived and marked with an
/// `Mppx-Body-Truncated: true` header, as mppx does.
async fn detach(mut response: Response) -> Response {
    use reqwest::ResponseBuilderExt;

    let mut builder = http_types::Response::builder()
        .status(response.status())
        .version(response.version())
        .url(response.url().clone());
    let mut headers = response.headers().clone();
    let mut body: Vec<u8> = Vec::new();
    let read = tokio::time::timeout(FALLBACK_TIMEOUT, async {
        while let Some(chunk) = response.chunk().await? {
            body.extend_from_slice(&chunk);
            if body.len() > MAX_FALLBACK_BYTES {
                return Ok::<bool, reqwest::Error>(true);
            }
        }
        Ok(false)
    })
    .await;
    drop(response);
    if !matches!(read, Ok(Ok(false))) {
        body.truncate(MAX_FALLBACK_BYTES);
        headers.remove(reqwest::header::CONTENT_LENGTH);
        headers.insert(
            HeaderName::from_static("mppx-body-truncated"),
            HeaderValue::from_static("true"),
        );
    }
    if let Some(slot) = builder.headers_mut() {
        *slot = headers;
    }
    match builder.body(body) {
        Ok(copy) => Response::from(copy),
        // Every part came from a valid response.
        Err(_) => Response::from(http_types::Response::new(Vec::new())),
    }
}

/// An [`Exchange`] that proves every request it sends with an
/// [`IdentityClient`]'s in-scope provers, as mppx's identity `send`.
///
/// The inner exchange must never follow redirects, so proofs never reach
/// another URL: [`ChargeClient`](crate::client::ChargeClient) is the one
/// transport that uses it.
pub(crate) struct IdentityExchange<'a, X> {
    pub(crate) inner: X,
    pub(crate) identity: &'a IdentityClient,
    /// Headers a retry returned earlier in the same logical request, carried
    /// to the paid attempt.
    carried: Vec<(HeaderName, HeaderValue)>,
    /// Whether the last send failed in a prover, before the request left.
    unsent: bool,
}

impl<'a, X> IdentityExchange<'a, X> {
    pub(crate) fn new(inner: X, identity: &'a IdentityClient) -> Self {
        Self {
            inner,
            identity,
            carried: Vec::new(),
            unsent: false,
        }
    }
}

impl<X> IdentityExchange<'_, X>
where
    X: Exchange,
    X::Error: From<HttpError>,
{
    /// Proves and sends one attempt, with `headers` set before the provers run.
    ///
    /// With `deadline`, the attempt is sent only if that Challenge has not
    /// expired once the provers ran; otherwise nothing is sent and the result
    /// is `None`.
    async fn send_once(
        &mut self,
        mut request: Request,
        headers: &[(HeaderName, HeaderValue)],
        deadline: Option<&ChallengeEcho>,
    ) -> Result<Option<(Option<Request>, Response)>, X::Error> {
        let scoped = self.identity.in_scope(request.url());
        if scoped.is_empty() {
            if deadline.is_some_and(|challenge| !is_unexpired(challenge)) {
                return Ok(None);
            }
            let sent = request.try_clone();
            return Ok(Some((sent, self.inner.send(request).await?)));
        }
        let challenge = credential_challenge(request.headers());
        // Retry headers never replace a payment credential: the fixed credential
        // headers, the one the Challenge names, or any header holding a Payment credential.
        let mut protected: Vec<String> = CREDENTIAL_HEADERS
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        if let Some(challenge) = &challenge {
            if let Some(header) = challenge.header.as_deref() {
                protected.push(header.to_ascii_lowercase());
            }
        }
        for (name, value) in request.headers() {
            if value
                .to_str()
                .ok()
                .and_then(extract_payment_scheme)
                .is_some()
            {
                protected.push(name.as_str().to_owned());
            }
        }
        for (name, value) in headers {
            if !protected.iter().any(|protected| protected == name.as_str()) {
                request.headers_mut().insert(name.clone(), value.clone());
            }
        }
        let context = ProveContext::create(challenge);
        for prover in &scoped {
            if let Err(error) = prover.prove(&mut request, &context).await {
                self.unsent = true;
                return Err(X::Error::from(prover_failed(error)));
            }
        }
        // The Challenge may expire while provers refresh identity.
        if deadline.is_some_and(|challenge| !is_unexpired(challenge)) {
            return Ok(None);
        }
        let sent = request.try_clone();
        Ok(Some((sent, self.inner.send(request).await?)))
    }
}

/// Asks each in-scope prover whether to resend a rejected response.
/// Same-named headers from several provers are combined, comma-separated.
async fn resend_headers(
    identity: &IdentityClient,
    response: &Response,
    request: &Request,
) -> Option<Vec<(HeaderName, HeaderValue)>> {
    let parts = ResponseParts::of(response);
    let mut resend = false;
    let mut combined: Vec<(HeaderName, Vec<u8>)> = Vec::new();
    for prover in identity.in_scope(request.url()) {
        let Some(headers) = prover.retry(&parts, RetryContext { request }).await else {
            continue;
        };
        resend = true;
        for (name, value) in &headers {
            if CREDENTIAL_HEADERS.contains(&name.as_str()) {
                continue;
            }
            match combined.iter_mut().find(|(seen, _)| seen == name) {
                Some((_, joined)) => {
                    joined.extend_from_slice(b", ");
                    joined.extend_from_slice(value.as_bytes());
                }
                None => combined.push((name.clone(), value.as_bytes().to_vec())),
            }
        }
    }
    if !resend {
        return None;
    }
    Some(
        combined
            .into_iter()
            .filter_map(|(name, value)| Some((name, HeaderValue::from_bytes(&value).ok()?)))
            .collect(),
    )
}

impl<X> Exchange for IdentityExchange<'_, X>
where
    X: Exchange,
    X::Error: From<HttpError>,
{
    type Error = X::Error;

    fn check_challenge(&self, challenge: &PaymentChallenge) -> Result<(), HttpError> {
        self.inner.check_challenge(challenge)
    }

    fn allows_prepaid(&self) -> bool {
        self.inner.allows_prepaid()
    }

    fn http_client(&self) -> Option<reqwest::Client> {
        self.inner.http_client()
    }

    fn redirected(&self, request_url: &Url, response: &Response) -> bool {
        self.inner.redirected(request_url, response)
    }

    async fn prepare_challenge(
        &mut self,
        response: &Response,
        challenge: &PaymentChallenge,
    ) -> Result<(), HttpError> {
        self.identity.prepare(response, challenge).await?;
        self.inner.prepare_challenge(response, challenge).await
    }

    fn unsent(&self) -> bool {
        self.unsent
    }

    async fn send(&mut self, request: Request) -> Result<Response, Self::Error> {
        self.unsent = false;
        let paid = is_paid(&request);
        // A paid attempt may be resent once, after a 401, only with the
        // Payment credential for its Challenge and while that Challenge has
        // not expired: servers check other authentication before verifying a
        // Payment credential, so a 401 means nothing settled.
        let paid_challenge = if paid {
            resendable_challenge(&request).filter(is_unexpired)
        } else {
            None
        };
        // Keep a copy only when the attempt may be resent.
        let original = if !paid || paid_challenge.is_some() {
            request.try_clone()
        } else {
            None
        };
        let carried = self.carried.clone();
        // Without a deadline, an attempt is always sent.
        let Some((sent, response)) = self.send_once(request, &carried, None).await? else {
            return Err(X::Error::from(unsent_resend()));
        };
        let status = response.status();
        let rejected = match &paid_challenge {
            Some(challenge) => can_resend_paid(&response, challenge),
            None => {
                !paid
                    && (status.is_client_error() || status.is_server_error())
                    && status != StatusCode::PAYMENT_REQUIRED
            }
        };
        let (Some(original), Some(sent), true) = (original, sent, rejected) else {
            return Ok(response);
        };
        let Some(resend) = resend_headers(self.identity, &response, &sent).await else {
            return Ok(response);
        };
        // The rejected response is released before the provers run again. A
        // paid attempt keeps a bounded copy to return if it is not resent.
        let fallback = match &paid_challenge {
            Some(_) => Some(detach(response).await),
            None => {
                drop(response);
                None
            }
        };
        // Later headers replace same-named earlier ones.
        let mut headers = carried;
        for (name, value) in resend {
            headers.retain(|(seen, _)| *seen != name);
            headers.push((name, value));
        }
        if fallback.is_none() {
            self.carried = headers.clone();
        }
        match (
            self.send_once(original, &headers, paid_challenge.as_ref())
                .await,
            fallback,
        ) {
            (Ok(Some((_, response))), _) => {
                // A later paid attempt carries the headers this one was resent with.
                self.carried = headers;
                Ok(response)
            }
            // The Challenge expired, or a prover failed, before the paid
            // resend left: the 401 stands, and nothing was resent.
            (Ok(None), Some(fallback)) => Ok(fallback),
            (Err(_), Some(fallback)) if self.unsent => {
                self.unsent = false;
                Ok(fallback)
            }
            (Ok(None), None) => Err(X::Error::from(unsent_resend())),
            (Err(error), _) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::protocol::core::{
        format_authorization, Base64UrlJson, PaymentCredential, PaymentPayload,
    };

    /// Sets `x-proof` with each attempt's nonce, and asks to resend a 401 once with `x-retry`.
    struct RecordingProver {
        scope: Scope,
        contexts: Mutex<Vec<ProveContext>>,
        retries: Mutex<usize>,
    }

    impl Prover for RecordingProver {
        fn scope(&self) -> &Scope {
            &self.scope
        }

        fn prove<'a>(
            &'a self,
            request: &'a mut Request,
            context: &'a ProveContext,
        ) -> BoxFuture<'a, Result<(), ProverError>> {
            self.contexts.lock().unwrap().push(context.clone());
            request
                .headers_mut()
                .insert("x-proof", HeaderValue::from_str(&context.nonce).unwrap());
            Box::pin(std::future::ready(Ok(())))
        }

        fn retry<'a>(
            &'a self,
            response: &'a ResponseParts,
            _context: RetryContext<'a>,
        ) -> BoxFuture<'a, Option<HeaderMap>> {
            *self.retries.lock().unwrap() += 1;
            let resend = (response.status == StatusCode::UNAUTHORIZED).then(|| {
                let mut headers = HeaderMap::new();
                headers.insert("x-retry", HeaderValue::from_static("1"));
                // Never applied: retries cannot set credential headers.
                headers.insert("authorization", HeaderValue::from_static("Bearer stolen"));
                headers
            });
            Box::pin(std::future::ready(resend))
        }
    }

    /// Answers every request with `status`, recording what it was sent.
    struct Scripted {
        status: u16,
        sent: Vec<Request>,
    }

    impl Exchange for Scripted {
        type Error = HttpError;

        async fn send(&mut self, request: Request) -> Result<Response, HttpError> {
            self.sent.push(request);
            let response = http_types::Response::builder()
                .status(self.status)
                .body("")
                .unwrap();
            Ok(Response::from(response))
        }
    }

    fn prover(scope: Scope) -> Arc<RecordingProver> {
        Arc::new(RecordingProver {
            scope,
            contexts: Mutex::default(),
            retries: Mutex::default(),
        })
    }

    fn get(url: &str) -> Request {
        Request::new(reqwest::Method::GET, url.parse().unwrap())
    }

    #[test]
    fn needs_a_prover_and_matches_scope_exactly() {
        assert!(IdentityClient::new(Vec::new()).is_err());
        let scope = Scope::origins(["https://api.example", "not a url"]);
        assert!(scope.contains(&"https://api.example/a?b".parse().unwrap()));
        assert!(!scope.contains(&"https://api.example.evil/".parse().unwrap()));
        assert!(!scope.contains(&"http://api.example/".parse().unwrap()));
        assert!(Scope::Any.contains(&"https://anything.example/".parse().unwrap()));
    }

    #[tokio::test]
    async fn rejected_unpaid_attempt_is_proved_again_and_resent_once() {
        let recorder = prover(Scope::origins(["https://api.example"]));
        let identity = IdentityClient::new(vec![recorder.clone() as Arc<dyn Prover>]).unwrap();
        let mut exchange = IdentityExchange::new(
            Scripted {
                status: 401,
                sent: Vec::new(),
            },
            &identity,
        );
        let response = exchange
            .send(get("https://api.example/paid"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let sent = &exchange.inner.sent;
        assert_eq!(sent.len(), 2, "resent once");
        assert!(sent[0].headers().get("x-retry").is_none());
        assert_eq!(sent[1].headers()["x-retry"], "1");
        assert!(sent[1].headers().get("authorization").is_none());
        // Each attempt gets a new context.
        assert_ne!(sent[0].headers()["x-proof"], sent[1].headers()["x-proof"]);
        // The resend's response is final.
        assert_eq!(*recorder.retries.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn paid_attempt_binds_its_challenge_and_is_never_resent() {
        let recorder = prover(Scope::Any);
        let identity = IdentityClient::new(vec![recorder.clone() as Arc<dyn Prover>]).unwrap();
        let mut exchange = IdentityExchange::new(
            Scripted {
                status: 401,
                sent: Vec::new(),
            },
            &identity,
        );
        let challenge = PaymentChallenge::new(
            "challenge-1",
            "api.example",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "1"})).unwrap(),
        );
        let credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xabc"));
        let mut request = get("https://api.example/paid");
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_str(&format_authorization(&credential).unwrap()).unwrap(),
        );
        exchange.send(request).await.unwrap();
        assert_eq!(exchange.inner.sent.len(), 1);
        assert_eq!(*recorder.retries.lock().unwrap(), 0);
        let contexts = recorder.contexts.lock().unwrap();
        assert_eq!(
            contexts[0].challenge.as_ref().map(|c| c.id.as_str()),
            Some("challenge-1")
        );
    }

    /// A request carrying a Payment credential for a Challenge that expires
    /// `expires_in` seconds from now.
    fn paid_get(url: &str, expires_in: i64) -> Request {
        let mut challenge = PaymentChallenge::new(
            "challenge-1",
            "api.example",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "1"})).unwrap(),
        );
        challenge.expires = Some(
            (time::OffsetDateTime::now_utc() + time::Duration::seconds(expires_in))
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap(),
        );
        let credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xabc"));
        let mut request = get(url);
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_str(&format_authorization(&credential).unwrap()).unwrap(),
        );
        request
    }

    /// Answers every request with `status` and `headers`, recording what it was sent.
    struct Answering {
        status: u16,
        headers: Vec<(&'static str, &'static str)>,
        sent: Vec<Request>,
    }

    impl Exchange for Answering {
        type Error = HttpError;

        async fn send(&mut self, request: Request) -> Result<Response, HttpError> {
            self.sent.push(request);
            let mut response = http_types::Response::builder().status(self.status);
            for (name, value) in &self.headers {
                response = response.header(*name, *value);
            }
            Ok(Response::from(response.body("token expired").unwrap()))
        }
    }

    fn answering(status: u16, headers: Vec<(&'static str, &'static str)>) -> Answering {
        Answering {
            status,
            headers,
            sent: Vec::new(),
        }
    }

    #[tokio::test]
    async fn paid_attempt_is_resent_once_after_a_401_with_the_same_credential() {
        let recorder = prover(Scope::Any);
        let identity = IdentityClient::new(vec![recorder.clone() as Arc<dyn Prover>]).unwrap();
        let mut exchange = IdentityExchange::new(answering(401, Vec::new()), &identity);
        let response = exchange
            .send(paid_get("https://api.example/paid", 300))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let sent = &exchange.inner.sent;
        assert_eq!(sent.len(), 2, "resent once");
        assert_eq!(
            sent[0].headers()["authorization"],
            sent[1].headers()["authorization"]
        );
        assert!(sent[0].headers().get("x-retry").is_none());
        assert_eq!(sent[1].headers()["x-retry"], "1");
        // Identity is proved again for the resend.
        assert_ne!(sent[0].headers()["x-proof"], sent[1].headers()["x-proof"]);
        assert_eq!(*recorder.retries.lock().unwrap(), 1);
        // A later attempt carries the headers the paid attempt was resent with.
        assert_eq!(exchange.carried.len(), 1);
    }

    #[tokio::test]
    async fn paid_attempt_stays_final_when_the_response_may_follow_settlement() {
        for (status, headers, expires_in) in [
            (403, Vec::new(), 300),
            (500, Vec::new(), 300),
            (401, vec![("payment-receipt", "receipt")], 300),
            (401, vec![("x-payment-response", "settled")], 300),
            // The Challenge has expired.
            (401, Vec::new(), -1),
        ] {
            let recorder = prover(Scope::Any);
            let identity = IdentityClient::new(vec![recorder.clone() as Arc<dyn Prover>]).unwrap();
            let mut exchange = IdentityExchange::new(answering(status, headers.clone()), &identity);
            let response = exchange
                .send(paid_get("https://api.example/paid", expires_in))
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), status);
            assert_eq!(exchange.inner.sent.len(), 1, "{status} {headers:?}");
            assert_eq!(*recorder.retries.lock().unwrap(), 0, "{status} {headers:?}");
        }
    }

    #[tokio::test]
    async fn paid_attempt_with_an_x402_credential_is_never_resent() {
        let recorder = prover(Scope::Any);
        let identity = IdentityClient::new(vec![recorder.clone() as Arc<dyn Prover>]).unwrap();
        let mut exchange = IdentityExchange::new(answering(401, Vec::new()), &identity);
        let mut request = paid_get("https://api.example/paid", 300);
        request
            .headers_mut()
            .insert("x-payment", HeaderValue::from_static("x402"));
        exchange.send(request).await.unwrap();
        assert_eq!(exchange.inner.sent.len(), 1);
        assert_eq!(*recorder.retries.lock().unwrap(), 0);
    }

    /// Proves the first attempt, then fails, and always asks to resend.
    struct FailsOnResend(Mutex<usize>);

    impl Prover for FailsOnResend {
        fn scope(&self) -> &Scope {
            &Scope::Any
        }

        fn prove<'a>(
            &'a self,
            _request: &'a mut Request,
            _context: &'a ProveContext,
        ) -> BoxFuture<'a, Result<(), ProverError>> {
            let mut proved = self.0.lock().unwrap();
            *proved += 1;
            let result = if *proved == 1 {
                Ok(())
            } else {
                Err(ProverError::new("refresh failed"))
            };
            Box::pin(std::future::ready(result))
        }

        fn retry<'a>(
            &'a self,
            _response: &'a ResponseParts,
            _context: RetryContext<'a>,
        ) -> BoxFuture<'a, Option<HeaderMap>> {
            Box::pin(std::future::ready(Some(HeaderMap::new())))
        }
    }

    #[tokio::test]
    async fn paid_attempt_returns_the_401_when_reproving_fails() {
        let identity = IdentityClient::new(vec![
            Arc::new(FailsOnResend(Mutex::default())) as Arc<dyn Prover>
        ])
        .unwrap();
        let mut exchange = IdentityExchange::new(answering(401, Vec::new()), &identity);
        let response = exchange
            .send(paid_get("https://api.example/paid", 300))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!exchange.unsent());
        assert_eq!(exchange.inner.sent.len(), 1);
        assert_eq!(response.text().await.unwrap(), "token expired");
    }

    /// Refuses every request.
    struct Refusing(Scope);

    impl Prover for Refusing {
        fn scope(&self) -> &Scope {
            &self.0
        }

        fn prove<'a>(
            &'a self,
            _request: &'a mut Request,
            _context: &'a ProveContext,
        ) -> BoxFuture<'a, Result<(), ProverError>> {
            Box::pin(std::future::ready(Err(ProverError::new("no token"))))
        }
    }

    #[tokio::test]
    async fn prover_failure_reports_the_attempt_unsent() {
        let identity =
            IdentityClient::new(vec![Arc::new(Refusing(Scope::Any)) as Arc<dyn Prover>]).unwrap();
        let mut exchange = IdentityExchange::new(
            Scripted {
                status: 200,
                sent: Vec::new(),
            },
            &identity,
        );
        assert!(exchange
            .send(get("https://api.example/paid"))
            .await
            .is_err());
        assert!(exchange.unsent());
        assert!(exchange.inner.sent.is_empty());
    }

    #[tokio::test]
    async fn prepare_reads_every_identity_required_line() {
        struct Requirements(Mutex<Vec<Requirement>>);
        impl Prover for Requirements {
            fn scope(&self) -> &Scope {
                &Scope::Any
            }
            fn prove<'a>(
                &'a self,
                _request: &'a mut Request,
                _context: &'a ProveContext,
            ) -> BoxFuture<'a, Result<(), ProverError>> {
                Box::pin(std::future::ready(Ok(())))
            }
            fn prepare<'a>(
                &'a self,
                _response: &'a ResponseParts,
                context: &'a PrepareContext,
            ) -> BoxFuture<'a, Result<(), ProverError>> {
                *self.0.lock().unwrap() = context.requirements.clone();
                Box::pin(std::future::ready(Ok(())))
            }
        }
        let recorder = Arc::new(Requirements(Mutex::default()));
        let identity = IdentityClient::new(vec![recorder.clone() as Arc<dyn Prover>]).unwrap();
        let response = http_types::Response::builder()
            .status(402)
            .header(requirements::HEADER, "kyc")
            .header(requirements::HEADER, "email")
            .body("")
            .unwrap();
        let challenge = PaymentChallenge::new(
            "id",
            "realm",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        );
        identity
            .prepare(&Response::from(response), &challenge)
            .await
            .unwrap();
        let kinds: Vec<String> = recorder
            .0
            .lock()
            .unwrap()
            .iter()
            .map(|requirement| requirement.kind.clone())
            .collect();
        assert_eq!(kinds, ["kyc", "email"]);
    }

    #[tokio::test]
    async fn out_of_scope_requests_are_sent_unchanged() {
        let recorder = prover(Scope::origins(["https://api.example"]));
        let identity = IdentityClient::new(vec![recorder.clone() as Arc<dyn Prover>]).unwrap();
        let mut exchange = IdentityExchange::new(
            Scripted {
                status: 401,
                sent: Vec::new(),
            },
            &identity,
        );
        exchange.send(get("https://other.example/")).await.unwrap();
        assert_eq!(exchange.inner.sent.len(), 1);
        assert!(exchange.inner.sent[0].headers().get("x-proof").is_none());
        assert!(recorder.contexts.lock().unwrap().is_empty());
    }
}
