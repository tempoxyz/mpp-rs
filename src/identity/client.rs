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
    /// ignored. Return `None` not to resend. Paid attempts are never resent.
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
            requirements: requirements::parse(
                response
                    .headers()
                    .get(requirements::HEADER)
                    .and_then(|value| value.to_str().ok()),
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

fn prover_failed(error: ProverError) -> HttpError {
    HttpError::Payment(MppError::Internal(format!(
        "identity prover failed: {error}"
    )))
}

/// The Challenge of a Payment credential in `headers`, if any.
fn credential_challenge(headers: &HeaderMap) -> Option<ChallengeEcho> {
    headers.values().find_map(|value| {
        let value = value.to_str().ok()?;
        extract_payment_scheme(value)?;
        parse_authorization(value)
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
}

impl<'a, X> IdentityExchange<'a, X> {
    pub(crate) fn new(inner: X, identity: &'a IdentityClient) -> Self {
        Self {
            inner,
            identity,
            carried: Vec::new(),
        }
    }
}

impl<X> IdentityExchange<'_, X>
where
    X: Exchange,
    X::Error: From<HttpError>,
{
    /// Proves and sends one attempt, with `headers` set before the provers run.
    async fn send_once(
        &mut self,
        mut request: Request,
        headers: &[(HeaderName, HeaderValue)],
    ) -> Result<(Option<Request>, Response), X::Error> {
        let scoped = self.identity.in_scope(request.url());
        if scoped.is_empty() {
            let sent = request.try_clone();
            return Ok((sent, self.inner.send(request).await?));
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
            prover
                .prove(&mut request, &context)
                .await
                .map_err(|error| X::Error::from(prover_failed(error)))?;
        }
        let sent = request.try_clone();
        Ok((sent, self.inner.send(request).await?))
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

    async fn send(&mut self, request: Request) -> Result<Response, Self::Error> {
        let paid = is_paid(&request);
        // Keep a copy only when the attempt may be resent: paid attempts never are.
        let original = if paid { None } else { request.try_clone() };
        let carried = self.carried.clone();
        let (sent, response) = self.send_once(request, &carried).await?;
        let status = response.status();
        let rejected = (status.is_client_error() || status.is_server_error())
            && status != StatusCode::PAYMENT_REQUIRED;
        let (Some(original), Some(sent), true) = (original, sent, rejected) else {
            return Ok(response);
        };
        let Some(resend) = resend_headers(self.identity, &response, &sent).await else {
            return Ok(response);
        };
        drop(response);
        // Later headers replace same-named earlier ones.
        let mut headers = carried;
        for (name, value) in resend {
            headers.retain(|(seen, _)| *seen != name);
            headers.push((name, value));
        }
        self.carried = headers.clone();
        Ok(self.send_once(original, &headers).await?.1)
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
