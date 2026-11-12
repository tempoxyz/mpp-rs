//! Client prover that presents and obtains attestations.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Request, StatusCode, Url};
use serde_json::Value;
use sfv::{BareItem, ListEntry};

use super::token::{decode, is_issuer, parse_header};
use super::{now, origin_of, trim_issuer, IdentityError, CLOCK_TOLERANCE, REFRESH_MARGIN};
use super::{HEADER, REQUIRED_HEADER};
use crate::identity::client::{
    ProveContext, Prover, ProverError, ResponseParts, RetryContext, Scope,
};
use crate::identity::BoxFuture;

/// One attestation a server requires: its type and, when named, its issuer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AttestationRequirement {
    /// Attestation type, such as `email`.
    pub attestation_type: String,
    /// Issuer the server names, if any.
    pub issuer: Option<String>,
}

/// What an acquirer is asked for: an attestation of `attestation_type` from
/// `issuer`, bound to `audience` (the request's origin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationRequest {
    /// Origin the attestation must be bound to: always the request's own.
    pub audience: String,
    /// Trusted issuer to ask.
    pub issuer: String,
    /// Attestation type.
    pub attestation_type: String,
}

type AcquireFuture = Pin<Box<dyn Future<Output = Result<Option<String>, IdentityError>> + Send>>;
type Acquire = dyn Fn(AttestationRequest) -> AcquireFuture + Send + Sync;

/// Cache key of an attestation: audience, issuer and type.
type Key = (String, String, String);

/// A cached attestation.
#[derive(Debug, Clone)]
struct Entry {
    token: String,
    aud: String,
    iss: String,
    attestation_type: String,
    iat: u64,
    exp: u64,
    /// When the client received it, for acquired attestations.
    received: Option<u64>,
}

impl Entry {
    fn from_token(token: &str, received: Option<u64>) -> Result<Self, IdentityError> {
        let claims = decode(token)
            .ok_or(IdentityError::MalformedAttestation)?
            .claims;
        let text = |key: &str| {
            claims
                .get(key)
                .and_then(Value::as_str)
                .map(String::from)
                .ok_or(IdentityError::MalformedAttestation)
        };
        let time = |key: &str| {
            claims
                .get(key)
                .and_then(Value::as_u64)
                .ok_or(IdentityError::MalformedAttestation)
        };
        Ok(Self {
            token: token.to_string(),
            aud: text("aud")?,
            iss: text("iss")?,
            attestation_type: text("type")?,
            iat: time("iat")?,
            exp: time("exp")?,
            received,
        })
    }

    fn key(&self) -> Key {
        (
            self.aud.clone(),
            self.iss.clone(),
            self.attestation_type.clone(),
        )
    }

    /// Seconds before expiry at which an unpaid attempt stops sending it: the
    /// refresh margin, capped at half its lifetime so a short-lived
    /// attestation is still sent. The lifetime of an acquired attestation runs
    /// from when the client received it, so an issuer whose clock trails the
    /// client's cannot force a new acquisition on each request.
    fn margin(&self) -> u64 {
        let start = self.received.unwrap_or(self.iat);
        REFRESH_MARGIN.min(self.exp.saturating_sub(start) / 2)
    }

    /// Whether it may be sent at `now`: on a paid attempt until it expires
    /// beyond the clock tolerance, since dropping it could reject a payment
    /// already pushed; on an unpaid one only outside the refresh margin, so it
    /// is replaced before paying.
    fn usable(&self, now: u64, paid: bool) -> bool {
        if self.exp.saturating_add(CLOCK_TOLERANCE) <= now {
            return false;
        }
        paid || self.exp.saturating_sub(now) > self.margin()
    }
}

/// How a retry answers one requirement.
enum Decision {
    Reuse(String),
    Acquire { rejected: Option<String> },
}

impl Decision {
    fn rank(&self) -> u8 {
        match self {
            Self::Reuse(_) => 0,
            Self::Acquire { .. } => 1,
        }
    }
}

#[derive(Default)]
struct State {
    slots: HashMap<Key, Entry>,
    /// Tokens a retry replaced because the server rejected them, dropped if a
    /// request carries them again.
    replaced: HashSet<String>,
}

/// The cache clones of a prover share.
#[derive(Default)]
struct Cache {
    state: Mutex<State>,
    /// One lock per cache key, held while acquiring, so concurrent retries
    /// for one requirement share an acquisition.
    acquiring: Mutex<HashMap<Key, Arc<tokio::sync::Mutex<()>>>>,
}

/// Presents identity attestations, and obtains them when a server asks, as
/// mppx's `Attestation.Client.prover`.
///
/// Each in-scope request carries, in `Identity-Attestation`, the cached
/// attestations whose audience is the request's origin: on a paid attempt
/// every one not expired beyond the clock tolerance, on an unpaid one only
/// those outside the refresh margin, so one close to expiry is replaced
/// before paying. When a server answers an unpaid request with 401 or 403 and
/// `Identity-Attestation-Required`, [`retry`](Self::retry) meets each listed
/// group with one attestation from a trusted issuer. Within a group of
/// alternatives it prefers one it holds, and otherwise acquires them in
/// listed order until one succeeds.
///
/// Trust is set by two lists together:
/// - `scope`: the origins that may receive attestations and ask for new
///   ones. The audience is always the request's own origin, never one a
///   server names, so a server cannot obtain an attestation it could replay
///   elsewhere.
/// - `issuers`: the issuers an acquirer may be asked for. A server only names
///   an issuer; an untrusted one could relay a code and obtain an attestation
///   for another origin.
///
/// Attestations are bearer proofs: they are never sent over plain `http`
/// except to localhost. Add it to an
/// [`IdentityClient`](crate::identity::client::IdentityClient) (such as with
/// [`ChargeClient::with_identity`](crate::client::ChargeClient::with_identity)),
/// which never follows redirects, so an attestation never reaches another origin.
///
/// Clones share their cache.
#[derive(Clone)]
pub struct AttestationProver {
    scope: Vec<String>,
    /// `scope` as a [`Scope`], for [`Prover::scope`].
    prover_scope: Scope,
    issuers: Vec<String>,
    types: Option<Vec<String>>,
    acquire: Option<Arc<Acquire>>,
    cache: Arc<Cache>,
}

impl std::fmt::Debug for AttestationProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationProver")
            .field("scope", &self.scope)
            .field("issuers", &self.issuers)
            .field("types", &self.types)
            .finish_non_exhaustive()
    }
}

impl AttestationProver {
    /// Creates a prover for requests to the `scope` origins (such as
    /// `https://api.example`) that trusts attestations from `issuers`.
    ///
    /// Fails when a scope entry is not an origin.
    pub fn new<S, I>(
        scope: impl IntoIterator<Item = S>,
        issuers: impl IntoIterator<Item = I>,
    ) -> Result<Self, IdentityError>
    where
        S: AsRef<str>,
        I: AsRef<str>,
    {
        let scope = scope
            .into_iter()
            .map(|origin| {
                let origin = origin.as_ref();
                Url::parse(origin)
                    .ok()
                    .filter(|url| url.origin().is_tuple())
                    .map(|url| origin_of(&url))
                    .ok_or_else(|| {
                        IdentityError::InvalidConfig(format!("scope {origin:?} is not an origin"))
                    })
            })
            .collect::<Result<Vec<String>, _>>()?;
        let issuers = issuers
            .into_iter()
            .map(|issuer| trim_issuer(issuer.as_ref()).to_string())
            .collect();
        Ok(Self {
            prover_scope: Scope::Origins(scope.clone()),
            scope,
            issuers,
            types: None,
            acquire: None,
            cache: Arc::default(),
        })
    }

    /// Answers only requirements of these types.
    pub fn with_types<T: AsRef<str>>(mut self, types: impl IntoIterator<Item = T>) -> Self {
        self.types = Some(types.into_iter().map(|t| t.as_ref().to_string()).collect());
        self
    }

    /// Obtains attestations with `acquire` when a server asks for one from a
    /// trusted issuer. `Ok(None)` declines; an attestation for another
    /// audience, issuer or type is discarded.
    pub fn with_acquire<F, Fut>(mut self, acquire: F) -> Self
    where
        F: Fn(AttestationRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Option<String>, IdentityError>> + Send + 'static,
    {
        self.acquire = Some(Arc::new(move |request| -> AcquireFuture {
            Box::pin(acquire(request))
        }));
        self
    }

    /// Adds attestations obtained beforehand to the cache.
    pub fn with_attestations<T: AsRef<str>>(
        self,
        attestations: impl IntoIterator<Item = T>,
    ) -> Result<Self, IdentityError> {
        for token in attestations {
            self.insert(token.as_ref())?;
        }
        Ok(self)
    }

    /// Adds an attestation obtained elsewhere to the cache, replacing any for
    /// the same audience, issuer and type.
    pub fn insert(&self, attestation: &str) -> Result<(), IdentityError> {
        let entry = Entry::from_token(attestation, None)?;
        self.state().slots.insert(entry.key(), entry);
        Ok(())
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.cache.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether requests to `url` are in this prover's scope and may carry
    /// attestations: an in-scope origin over `https` (or `http` to localhost).
    pub fn in_scope(&self, url: &Url) -> bool {
        let origin = origin_of(url);
        is_issuer(&origin) && self.scope.contains(&origin)
    }

    /// Adds the cached attestations for the request's origin to its
    /// `Identity-Attestation` header. `paid` says whether the request carries
    /// a payment credential.
    ///
    /// An attestation the request already carries (such as one a retry
    /// added) is dropped once it has expired beyond the clock tolerance or a
    /// retry replaced it.
    pub fn present(&self, request: &mut Request, paid: bool) {
        if !self.in_scope(request.url()) {
            return;
        }
        let origin = origin_of(request.url());
        let time = now();
        let carried = header_tokens(request.headers());
        let mut state = self.state();
        state
            .replaced
            .retain(|token| !expired(token, &origin, time));
        let mut kept: Vec<String> = Vec::new();
        for token in &carried {
            if !kept.contains(token)
                && !state.replaced.contains(token)
                && !expired(token, &origin, time)
            {
                kept.push(token.clone());
            }
        }
        let added: Vec<String> = state
            .slots
            .values()
            .filter(|entry| {
                entry.aud == origin && entry.usable(time, paid) && !kept.contains(&entry.token)
            })
            .map(|entry| entry.token.clone())
            .collect();
        drop(state);
        if added.is_empty() && kept.len() == carried.len() {
            return;
        }
        let value = kept.into_iter().chain(added).collect::<Vec<_>>().join(", ");
        let headers = request.headers_mut();
        match HeaderValue::from_str(&value) {
            Ok(value) if !value.is_empty() => {
                headers.insert(HEADER, value);
            }
            _ => {
                headers.remove(HEADER);
            }
        }
    }

    /// Decides whether to resend a rejected unpaid request, and with which
    /// `Identity-Attestation` value.
    ///
    /// `request_url` and `request_headers` are those of the request that got
    /// `response`. [`Prover::retry`] calls it. Returns `Ok(None)` when the response is not a 401 or 403
    /// asking for an attestation this prover can supply, when it came from
    /// another origin (a followed redirect), or when every acquirer declined.
    /// An acquisition error is returned only when nothing was obtained.
    ///
    /// Never resend a paid request with the result: its payment may already
    /// have settled.
    pub fn retry_value(
        &self,
        request_url: &Url,
        request_headers: &HeaderMap,
        response: &ResponseParts,
    ) -> impl Future<Output = Result<Option<HeaderValue>, IdentityError>> + Send + '_ {
        // Read what the retry needs now, so the future does not borrow the response.
        let answerable = matches!(
            response.status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        );
        // The resend goes to the request's URL, so attestations are bound to
        // its origin, and a response from any other origin is never answered.
        let audience = origin_of(request_url);
        let answerable =
            answerable && origin_of(&response.url) == audience && self.in_scope(request_url);
        let groups = if answerable {
            requirements(&response.headers)
        } else {
            Vec::new()
        };
        let sent = sent_tokens(request_headers);
        self.answer(audience, groups, sent)
    }

    async fn answer(
        &self,
        audience: String,
        groups: Vec<Vec<AttestationRequirement>>,
        sent: Vec<(Key, Vec<String>)>,
    ) -> Result<Option<HeaderValue>, IdentityError> {
        let mut obtained: Vec<(Key, String)> = Vec::new();
        let mut tried: HashSet<Key> = HashSet::new();
        let mut failure = None;

        // Every group must be met; one alternative meets it.
        for group in groups {
            let alternatives = self.trusted(&group, &audience);
            if alternatives
                .iter()
                .any(|(key, _)| obtained.iter().any(|(k, _)| k == key))
            {
                continue;
            }
            let mut decided: Vec<(Key, Decision)> = alternatives
                .into_iter()
                .filter(|(key, _)| !tried.contains(key))
                .map(|(key, _)| {
                    let decision = self.decide(&key, tokens_for(&sent, &key));
                    (key, decision)
                })
                .collect();
            decided.sort_by_key(|(_, decision)| decision.rank());
            for (key, decision) in decided {
                tried.insert(key.clone());
                let result = match decision {
                    Decision::Reuse(token) => Ok(Some(token)),
                    Decision::Acquire { .. } => self.acquire(&key, tokens_for(&sent, &key)).await,
                };
                match result {
                    Ok(Some(token)) => {
                        obtained.push((key, token));
                        break;
                    }
                    Ok(None) => {}
                    // One issuer failing does not stop the next alternative or the other groups.
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
            }
        }

        // A failure surfaces only when nothing was obtained, so another
        // attestation still resends.
        if obtained.is_empty() {
            return failure.map_or(Ok(None), Err);
        }
        let is_obtained = |key: &Key| obtained.iter().any(|(k, _)| k == key);
        let mut state = self.state();
        let mut kept = Vec::new();
        for (key, tokens) in &sent {
            if is_obtained(key) {
                state.replaced.extend(tokens.iter().cloned());
            } else {
                kept.extend(tokens.iter().cloned());
            }
        }
        drop(state);
        let value = kept
            .into_iter()
            .chain(obtained.into_iter().map(|(_, token)| token))
            .collect::<Vec<_>>()
            .join(", ");
        Ok(HeaderValue::from_str(&value).ok())
    }

    /// The trusted requirements of a group, each once, in listed order.
    fn trusted(
        &self,
        group: &[AttestationRequirement],
        audience: &str,
    ) -> Vec<(Key, AttestationRequirement)> {
        let mut result: Vec<(Key, AttestationRequirement)> = Vec::new();
        for requirement in group {
            let Some(issuer) = &requirement.issuer else {
                continue;
            };
            if !self.issuers.contains(issuer) {
                continue;
            }
            if let Some(types) = &self.types {
                if !types.contains(&requirement.attestation_type) {
                    continue;
                }
            }
            let key = (
                audience.to_string(),
                issuer.clone(),
                requirement.attestation_type.clone(),
            );
            if !result.iter().any(|(k, _)| *k == key) {
                result.push((key, requirement.clone()));
            }
        }
        result
    }

    /// Decides how a retry answers one requirement, from the cache and the
    /// tokens for it that the rejected request sent:
    /// - A cached attestation the request sent is replaced: the server rejected it.
    /// - A different, unexpired one is reused: it is newer than what the
    ///   request sent, or the request sent none and it is outside the refresh margin.
    /// - Otherwise a new one is acquired.
    fn decide(&self, key: &Key, sent: &[String]) -> Decision {
        let state = self.state();
        let Some(entry) = state.slots.get(key) else {
            return Decision::Acquire { rejected: None };
        };
        let time = now();
        if !entry.usable(time, true) || sent.contains(&entry.token) {
            return Decision::Acquire {
                rejected: Some(entry.token.clone()),
            };
        }
        if !sent.is_empty() || entry.usable(time, false) {
            return Decision::Reuse(entry.token.clone());
        }
        Decision::Acquire { rejected: None }
    }

    /// Acquires an attestation for `key`, or joins an acquisition another
    /// retry started and reuses its result.
    async fn acquire(&self, key: &Key, sent: &[String]) -> Result<Option<String>, IdentityError> {
        let Some(acquire) = self.acquire.clone() else {
            return Ok(None);
        };
        let lock = self
            .cache
            .acquiring
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_default()
            .clone();
        let _guard = lock.lock().await;
        // Another retry may have acquired one while this one waited.
        let rejected = match self.decide(key, sent) {
            Decision::Reuse(token) => return Ok(Some(token)),
            Decision::Acquire { rejected } => rejected,
        };
        if let Some(rejected) = rejected {
            // The server rejected it, so it is not kept while a new one is acquired.
            let mut state = self.state();
            if state
                .slots
                .get(key)
                .is_some_and(|entry| entry.token == rejected)
            {
                state.slots.remove(key);
            }
        }
        let (audience, issuer, attestation_type) = key.clone();
        let token = acquire(AttestationRequest {
            audience,
            issuer,
            attestation_type,
        })
        .await?;
        let Some(token) = token else {
            return Ok(None);
        };
        let entry = Entry::from_token(&token, Some(now()))?;
        // Only an attestation for this requirement is kept, so an issuer cannot plant one.
        if entry.key() != *key {
            return Ok(None);
        }
        self.state().slots.insert(key.clone(), entry);
        Ok(Some(token))
    }
}

/// Parses the attestation requirements of a rejected response as groups,
/// every one of which a request must meet with any one of its requirements:
///
/// - An item, such as `phone;issuer="https://a.example"`, is a group of one.
/// - An inner list, such as
///   `(email;issuer="https://a.example" email;issuer="https://b.example")`,
///   is a group of alternatives.
///
/// Malformed members are skipped, and a group left with none is dropped.
pub fn requirements(headers: &HeaderMap) -> Vec<Vec<AttestationRequirement>> {
    let values: Vec<&str> = headers
        .get_all(REQUIRED_HEADER)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    if values.is_empty() {
        return Vec::new();
    }
    let joined = values.join(", ");
    let Ok(list) = sfv::Parser::new(joined.as_str()).parse::<sfv::List>() else {
        return Vec::new();
    };
    list.iter()
        .map(|member| {
            let items = match member {
                ListEntry::Item(item) => std::slice::from_ref(item),
                ListEntry::InnerList(inner) => inner.items.as_slice(),
            };
            items
                .iter()
                .filter_map(|item| {
                    let BareItem::Token(attestation_type) = &item.bare_item else {
                        return None;
                    };
                    // A repeated key keeps its last value (RFC 9651).
                    let issuer = match item
                        .params
                        .iter()
                        .rev()
                        .find(|(key, _)| key.as_str() == "issuer")
                    {
                        None => None,
                        Some((_, BareItem::String(issuer))) if is_issuer(issuer.as_str()) => {
                            Some(issuer.as_str().to_owned())
                        }
                        Some(_) => return None,
                    };
                    Some(AttestationRequirement {
                        attestation_type: attestation_type.as_str().to_owned(),
                        issuer,
                    })
                })
                .collect::<Vec<_>>()
        })
        .filter(|group| !group.is_empty())
        .collect()
}

/// The tokens `sent` holds for `key`.
fn tokens_for<'a>(sent: &'a [(Key, Vec<String>)], key: &Key) -> &'a [String] {
    sent.iter()
        .find(|(k, _)| k == key)
        .map(|(_, tokens)| tokens.as_slice())
        .unwrap_or(&[])
}

fn header_tokens(headers: &HeaderMap) -> Vec<String> {
    parse_header(
        headers
            .get_all(HEADER)
            .iter()
            .filter_map(|value| value.to_str().ok()),
    )
}

/// Whether a token for `origin` has expired beyond the clock tolerance at `now`.
fn expired(token: &str, origin: &str, now: u64) -> bool {
    let Some(decoded) = decode(token) else {
        return false;
    };
    decoded.claims.get("aud").and_then(Value::as_str) == Some(origin)
        && decoded
            .claims
            .get("exp")
            .and_then(Value::as_u64)
            .is_some_and(|exp| exp.saturating_add(CLOCK_TOLERANCE) <= now)
}

/// The attestation tokens a request sent, by cache key, in first-seen order.
fn sent_tokens(headers: &HeaderMap) -> Vec<(Key, Vec<String>)> {
    let mut sent: Vec<(Key, Vec<String>)> = Vec::new();
    for token in header_tokens(headers) {
        let Some(decoded) = decode(&token) else {
            continue;
        };
        let text = |key: &str| {
            decoded
                .claims
                .get(key)
                .and_then(Value::as_str)
                .map(String::from)
        };
        let (Some(aud), Some(iss), Some(kind)) = (text("aud"), text("iss"), text("type")) else {
            continue;
        };
        let key = (aud, iss, kind);
        match sent.iter_mut().find(|(k, _)| *k == key) {
            Some((_, tokens)) => tokens.push(token),
            None => sent.push((key, vec![token])),
        }
    }
    sent
}

/// Credential headers whose presence makes a request a paid attempt, lowercased.
const X402_CREDENTIAL_HEADERS: &[&str] = &["payment-signature", "x-payment"];

/// Whether `request` is a paid attempt: it answers a Challenge, or carries an
/// x402 credential.
fn is_paid(request: &Request, context: &ProveContext) -> bool {
    context.challenge.is_some()
        || X402_CREDENTIAL_HEADERS
            .iter()
            .any(|name| request.headers().contains_key(*name))
}

impl Prover for AttestationProver {
    fn scope(&self) -> &Scope {
        &self.prover_scope
    }

    fn prove<'a>(
        &'a self,
        request: &'a mut Request,
        context: &'a ProveContext,
    ) -> BoxFuture<'a, Result<(), ProverError>> {
        let paid = is_paid(request, context);
        self.present(request, paid);
        Box::pin(std::future::ready(Ok(())))
    }

    /// Resends an unpaid request rejected with `Identity-Attestation-Required`
    /// once, with the attestations [`retry_value`](Self::retry_value)
    /// returns. An acquisition that fails resends nothing: the client gets the
    /// rejection.
    fn retry<'a>(
        &'a self,
        response: &'a ResponseParts,
        context: RetryContext<'a>,
    ) -> BoxFuture<'a, Option<HeaderMap>> {
        Box::pin(async move {
            let value = self
                .retry_value(context.request.url(), context.request.headers(), response)
                .await
                .ok()
                .flatten()?;
            let mut headers = HeaderMap::new();
            headers.insert(HeaderName::from_static("identity-attestation"), value);
            Some(headers)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ext::attestation::sign;
    use crate::identity::ext::attestation::token::tests::{signing_key, AUDIENCE, ISSUER, KID};

    fn token(exp_in: i64, edit: impl FnOnce(&mut Value)) -> String {
        let now = now() as i64;
        let mut claims = serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": "a@example.com", "type": "email",
            "iat": now, "exp": now + exp_in, "jti": format!("{}", rand_id()),
        });
        edit(&mut claims);
        sign(&claims, &signing_key(), KID).unwrap()
    }

    fn rand_id() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        NEXT.fetch_add(1, Ordering::SeqCst)
    }

    fn request(url: &str) -> Request {
        Request::new(reqwest::Method::GET, url.parse().unwrap())
    }

    fn sent(request: &Request) -> Vec<String> {
        header_tokens(request.headers())
    }

    #[test]
    fn requirements_parse_groups_and_skip_malformed_members() {
        let mut headers = HeaderMap::new();
        headers.insert(
            REQUIRED_HEADER,
            r#"email;issuer="https://a.example", (email;issuer="https://b.example" email;issuer="http://evil.example"), phone, sms;issuer=bad"#
                .parse()
                .unwrap(),
        );
        let groups = requirements(&headers);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0][0].issuer.as_deref(), Some("https://a.example"));
        assert_eq!(groups[1].len(), 1, "a plain-http issuer is skipped");
        assert_eq!(groups[2][0].issuer, None);
        headers.insert(REQUIRED_HEADER, "email,".parse().unwrap());
        assert!(requirements(&headers).is_empty());
    }

    #[test]
    fn proves_only_in_scope_and_never_over_plain_http() {
        let prover = AttestationProver::new([AUDIENCE, "http://insecure.example"], [ISSUER])
            .unwrap()
            .with_attestations([token(3_600, |_| {})])
            .unwrap();
        let mut in_scope = request("https://api.example/x");
        prover.present(&mut in_scope, false);
        assert_eq!(sent(&in_scope).len(), 1);

        let mut other = request("https://other.example/x");
        prover.present(&mut other, false);
        assert!(sent(&other).is_empty());

        let insecure = token(3_600, |c| c["aud"] = "http://insecure.example".into());
        prover.insert(&insecure).unwrap();
        let mut plain = request("http://insecure.example/x");
        prover.present(&mut plain, false);
        assert!(sent(&plain).is_empty());
    }

    #[test]
    fn unpaid_attempts_skip_attestations_near_expiry_but_paid_ones_keep_them() {
        // Expires in 100 s, issued 1000 s ago: inside the 300 s refresh margin.
        let near = token(100, |c| c["iat"] = (now() - 1_000).into());
        let prover = AttestationProver::new([AUDIENCE], [ISSUER])
            .unwrap()
            .with_attestations([&near])
            .unwrap();
        let mut unpaid = request("https://api.example/");
        prover.present(&mut unpaid, false);
        assert!(sent(&unpaid).is_empty());
        let mut paid = request("https://api.example/");
        prover.present(&mut paid, true);
        assert_eq!(sent(&paid), vec![near]);
    }

    #[test]
    fn rejects_scope_entries_that_are_not_origins() {
        assert!(AttestationProver::new(["not a url"], [ISSUER]).is_err());
        assert!(AttestationProver::new(["data:text/plain,hi"], [ISSUER]).is_err());
    }
}
