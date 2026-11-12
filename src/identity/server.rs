//! Server-side identity: verifiers, payment checks and the per-request
//! state that runs them, as mppx's `Identity.Server`.

use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use http_types::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};

use super::requirements::{self, ALTERNATIVE_HEADERS};
use super::{BoxFuture, Rejection, RejectionStatus, Requirement, Verification};
use crate::protocol::core::{ChallengeEcho, PaymentCredential};

type AnyValue = Arc<dyn Any + Send + Sync>;

fn next_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

// ==================== Request ====================

/// The request an identity verifier or payment check sees: its method, URI
/// and headers, and a per-request memo.
///
/// One request yields one [`IdentityRequest`], shared by every verifier and
/// the payment check that run for it, so a verifier can compute something
/// once (such as spending a single-use proof) with [`memoize`](Self::memoize).
pub struct IdentityRequest {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    memo: Mutex<HashMap<u64, AnyValue>>,
}

impl IdentityRequest {
    /// A request with `method`, `uri` and `headers`.
    pub fn new(method: Method, uri: Uri, headers: HeaderMap) -> Self {
        Self {
            method,
            uri,
            headers,
            memo: Mutex::new(HashMap::new()),
        }
    }

    /// A request from an HTTP request's head.
    pub fn from_parts(parts: &http_types::request::Parts) -> Self {
        Self::new(
            parts.method.clone(),
            parts.uri.clone(),
            parts.headers.clone(),
        )
    }

    /// The request method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The request URI, as the server received it (often only a path).
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// The request headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The first value of header `name`, if it is visible ASCII.
    pub fn header(&self, name: impl header::AsHeaderName) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// Runs `compute` once per request and key, returning its value to every
    /// later call with the same key.
    pub async fn memoize<T, F>(&self, key: &MemoKey, compute: F) -> T
    where
        T: Clone + Send + Sync + 'static,
        F: Future<Output = T>,
    {
        if let Some(value) = self.memoized::<T>(key) {
            return value;
        }
        let value = compute.await;
        let mut memo = self.memo.lock().unwrap_or_else(|e| e.into_inner());
        let stored = memo
            .entry(key.0)
            .or_insert_with(|| Arc::new(value.clone()) as AnyValue);
        stored.downcast_ref::<T>().cloned().unwrap_or(value)
    }

    fn memoized<T: Clone + 'static>(&self, key: &MemoKey) -> Option<T> {
        let memo = self.memo.lock().unwrap_or_else(|e| e.into_inner());
        memo.get(&key.0)?.downcast_ref::<T>().cloned()
    }
}

impl fmt::Debug for IdentityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Headers may carry bearer proofs: never print them.
        f.debug_struct("IdentityRequest")
            .field("method", &self.method)
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

/// A key for [`IdentityRequest::memoize`], unique to the process.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct MemoKey(u64);

impl MemoKey {
    /// A new key, distinct from every other.
    pub fn new() -> Self {
        Self(next_id())
    }
}

impl Default for MemoKey {
    fn default() -> Self {
        Self::new()
    }
}

// ==================== Verifiers and payment checks ====================

/// Verifies one identity protocol on the server, before any payment
/// Challenge is issued, as mppx's `Verifier`.
pub trait Verifier: Send + Sync + 'static {
    /// The verified identity.
    type Value: Clone + Send + Sync + 'static;

    /// Whether the verifier reads its credential from `Authorization`. A route
    /// that uses it needs a server created with `requires_auth`, so Payment
    /// Credentials travel in `Payment-Authorization`.
    fn reads_authorization(&self) -> bool {
        false
    }

    /// Returns the protocol's verification outcome for the request.
    fn verify<'a>(
        &'a self,
        request: &'a IdentityRequest,
    ) -> BoxFuture<'a, Verification<Self::Value>>;

    /// The members of an [`any_of`] verifier. Only [`AnyOf`] returns some.
    #[doc(hidden)]
    fn any_of_members(&self) -> Option<&[ErasedVerifier]> {
        None
    }
}

/// What a [`PaymentCheck`] checks: the request, the answered Challenge and,
/// on the paid retry, its Credential.
#[derive(Debug, Clone, Copy)]
pub struct PaymentCheckInput<'a> {
    /// The request.
    pub request: &'a IdentityRequest,
    /// The Challenge the Credential answers.
    pub challenge: &'a ChallengeEcho,
    /// The Credential of the paid retry.
    pub credential: Option<&'a PaymentCredential>,
}

/// Checks the payer's identity on the paid retry, before the Credential is
/// settled, as mppx's experimental `PaymentCheck`.
///
/// Every 402 the route issues lists [`requires`](Self::requires) in its
/// `Identity-Required` header. [`verify`](Self::verify) runs once on the paid
/// retry, after the Credential's HMAC, pinned fields and expiry are checked;
/// any rejection is sent with its fixed status code and no fresh 402, because
/// the client may already have pushed the payment.
pub trait PaymentCheck: Send + Sync + 'static {
    /// The verified payer identity.
    type Value: Clone + Send + Sync + 'static;

    /// Identities the check requires, advertised in every 402 of the route.
    fn requires(&self) -> &[Requirement];

    /// Returns the check's outcome for the paid retry.
    fn verify<'a>(
        &'a self,
        input: PaymentCheckInput<'a>,
    ) -> BoxFuture<'a, Verification<Self::Value>>;
}

/// A shared verifier or payment check, and the key its verified value is
/// looked up by in [`IdentityResults`].
///
/// mppx looks values up by the verifier object itself; Rust has no object
/// identity, so each handle carries an ID. Clones share it.
pub struct Handle<V> {
    inner: Arc<V>,
    id: u64,
}

impl<V> Handle<V> {
    /// Wraps a verifier or payment check.
    pub fn new(inner: V) -> Self {
        Self {
            inner: Arc::new(inner),
            id: next_id(),
        }
    }
}

impl<V> Clone for Handle<V> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            id: self.id,
        }
    }
}

impl<V> std::ops::Deref for Handle<V> {
    type Target = V;

    fn deref(&self) -> &V {
        &self.inner
    }
}

impl<V> fmt::Debug for Handle<V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

trait DynVerifier: Send + Sync {
    fn verify_any<'a>(
        &'a self,
        request: &'a IdentityRequest,
    ) -> BoxFuture<'a, Verification<AnyValue>>;
    fn reads_authorization(&self) -> bool;
    fn members(&self) -> Option<&[ErasedVerifier]>;
}

impl<V: Verifier> DynVerifier for V {
    fn verify_any<'a>(
        &'a self,
        request: &'a IdentityRequest,
    ) -> BoxFuture<'a, Verification<AnyValue>> {
        Box::pin(async move {
            Verifier::verify(self, request)
                .await
                .map(|value| Arc::new(value) as AnyValue)
        })
    }

    fn reads_authorization(&self) -> bool {
        Verifier::reads_authorization(self)
    }

    fn members(&self) -> Option<&[ErasedVerifier]> {
        self.any_of_members()
    }
}

/// A verifier of any value type, as a route or [`any_of`] holds it.
#[derive(Clone)]
pub struct ErasedVerifier {
    id: u64,
    inner: Arc<dyn DynVerifier>,
}

impl ErasedVerifier {
    /// Whether the verifier, or any of its `any_of` members, reads `Authorization`.
    pub fn reads_authorization(&self) -> bool {
        self.inner.reads_authorization()
    }
}

impl fmt::Debug for ErasedVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErasedVerifier")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<V: Verifier> From<&Handle<V>> for ErasedVerifier {
    fn from(handle: &Handle<V>) -> Self {
        Self {
            id: handle.id,
            inner: handle.inner.clone(),
        }
    }
}

impl<V: Verifier> From<Handle<V>> for ErasedVerifier {
    fn from(handle: Handle<V>) -> Self {
        Self::from(&handle)
    }
}

trait DynCheck: Send + Sync {
    fn requires(&self) -> &[Requirement];
    fn verify_any<'a>(
        &'a self,
        input: PaymentCheckInput<'a>,
    ) -> BoxFuture<'a, Verification<AnyValue>>;
}

impl<C: PaymentCheck> DynCheck for C {
    fn requires(&self) -> &[Requirement] {
        PaymentCheck::requires(self)
    }

    fn verify_any<'a>(
        &'a self,
        input: PaymentCheckInput<'a>,
    ) -> BoxFuture<'a, Verification<AnyValue>> {
        Box::pin(async move {
            PaymentCheck::verify(self, input)
                .await
                .map(|value| Arc::new(value) as AnyValue)
        })
    }
}

/// A payment check of any value type, as a route holds it.
#[derive(Clone)]
pub struct ErasedCheck {
    id: u64,
    inner: Arc<dyn DynCheck>,
}

impl ErasedCheck {
    /// Identities the check requires.
    pub fn requires(&self) -> &[Requirement] {
        self.inner.requires()
    }
}

impl fmt::Debug for ErasedCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErasedCheck")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl<C: PaymentCheck> From<&Handle<C>> for ErasedCheck {
    fn from(handle: &Handle<C>) -> Self {
        Self {
            id: handle.id,
            inner: handle.inner.clone(),
        }
    }
}

impl<C: PaymentCheck> From<Handle<C>> for ErasedCheck {
    fn from(handle: Handle<C>) -> Self {
        Self::from(&handle)
    }
}

// ==================== Combining outcomes ====================

/// Decides one rejection from rejected outcomes: the outcome whose status has
/// the highest precedence decides status and reason (the first on ties), and
/// the headers of every outcome are merged in order.
pub(crate) fn decide(rejections: &[Rejection]) -> Rejection {
    let winner = rejections
        .iter()
        .min_by_key(|rejection| rejection.status.rank())
        .cloned()
        .unwrap_or_else(|| Rejection::invalid("An identity decision needs a rejected outcome."));
    let mut headers = HeaderMap::new();
    for rejection in rejections {
        for (name, value) in &rejection.headers {
            headers.append(name.clone(), value.clone());
        }
    }
    Rejection { headers, ..winner }
}

/// Merges the headers of `any_of` members: each requirements header once,
/// its values grouped as alternatives; every other header as it is.
fn group_alternatives(rejections: &[Rejection]) -> HeaderMap {
    let mut others = HeaderMap::new();
    let mut grouped: Vec<(HeaderName, Vec<String>)> = Vec::new();
    for rejection in rejections {
        for (name, value) in &rejection.headers {
            if !ALTERNATIVE_HEADERS.contains(&name.as_str()) {
                others.append(name.clone(), value.clone());
                continue;
            }
            let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
            match grouped.iter_mut().find(|(seen, _)| seen == name) {
                Some((_, values)) => values.push(value),
                None => grouped.push((name.clone(), vec![value])),
            }
        }
    }
    for (name, values) in grouped {
        if let Ok(value) = HeaderValue::from_str(&requirements::alternatives(&values)) {
            others.append(name, value);
        }
    }
    others
}

/// The value of an `any_of` verifier while it is evaluated: the first valid
/// member's index and value.
struct AnyOfValue {
    index: usize,
    value: AnyValue,
}

/// Combines `any_of` members' outcomes: valid with the first valid member,
/// otherwise the precedence rule with grouped headers.
fn combine_any_of(outcomes: Vec<Verification<AnyValue>>) -> Verification<AnyOfValue> {
    let mut rejections = Vec::new();
    for (index, outcome) in outcomes.into_iter().enumerate() {
        match outcome {
            Verification::Valid(value) => return Verification::Valid(AnyOfValue { index, value }),
            Verification::Rejected(rejection) => rejections.push(rejection),
        }
    }
    let mut decision = decide(&rejections);
    decision.headers = group_alternatives(&rejections);
    if decision.status == RejectionStatus::Missing {
        decision.reason = "None of the accepted identity proofs was presented.".to_owned();
    }
    Verification::Rejected(decision)
}

// ==================== any_of and from_fn ====================

/// A verifier that accepts the first of several identity protocols that verifies.
pub struct AnyOf {
    members: Vec<ErasedVerifier>,
}

/// The verified value of an [`AnyOf`]: which member verified.
///
/// Read that member's own value from [`IdentityResults`] with its handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnyOfMatch {
    /// Index of the first member that verified.
    pub index: usize,
}

impl Verifier for AnyOf {
    type Value = AnyOfMatch;

    fn reads_authorization(&self) -> bool {
        self.members.iter().any(ErasedVerifier::reads_authorization)
    }

    fn verify<'a>(
        &'a self,
        request: &'a IdentityRequest,
    ) -> BoxFuture<'a, Verification<AnyOfMatch>> {
        Box::pin(async move {
            let mut outcomes = Vec::with_capacity(self.members.len());
            for member in &self.members {
                outcomes.push(member.inner.verify_any(request).await);
            }
            combine_any_of(outcomes).map(|matched| AnyOfMatch {
                index: matched.index,
            })
        })
    }

    fn any_of_members(&self) -> Option<&[ErasedVerifier]> {
        Some(&self.members)
    }
}

/// Accepts the first of several identity protocols that verifies, as mppx's `anyOf`.
///
/// Every member runs, so each presented proof's replay nonce is consumed even
/// when an earlier member already verified. The result is valid if any member
/// verifies (the first valid member wins). Otherwise the rejected member whose
/// status has the highest precedence decides, with every member's headers;
/// members' `Identity-Attestation-Required` values become one inner list of
/// alternatives, so a client obtains one of them rather than all.
///
/// # Panics
///
/// With fewer than two members, as mppx's type requires.
pub fn any_of(members: impl IntoIterator<Item = ErasedVerifier>) -> Handle<AnyOf> {
    let members: Vec<_> = members.into_iter().collect();
    assert!(
        members.len() >= 2,
        "identity any_of needs at least two verifiers"
    );
    Handle::new(AnyOf { members })
}

/// A verifier built from a function: see [`from_fn`].
pub struct FnVerifier<T, F> {
    verify: F,
    challenge: HeaderMap,
    _value: std::marker::PhantomData<fn() -> T>,
}

impl<T, F, Fut> Verifier for FnVerifier<T, F>
where
    T: Clone + Send + Sync + 'static,
    F: Fn(&IdentityRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<T>, Rejection>> + Send + 'static,
{
    type Value = T;

    fn verify<'a>(&'a self, request: &'a IdentityRequest) -> BoxFuture<'a, Verification<T>> {
        let pending = (self.verify)(request);
        Box::pin(async move {
            match pending.await {
                Ok(Some(value)) => Verification::Valid(value),
                // A lookup that found nothing: the request carries no identity.
                Ok(None) => {
                    Verification::Rejected(Rejection::missing().with_headers(&self.challenge))
                }
                Err(rejection) => Verification::Rejected(rejection.with_headers(&self.challenge)),
            }
        })
    }
}

/// Creates a verifier from a function, such as a lookup in your own database,
/// session store or KYC provider, as mppx's `Identity.from`.
///
/// The function returns `Ok(Some(identity))`, which the route reads from
/// [`IdentityResults::get`]; `Ok(None)` when the request carries none
/// (`missing`, 401); or `Err(rejection)` to reject the identity it carries.
/// The returned future must not borrow the request: copy what it needs first.
///
/// ```
/// use mpp::identity::{from_fn, Rejection};
///
/// let customer = from_fn(|request| {
///     let key = request.header("x-api-key").map(str::to_owned);
///     async move {
///         match key.as_deref() {
///             None => Ok(None),
///             Some("secret") => Ok(Some("customer-1".to_owned())),
///             Some(_) => Err(Rejection::forbidden("Unknown API key.")),
///         }
///     }
/// });
/// # let _ = customer;
/// ```
pub fn from_fn<T, F, Fut>(verify: F) -> Handle<FnVerifier<T, F>>
where
    T: Clone + Send + Sync + 'static,
    F: Fn(&IdentityRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<T>, Rejection>> + Send + 'static,
{
    from_fn_with_challenge(HeaderMap::new(), verify)
}

/// Like [`from_fn`], sending `challenge` headers with every rejection to
/// tell the client what identity to present.
pub fn from_fn_with_challenge<T, F, Fut>(
    challenge: HeaderMap,
    verify: F,
) -> Handle<FnVerifier<T, F>>
where
    T: Clone + Send + Sync + 'static,
    F: Fn(&IdentityRequest) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Option<T>, Rejection>> + Send + 'static,
{
    Handle::new(FnVerifier {
        verify,
        challenge,
        _value: std::marker::PhantomData,
    })
}

// ==================== Per-request context ====================

type Values = HashMap<u64, AnyValue>;

/// The combined outcome of verifiers or a payment check.
#[derive(Clone)]
pub(crate) enum Outcome {
    Valid(Values),
    Rejected(Rejection),
}

/// The identity state of one request. Every verifier runs at most once per
/// context, and a payment check at most once per Challenge and attempt, so
/// replay-protected nonces are consumed once.
#[derive(Clone)]
pub struct IdentityContext {
    inner: Arc<ContextInner>,
}

struct ContextInner {
    request: IdentityRequest,
    verifications: Mutex<HashMap<u64, Verification<AnyValue>>>,
    checks: Mutex<HashMap<(u64, String, bool), Outcome>>,
}

impl fmt::Debug for IdentityContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityContext")
            .field("request", &self.inner.request)
            .finish_non_exhaustive()
    }
}

impl IdentityContext {
    /// The identity context of `request`.
    pub fn new(request: IdentityRequest) -> Self {
        Self {
            inner: Arc::new(ContextInner {
                request,
                verifications: Mutex::new(HashMap::new()),
                checks: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// The request.
    pub fn request(&self) -> &IdentityRequest {
        &self.inner.request
    }

    /// Runs one verifier, or each `any_of` member, at most once per context.
    fn evaluate<'a>(
        &'a self,
        verifier: &'a ErasedVerifier,
    ) -> BoxFuture<'a, Verification<AnyValue>> {
        Box::pin(async move {
            if let Some(outcome) = self.lock_verifications().get(&verifier.id) {
                return outcome.clone();
            }
            let outcome = match verifier.inner.members() {
                Some(members) => {
                    let mut outcomes = Vec::with_capacity(members.len());
                    for member in members {
                        outcomes.push(self.evaluate(member).await);
                    }
                    combine_any_of(outcomes).map(|matched| Arc::new(matched) as AnyValue)
                }
                None => verifier.inner.verify_any(self.request()).await,
            };
            self.lock_verifications()
                .entry(verifier.id)
                .or_insert(outcome)
                .clone()
        })
    }

    fn lock_verifications(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<u64, Verification<AnyValue>>> {
        self.inner
            .verifications
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Runs request-stage verifiers and combines their outcomes: valid only
    /// if every verifier is valid, with each value recorded at every `any_of`
    /// level; otherwise the precedence rule.
    pub(crate) async fn verify(&self, verifiers: &[ErasedVerifier]) -> Outcome {
        let mut values = Values::new();
        let mut rejected = Vec::new();
        for verifier in verifiers {
            match self.evaluate(verifier).await {
                Verification::Rejected(rejection) => rejected.push(rejection),
                Verification::Valid(value) => record(&mut values, verifier, value),
            }
        }
        if rejected.is_empty() {
            Outcome::Valid(values)
        } else {
            Outcome::Rejected(decide(&rejected))
        }
    }

    /// Runs a payment check at most once per context, Challenge and attempt.
    pub(crate) async fn check(
        &self,
        check: &ErasedCheck,
        challenge: &ChallengeEcho,
        credential: Option<&PaymentCredential>,
    ) -> Outcome {
        let key = (check.id, challenge.id.clone(), credential.is_some());
        if let Some(outcome) = self.lock_checks().get(&key) {
            return outcome.clone();
        }
        let input = PaymentCheckInput {
            request: self.request(),
            challenge,
            credential,
        };
        let outcome = match check.inner.verify_any(input).await {
            Verification::Valid(value) => Outcome::Valid(HashMap::from([(check.id, value)])),
            Verification::Rejected(rejection) => Outcome::Rejected(decide(&[rejection])),
        };
        self.lock_checks().entry(key).or_insert(outcome).clone()
    }

    fn lock_checks(&self) -> std::sync::MutexGuard<'_, HashMap<(u64, String, bool), Outcome>> {
        self.inner.checks.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Records a verified value at every `any_of` level, so the leaf's value is
/// found by its own handle when nested.
fn record(values: &mut Values, verifier: &ErasedVerifier, value: AnyValue) {
    let mut current = verifier.clone();
    let mut value = value;
    loop {
        let Some(members) = current.inner.members() else {
            values.insert(current.id, value);
            return;
        };
        let Some(matched) = value.downcast_ref::<AnyOfValue>() else {
            values.insert(current.id, value);
            return;
        };
        let (index, inner) = (matched.index, matched.value.clone());
        values.insert(current.id, Arc::new(AnyOfMatch { index }));
        let Some(next) = members.get(index).cloned() else {
            return;
        };
        current = next;
        value = inner;
    }
}

// ==================== State machine ====================

/// Which stage rejected an identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionStage {
    /// A request-stage verifier.
    Request,
    /// The payment check on the paid retry.
    Payment,
}

impl RejectionStage {
    /// The stage as mppx names it: `request` or `payment`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Payment => "payment",
        }
    }
}

/// The identity state of one route call, as mppx's server state machine.
#[derive(Clone)]
pub(crate) enum State {
    /// Nothing checked yet.
    Request,
    /// Request-stage verifiers passed; no payment decision yet.
    Identified(Values),
    /// The payment check runs for a Challenge, `paid` with the paid retry's Credential.
    Payment { values: Values, paid: bool },
    /// The payment check passed (or the route has none): paid work may run.
    Accepted(Values),
    /// The route issued a 402 carrying requirements.
    Challenged(Values),
    /// Identity was rejected; the response is sent as is, never a fresh 402.
    Rejected(IdentityRejection),
}

/// An input to [`transition`]. The caller runs verifiers and checks (the
/// only I/O) and feeds their outcomes in.
pub(crate) enum Event {
    /// Request-stage verifiers ran.
    Verified(Outcome),
    /// The payment check is about to run, `paid` with the paid retry's Credential.
    Pay { paid: bool },
    /// The payment check ran (a valid outcome with no values when the route has none).
    Checked(Outcome),
    /// The route issues a 402.
    Challenge,
}

impl Event {
    fn name(&self) -> &'static str {
        match self {
            Self::Verified(_) => "verified",
            Self::Pay { .. } => "pay",
            Self::Checked(_) => "checked",
            Self::Challenge => "challenge",
        }
    }
}

impl State {
    fn phase(&self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Identified(_) => "identified",
            Self::Payment { .. } => "payment",
            Self::Accepted(_) => "accepted",
            Self::Challenged(_) => "challenged",
            Self::Rejected(_) => "rejected",
        }
    }

    fn values(&self) -> Values {
        match self {
            Self::Identified(values)
            | Self::Payment { values, .. }
            | Self::Accepted(values)
            | Self::Challenged(values) => values.clone(),
            Self::Request | Self::Rejected(_) => Values::new(),
        }
    }
}

/// An event the current phase does not accept.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("illegal identity transition {event:?} from phase {phase:?}")]
pub(crate) struct IllegalTransition {
    event: &'static str,
    phase: &'static str,
}

/// Returns the next identity state. Pure: it never runs verifiers.
///
/// | Phase                  | Event                 | Next                         |
/// | ---------------------- | --------------------- | ---------------------------- |
/// | request                | verified (valid)      | identified                   |
/// | request                | verified (rejected)   | rejected (stage request)     |
/// | identified             | pay                   | payment                      |
/// | payment                | checked (valid)       | accepted                     |
/// | payment, paid          | checked (rejected)    | rejected (stage payment)     |
/// | payment, unpaid        | checked (rejected)    | identified (not authorized)  |
/// | identified, accepted   | challenge             | challenged                   |
pub(crate) fn transition(state: State, event: Event) -> Result<State, IllegalTransition> {
    let illegal = |state: &State, event: &Event| IllegalTransition {
        event: event.name(),
        phase: state.phase(),
    };
    match (state, event) {
        (State::Request, Event::Verified(Outcome::Valid(values))) => Ok(State::Identified(values)),
        (State::Request, Event::Verified(Outcome::Rejected(rejection))) => {
            Ok(State::Rejected(IdentityRejection {
                stage: RejectionStage::Request,
                rejection,
            }))
        }
        (State::Identified(values), Event::Pay { paid }) => Ok(State::Payment { values, paid }),
        (State::Payment { mut values, .. }, Event::Checked(Outcome::Valid(checked))) => {
            values.extend(checked);
            Ok(State::Accepted(values))
        }
        // A paid retry may already have pushed the payment: reject instead of a fresh 402.
        (State::Payment { paid: true, .. }, Event::Checked(Outcome::Rejected(rejection))) => {
            Ok(State::Rejected(IdentityRejection {
                stage: RejectionStage::Payment,
                rejection,
            }))
        }
        (
            State::Payment {
                values,
                paid: false,
            },
            Event::Checked(Outcome::Rejected(_)),
        ) => Ok(State::Identified(values)),
        (State::Identified(values) | State::Accepted(values), Event::Challenge) => {
            Ok(State::Challenged(values))
        }
        (state, event) => Err(illegal(&state, &event)),
    }
}

// ==================== Rejections and results ====================

/// Why a route rejected a request's identity, as mppx's `Rejection` result:
/// the stage, and the deciding rejection whose reason is the response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRejection {
    /// The stage that rejected.
    pub stage: RejectionStage,
    /// The deciding rejection, with every rejecting verifier's headers.
    pub rejection: Rejection,
}

impl IdentityRejection {
    /// The HTTP status code of the rejection response.
    pub fn status_code(&self) -> StatusCode {
        self.rejection.status.code()
    }

    /// The rejection response: its status code, the rejection's headers,
    /// `Cache-Control: no-store` and the reason as a plain-text body.
    pub fn into_response(self) -> http_types::Response<String> {
        let mut response = http_types::Response::new(self.rejection.reason);
        *response.status_mut() = self.rejection.status.code();
        *response.headers_mut() = self.rejection.headers;
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        response
    }
}

impl fmt::Display for IdentityRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} stage: {}", self.stage.as_str(), self.rejection)
    }
}

impl std::error::Error for IdentityRejection {}

/// Verified identity values, looked up by the handle of the verifier or
/// payment check that produced them.
#[derive(Clone, Default)]
pub struct IdentityResults {
    values: Arc<Values>,
}

impl IdentityResults {
    fn from_values(values: Values) -> Self {
        Self {
            values: Arc::new(values),
        }
    }

    /// The verified value of a request-stage verifier, or `None` if it did
    /// not run or match.
    pub fn get<V: Verifier>(&self, verifier: &Handle<V>) -> Option<&V::Value> {
        self.values.get(&verifier.id)?.downcast_ref()
    }

    /// The verified value of a payment check, or `None` if it did not run.
    pub fn payment<C: PaymentCheck>(&self, check: &Handle<C>) -> Option<&C::Value> {
        self.values.get(&check.id)?.downcast_ref()
    }

    /// Whether no verifier or check produced a value.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl fmt::Debug for IdentityResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityResults")
            .field("len", &self.values.len())
            .finish()
    }
}

// ==================== Routes ====================

/// A route's identity, as mppx's `identity` route option: request-stage
/// verifiers, all of which must be valid, and an optional payment check.
///
/// With the `axum` feature, add it to a route as a request extension
/// (`.layer(axum::Extension(identity))`) and [`MppCharge`](crate::server::axum::MppCharge)
/// runs it, exposing [`IdentityResults`] as `charge.identity`.
#[derive(Clone, Default, Debug)]
pub struct RouteIdentity {
    request: Vec<ErasedVerifier>,
    payment: Option<ErasedCheck>,
    required: Option<HeaderValue>,
}

impl RouteIdentity {
    /// A route with no identity checks.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a request-stage verifier.
    pub fn verifier(mut self, verifier: impl Into<ErasedVerifier>) -> Self {
        self.request.push(verifier.into());
        self
    }

    /// Sets the payment check.
    ///
    /// # Panics
    ///
    /// If its requirements cannot be sent in a structured-field list (a type
    /// that is not a token), as mppx throws for them when the route is built.
    pub fn payment(mut self, check: impl Into<ErasedCheck>) -> Self {
        let check = check.into();
        let value = requirements::serialize(check.requires())
            .unwrap_or_else(|error| panic!("invalid identity payment check: {error}"));
        self.required = (!value.is_empty())
            .then(|| HeaderValue::from_str(&value).ok())
            .flatten();
        self.payment = Some(check);
        self
    }

    /// Whether any verifier reads `Authorization`, so the server must be
    /// created with `requires_auth`.
    pub fn reads_authorization(&self) -> bool {
        self.request.iter().any(ErasedVerifier::reads_authorization)
    }

    /// Identities the payment check requires.
    pub fn requirements(&self) -> &[Requirement] {
        self.payment
            .as_ref()
            .map(ErasedCheck::requires)
            .unwrap_or_default()
    }

    /// The `Identity-Required` value every 402 of the route carries, if any.
    pub fn required_header(&self) -> Option<&HeaderValue> {
        self.required.as_ref()
    }

    /// Whether the route has a payment check.
    pub fn has_payment_check(&self) -> bool {
        self.payment.is_some()
    }

    /// Starts a route call: runs the request-stage verifiers.
    ///
    /// A rejection is sent as is ([`IdentityRejection::into_response`]),
    /// never with a 402.
    // Rejections are the cold path; keep the public type unboxed, as mppx's.
    #[allow(clippy::result_large_err)]
    pub async fn verify_request(
        &self,
        context: &IdentityContext,
    ) -> Result<IdentityCall, IdentityRejection> {
        let outcome = context.verify(&self.request).await;
        match transition(State::Request, Event::Verified(outcome)) {
            Ok(State::Rejected(rejection)) => Err(rejection),
            Ok(state) => Ok(IdentityCall {
                route: self.clone(),
                context: context.clone(),
                state,
            }),
            Err(error) => Err(internal_rejection(error)),
        }
    }
}

fn internal_rejection(error: IllegalTransition) -> IdentityRejection {
    IdentityRejection {
        stage: RejectionStage::Request,
        rejection: Rejection::invalid(error.to_string()),
    }
}

/// One route call whose request-stage verifiers passed.
#[derive(Clone)]
pub struct IdentityCall {
    route: RouteIdentity,
    context: IdentityContext,
    state: State,
}

impl fmt::Debug for IdentityCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityCall")
            .field("phase", &self.state.phase())
            .finish_non_exhaustive()
    }
}

impl IdentityCall {
    /// The verified values so far.
    pub fn results(&self) -> IdentityResults {
        IdentityResults::from_values(self.state.values())
    }

    /// The `Identity-Required` value to add to the 402 the route issues, if any.
    pub fn challenge(&mut self) -> Option<HeaderValue> {
        if let Ok(next) = transition(self.state.clone(), Event::Challenge) {
            self.state = next;
        }
        self.route.required_header().cloned()
    }

    /// The gate a paid retry's Credential must pass before it settles, or
    /// `None` when the route has no payment check.
    pub fn payment_gate(&self) -> Option<PaymentGate> {
        Some(PaymentGate {
            context: self.context.clone(),
            check: self.route.payment.clone()?,
        })
    }

    /// Runs the payment check for the paid retry's Credential (the same,
    /// memoized outcome a [`PaymentGate`] got) and returns every verified
    /// value, or the rejection to send as is.
    #[allow(clippy::result_large_err)]
    pub async fn accept(
        mut self,
        credential: &PaymentCredential,
    ) -> Result<IdentityResults, IdentityRejection> {
        let state = transition(self.state.clone(), Event::Pay { paid: true })
            .map_err(internal_rejection)?;
        let outcome = match &self.route.payment {
            Some(check) => {
                self.context
                    .check(check, &credential.challenge, Some(credential))
                    .await
            }
            None => Outcome::Valid(Values::new()),
        };
        self.state = transition(state, Event::Checked(outcome)).map_err(internal_rejection)?;
        match &self.state {
            State::Rejected(rejection) => Err(rejection.clone()),
            state => Ok(IdentityResults::from_values(state.values())),
        }
    }
}

/// The payment check a paid retry's Credential must pass before it settles.
///
/// Servers run it after the Credential's HMAC, pinned fields and expiry
/// check, and before the payment is broadcast. Its outcome is memoized per
/// request, Challenge and attempt, so [`IdentityCall::accept`] reads the same one.
#[derive(Clone, Debug)]
pub struct PaymentGate {
    context: IdentityContext,
    check: ErasedCheck,
}

impl PaymentGate {
    /// Whether the payment check accepts `credential`.
    pub async fn admit(&self, credential: &PaymentCredential) -> bool {
        matches!(
            self.context
                .check(&self.check, &credential.challenge, Some(credential))
                .await,
            Outcome::Valid(_)
        )
    }
}

#[cfg(feature = "server")]
impl crate::server::CredentialGate for PaymentGate {
    fn admit<'a>(&'a self, credential: &'a PaymentCredential) -> BoxFuture<'a, bool> {
        Box::pin(PaymentGate::admit(self, credential))
    }
}

#[cfg(test)]
mod tests;
