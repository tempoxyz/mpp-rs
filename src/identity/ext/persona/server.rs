//! Persona on the server: inquiries, a payment check and a verifier, as mppx's `Persona.Server`.

use std::fmt;
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, Signature};
use http_types::header::LINK;
use http_types::{HeaderMap, HeaderValue};
use reqwest::{Method, Url};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::constants::{
    API_URL, API_VERSION, CACHE_TTL_SECS, INQUIRIES_PATH, ISSUER, MAX_PAGES, REL, TIMEOUT_SECS,
    TYPE,
};
use crate::identity::{
    BoxFuture, IdentityRequest, PaymentCheck, PaymentCheckInput, Rejection, Requirement,
    Verification, Verifier,
};
use crate::store::Store;

/// Status of a Persona inquiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InquiryStatus {
    /// Created, not started.
    Created,
    /// Started, not completed.
    Pending,
    /// Completed, not yet decisioned.
    Completed,
    /// Approved by your Persona workflow or reviewer.
    Approved,
    /// Declined.
    Declined,
    /// Failed.
    Failed,
    /// Expired before it was completed.
    Expired,
    /// Waiting on a manual review.
    NeedsReview,
}

impl InquiryStatus {
    /// Every status, in Persona's order.
    pub const ALL: [Self; 8] = [
        Self::Created,
        Self::Pending,
        Self::Completed,
        Self::Approved,
        Self::Declined,
        Self::Failed,
        Self::Expired,
        Self::NeedsReview,
    ];

    /// The status as Persona names it, such as `approved` or `needs_review`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Approved => "approved",
            Self::Declined => "declined",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::NeedsReview => "needs_review",
        }
    }

    /// Parses a status as Persona names it.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|status| status.as_str() == value)
    }
}

impl fmt::Display for InquiryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A payer with an accepted Persona inquiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInquiry {
    /// Persona inquiry ID, such as `inq_…`.
    pub inquiry_id: String,
    /// Reference ID the inquiry was created with, which the check matched.
    pub reference_id: String,
    /// Inquiry status, such as `approved`.
    pub status: InquiryStatus,
    /// When the inquiry was decisioned, or completed if it was never decisioned.
    pub verified_at: Option<OffsetDateTime>,
}

/// A started Persona inquiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedInquiry {
    /// Persona inquiry ID, such as `inq_…`.
    pub inquiry_id: String,
    /// One-time link to Persona's hosted flow, for the person to complete KYC.
    pub url: String,
}

/// A misconfigured client, a failed or malformed Persona API call, or a
/// wallet proof that did not verify.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PersonaError {
    /// The client or the call is misconfigured.
    #[error("{0}")]
    Config(String),
    /// The Persona API call failed or answered something malformed. It never
    /// carries the upstream body, which may hold request details.
    #[error("{0}")]
    Api(String),
    /// The wallet proof did not verify.
    #[error("{0}")]
    Wallet(String),
}

impl PersonaError {
    fn malformed() -> Self {
        Self::Api("The Persona API response is malformed.".into())
    }
}

/// Persona client options, as mppx's `Persona.Server.create` config.
#[derive(Clone)]
pub struct Config {
    api_key: String,
    template_id: Option<String>,
    api_url: String,
    api_version: String,
    http: Option<reqwest::Client>,
    timeout: Duration,
}

impl fmt::Debug for Config {
    // Never prints the API key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("template_id", &self.template_id)
            .field("api_url", &self.api_url)
            .field("api_version", &self.api_version)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Options for the Persona organization `api_key` belongs to. Keep the key on the server.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            template_id: None,
            api_url: API_URL.to_owned(),
            api_version: API_VERSION.to_owned(),
            http: None,
            timeout: Duration::from_secs(TIMEOUT_SECS),
        }
    }

    /// Inquiry template (`itmpl_…`) to start inquiries from and to accept them from.
    pub fn template_id(mut self, template_id: impl Into<String>) -> Self {
        self.template_id = Some(template_id.into());
        self
    }

    /// Persona API origin. Default: `https://api.withpersona.com`.
    pub fn api_url(mut self, api_url: impl Into<String>) -> Self {
        self.api_url = api_url.into();
        self
    }

    /// `Persona-Version` header. Default: `2023-01-05`.
    pub fn api_version(mut self, api_version: impl Into<String>) -> Self {
        self.api_version = api_version.into();
        self
    }

    /// The HTTP client for the Persona API. It should not follow redirects: a
    /// response from any origin but the API's is a failure either way.
    /// Default: a client that follows none.
    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    /// Time before a Persona API call is abandoned as `unavailable`. Default: 5 seconds.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// Where a rejected payer starts KYC.
#[derive(Clone)]
enum Onboarding {
    Url(String),
    Fn(OnboardingFn),
}

type OnboardingFn = Arc<dyn Fn(&IdentityRequest, Option<&str>) -> Option<String> + Send + Sync>;

/// Options shared by [`Persona::payment_check`] and [`Persona::verifier`].
#[derive(Clone)]
pub struct LookupOptions {
    statuses: Vec<InquiryStatus>,
    max_age: Option<Duration>,
    onboarding: Option<Onboarding>,
    cache: Option<Arc<dyn Store>>,
    cache_ttl: Duration,
}

impl fmt::Debug for LookupOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LookupOptions")
            .field("statuses", &self.statuses)
            .field("max_age", &self.max_age)
            .field("cache", &self.cache.is_some())
            .field("cache_ttl", &self.cache_ttl)
            .finish_non_exhaustive()
    }
}

impl Default for LookupOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl LookupOptions {
    /// Accepts approved inquiries of any age, without a cache or onboarding URL.
    pub fn new() -> Self {
        Self {
            statuses: vec![InquiryStatus::Approved],
            max_age: None,
            onboarding: None,
            cache: None,
            cache_ttl: Duration::from_secs(CACHE_TTL_SECS),
        }
    }

    /// Accepted inquiry statuses. Default: `approved`. With none, every lookup
    /// is `unavailable` (503), as a misconfigured server.
    pub fn statuses(mut self, statuses: impl IntoIterator<Item = InquiryStatus>) -> Self {
        self.statuses = statuses.into_iter().collect();
        self
    }

    /// Oldest accepted verification, measured from when the inquiry was
    /// decisioned or completed. An inquiry with neither time is not accepted.
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Where a rejected payer starts KYC, sent as `Link: <url>; rel="kyc"`
    /// with 401 and 403 responses, such as your endpoint that calls
    /// [`Persona::start_inquiry`].
    pub fn onboarding(mut self, url: impl Into<String>) -> Self {
        self.onboarding = Some(Onboarding::Url(url.into()));
        self
    }

    /// Like [`onboarding`](Self::onboarding), from the request and the
    /// reference ID, if any.
    pub fn onboarding_fn<F>(mut self, onboarding: F) -> Self
    where
        F: Fn(&IdentityRequest, Option<&str>) -> Option<String> + Send + Sync + 'static,
    {
        self.onboarding = Some(Onboarding::Fn(Arc::new(onboarding)));
        self
    }

    /// Caches approvals by reference ID, so a paid request skips the Persona
    /// API. Only approvals are cached, so a person who just passed KYC is
    /// never served a stale rejection.
    pub fn cache(mut self, cache: Arc<dyn Store>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// How long an approval stays cached. Each check applies its own, so a
    /// longer-lived check sharing the store never extends a stricter one's.
    /// Default: 300 seconds.
    pub fn cache_ttl(mut self, cache_ttl: Duration) -> Self {
        self.cache_ttl = cache_ttl;
        self
    }

    fn headers(&self, request: &IdentityRequest, reference_id: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        let url = match &self.onboarding {
            Some(Onboarding::Url(url)) => Some(url.clone()),
            Some(Onboarding::Fn(onboarding)) => onboarding(request, reference_id),
            None => None,
        };
        if let Some(value) = url
            .filter(|url| !url.is_empty())
            .and_then(|url| HeaderValue::from_str(&format!("<{url}>; rel=\"{REL}\"")).ok())
        {
            headers.append(LINK, value);
        }
        headers
    }
}

/// Parameters of [`Persona::start_inquiry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartInquiry {
    reference_id: String,
    template_id: Option<String>,
    redirect_uri: Option<String>,
}

impl StartInquiry {
    /// Starts an inquiry for `reference_id`, such as [`did`](super::did) of a
    /// wallet the person proved they own with [`verify_wallet`].
    pub fn new(reference_id: impl Into<String>) -> Self {
        Self {
            reference_id: reference_id.into(),
            template_id: None,
            redirect_uri: None,
        }
    }

    /// Inquiry template, overriding the client's.
    pub fn template_id(mut self, template_id: impl Into<String>) -> Self {
        self.template_id = Some(template_id.into());
        self
    }

    /// Where Persona sends the person after the flow.
    pub fn redirect_uri(mut self, redirect_uri: impl Into<String>) -> Self {
        self.redirect_uri = Some(redirect_uri.into());
        self
    }
}

/// A Persona client for one Persona organization and inquiry template, as
/// the object mppx's `Persona.Server.create` returns.
///
/// Link a wallet to a person by proving they own it ([`verify_wallet`])
/// before you start an inquiry with its DID as the reference ID. Otherwise
/// anyone can complete KYC as themselves for someone else's wallet.
#[derive(Clone)]
pub struct Persona {
    inner: Arc<Inner>,
}

struct Inner {
    api_key: String,
    api_url: Url,
    api_version: String,
    http: reqwest::Client,
    template_id: Option<String>,
    timeout: Duration,
    /// A digest of the API origin and key: identifies the Persona
    /// organization without storing the key.
    scope: String,
}

impl fmt::Debug for Persona {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Persona")
            .field("api_url", &self.inner.api_url.as_str())
            .field("template_id", &self.inner.template_id)
            .finish_non_exhaustive()
    }
}

impl Persona {
    /// Creates a client. Fails without an API key, with a zero timeout or an
    /// API URL that does not parse.
    pub fn new(config: Config) -> Result<Self, PersonaError> {
        if config.api_key.is_empty() {
            return Err(PersonaError::Config("Persona needs an api_key.".into()));
        }
        if config.timeout.is_zero() {
            return Err(PersonaError::Config(
                "Persona needs a positive timeout.".into(),
            ));
        }
        let api_url = Url::parse(&config.api_url)
            .ok()
            .filter(|url| url.has_host())
            .ok_or_else(|| PersonaError::Config("Persona's api_url is not a valid URL.".into()))?;
        let http = match config.http {
            Some(http) => http,
            None => reqwest::Client::builder()
                // A redirect is a failure: never send the bearer key on, nor read another origin's body.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| {
                    PersonaError::Config("Persona's HTTP client failed to build.".into())
                })?,
        };
        let digest = Sha256::digest(
            format!(
                "{}\n{}",
                api_url.origin().ascii_serialization(),
                config.api_key
            )
            .as_bytes(),
        );
        Ok(Self {
            inner: Arc::new(Inner {
                scope: hex::encode(&digest[..16]),
                api_key: config.api_key,
                api_url,
                api_version: config.api_version,
                http,
                template_id: config.template_id,
                timeout: config.timeout,
            }),
        })
    }

    /// Starts an inquiry for a reference ID and returns a one-time link to
    /// Persona's hosted flow.
    pub async fn start_inquiry(
        &self,
        parameters: StartInquiry,
    ) -> Result<StartedInquiry, PersonaError> {
        if parameters.reference_id.is_empty() {
            return Err(PersonaError::Config(
                "start_inquiry needs a reference_id.".into(),
            ));
        }
        let template_id = parameters
            .template_id
            .or_else(|| self.inner.template_id.clone())
            .ok_or_else(|| PersonaError::Config("start_inquiry needs a template_id.".into()))?;
        let mut attributes = json!({
            "inquiry-template-id": template_id,
            "reference-id": parameters.reference_id,
        });
        if let Some(redirect_uri) = parameters.redirect_uri.filter(|uri| !uri.is_empty()) {
            attributes["redirect-uri"] = Value::String(redirect_uri);
        }
        let created = self
            .call(
                Method::POST,
                self.endpoint(),
                Some(json!({ "data": { "attributes": attributes } })),
            )
            .await?;
        let inquiry_id = created
            .pointer("/data/id")
            .and_then(Value::as_str)
            .ok_or_else(PersonaError::malformed)?
            .to_owned();
        let mut link = self.endpoint();
        link.path_segments_mut()
            .map_err(|_| PersonaError::malformed())?
            .push(&inquiry_id)
            .push("generate-one-time-link");
        let link = self.call(Method::POST, link, Some(json!({}))).await?;
        let url = link
            .pointer("/meta/one-time-link")
            .and_then(Value::as_str)
            .ok_or_else(PersonaError::malformed)?
            .to_owned();
        Ok(StartedInquiry { inquiry_id, url })
    }

    /// Returns a payment check that requires the payer to have passed Persona KYC.
    ///
    /// Every 402 of the route advertises
    /// `Identity-Required: kyc;issuer="https://api.withpersona.com"`. On the
    /// paid retry, before the Credential settles, it accepts the most recent
    /// inquiry whose reference ID `reference_id` returns. Derive it from
    /// something your server authenticated, such as your own session, or a
    /// payer address your payment method verified. A Credential's `source` is
    /// client-supplied and some payment flows do not check it against the
    /// payer, so returning it as is lets a payer present another wallet's KYC.
    pub fn payment_check<F>(&self, reference_id: F, options: LookupOptions) -> PersonaPaymentCheck
    where
        F: Fn(&PaymentCheckInput<'_>) -> Option<String> + Send + Sync + 'static,
    {
        PersonaPaymentCheck {
            persona: self.clone(),
            reference_id: Arc::new(reference_id),
            options,
            requires: vec![Requirement::new(TYPE).with_issuer(ISSUER)],
        }
    }

    /// Returns a request-stage verifier that requires an approved inquiry
    /// before any 402, for a caller `reference_id` identifies from the
    /// request, such as by your own session.
    pub fn verifier<F>(&self, reference_id: F, options: LookupOptions) -> PersonaVerifier
    where
        F: Fn(&IdentityRequest) -> Option<String> + Send + Sync + 'static,
    {
        PersonaVerifier {
            persona: self.clone(),
            reference_id: Arc::new(reference_id),
            options,
        }
    }

    fn endpoint(&self) -> Url {
        let mut url = self.inner.api_url.clone();
        url.set_path(INQUIRIES_PATH);
        url.set_query(None);
        url.set_fragment(None);
        url
    }

    async fn call(
        &self,
        method: Method,
        url: Url,
        body: Option<Value>,
    ) -> Result<Value, PersonaError> {
        let failed = || PersonaError::Api("The Persona API request failed.".into());
        let mut request = self
            .inner
            .http
            .request(method, url)
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(&self.inner.api_key)
            .header("Persona-Version", &self.inner.api_version)
            .timeout(self.inner.timeout);
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_string());
        }
        let response = request.send().await.map_err(|_| failed())?;
        // A response from another origin (a redirect a custom client followed) is a failure.
        if response.url().origin() != self.inner.api_url.origin() {
            return Err(failed());
        }
        // Never surface the upstream body: it may carry request details.
        if !response.status().is_success() {
            return Err(PersonaError::Api(format!(
                "The Persona API returned {}.",
                response.status().as_u16()
            )));
        }
        response.json().await.map_err(|_| PersonaError::malformed())
    }

    /// Returns the most recent accepted inquiry for a reference ID.
    async fn find(
        &self,
        reference_id: &str,
        options: &LookupOptions,
    ) -> Result<Option<VerifiedInquiry>, PersonaError> {
        let template_id = self.inner.template_id.as_deref();
        let statuses = options
            .statuses
            .iter()
            .map(|status| status.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let mut url = self.endpoint();
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("filter[reference-id]", reference_id);
            query.append_pair("filter[status]", &statuses);
            if let Some(template_id) = template_id {
                query.append_pair("filter[inquiry-template-id]", template_id);
            }
            query.append_pair("page[size]", "25");
        }
        let now = OffsetDateTime::now_utc();
        let mut next = Some(url);
        for _ in 0..MAX_PAGES {
            let Some(url) = next.take() else { break };
            let body = self.call(Method::GET, url, None).await?;
            let data = body
                .get("data")
                .and_then(Value::as_array)
                .ok_or_else(PersonaError::malformed)?;
            // Persona lists the most recent inquiries first.
            for inquiry in data {
                let (Some(id), Some(attributes)) = (
                    inquiry.get("id").and_then(Value::as_str),
                    inquiry.get("attributes").and_then(Value::as_object),
                ) else {
                    continue;
                };
                // Recheck what the filters asked for, so an API or proxy that ignores them cannot widen them.
                if attributes.get("reference-id").and_then(Value::as_str) != Some(reference_id) {
                    continue;
                }
                let Some(status) = attributes
                    .get("status")
                    .and_then(Value::as_str)
                    .and_then(InquiryStatus::parse)
                    .filter(|status| options.statuses.contains(status))
                else {
                    continue;
                };
                // Fails closed when the inquiry does not name its template.
                if let Some(template_id) = template_id {
                    let named = inquiry
                        .pointer("/relationships/inquiry-template/data/id")
                        .and_then(Value::as_str);
                    if named != Some(template_id) {
                        continue;
                    }
                }
                let verified_at = date(
                    attributes
                        .get("decisioned-at")
                        .filter(|value| !value.is_null())
                        .or_else(|| attributes.get("completed-at")),
                );
                if !fresh(verified_at, options.max_age, now) {
                    continue;
                }
                return Ok(Some(VerifiedInquiry {
                    inquiry_id: id.to_owned(),
                    reference_id: reference_id.to_owned(),
                    status,
                    verified_at,
                }));
            }
            next = body
                .pointer("/links/next")
                .and_then(Value::as_str)
                .and_then(|link| self.same_origin(link));
        }
        Ok(None)
    }

    /// Resolves a pagination link, or `None` unless it is on the Persona API
    /// origin, so the API key is never sent to an origin a response names.
    fn same_origin(&self, link: &str) -> Option<Url> {
        // The resolved absolute URL, not the link's path: a path such as
        // `//host/x` resolves to another origin.
        self.inner
            .api_url
            .join(link)
            .ok()
            .filter(|url| url.origin() == self.inner.api_url.origin())
    }

    /// Looks a reference ID up, through the cache when set, and maps the result to a verification.
    async fn lookup(
        &self,
        reference_id: Option<String>,
        options: &LookupOptions,
        request: &IdentityRequest,
    ) -> Verification<VerifiedInquiry> {
        if options.statuses.is_empty() {
            return Rejection::unavailable("Persona needs at least one accepted status.").into();
        }
        let reference_id = reference_id.filter(|id| !id.is_empty());
        let headers = options.headers(request, reference_id.as_deref());
        let Some(reference_id) = reference_id else {
            return Rejection::missing()
                .with_reason("Persona KYC requires a payer.")
                .with_headers(&headers)
                .into();
        };

        // Scoped to the Persona organization and template, so clients sharing
        // a store never accept each other's approvals.
        let key = format!(
            "mppx:persona:{}:{}:{reference_id}",
            self.inner.scope,
            self.inner.template_id.as_deref().unwrap_or_default()
        );
        let now = OffsetDateTime::now_utc();
        if let Some(cache) = &options.cache {
            if let Ok(Some(entry)) = cache.get(&key).await {
                if let Some(inquiry) = cached(&entry, &reference_id, options, now) {
                    return Verification::Valid(inquiry);
                }
            }
        }

        let inquiry = match self.find(&reference_id, options).await {
            Ok(Some(inquiry)) => inquiry,
            Ok(None) => {
                return Rejection::forbidden("The payer has not passed Persona KYC.")
                    .with_headers(&headers)
                    .into()
            }
            Err(_) => {
                return Rejection::unavailable("Persona KYC verification is unavailable.").into()
            }
        };
        // Only approvals are cached, so a person who just passed KYC is never kept waiting.
        if let Some(cache) = &options.cache {
            let mut entry = json!({
                "cachedAt": unix_millis(now),
                "inquiryId": inquiry.inquiry_id,
                "status": inquiry.status.as_str(),
            });
            if let Some(verified_at) = inquiry.verified_at.and_then(|at| at.format(&Rfc3339).ok()) {
                entry["verifiedAt"] = Value::String(verified_at);
            }
            // A cache that fails to store only costs the next request a lookup.
            let _ = cache.put(&key, entry).await;
        }
        Verification::Valid(inquiry)
    }
}

/// Reads a cached approval, if it is within this check's lifetime and still acceptable.
fn cached(
    entry: &Value,
    reference_id: &str,
    options: &LookupOptions,
    now: OffsetDateTime,
) -> Option<VerifiedInquiry> {
    let cached_at = entry.get("cachedAt").and_then(Value::as_f64)?;
    let ttl = options.cache_ttl.as_millis() as f64;
    // Each check applies its own lifetime, so a longer-lived check sharing the
    // store never extends a stricter one's revalidation window.
    if cached_at + ttl <= unix_millis(now) as f64 {
        return None;
    }
    let status = entry
        .get("status")
        .and_then(Value::as_str)
        .and_then(InquiryStatus::parse)
        .filter(|status| options.statuses.contains(status))?;
    let verified_at = date(entry.get("verifiedAt"));
    if !fresh(verified_at, options.max_age, now) {
        return None;
    }
    Some(VerifiedInquiry {
        inquiry_id: entry.get("inquiryId").and_then(Value::as_str)?.to_owned(),
        reference_id: reference_id.to_owned(),
        status,
        verified_at,
    })
}

fn unix_millis(at: OffsetDateTime) -> i128 {
    at.unix_timestamp_nanos() / 1_000_000
}

fn fresh(
    verified_at: Option<OffsetDateTime>,
    max_age: Option<Duration>,
    now: OffsetDateTime,
) -> bool {
    let Some(max_age) = max_age else {
        return true;
    };
    verified_at.is_some_and(|at| now - at <= max_age)
}

fn date(value: Option<&Value>) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value?.as_str()?, &Rfc3339).ok()
}

type ReferenceFn = Arc<dyn Fn(&PaymentCheckInput<'_>) -> Option<String> + Send + Sync>;
type RequestReferenceFn = Arc<dyn Fn(&IdentityRequest) -> Option<String> + Send + Sync>;

/// A [`PaymentCheck`] that requires an approved Persona inquiry, from
/// [`Persona::payment_check`].
#[derive(Clone)]
pub struct PersonaPaymentCheck {
    persona: Persona,
    reference_id: ReferenceFn,
    options: LookupOptions,
    requires: Vec<Requirement>,
}

impl fmt::Debug for PersonaPaymentCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersonaPaymentCheck")
            .field("persona", &self.persona)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl PaymentCheck for PersonaPaymentCheck {
    type Value = VerifiedInquiry;

    fn requires(&self) -> &[Requirement] {
        &self.requires
    }

    fn verify<'a>(
        &'a self,
        input: PaymentCheckInput<'a>,
    ) -> BoxFuture<'a, Verification<VerifiedInquiry>> {
        Box::pin(async move {
            let reference_id = (self.reference_id)(&input);
            self.persona
                .lookup(reference_id, &self.options, input.request)
                .await
        })
    }
}

/// A [`Verifier`] that requires an approved Persona inquiry before any 402,
/// from [`Persona::verifier`].
#[derive(Clone)]
pub struct PersonaVerifier {
    persona: Persona,
    reference_id: RequestReferenceFn,
    options: LookupOptions,
}

impl fmt::Debug for PersonaVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersonaVerifier")
            .field("persona", &self.persona)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl Verifier for PersonaVerifier {
    type Value = VerifiedInquiry;

    fn verify<'a>(
        &'a self,
        request: &'a IdentityRequest,
    ) -> BoxFuture<'a, Verification<VerifiedInquiry>> {
        Box::pin(async move {
            let reference_id = (self.reference_id)(request);
            self.persona
                .lookup(reference_id, &self.options, request)
                .await
        })
    }
}

/// A signed message that links a wallet to a person, for [`verify_wallet`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletProof {
    /// Wallet address the person claims.
    pub address: Address,
    /// Chain ID of the wallet, such as `4217` for Tempo mainnet.
    pub chain_id: u64,
    /// Message the wallet signed, containing `nonce` and the wallet's DID ([`did`](super::did)).
    pub message: String,
    /// Hex signature over `message` (EIP-191 `personal_sign`).
    pub signature: String,
    /// Single-use value your server issued and the message must contain.
    pub nonce: String,
}

impl WalletProof {
    /// Checks the nonce and the DID in the message, and returns the DID.
    fn reference_id(&self) -> Result<String, PersonaError> {
        if self.nonce.is_empty() || !self.message.contains(&self.nonce) {
            return Err(PersonaError::Wallet(
                "The signed message must contain the nonce.".into(),
            ));
        }
        let reference_id = super::did(&self.address.to_string(), self.chain_id);
        // The signer commits to the chain as well as the address: the same
        // address can have different owners on different chains.
        if !self
            .message
            .to_lowercase()
            .contains(&reference_id.to_lowercase())
        {
            return Err(PersonaError::Wallet(format!(
                "The signed message must contain the wallet's DID, {reference_id}."
            )));
        }
        Ok(reference_id)
    }
}

fn mismatch() -> PersonaError {
    PersonaError::Wallet("The signature does not match the address.".into())
}

/// Verifies that the signer of `message` owns `address` and returns the
/// wallet's reference ID ([`did`](super::did)), to start an inquiry with, as
/// mppx's `Persona.Server.verifyWallet`.
///
/// `message` must contain `nonce`, a single-use value your server issued for
/// this person, so a signature cannot be replayed, and the wallet's DID, so
/// the signer commits to the chain. It accepts EOA signatures only; use
/// [`verify_wallet_with`] for smart accounts.
pub fn verify_wallet(proof: &WalletProof) -> Result<String, PersonaError> {
    let reference_id = proof.reference_id()?;
    let signature = Signature::from_str(&proof.signature).map_err(|_| mismatch())?;
    match signature.recover_address_from_msg(proof.message.as_bytes()) {
        Ok(signer) if signer == proof.address => Ok(reference_id),
        _ => Err(mismatch()),
    }
}

/// Like [`verify_wallet`], with `verify` checking the signature, such as an
/// ERC-1271 or ERC-6492 check against the wallet's chain (`proof.chain_id`)
/// for smart accounts.
pub async fn verify_wallet_with<F, Fut>(
    proof: &WalletProof,
    verify: F,
) -> Result<String, PersonaError>
where
    F: FnOnce(&WalletProof) -> Fut,
    Fut: Future<Output = bool>,
{
    let reference_id = proof.reference_id()?;
    if verify(proof).await {
        Ok(reference_id)
    } else {
        Err(mismatch())
    }
}
