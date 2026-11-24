//! Tempo ID on the client: a prover, as mppx's `TempoId.Client.prover`, and,
//! with `identity-attestation`, [`attestations`] and [`attest`], as mppx's
//! `TempoId.Client.attestations` and `TempoId.Client.attest`.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::Request;

use super::constants::ID_TOKEN_HEADER;
use super::jwt;
use super::DpopKey;
#[cfg(feature = "identity-attestation")]
use crate::identity::client::RetryContext;
use crate::identity::client::{
    PrepareContext, ProveContext, Prover, ProverError, ResponseParts, Scope,
};
#[cfg(feature = "identity-attestation")]
use crate::identity::ext::attestation::{
    canonical_issuer, decode, is_loopback, loopback_only, origin_of, parse_header, requirements,
    trim_issuer, AttestationProver, IdentityError, HEADER as ATTESTATION_HEADER, MAX_LENGTH,
};
use crate::identity::BoxFuture;
use crate::protocol::core::headers::extract_payment_scheme;
#[cfg(feature = "identity-attestation")]
use reqwest::header::HeaderMap;

type TokenFn = Arc<dyn Fn() -> BoxFuture<'static, Result<String, ProverError>> + Send + Sync>;
type IdTokenFn = Arc<dyn Fn() -> BoxFuture<'static, Option<String>> + Send + Sync>;

/// Tempo ID prover options, as mppx's `TempoId.Client.prover` config.
#[derive(Clone)]
pub struct ProverConfig {
    access_token: TokenFn,
    dpop: Option<DpopKey>,
    id_token: Option<IdTokenFn>,
    scope: Scope,
}

impl fmt::Debug for ProverConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProverConfig")
            .field("dpop", &self.dpop)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl ProverConfig {
    /// Sends the live access token `access_token` returns to the origins in
    /// `scope`. Send it only to the API it was issued for.
    pub fn new<F, Fut>(scope: Scope, access_token: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, ProverError>> + Send + 'static,
    {
        Self {
            access_token: Arc::new(move || Box::pin(access_token())),
            dpop: None,
            id_token: None,
            scope,
        }
    }

    /// The DPoP key that binds the token. Without one, the token is sent as a Bearer token.
    pub fn dpop(mut self, key: DpopKey) -> Self {
        self.dpop = Some(key);
        self
    }

    /// Returns the user's ID token, so the API reads their email.
    pub fn id_token<F, Fut>(mut self, id_token: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<String>> + Send + 'static,
    {
        self.id_token = Some(Arc::new(move || Box::pin(id_token())));
        self
    }
}

/// Creates a prover that sends a Tempo ID access token with each request: as
/// `DPoP` with a new proof when a DPoP key is set, else as `Bearer`.
pub fn prover(config: ProverConfig) -> TempoIdProver {
    TempoIdProver { config }
}

/// The prover [`prover`] returns.
#[derive(Debug, Clone)]
pub struct TempoIdProver {
    config: ProverConfig,
}

const HEADERS: &[&str] = &["dpop", "tempo-id-token"];

const REQUIRES_AUTH: &str = "the Tempo ID access token needs Authorization, which holds the Payment Credential: the server must set requires_auth";

impl Prover for TempoIdProver {
    fn scope(&self) -> &Scope {
        &self.config.scope
    }

    fn headers(&self) -> &[&'static str] {
        HEADERS
    }

    // Refuses before the client pays: the access token needs Authorization,
    // and a Challenge naming it would put the Payment Credential there too.
    fn prepare<'a>(
        &'a self,
        _response: &'a ResponseParts,
        context: &'a PrepareContext,
    ) -> BoxFuture<'a, Result<(), ProverError>> {
        let result = if context
            .challenge
            .credential_header()
            .eq_ignore_ascii_case(AUTHORIZATION.as_str())
        {
            Err(ProverError::new(REQUIRES_AUTH))
        } else {
            Ok(())
        };
        Box::pin(std::future::ready(result))
    }

    fn prove<'a>(
        &'a self,
        request: &'a mut Request,
        _context: &'a ProveContext,
    ) -> BoxFuture<'a, Result<(), ProverError>> {
        Box::pin(async move {
            let access_token = (self.config.access_token)().await?;
            let scheme = if self.config.dpop.is_some() {
                "DPoP"
            } else {
                "Bearer"
            };
            let value =
                HeaderValue::from_str(&format!("{scheme} {access_token}")).map_err(|_| {
                    ProverError::new("the Tempo ID access token is not a valid header value")
                })?;
            // The access token would replace a Payment Credential in
            // Authorization; a server created with requires_auth takes the
            // Credential in Payment-Authorization instead.
            let holds_credential = request
                .headers()
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .and_then(extract_payment_scheme)
                .is_some();
            if holds_credential {
                return Err(ProverError::new(REQUIRES_AUTH));
            }
            request.headers_mut().insert(AUTHORIZATION, value);
            if let Some(key) = &self.config.dpop {
                let proof = proof(key, &access_token, request);
                let value = HeaderValue::from_str(&proof)
                    .map_err(|_| ProverError::new("the DPoP proof is not a valid header value"))?;
                request.headers_mut().insert("DPoP", value);
            }
            if let Some(id_token) = &self.config.id_token {
                if let Some(token) = id_token().await.filter(|token| !token.is_empty()) {
                    let value = HeaderValue::from_str(&token).map_err(|_| {
                        ProverError::new("the Tempo ID ID token is not a valid header value")
                    })?;
                    request.headers_mut().insert(ID_TOKEN_HEADER, value);
                }
            }
            Ok(())
        })
    }
}

/// HTTP options of a Tempo ID attestation exchange, shared by [`attest`] and
/// [`attestations`], as mppx's `TempoId.Client.attest` parameters.
#[cfg(feature = "identity-attestation")]
#[derive(Clone)]
pub struct AttestConfig {
    issuer: String,
    access_token: TokenFn,
    dpop: Option<DpopKey>,
    id_token: Option<IdTokenFn>,
    timeout: std::time::Duration,
    client: reqwest::Client,
}

#[cfg(feature = "identity-attestation")]
impl fmt::Debug for AttestConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttestConfig")
            .field("issuer", &self.issuer)
            .field("dpop", &self.dpop)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "identity-attestation")]
impl AttestConfig {
    /// Exchanges the live access token `access_token` returns at the Tempo ID
    /// attestation issuer `issuer` ([`issuer::create`](super::issuer::create)).
    ///
    /// `access_token` must return this client's own access token, from its
    /// own Tempo ID sign-in: [`attestations`] picks the cached attestations it
    /// presents by the token's `sub` and `client_id` without verifying its
    /// signature (only the issuer can), so a token from anywhere else would
    /// select another user's cached attestations.
    ///
    /// Fails unless `issuer` is an `https` URL (`http` only on localhost)
    /// without userinfo, a query, a fragment, whitespace or a backslash,
    /// since it receives the user's tokens. The URL is kept as the URL parser
    /// serializes it, without trailing slashes, as
    /// [`issuer::create`](super::issuer::create) keeps it, so both name the
    /// same attest endpoint.
    pub fn new<F, Fut>(issuer: &str, access_token: F) -> Result<Self, IdentityError>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, ProverError>> + Send + 'static,
    {
        let issuer = canonical_issuer(issuer).ok_or_else(|| {
            IdentityError::InvalidConfig(
                "the Tempo ID attestation issuer must be an https URL (http only on localhost) without userinfo, a query, a fragment, whitespace or a backslash".into(),
            )
        })?;
        let client = exchange_client(reqwest::Client::builder(), &issuer)?;
        Ok(Self {
            issuer,
            access_token: Arc::new(move || Box::pin(access_token())),
            dpop: None,
            id_token: None,
            timeout: std::time::Duration::from_secs(10),
            client,
        })
    }

    /// The DPoP key that binds the token. Without one, the token is sent as a Bearer token.
    pub fn dpop(mut self, key: DpopKey) -> Self {
        self.dpop = Some(key);
        self
    }

    /// Returns the user's ID token, which `email` needs and an issuer's policy may read.
    pub fn id_token<F, Fut>(mut self, id_token: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<String>> + Send + 'static,
    {
        self.id_token = Some(Arc::new(move || Box::pin(id_token())));
        self
    }

    /// How long to wait for the issuer before the exchange fails. Default: 10 seconds.
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sends exchanges with a client built from `builder`, such as for a
    /// proxy or TLS settings, with redirects turned off whatever it sets, and
    /// no proxy for a localhost issuer.
    pub fn http_client_builder(
        mut self,
        builder: reqwest::ClientBuilder,
    ) -> Result<Self, IdentityError> {
        self.client = exchange_client(builder, &self.issuer)?;
        Ok(self)
    }

    /// The issuer's URL, without a trailing slash.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// The client for exchanges with `issuer`: it follows no redirects, and a
/// localhost exchange, allowed over plaintext because the tokens stay on
/// this host, never goes through a proxy nor to an address off this host.
#[cfg(feature = "identity-attestation")]
fn exchange_client(
    builder: reqwest::ClientBuilder,
    issuer: &str,
) -> Result<reqwest::Client, IdentityError> {
    let builder = builder.redirect(reqwest::redirect::Policy::none());
    let builder = if is_loopback(issuer) {
        loopback_only(builder)
    } else {
        builder
    };
    builder.build().map_err(IdentityError::Request)
}

/// The largest issuer response [`attest`] reads, in bytes: an attestation of
/// at most [`MAX_LENGTH`] characters with room for its JSON envelope.
#[cfg(feature = "identity-attestation")]
const MAX_RESPONSE: usize = 2 * MAX_LENGTH;

/// One attestation a Tempo ID attestation issuer returned.
///
/// Its `Debug` output leaves the attestation out: it is a bearer proof for
/// its audience until it expires.
#[cfg(feature = "identity-attestation")]
#[derive(Clone, PartialEq, Eq)]
pub struct Attested {
    /// The attestation.
    pub attestation: String,
    /// When it expires.
    pub expires_at: std::time::SystemTime,
}

#[cfg(feature = "identity-attestation")]
impl fmt::Debug for Attested {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Attested")
            .field("attestation", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Reads at most `limit` bytes of `response`'s body, or returns `None` when
/// it is longer or cannot be read.
#[cfg(feature = "identity-attestation")]
async fn read_limited(response: &mut reqwest::Response, limit: usize) -> Option<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if body.len() + chunk.len() > limit {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(body)
}

/// Exchanges a Tempo ID access token for one attestation of
/// `attestation_type` for `audience` at a Tempo ID attestation issuer, as
/// mppx's `TempoId.Client.attest`.
///
/// Returns `Ok(None)` when the issuer refuses this user that type (403, such
/// as `email` without a verified address), and an error on any other failure.
///
/// It reads at most 16,384 bytes of the issuer's response, and none of a
/// refusal's. The attestation must decode, name this issuer as `iss`
/// exactly (as verifiers compare it), the requested audience's origin as
/// `aud` and the requested type, and expire in the second `expires_at`
/// names, or the exchange fails. The returned `expires_at` is the signed
/// `exp`, so it is never later than the attestation's own expiry.
#[cfg(feature = "identity-attestation")]
pub async fn attest(
    config: &AttestConfig,
    audience: &str,
    attestation_type: &str,
) -> Result<Option<Attested>, IdentityError> {
    let failed = |message: String| IdentityError::Acquire(message);
    let access_token = (config.access_token)()
        .await
        .map_err(|err| failed(err.to_string()))?;
    let url = reqwest::Url::parse(&format!(
        "{}{}",
        config.issuer,
        super::constants::ATTEST_PATH
    ))
    .map_err(|err| failed(format!("the issuer URL is invalid: {err}")))?;
    let scheme = if config.dpop.is_some() {
        "DPoP"
    } else {
        "Bearer"
    };
    let mut request = config
        .client
        .post(url.clone())
        .header(AUTHORIZATION, format!("{scheme} {access_token}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(serde_json::json!({ "audience": audience, "type": attestation_type }).to_string())
        .timeout(config.timeout);
    if let Some(key) = &config.dpop {
        let target = Request::new(reqwest::Method::POST, url);
        request = request.header("DPoP", proof(key, &access_token, &target));
    }
    // Sent on every exchange: an issuer's allow may read the verified email for any type.
    if let Some(id_token) = &config.id_token {
        if let Some(token) = id_token().await.filter(|token| !token.is_empty()) {
            request = request.header(ID_TOKEN_HEADER, token);
        }
    }
    let mut response = request.send().await.map_err(IdentityError::Request)?;
    let status = response.status();
    // A refusal's body is never used, so it is never read.
    if status == reqwest::StatusCode::FORBIDDEN {
        return Ok(None);
    }
    let body: Option<serde_json::Value> = read_limited(&mut response, MAX_RESPONSE)
        .await
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    if !status.is_success() {
        return Err(failed(
            body.as_ref()
                .and_then(|body| body.get("error"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("The issuer answered {}.", status.as_u16())),
        ));
    }
    let malformed = || failed("The issuer returned a malformed attestation.".into());
    let body = body.ok_or_else(malformed)?;
    let attestation = body
        .get("attestation")
        .and_then(serde_json::Value::as_str)
        .filter(|attestation| !attestation.is_empty())
        .ok_or_else(malformed)?;
    let expires_at = body
        .get("expires_at")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
        })
        .ok_or_else(malformed)?;
    let claims = decode(attestation).ok_or_else(malformed)?.claims;
    let text = |key: &str| claims.get(key).and_then(serde_json::Value::as_str);
    let requested = reqwest::Url::parse(audience)
        .ok()
        .map(|url| origin_of(&url));
    let matches = requested.is_some()
        && text("aud") == requested.as_deref()
        && text("type") == Some(attestation_type)
        && text("iss") == Some(config.issuer.as_str())
        && claims.get("exp").and_then(serde_json::Value::as_i64)
            == Some(expires_at.unix_timestamp());
    if !matches {
        return Err(failed(
            "The issuer returned an attestation that does not match the request.".into(),
        ));
    }
    // The envelope's instant may carry a fraction past the signed second.
    let exp = std::time::UNIX_EPOCH
        + std::time::Duration::from_secs(u64::try_from(expires_at.unix_timestamp()).unwrap_or(0));
    Ok(Some(Attested {
        attestation: attestation.to_owned(),
        expires_at: exp,
    }))
}

/// Creates a prover that presents Tempo ID attestations, obtaining them from
/// a Tempo ID attestation issuer when a server asks, as mppx's
/// `TempoId.Client.attestations`: an
/// [`AttestationProver`] whose acquirer exchanges the user's access token
/// (and ID token, for `email`) at the issuer with [`attest`].
///
/// Unlike [`prover`], the access token goes only to the issuer: servers in
/// `scope` get short-lived attestations bound to their origin, and verify
/// them like any other issuer's.
///
/// Attestations are kept per signed-in user and app, as the access token's
/// `sub` and `client_id` name them: when it names another user or app (or
/// none), the cache is dropped, so a new session never presents the previous
/// user's attestations. Only attestations whose `uid` is that user and whose
/// `azp` is that app are kept. When a 402 asks for one of these attestations,
/// or comes from an origin the previous user held one for, and the user
/// changed since this prover last looked, the payment is refused before it
/// is made. A paid attempt that carries attestations for another user than
/// the one signed in now (or while the access token cannot be read) is
/// refused before it is sent, so its Credential is released unused, rather
/// than sent without them. An unpaid request rejected for an attestation is
/// not resent when it carried one for another user. Sending the request
/// again presents the new user's.
///
/// The access token is read without verifying it: [`AttestConfig::new`]'s
/// `access_token` must return this client's own token. `types` defaults to
/// [`ATTESTATION_TYPES`](super::constants::ATTESTATION_TYPES), and
/// `attestations` restores ones held before, such as from storage.
///
/// Fails when a scope entry is not an origin.
#[cfg(feature = "identity-attestation")]
pub fn attestations<S, T, A>(
    config: AttestConfig,
    scope: impl IntoIterator<Item = S>,
    types: Option<impl IntoIterator<Item = T>>,
    attestations: impl IntoIterator<Item = A>,
) -> Result<TempoIdAttestations, IdentityError>
where
    S: AsRef<str>,
    T: AsRef<str>,
    A: AsRef<str>,
{
    let scope: Vec<String> = scope.into_iter().map(|s| s.as_ref().to_owned()).collect();
    let types: Vec<String> = match types {
        Some(types) => types.into_iter().map(|t| t.as_ref().to_owned()).collect(),
        None => super::constants::ATTESTATION_TYPES
            .iter()
            .map(|t| (*t).to_owned())
            .collect(),
    };
    let unavailable = AttestationProver::new(&scope, [config.issuer()])?.with_types(&types);
    Ok(TempoIdAttestations {
        prover_scope: Scope::origins(&scope),
        inner: Arc::new(AttestationsInner {
            config,
            scope,
            types,
            held: attestations
                .into_iter()
                .map(|a| a.as_ref().to_owned())
                .collect(),
            state: std::sync::Mutex::new(AttestationsState::default()),
            unavailable,
        }),
    })
}

/// The prover [`attestations`] returns. Clones share their cache.
#[cfg(feature = "identity-attestation")]
#[derive(Clone)]
pub struct TempoIdAttestations {
    prover_scope: Scope,
    inner: Arc<AttestationsInner>,
}

#[cfg(feature = "identity-attestation")]
impl fmt::Debug for TempoIdAttestations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempoIdAttestations")
            .field("issuer", &self.inner.config.issuer)
            .field("scope", &self.inner.scope)
            .field("types", &self.inner.types)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "identity-attestation")]
struct AttestationsInner {
    config: AttestConfig,
    scope: Vec<String>,
    types: Vec<String>,
    /// Attestations held before, restored for the first user only.
    held: Vec<String>,
    state: std::sync::Mutex<AttestationsState>,
    /// Used while the access token cannot be read: presents nothing, keeps the cache.
    unavailable: AttestationProver,
}

#[cfg(feature = "identity-attestation")]
#[derive(Default)]
struct AttestationsState {
    /// The signed-in user and their prover.
    current: Option<(Option<Holder>, AttestationProver)>,
    /// The sequence number the last lookup took.
    latest: u64,
    /// The sequence number of the newest lookup that set or confirmed
    /// `current`. A lookup replaces `current` only when no newer lookup has
    /// set or confirmed it, so a slow lookup cannot roll it back, while
    /// overlapping lookups still keep a prover.
    stored: u64,
    /// The sequence number of the newest lookup that could not read the
    /// access token. An older lookup that ends later presents nothing.
    unreadable: u64,
}

/// Who an attestation or access token names: the user and the app.
#[cfg(feature = "identity-attestation")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct Holder {
    user: String,
    app: Option<String>,
}

#[cfg(feature = "identity-attestation")]
impl Holder {
    /// The user (`sub`) and app (`client_id`) an access token names.
    fn of_access_token(token: &str) -> Option<Self> {
        let claims = jwt::decode(token)?.claims;
        let text = |key: &str| {
            claims
                .get(key)
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        Some(Self {
            user: text("sub")?,
            app: text("client_id"),
        })
    }

    /// The user (`uid`) and app (`azp`) an attestation names.
    fn of_attestation(token: &str) -> Option<Self> {
        let claims = decode(token)?.claims;
        let text = |key: &str| {
            claims
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        Some(Self {
            user: text("uid")?,
            app: text("azp"),
        })
    }
}

/// A lookup of the signed-in user.
#[cfg(feature = "identity-attestation")]
struct Resolved {
    /// The user the cache belonged to before this lookup, and their prover,
    /// if it had one.
    previous: Option<(Option<Holder>, AttestationProver)>,
    /// The user this prover presents for, or `None` when the token names
    /// nobody or could not be read.
    holder: Option<Holder>,
    prover: AttestationProver,
    /// Whether the access token could not be read.
    unreadable: bool,
}

#[cfg(feature = "identity-attestation")]
impl TempoIdAttestations {
    fn state(&self) -> std::sync::MutexGuard<'_, AttestationsState> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `token` is an attestation this prover obtains, and who it names.
    fn ours(&self, token: &str) -> Option<Holder> {
        let claims = decode(token)?.claims;
        let text = |key: &str| claims.get(key).and_then(serde_json::Value::as_str);
        let attestation_type = text("type")?;
        (text("iss")? == self.inner.config.issuer
            && self.inner.types.iter().any(|t| t == attestation_type))
        .then(|| Holder::of_attestation(token))
        .flatten()
    }

    fn create(
        &self,
        user: Option<Holder>,
        held: &[String],
    ) -> Result<AttestationProver, IdentityError> {
        let config = self.inner.config.clone();
        let wanted = user.clone();
        let prover = AttestationProver::new(&self.inner.scope, [config.issuer()])?
            .with_types(&self.inner.types)
            .with_acquire(move |request| {
                let config = config.clone();
                let user = wanted.clone();
                async move {
                    let Some(attested) =
                        attest(&config, &request.audience, &request.attestation_type).await?
                    else {
                        return Ok(None);
                    };
                    // Only keep an attestation for the user and app this cache belongs to.
                    let holder = Holder::of_attestation(&attested.attestation);
                    Ok((user.is_some() && holder == user).then_some(attested.attestation))
                }
            });
        for token in held {
            // A malformed stored attestation is skipped, not fatal.
            let _ = prover.insert(token);
        }
        Ok(prover)
    }

    /// The prover for the user the access token names now.
    async fn resolve(&self) -> Resolved {
        let lookup = {
            let mut state = self.state();
            state.latest += 1;
            state.latest
        };
        let token = (self.inner.config.access_token)().await;
        let mut state = self.state();
        let previous = state.current.clone();
        let unavailable = |previous| Resolved {
            previous,
            holder: None,
            prover: self.inner.unavailable.clone(),
            unreadable: true,
        };
        let user = match token {
            Ok(token) => Holder::of_access_token(&token),
            // The token could not be read this time: present nothing, but keep the user's cache.
            Err(_) => {
                state.unreadable = state.unreadable.max(lookup);
                return unavailable(previous);
            }
        };
        // A newer lookup found the token unreadable (such as after sign-out):
        // an older one ending later presents nothing either.
        if lookup < state.unreadable {
            return unavailable(previous);
        }
        if let Some((current, prover)) = state.current.clone() {
            if current == user {
                // Confirming the user counts as the newest lookup, so an older
                // lookup that saw another user cannot replace it afterwards.
                state.stored = state.stored.max(lookup);
                return Resolved {
                    previous,
                    holder: user,
                    prover,
                    unreadable: false,
                };
            }
            // A newer lookup already installed its user: present for that user, so a
            // slow lookup never presents for a user the cache no longer belongs to.
            if lookup < state.stored {
                return Resolved {
                    holder: current,
                    prover,
                    previous,
                    unreadable: false,
                };
            }
        }
        // Stored attestations are restored only for this issuer and the user they name.
        let held: Vec<String> = match (&state.current, &user) {
            (None, Some(user)) => self
                .inner
                .held
                .iter()
                .filter(|token| self.ours(token).as_ref() == Some(user))
                .cloned()
                .collect(),
            _ => Vec::new(),
        };
        let prover = match self.create(user.clone(), &held) {
            Ok(prover) => prover,
            Err(_) => return unavailable(previous),
        };
        state.current = Some((user.clone(), prover.clone()));
        state.stored = lookup;
        Resolved {
            previous,
            holder: user,
            prover,
            unreadable: false,
        }
    }

    /// Whether `request` carries an attestation this prover obtains for
    /// another user than `user`.
    fn carries_other(&self, request: &Request, user: Option<&Holder>) -> bool {
        parse_header(
            request
                .headers()
                .get_all(ATTESTATION_HEADER)
                .iter()
                .filter_map(|value| value.to_str().ok()),
        )
        .iter()
        .any(|token| self.ours(token).is_some_and(|holder| Some(&holder) != user))
    }

    /// Whether `requirements` ask for an attestation this prover obtains.
    fn required(&self, requirements: &[crate::identity::Requirement]) -> bool {
        requirements.iter().any(|requirement| {
            self.inner.types.contains(&requirement.kind)
                && requirement
                    .issuer
                    .as_deref()
                    .is_none_or(|issuer| trim_issuer(issuer) == self.inner.config.issuer)
        })
    }
}

#[cfg(feature = "identity-attestation")]
impl Prover for TempoIdAttestations {
    fn scope(&self) -> &Scope {
        &self.prover_scope
    }

    fn prove<'a>(
        &'a self,
        request: &'a mut Request,
        context: &'a ProveContext,
    ) -> BoxFuture<'a, Result<(), ProverError>> {
        Box::pin(async move {
            let Resolved {
                holder: user,
                prover,
                unreadable,
                ..
            } = self.resolve().await;
            // A request already in flight (such as a payment retry) may still
            // carry the previous user's attestations from this prover: drop
            // those, and only those, naming another user.
            let sent = parse_header(
                request
                    .headers()
                    .get_all(ATTESTATION_HEADER)
                    .iter()
                    .filter_map(|value| value.to_str().ok()),
            );
            let kept: Vec<String> = sent
                .iter()
                .filter(|token| match self.ours(token) {
                    Some(uid) => user.as_ref() == Some(&uid),
                    None => true,
                })
                .cloned()
                .collect();
            if kept.len() != sent.len() {
                // A paid attempt sent without them would carry a Credential to a
                // route that refuses it: refuse before it leaves, so the
                // Credential is released unused.
                if is_paid(request, context) {
                    return Err(ProverError::new(if unreadable {
                        "The Tempo ID access token could not be read: send the request again."
                    } else {
                        USER_CHANGED
                    }));
                }
                let headers = request.headers_mut();
                match HeaderValue::from_str(&kept.join(", ")) {
                    Ok(value) if !kept.is_empty() => {
                        headers.insert(ATTESTATION_HEADER, value);
                    }
                    _ => {
                        headers.remove(ATTESTATION_HEADER);
                    }
                }
            }
            prover.prove(request, context).await
        })
    }

    fn prepare<'a>(
        &'a self,
        response: &'a ResponseParts,
        context: &'a PrepareContext,
    ) -> BoxFuture<'a, Result<(), ProverError>> {
        Box::pin(async move {
            let resolved = self.resolve().await;
            // The paid attempt cannot carry the previous user's attestations, and a
            // route that requires them would refuse it after the payment: refuse
            // before paying when the 402 lists one, or (for a route that asks
            // only with Identity-Attestation-Required) when the previous user
            // held one for this origin.
            if let Some((Some(previous), previous_prover)) = &resolved.previous {
                if resolved.holder.as_ref() != Some(previous)
                    && (self.required(&context.requirements)
                        || holds_for(previous_prover, &response.url))
                {
                    return Err(ProverError::new(USER_CHANGED));
                }
            }
            resolved.prover.prepare(response, context).await
        })
    }

    fn retry<'a>(
        &'a self,
        response: &'a ResponseParts,
        context: RetryContext<'a>,
    ) -> BoxFuture<'a, Option<HeaderMap>> {
        Box::pin(async move {
            // Only a 401 or 403 asking for an attestation can be answered: never
            // read the access token for any other rejection.
            let answerable = matches!(
                response.status,
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
            ) && !requirements(&response.headers).is_empty();
            if !answerable {
                return None;
            }
            let resolved = self.resolve().await;
            // A request proved for another user is not resent under this one.
            if self.carries_other(context.request, resolved.holder.as_ref()) {
                return None;
            }
            resolved.prover.retry(response, context).await
        })
    }
}

#[cfg(feature = "identity-attestation")]
const USER_CHANGED: &str = "The signed-in Tempo ID user changed: send the request again.";

/// Whether a request is a paid attempt, as [`AttestationProver`] decides.
#[cfg(feature = "identity-attestation")]
fn is_paid(request: &Request, context: &ProveContext) -> bool {
    context.challenge.is_some()
        || ["payment-signature", "x-payment"]
            .iter()
            .any(|name| request.headers().contains_key(*name))
        || request
            .headers()
            .values()
            .filter_map(|value| value.to_str().ok())
            .any(|value| extract_payment_scheme(value).is_some())
}

/// Whether `prover` holds an attestation it would present on a paid
/// request to `url`'s origin.
#[cfg(feature = "identity-attestation")]
fn holds_for(prover: &AttestationProver, url: &reqwest::Url) -> bool {
    let mut probe = Request::new(reqwest::Method::GET, url.clone());
    prover.present(&mut probe, true);
    probe.headers().contains_key(ATTESTATION_HEADER)
}

/// Signs a DPoP proof (RFC 9449) of `access_token` for one request.
pub(crate) fn proof(key: &DpopKey, access_token: &str, request: &Request) -> String {
    use p256::ecdsa::signature::Signer as _;
    let (x, y) = key.public_coordinates();
    let header = jwt::encode(&serde_json::json!({
        "alg": "ES256",
        "jwk": { "crv": "P-256", "kty": "EC", "x": x, "y": y },
        "typ": "dpop+jwt",
    }));
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let claims = jwt::encode(&serde_json::json!({
        "ath": jwt::sha256(access_token),
        "htm": request.method().as_str(),
        "htu": jwt::htu(request.url()),
        "iat": iat,
        "jti": uuid::Uuid::new_v4().to_string(),
    }));
    let input = format!("{header}.{claims}");
    let signature: p256::ecdsa::Signature = key.signing_key.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}
