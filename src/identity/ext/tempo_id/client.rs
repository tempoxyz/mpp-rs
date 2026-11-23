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
    decode, is_issuer, parse_header, AttestationProver, IdentityError, HEADER as ATTESTATION_HEADER,
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
    /// Fails unless `issuer` is an `https` URL (`http` only on localhost)
    /// without a query or fragment, since it receives the user's tokens.
    pub fn new<F, Fut>(issuer: &str, access_token: F) -> Result<Self, IdentityError>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String, ProverError>> + Send + 'static,
    {
        let issuer = issuer.trim_end_matches('/');
        if !is_issuer(issuer) || issuer.contains(['?', '#']) {
            return Err(IdentityError::InvalidConfig(
                "the Tempo ID attestation issuer must be an https URL (http only on localhost) without a query or fragment".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(IdentityError::Request)?;
        Ok(Self {
            issuer: issuer.to_owned(),
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
    /// proxy or TLS settings, with redirects turned off whatever it sets.
    pub fn http_client_builder(
        mut self,
        builder: reqwest::ClientBuilder,
    ) -> Result<Self, IdentityError> {
        self.client = builder
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(IdentityError::Request)?;
        Ok(self)
    }

    /// The issuer's URL, without a trailing slash.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

/// One attestation a Tempo ID attestation issuer returned.
#[cfg(feature = "identity-attestation")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    /// The attestation.
    pub attestation: String,
    /// When it expires.
    pub expires_at: std::time::SystemTime,
}

/// Exchanges a Tempo ID access token for one attestation of
/// `attestation_type` for `audience` at a Tempo ID attestation issuer, as
/// mppx's `TempoId.Client.attest`.
///
/// Returns `Ok(None)` when the issuer refuses this user that type (403, such
/// as `email` without a verified address), and an error on any other failure.
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
    let response = request.send().await.map_err(IdentityError::Request)?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    if status == reqwest::StatusCode::FORBIDDEN {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(failed(
            body.get("error")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| format!("The issuer answered {}.", status.as_u16())),
        ));
    }
    let malformed = || failed("The issuer returned a malformed attestation.".into());
    let attestation = body
        .get("attestation")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(malformed)?;
    let expires_at = body
        .get("expires_at")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| {
            time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
        })
        .ok_or_else(malformed)?;
    Ok(Some(Attested {
        attestation: attestation.to_owned(),
        expires_at: expires_at.into(),
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
/// Attestations are kept per signed-in user, as the access token's `sub`
/// names them: when it names another user (or none), the cache is dropped,
/// so a new session never presents the previous user's attestations. Only
/// attestations whose `uid` is that user are kept. `types` defaults to
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
    current: Option<(Option<String>, AttestationProver)>,
    /// The sequence number the last lookup took.
    latest: u64,
    /// The sequence number of the lookup that set `current`. A lookup replaces
    /// `current` only when no newer lookup has, so a slow lookup cannot roll
    /// it back, while overlapping lookups still keep a prover.
    stored: u64,
}

#[cfg(feature = "identity-attestation")]
impl TempoIdAttestations {
    fn state(&self) -> std::sync::MutexGuard<'_, AttestationsState> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `token` is an attestation this prover obtains, and the user it names.
    fn ours(&self, token: &str) -> Option<String> {
        let claims = decode(token)?.claims;
        let text = |key: &str| claims.get(key).and_then(serde_json::Value::as_str);
        let attestation_type = text("type")?;
        (text("iss")? == self.inner.config.issuer
            && self.inner.types.iter().any(|t| t == attestation_type))
        .then(|| text("uid").map(str::to_owned))
        .flatten()
    }

    fn create(
        &self,
        user: Option<String>,
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
                    // Only keep an attestation for the user this cache belongs to.
                    let uid = decode(&attested.attestation).and_then(|decoded| {
                        decoded
                            .claims
                            .get("uid")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    });
                    Ok((user.is_some() && uid == user).then_some(attested.attestation))
                }
            });
        for token in held {
            // A malformed stored attestation is skipped, not fatal.
            let _ = prover.insert(token);
        }
        Ok(prover)
    }

    /// The prover for the user the access token names now.
    async fn resolve(&self) -> (Option<String>, AttestationProver) {
        let lookup = {
            let mut state = self.state();
            state.latest += 1;
            state.latest
        };
        let user = match (self.inner.config.access_token)().await {
            Ok(token) => jwt::decode(&token).and_then(|decoded| {
                decoded
                    .claims
                    .get("sub")
                    .and_then(serde_json::Value::as_str)
                    .filter(|sub| !sub.is_empty())
                    .map(str::to_owned)
            }),
            // The token could not be read this time: present nothing, but keep the user's cache.
            Err(_) => return (None, self.inner.unavailable.clone()),
        };
        let mut state = self.state();
        if let Some((current, prover)) = &state.current {
            if *current == user {
                return (user, prover.clone());
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
            Err(_) => return (None, self.inner.unavailable.clone()),
        };
        if lookup > state.stored {
            state.current = Some((user.clone(), prover.clone()));
            state.stored = lookup;
        }
        (user, prover)
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
            let (user, prover) = self.resolve().await;
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
        Box::pin(async move { self.resolve().await.1.prepare(response, context).await })
    }

    fn retry<'a>(
        &'a self,
        response: &'a ResponseParts,
        context: RetryContext<'a>,
    ) -> BoxFuture<'a, Option<HeaderMap>> {
        Box::pin(async move { self.resolve().await.1.retry(response, context).await })
    }
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
