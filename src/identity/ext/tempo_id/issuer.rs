//! A Tempo ID attestation issuer, as mppx's `TempoId.Issuer`: exchanges a
//! signed-in user's Tempo ID access token for `Identity-Attestation` tokens.

use std::fmt;
use std::future::Future;
use std::sync::Arc;

use http_types::header::{ALLOW, CACHE_CONTROL, CONTENT_LENGTH, RETRY_AFTER};
use http_types::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use serde_json::{json, Map, Value};

use super::constants::{ATTESTATION_TYPES, ATTEST_PATH};
use super::server::{self, AllowFn, Config, TempoId};
use super::Payer;
use crate::identity::ext::attestation::issuer::json_response;
use crate::identity::ext::attestation::{
    canonical_issuer, decode, is_issuer, is_loopback, loopback_only, origin_of, AttestationIssuer,
    IdentityError, SignParameters, SigningKey,
};
use crate::identity::{IdentityRequest, RejectionStatus, Verification, Verifier};
use crate::store::Store;

/// The largest request body the issuer reads, in bytes.
pub const MAX_BODY: usize = 4_096;

/// Tempo ID attestation issuer options, as mppx's `TempoId.Issuer.create` config.
#[derive(Clone)]
pub struct IssuerConfig {
    url: String,
    signing_key: SigningKey,
    client_ids: Vec<String>,
    store: Arc<dyn Store>,
    types: Vec<String>,
    ttl: Option<u64>,
    allow: Option<AllowFn>,
    token_audience: Option<String>,
    issuer: Option<String>,
    http: Option<reqwest::Client>,
    chain_id: Option<u64>,
    audiences: Option<Vec<String>>,
}

impl fmt::Debug for IssuerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuerConfig")
            .field("url", &self.url)
            .field("client_ids", &self.client_ids)
            .field("types", &self.types)
            .field("ttl", &self.ttl)
            .field("token_audience", &self.token_audience)
            .field("issuer", &self.issuer)
            .field("chain_id", &self.chain_id)
            .field("audiences", &self.audiences)
            .finish_non_exhaustive()
    }
}

impl IssuerConfig {
    /// An issuer at `url` (which attestations carry as `iss`) that signs with
    /// `signing_key`, exchanges tokens of the app `client_id`, and accepts each
    /// DPoP proof once with `store`, so a captured proof cannot be exchanged
    /// again. The store must implement `put_if_absent_with_ttl` atomically.
    pub fn new(
        url: impl Into<String>,
        signing_key: SigningKey,
        client_id: impl Into<String>,
        store: Arc<dyn Store>,
    ) -> Self {
        Self {
            url: url.into(),
            signing_key,
            client_ids: vec![client_id.into()],
            store,
            types: ATTESTATION_TYPES.iter().map(|t| (*t).to_owned()).collect(),
            ttl: None,
            allow: None,
            token_audience: None,
            issuer: None,
            http: None,
            chain_id: None,
            audiences: None,
        }
    }

    /// Also exchanges tokens of the app `client_id`.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_ids.push(client_id.into());
        self
    }

    /// Attestation types this issuer signs, from [`ATTESTATION_TYPES`].
    /// Default: all of them.
    pub fn types<T: AsRef<str>>(mut self, types: impl IntoIterator<Item = T>) -> Self {
        self.types = types.into_iter().map(|t| t.as_ref().to_owned()).collect();
        self
    }

    /// Seconds each attestation is valid. Default: 3600.
    pub fn ttl(mut self, ttl: u64) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Decides whether a verified user may get attestations.
    pub fn allow<F>(self, allow: F) -> Self
    where
        F: Fn(&Payer) -> bool + Send + Sync + 'static,
    {
        self.allow_async(move |user| std::future::ready(allow(user)))
    }

    /// Like [`allow`](Self::allow), deciding asynchronously.
    pub fn allow_async<F, Fut>(mut self, allow: F) -> Self
    where
        F: Fn(&Payer) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = bool> + Send + 'static,
    {
        self.allow = Some(Arc::new(move |user| Box::pin(allow(user))));
        self
    }

    /// The audience access tokens must name. Default: this issuer's `url`, so
    /// a token Tempo ID issued for another API cannot be exchanged here.
    pub fn token_audience(mut self, audience: impl Into<String>) -> Self {
        self.token_audience = Some(audience.into());
        self
    }

    /// Tempo ID's origin, whose keys verify access tokens: an `https` URL
    /// (`http` only on localhost). Default: `https://id.tempo.xyz`.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// The only audience origins this issuer signs attestations for. A
    /// request for any other audience is refused with 403. Default: any
    /// `https` origin, as mppx.
    ///
    /// A DPoP proof covers the request's method and URL, not its body, so
    /// whoever holds a user's access token and an unspent proof can choose
    /// the audience and type. Set this when the issuer serves a known set of
    /// APIs, so a captured token can only be exchanged for them.
    pub fn audiences<T: AsRef<str>>(mut self, audiences: impl IntoIterator<Item = T>) -> Self {
        self.audiences = Some(
            audiences
                .into_iter()
                .map(|a| a.as_ref().to_owned())
                .collect(),
        );
        self
    }

    /// The HTTP client that fetches Tempo ID's keys. It should not follow
    /// redirects, since the keys it fetches decide whom the issuer signs
    /// for. Default: a client that follows no redirects (and, for a
    /// localhost Tempo ID, uses no proxy). [`create`] refuses one with an
    /// `http` (localhost) Tempo ID origin, whose plaintext key discovery
    /// must never go through a proxy.
    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    /// The chain whose accounts `allow` sees, such as Moderato `42431`. Default: 4217.
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = Some(chain_id);
        self
    }
}

/// A Tempo ID attestation issuer from [`create`].
#[derive(Clone)]
pub struct TempoIdIssuer {
    attestation: AttestationIssuer,
    tempo_id: TempoId,
    types: Vec<String>,
    attest_path: String,
    audiences: Option<Vec<String>>,
}

impl fmt::Debug for TempoIdIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempoIdIssuer")
            .field("issuer", &self.attestation.issuer())
            .field("types", &self.types)
            .finish_non_exhaustive()
    }
}

/// Creates a Tempo ID attestation issuer, as mppx's `TempoId.Issuer.create`:
/// it exchanges a signed-in user's Tempo ID access token for
/// `Identity-Attestation` tokens that any MPP server verifies with an
/// [`AttestationVerifier`](crate::identity::ext::attestation::AttestationVerifier),
/// like those of any other issuer.
///
/// - `tempo-id`: `sub` is the user's Tempo ID user ID.
/// - `email`: `sub` is the user's email address, only when the client sends
///   an ID token (`Tempo-Id-Token`) and Tempo ID verified the address.
///
/// Every attestation carries the user ID as `uid`, so a server can tell that
/// attestations of several types name one user, and the app that exchanged
/// the token as `azp`. The access token is checked as
/// [`server::create`] checks it, including its DPoP proof, which the client
/// signs for this issuer's attest endpoint.
///
/// [`handle`](TempoIdIssuer::handle) answers, relative to `url`:
/// - `POST /tempo-id/attest` ([`ATTEST_PATH`]) with `{ audience, type }`:
///   `200` `{ attestation, expires_at }`; `400`, `401`, `403` or `503` `{ error }`.
/// - `GET /.well-known/jwks.json`: the attestation key.
///
/// Fails unless `url` is an `https` URL (`http` only on localhost) without
/// userinfo, a query, a fragment, whitespace or a backslash, the Tempo ID
/// origin is an `https` URL (`http` only on localhost), every type is one of
/// [`ATTESTATION_TYPES`], every audience is an `https` origin, and a client
/// ID is set.
pub fn create(config: IssuerConfig) -> Result<TempoIdIssuer, IdentityError> {
    let url = canonical_issuer(&config.url).ok_or_else(|| {
        IdentityError::InvalidConfig(
            "Tempo ID attestation issuer url must be an https URL without userinfo, a query, a fragment, whitespace or a backslash"
                .into(),
        )
    })?;
    // Its keys decide whom this issuer signs for, so they never travel in plaintext off this host.
    if let Some(issuer) = &config.issuer {
        if !is_issuer(issuer) {
            return Err(IdentityError::InvalidConfig(
                "Tempo ID origin must be an https URL (http only on localhost)".into(),
            ));
        }
    }
    let audiences = match &config.audiences {
        Some(audiences) => Some(
            audiences
                .iter()
                .map(|audience| audience_origin(audience))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    IdentityError::InvalidConfig(
                        "Tempo ID attestation issuer audiences must be https origins".into(),
                    )
                })?,
        ),
        None => None,
    };
    for attestation_type in &config.types {
        if !ATTESTATION_TYPES.contains(&attestation_type.as_str()) {
            return Err(IdentityError::InvalidConfig(format!(
                "Tempo ID attestation issuer cannot sign type {attestation_type:?}"
            )));
        }
    }
    if config.client_ids.iter().all(String::is_empty) {
        return Err(IdentityError::InvalidConfig(
            "Tempo ID attestation issuer requires a client ID: the apps that may exchange tokens"
                .into(),
        ));
    }
    let mut attestation = AttestationIssuer::new(&url, config.signing_key.clone())?;
    if let Some(ttl) = config.ttl {
        attestation = attestation.with_ttl(ttl)?;
    }
    let parsed = reqwest::Url::parse(&url)
        .map_err(|err| IdentityError::InvalidConfig(format!("url: {err}")))?;
    let attest_path = format!("{}{ATTEST_PATH}", parsed.path().trim_end_matches('/'));

    let mut client_ids = config.client_ids.iter().filter(|id| !id.is_empty());
    let mut server_config = Config::new(client_ids.next().cloned().unwrap_or_default());
    for client_id in client_ids {
        server_config = server_config.client_id(client_id.clone());
    }
    server_config = server_config
        // Only tokens issued for this issuer: a token another API received cannot be exchanged here.
        .audience(config.token_audience.clone().unwrap_or_else(|| url.clone()))
        // DPoP proofs must name this issuer's configured endpoint, never one built from the Host header.
        .origin(parsed.origin().ascii_serialization())
        .store(config.store.clone());
    if let Some(issuer) = &config.issuer {
        server_config = server_config.issuer(issuer.clone());
    }
    let tempo_id = config.issuer.as_deref().unwrap_or(super::constants::ISSUER);
    // Plaintext key discovery is safe only on this host, through a client that
    // never sends it to a proxy; an injected client may have one.
    // Read from the parsed URL, so every spelling the parser accepts counts.
    let plaintext = reqwest::Url::parse(tempo_id).is_ok_and(|url| url.scheme() == "http");
    let http = match &config.http {
        Some(_) if plaintext => {
            return Err(IdentityError::InvalidConfig(
                "an http Tempo ID origin fetches its keys with the issuer's own client, which uses no proxy: leave http_client unset".into(),
            ))
        }
        Some(http) => http.clone(),
        None => {
            let builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
            let builder = if is_loopback(tempo_id) {
                loopback_only(builder)
            } else {
                builder
            };
            builder.build().map_err(IdentityError::Request)?
        }
    };
    server_config = server_config.http_client(http);
    if let Some(chain_id) = config.chain_id {
        server_config = server_config.chain_id(chain_id);
    }
    if let Some(allow) = config.allow.clone() {
        server_config = server_config.allow_async(move |user| allow(user));
    }

    Ok(TempoIdIssuer {
        attestation,
        tempo_id: server::create(server_config),
        types: config.types,
        attest_path,
        audiences,
    })
}

impl TempoIdIssuer {
    /// This issuer's URL, without a trailing slash.
    pub fn issuer(&self) -> &str {
        self.attestation.issuer()
    }

    /// The attestation issuer that signs, which also resolves this issuer's
    /// key in process (as a [`KeyResolver`](crate::identity::ext::attestation::KeyResolver))
    /// for a server that runs beside it.
    pub fn attestation_issuer(&self) -> &AttestationIssuer {
        &self.attestation
    }

    /// This issuer's JSON Web Key Set.
    pub fn jwks(&self) -> Value {
        self.attestation.jwks()
    }

    /// Answers the issuer's routes, and returns `None` for any other request.
    ///
    /// Read at most [`MAX_BODY`] bytes of the body before calling it: a longer
    /// body is refused.
    pub async fn handle<B: AsRef<[u8]>>(&self, request: &Request<B>) -> Option<Response<Vec<u8>>> {
        if request.uri().path() != self.attest_path {
            return self.attestation.handle(request);
        }
        if request.method() == Method::OPTIONS {
            let mut response = Response::new(Vec::new());
            *response.status_mut() = StatusCode::NO_CONTENT;
            let headers = response.headers_mut();
            for (name, value) in [
                ("access-control-allow-origin", "*"),
                (
                    "access-control-allow-headers",
                    "authorization, content-type, dpop, tempo-id-token",
                ),
                ("access-control-allow-methods", "POST"),
                ("access-control-max-age", "600"),
            ] {
                headers.insert(
                    HeaderName::from_static(name),
                    HeaderValue::from_static(value),
                );
            }
            return Some(response);
        }
        if request.method() != Method::POST {
            let mut headers = HeaderMap::new();
            headers.insert(ALLOW, HeaderValue::from_static("POST"));
            return Some(error(StatusCode::METHOD_NOT_ALLOWED, "Use POST.", headers));
        }
        Some(self.attest(request).await)
    }

    async fn attest<B: AsRef<[u8]>>(&self, request: &Request<B>) -> Response<Vec<u8>> {
        let bad_request = |message: &str| error(StatusCode::BAD_REQUEST, message, HeaderMap::new());
        let declared = request
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let bytes = request.body().as_ref();
        let body = (declared <= MAX_BODY as u64 && bytes.len() <= MAX_BODY)
            .then(|| serde_json::from_slice::<Value>(bytes).ok())
            .flatten();
        let Some(body) = body else {
            return bad_request(&format!(
                "The body must be JSON of at most {MAX_BODY} bytes."
            ));
        };
        let field = |name: &str| body.get(name).and_then(Value::as_str);
        let audience = match field("audience") {
            Some(audience) if audience.len() <= 2_048 && is_issuer(audience) => audience,
            _ => return bad_request("audience must be an https origin."),
        };
        if let Some(audiences) = &self.audiences {
            if audience_origin(audience).is_none_or(|origin| !audiences.contains(&origin)) {
                return error(
                    StatusCode::FORBIDDEN,
                    "This issuer does not sign attestations for that audience.",
                    HeaderMap::new(),
                );
            }
        }
        let attestation_type = match field("type") {
            Some(t) if self.types.iter().any(|known| known == t) => t,
            _ => {
                return bad_request(&format!("type must be one of {}.", self.types.join(", ")));
            }
        };

        let verified = self
            .tempo_id
            .verifier
            .verify(&IdentityRequest::new(
                request.method().clone(),
                Uri::try_from(self.attest_path.as_str()).unwrap_or_default(),
                request.headers().clone(),
            ))
            .await;
        let user = match verified {
            Verification::Valid(user) => user,
            Verification::Rejected(rejection) => {
                let headers = match rejection.status {
                    RejectionStatus::Missing | RejectionStatus::Invalid => rejection.headers,
                    _ => HeaderMap::new(),
                };
                return error(rejection.status.code(), &rejection.reason, headers);
            }
        };
        let sub = if attestation_type == "email" {
            match (&user.email, user.email_verified) {
                (Some(email), Some(true)) => email.clone(),
                _ => {
                    return error(
                        StatusCode::FORBIDDEN,
                        "Send an ID token naming an email address Tempo ID verified.",
                        HeaderMap::new(),
                    )
                }
            }
        } else {
            user.user_id.clone()
        };

        let mut claims = Map::new();
        // The app that exchanged the token, so a server can restrict which apps it accepts.
        claims.insert("azp".into(), user.client_id.clone().into());
        let signed = self.attestation.sign(
            SignParameters::new(audience, attestation_type, sub)
                .uid(user.user_id.clone())
                .claims(claims),
        );
        let token = match signed {
            Ok(token) => token,
            // Bad input is the caller's to fix; anything else is the signer's outage, worth a retry.
            Err(IdentityError::InvalidParameters(_)) => {
                return bad_request("The attestation cannot be signed for this request.")
            }
            Err(_) => {
                let mut headers = HeaderMap::new();
                headers.insert(RETRY_AFTER, HeaderValue::from_static("5"));
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The attestation signer is unavailable.",
                    headers,
                );
            }
        };
        let expires_at = decode(&token)
            .and_then(|decoded| decoded.claims.get("exp").and_then(Value::as_i64))
            .and_then(iso_time);
        let Some(expires_at) = expires_at else {
            return bad_request("The attestation cannot be signed for this request.");
        };
        let mut response = json_response(
            StatusCode::OK,
            &json!({ "attestation": token, "expires_at": expires_at }),
        );
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// The origin of `audience`, when it is an `https` URL (`http` only on localhost).
fn audience_origin(audience: &str) -> Option<String> {
    is_issuer(audience)
        .then(|| reqwest::Url::parse(audience).ok())
        .flatten()
        .map(|url| origin_of(&url))
}

/// Unix seconds as an ISO 8601 UTC time with milliseconds, as JavaScript's
/// `Date.prototype.toISOString` writes it.
fn iso_time(seconds: i64) -> Option<String> {
    let time = time::OffsetDateTime::from_unix_timestamp(seconds).ok()?;
    Some(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    ))
}

fn error(status: StatusCode, message: &str, mut headers: HeaderMap) -> Response<Vec<u8>> {
    let mut response = json_response(status, &json!({ "error": message }));
    for (name, value) in response.headers().iter() {
        headers.insert(name.clone(), value.clone());
    }
    *response.headers_mut() = headers;
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_times_as_javascript_does() {
        assert_eq!(iso_time(0).as_deref(), Some("1970-01-01T00:00:00.000Z"));
        assert_eq!(
            iso_time(1_800_000_000).as_deref(),
            Some("2027-01-15T08:00:00.000Z")
        );
    }
}
