//! Tempo ID on the client: a prover, as mppx's `TempoId.Client.prover`.

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
use crate::identity::client::{ProveContext, Prover, ProverError, Scope};
use crate::identity::BoxFuture;

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

impl Prover for TempoIdProver {
    fn scope(&self) -> &Scope {
        &self.config.scope
    }

    fn headers(&self) -> &[&'static str] {
        HEADERS
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
