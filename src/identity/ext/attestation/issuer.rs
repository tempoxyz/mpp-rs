//! An attestation issuer: signs attestations and publishes its key, as mppx's
//! `Attestation.Issuer`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use http_types::header::{ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL, CONTENT_TYPE};
use http_types::{HeaderValue, Method, Request, Response, StatusCode};
use serde_json::{Map, Value};

use super::jwks::{KeyResolver, KeyResolverFuture};
use super::token::{is_confirmation, is_issuer, sign as sign_token, thumbprint, Confirmation};
use super::{canonical_issuer, now, trim_issuer, IdentityError, ALGORITHM, JWKS_PATH, MAX_LENGTH};

/// Default attestation lifetime, in seconds.
pub const DEFAULT_TTL: u64 = 3_600;

/// Longest attestation lifetime an issuer accepts, in seconds: one year.
const MAX_TTL: u64 = 31_536_000;

/// What [`AttestationIssuer::sign`] attests.
#[derive(Debug, Clone, Default)]
pub struct SignParameters {
    /// Origin of the server the attestation is for, such as `https://api.example`.
    pub audience: String,
    /// Attestation type, such as `email` or `github`.
    pub attestation_type: String,
    /// The attested subject: an address, or the provider's stable account identifier.
    pub sub: String,
    /// The issuer's identifier for the user, shared by all of their attestations.
    pub uid: Option<String>,
    /// What the attestation is bound to (RFC 7800).
    pub cnf: Option<Confirmation>,
    /// Other claims to include. Registered claims (`iss`, `aud`, `sub`,
    /// `type`, times) win.
    pub claims: Option<Map<String, Value>>,
    /// Seconds this attestation is valid, instead of the issuer's lifetime.
    pub ttl: Option<u64>,
}

impl SignParameters {
    /// An attestation of `attestation_type` about `sub` for `audience`.
    pub fn new(
        audience: impl Into<String>,
        attestation_type: impl Into<String>,
        sub: impl Into<String>,
    ) -> Self {
        Self {
            audience: audience.into(),
            attestation_type: attestation_type.into(),
            sub: sub.into(),
            ..Self::default()
        }
    }

    /// Sets the issuer's identifier for the user.
    pub fn uid(mut self, uid: impl Into<String>) -> Self {
        self.uid = Some(uid.into());
        self
    }

    /// Binds the attestation (RFC 7800 `cnf`).
    pub fn cnf(mut self, cnf: Confirmation) -> Self {
        self.cnf = Some(cnf);
        self
    }

    /// Adds other claims.
    pub fn claims(mut self, claims: Map<String, Value>) -> Self {
        self.claims = Some(claims);
        self
    }

    /// Sets this attestation's lifetime, in seconds.
    pub fn ttl(mut self, ttl: u64) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

/// Signs audience-bound `Identity-Attestation` tokens with one Ed25519 key
/// and publishes that key as a JSON Web Key Set, as mppx's
/// `Attestation.Issuer.create`.
///
/// It is the building block for any identity provider that already knows who
/// its user is (an OpenID Connect sign-in, a wallet service, Tempo ID): after
/// its own check, it calls [`sign`](Self::sign) with the fact it verified, one
/// attestation per type, and serves [`handle`](Self::handle) so servers can
/// fetch its key. It also resolves its own key in process
/// ([`KeyResolver`]), for a server that runs beside it.
///
/// mppx's issuer also accepts a remote signer (a KMS, HSM or wallet
/// service); this issuer signs with a local Ed25519 key. To sign with a
/// [`RemoteSigner`](super::RemoteSigner), use [`sign_with`](super::sign_with).
///
/// ```
/// # fn example() -> Result<(), mpp::identity::ext::attestation::IdentityError> {
/// use mpp::identity::ext::attestation::{AttestationIssuer, SignParameters, SigningKey};
///
/// let key = SigningKey::from_bytes(&[7; 32]);
/// let issuer = AttestationIssuer::new("https://issuer.example", key)?;
/// // After the user signed in with GitHub:
/// let attestation = issuer.sign(
///     SignParameters::new("https://api.example", "github", "583231").uid("user_1"),
/// )?;
/// # let _ = attestation;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct AttestationIssuer {
    issuer: String,
    signing_key: SigningKey,
    key_id: String,
    ttl: u64,
    jwks_path: String,
}

impl std::fmt::Debug for AttestationIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationIssuer")
            .field("issuer", &self.issuer)
            .field("key_id", &self.key_id)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl AttestationIssuer {
    /// An issuer named `issuer` (which attestations carry as `iss`) that signs
    /// with `signing_key`. Its key ID defaults to the RFC 7638 thumbprint of
    /// the public key and its attestations last [`DEFAULT_TTL`] seconds.
    ///
    /// Fails unless `issuer` is an `https` URL (`http` only on localhost)
    /// without userinfo, a query, a fragment, whitespace or a backslash. The
    /// URL is stored (and signed as `iss`) as the URL parser serializes it,
    /// without trailing slashes, so key discovery finds the path
    /// [`handle`](Self::handle) serves.
    pub fn new(issuer: &str, signing_key: SigningKey) -> Result<Self, IdentityError> {
        // Key discovery appends a path to the issuer, which a query or fragment would
        // swallow, and `iss` is readable by every holder, so it never carries userinfo.
        let issuer = canonical_issuer(issuer).ok_or_else(|| {
            IdentityError::InvalidConfig(
                "attestation issuer must be an https URL (http only on localhost) without userinfo, a query, a fragment, whitespace or a backslash".into(),
            )
        })?;
        let path = reqwest::Url::parse(&issuer)
            .map(|url| url.path().trim_end_matches('/').to_string())
            .unwrap_or_default();
        Ok(Self {
            key_id: thumbprint(&signing_key.verifying_key()),
            jwks_path: format!("{path}{JWKS_PATH}"),
            issuer,
            signing_key,
            ttl: DEFAULT_TTL,
        })
    }

    /// Sets the key identifier, instead of the key's thumbprint.
    pub fn with_key_id(mut self, key_id: impl Into<String>) -> Result<Self, IdentityError> {
        let key_id = key_id.into();
        if key_id.is_empty() {
            return Err(IdentityError::InvalidConfig(
                "attestation issuer key ID must be a non-empty string".into(),
            ));
        }
        self.key_id = key_id;
        Ok(self)
    }

    /// Sets how many seconds each attestation is valid: positive, at most a year.
    pub fn with_ttl(mut self, ttl: u64) -> Result<Self, IdentityError> {
        if !is_ttl(ttl) {
            return Err(IdentityError::InvalidConfig(
                "attestation issuer ttl must be a positive integer of seconds".into(),
            ));
        }
        self.ttl = ttl;
        Ok(self)
    }

    /// This issuer's URL, without a trailing slash.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The key ID attestations name in `kid`.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The public key attestations verify with.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Signs one attestation for `parameters.audience`. Call it only after
    /// checking the fact it states: servers trust it because they trust this issuer.
    ///
    /// Fails with [`IdentityError::InvalidParameters`] for parameters it
    /// cannot sign, such as a malformed claim or a token longer than servers
    /// accept.
    pub fn sign(&self, parameters: SignParameters) -> Result<String, IdentityError> {
        let SignParameters {
            audience,
            attestation_type,
            sub,
            uid,
            cnf,
            claims,
            ttl,
        } = parameters;
        let audience = is_issuer(&audience)
            .then(|| reqwest::Url::parse(&audience).ok())
            .flatten()
            .map(|url| url.origin().ascii_serialization())
            .ok_or_else(|| {
                invalid("Attestation audience must be an https origin (http only on localhost).")
            })?;
        if !is_type(&attestation_type) {
            return Err(invalid(
                "Attestation type must be a structured-field token.",
            ));
        }
        if sub.is_empty() {
            return Err(invalid("Attestation subject must be a non-empty string."));
        }
        let lifetime = ttl.unwrap_or(self.ttl);
        if !is_ttl(lifetime) {
            return Err(invalid(
                "Attestation ttl must be a positive integer of seconds.",
            ));
        }
        let mut payload = claims.unwrap_or_default();
        if let Some(uid) = uid {
            payload.insert("uid".into(), Value::String(uid));
        }
        if let Some(cnf) = cnf {
            if cnf.colliding_member().is_some() {
                return Err(invalid(
                    "Attestation cnf must not repeat jkt or addr among its other members.",
                ));
            }
            let cnf = serde_json::to_value(cnf)
                .map_err(|_| invalid("Attestation cnf must be JSON-serializable."))?;
            payload.insert("cnf".into(), cnf);
        }
        let now = now();
        payload.insert("aud".into(), audience.into());
        payload.insert("exp".into(), now.saturating_add(lifetime).into());
        payload.insert("iat".into(), now.into());
        payload.insert("iss".into(), self.issuer.clone().into());
        payload.insert("jti".into(), uuid::Uuid::new_v4().to_string().into());
        payload.insert("sub".into(), sub.into());
        payload.insert("type".into(), attestation_type.into());
        // Extra claims may carry uid or cnf too: check what is signed, as verify will.
        if payload
            .get("uid")
            .is_some_and(|uid| uid.as_str().is_none_or(str::is_empty))
        {
            return Err(invalid("Attestation uid must be a non-empty string."));
        }
        if payload.get("cnf").is_some_and(|cnf| !is_confirmation(cnf)) {
            return Err(invalid(
                "Attestation cnf must be an object whose jkt and addr are strings.",
            ));
        }
        // `sign` refuses claims the decoder would reject, such as too deeply nested ones.
        let token = sign_token(&Value::Object(payload), &self.signing_key, &self.key_id).map_err(
            |err| match err {
                IdentityError::InvalidConfig(reason) => IdentityError::InvalidParameters(format!(
                    "Attestation cannot be signed: {reason}."
                )),
                other => other,
            },
        )?;
        // Servers reject longer tokens, so never hand one out.
        if token.len() > MAX_LENGTH {
            return Err(IdentityError::InvalidParameters(format!(
                "Attestation is longer than {MAX_LENGTH} characters."
            )));
        }
        Ok(token)
    }

    /// This issuer's JSON Web Key Set.
    pub fn jwks(&self) -> Value {
        let x = URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().as_bytes());
        serde_json::json!({
            "keys": [{
                "alg": ALGORITHM,
                "crv": "Ed25519",
                "kid": self.key_id,
                "kty": "OKP",
                "use": "sig",
                "x": x,
            }],
        })
    }

    /// Answers `GET <issuer path>/.well-known/jwks.json` (or `HEAD`) with the
    /// key set, and returns `None` for every other request.
    pub fn handle<B>(&self, request: &Request<B>) -> Option<Response<Vec<u8>>> {
        if request.uri().path() != self.jwks_path {
            return None;
        }
        if request.method() != Method::GET && request.method() != Method::HEAD {
            return None;
        }
        let mut response = json_response(StatusCode::OK, &self.jwks());
        response.headers_mut().insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        );
        Some(response)
    }
}

/// Resolves this issuer's key in process, for a server that runs beside it.
impl KeyResolver for AttestationIssuer {
    fn resolve<'a>(&'a self, issuer: &'a str, key_id: &'a str) -> KeyResolverFuture<'a> {
        let key = (trim_issuer(issuer) == self.issuer && key_id == self.key_id)
            .then(|| self.signing_key.verifying_key());
        Box::pin(std::future::ready(Ok(key)))
    }
}

/// A JSON response that any origin may read.
pub(crate) fn json_response(status: StatusCode, body: &Value) -> Response<Vec<u8>> {
    let mut response = Response::new(body.to_string().into_bytes());
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    response
}

fn invalid(message: &str) -> IdentityError {
    IdentityError::InvalidParameters(message.to_string())
}

/// Whether `value` can be sent as a structured-field token in `Identity-Attestation-Required`.
pub(crate) fn is_type(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'*')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&b))
}

/// Whether `value` is a usable attestation lifetime: positive, at most a year.
fn is_ttl(value: u64) -> bool {
    value > 0 && value <= MAX_TTL
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ext::attestation::{decode, verify, VerifyOptions};

    const ISSUER: &str = "https://issuer.example";
    const AUDIENCE: &str = "https://api.example";

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn issuer() -> AttestationIssuer {
        AttestationIssuer::new(ISSUER, key()).unwrap()
    }

    fn options(attestation_type: &str) -> VerifyOptions {
        VerifyOptions {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            attestation_type: attestation_type.into(),
            clock_tolerance: None,
            max_age: None,
            now: None,
        }
    }

    fn reason(result: Result<String, IdentityError>) -> String {
        match result {
            Err(IdentityError::InvalidParameters(reason)) => reason,
            other => panic!("expected InvalidParameters, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn signs_attestations_that_verify_with_its_key() {
        let issuer = issuer();
        let cnf = Confirmation {
            jkt: Some("thumb".into()),
            ..Confirmation::default()
        };
        let token = issuer
            .sign(
                SignParameters::new("https://api.example/path?q=1", "github", "583231")
                    .uid("user_1")
                    .cnf(cnf),
            )
            .unwrap();
        let claims = verify(&token, &options("github"), &issuer).await.unwrap();
        assert_eq!(claims.aud, AUDIENCE);
        assert_eq!(claims.iss, ISSUER);
        assert_eq!(claims.sub, "583231");
        assert_eq!(claims.uid(), Some("user_1"));
        assert_eq!(claims.cnf().unwrap().jkt.as_deref(), Some("thumb"));
        assert_eq!(claims.exp - claims.iat, DEFAULT_TTL);
        assert!(claims.jti.is_some());
        assert_eq!(decode(&token).unwrap().header["kid"], issuer.key_id());

        let short = issuer
            .sign(SignParameters::new(AUDIENCE, "email", "a@example.com").ttl(60))
            .unwrap();
        let claims = verify(&short, &options("email"), &issuer).await.unwrap();
        assert_eq!(claims.exp - claims.iat, 60);
    }

    #[test]
    fn trims_the_issuer_and_rejects_bad_config() {
        let issuer = AttestationIssuer::new("https://issuer.example//", key()).unwrap();
        assert_eq!(issuer.issuer(), ISSUER);
        for bad in [
            "http://issuer.example",
            "https://issuer.example?x=1",
            "https://issuer.example#x",
            "not a url",
            "https://user:secret@issuer.example",
            "https://user@issuer.example",
            "https://issuer.example/tenant/ ",
            "https://issuer.example/tenant\\",
            "https://issuer.example/a\\b",
        ] {
            assert!(AttestationIssuer::new(bad, key()).is_err(), "{bad}");
        }
        assert!(AttestationIssuer::new("http://localhost:8787", key()).is_ok());
        // A form the URL parser rewrites is refused: a verifier configured with
        // the same string would never trust the iss it signs.
        for rewritten in [
            "https://Issuer.Example/tenant",
            "https://issuer.example:443/tenant",
            "https://issuer.example/a/../tenant",
        ] {
            assert!(
                AttestationIssuer::new(rewritten, key()).is_err(),
                "{rewritten}"
            );
        }
        // Trailing slashes are dropped, so iss, key discovery and handle agree.
        let canonical = AttestationIssuer::new("https://issuer.example/tenant/", key()).unwrap();
        assert_eq!(canonical.issuer(), "https://issuer.example/tenant");
        let request = Request::builder()
            .uri("/tenant/.well-known/jwks.json")
            .body(())
            .unwrap();
        assert!(canonical.handle(&request).is_some());
        assert!(issuer.clone().with_ttl(0).is_err());
        assert!(issuer.clone().with_ttl(MAX_TTL + 1).is_err());
        assert!(issuer.clone().with_key_id("").is_err());
        assert_eq!(issuer.with_key_id("k1").unwrap().key_id(), "k1");
    }

    #[test]
    fn key_id_defaults_to_the_rfc_7638_thumbprint() {
        // RFC 8037 appendix A.3: the thumbprint of its example Ed25519 key.
        let x = URL_SAFE_NO_PAD
            .decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
            .unwrap();
        let key = VerifyingKey::from_bytes(&x.try_into().unwrap()).unwrap();
        assert_eq!(
            thumbprint(&key),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[test]
    fn accepts_structured_field_tokens_as_types() {
        for good in ["email", "tempo-id", "x:handle/v1", "*"] {
            assert!(is_type(good), "{good}");
        }
        for bad in ["", "1email", "e mail", "émail", "a,b"] {
            assert!(!is_type(bad), "{bad}");
        }
    }

    #[test]
    fn rejects_parameters_it_cannot_sign() {
        let issuer = issuer();
        let base = || SignParameters::new(AUDIENCE, "email", "a@example.com");
        let object = |value: Value| value.as_object().unwrap().clone();
        let cases: Vec<(SignParameters, &str)> = vec![
            (
                SignParameters {
                    audience: "http://api.example".into(),
                    ..base()
                },
                "Attestation audience must be an https origin (http only on localhost).",
            ),
            (
                SignParameters {
                    attestation_type: "e mail".into(),
                    ..base()
                },
                "Attestation type must be a structured-field token.",
            ),
            (
                SignParameters {
                    sub: String::new(),
                    ..base()
                },
                "Attestation subject must be a non-empty string.",
            ),
            (
                base().ttl(0),
                "Attestation ttl must be a positive integer of seconds.",
            ),
            (
                base().uid(""),
                "Attestation uid must be a non-empty string.",
            ),
            (
                base().claims(object(serde_json::json!({ "uid": 1 }))),
                "Attestation uid must be a non-empty string.",
            ),
            (
                base().claims(object(serde_json::json!({ "cnf": { "addr": 1 } }))),
                "Attestation cnf must be an object whose jkt and addr are strings.",
            ),
            (
                SignParameters {
                    sub: "a".repeat(MAX_LENGTH),
                    ..base()
                },
                "Attestation is longer than 8192 characters.",
            ),
            (
                base().cnf(Confirmation {
                    jkt: Some("thumb".into()),
                    extra: object(serde_json::json!({ "jkt": "other" })),
                    ..Confirmation::default()
                }),
                "Attestation cnf must not repeat jkt or addr among its other members.",
            ),
            (
                base().cnf(Confirmation {
                    addr: Some("0xabc".into()),
                    extra: object(serde_json::json!({ "addr": "0xdef" })),
                    ..Confirmation::default()
                }),
                "Attestation cnf must not repeat jkt or addr among its other members.",
            ),
        ];
        for (parameters, expected) in cases {
            assert_eq!(reason(issuer.sign(parameters)), expected);
        }
    }

    #[test]
    fn refuses_claims_too_deeply_nested_to_decode() {
        let mut nested = Value::Null;
        for _ in 0..140 {
            nested = Value::Array(vec![nested]);
        }
        let mut claims = Map::new();
        claims.insert("nested".into(), nested);
        let result =
            issuer().sign(SignParameters::new(AUDIENCE, "email", "a@example.com").claims(claims));
        assert!(
            matches!(result, Err(IdentityError::InvalidParameters(_))),
            "{result:?}"
        );
    }

    #[test]
    fn confirmation_serializes_typed_bindings_only() {
        let cnf = Confirmation {
            jkt: Some("thumb".into()),
            addr: Some("0xabc".into()),
            extra: serde_json::json!({ "x5t": "t" })
                .as_object()
                .unwrap()
                .clone(),
        };
        assert_eq!(
            serde_json::to_value(&cnf).unwrap(),
            serde_json::json!({ "jkt": "thumb", "addr": "0xabc", "x5t": "t" })
        );
        for key in ["jkt", "addr"] {
            let mut colliding = cnf.clone();
            colliding.extra.insert(key.into(), "other".into());
            assert!(serde_json::to_value(&colliding).is_err(), "{key}");
        }
    }

    #[test]
    fn registered_claims_win_over_extra_claims() {
        let extra = serde_json::json!({ "iss": "https://evil.example", "azp": "app_1" });
        let token = issuer()
            .sign(
                SignParameters::new(AUDIENCE, "email", "a@example.com")
                    .claims(extra.as_object().unwrap().clone()),
            )
            .unwrap();
        let claims = decode(&token).unwrap().claims;
        assert_eq!(claims["iss"], ISSUER);
        assert_eq!(claims["azp"], "app_1");
    }

    #[test]
    fn serves_its_key_set() {
        let issuer = AttestationIssuer::new("https://issuer.example/tenant/", key()).unwrap();
        let get = |method: Method, path: &str| {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(())
                .unwrap();
            issuer.handle(&request)
        };
        let response = get(Method::GET, "/tenant/.well-known/jwks.json").unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(response.headers()[CACHE_CONTROL], "public, max-age=300");
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(body, issuer.jwks());
        let jwk = &body["keys"][0];
        assert_eq!(jwk["kid"], issuer.key_id());
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert!(get(Method::HEAD, "/tenant/.well-known/jwks.json").is_some());
        assert!(get(Method::POST, "/tenant/.well-known/jwks.json").is_none());
        assert!(get(Method::GET, "/.well-known/jwks.json").is_none());
        assert!(get(Method::GET, "/tenant/other").is_none());
    }

    #[tokio::test]
    async fn resolves_only_its_own_key() {
        let issuer = issuer();
        let kid = issuer.key_id().to_string();
        assert!(issuer.resolve(ISSUER, &kid).await.unwrap().is_some());
        assert!(issuer
            .resolve("https://issuer.example/", &kid)
            .await
            .unwrap()
            .is_some());
        assert!(issuer.resolve(ISSUER, "other").await.unwrap().is_none());
        assert!(issuer
            .resolve("https://other.example", &kid)
            .await
            .unwrap()
            .is_none());
    }
}
