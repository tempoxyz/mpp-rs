//! Tempo ID on the server: a verifier and a payment check, as mppx's `TempoId.Server`.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::Arc;

use alloy::primitives::Address;
use http_types::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http_types::HeaderValue;
use reqwest::Url;
use serde_json::Value;

use super::constants::{CLOCK_TOLERANCE, ID_TOKEN_HEADER, ISSUER, PROOF_MAX_AGE, TYPE};
use super::jwt::{self, Decoded, Keys};
use super::{Caller, ComplianceState, Payer};
use crate::identity::{
    BoxFuture, Handle, IdentityRequest, MemoKey, PaymentCheck, PaymentCheckInput, Rejection,
    RejectionStatus, Requirement, Verification, Verifier,
};
use crate::store::Store;

/// Decides whether a verified user may call the API.
pub type AllowFn = Arc<dyn Fn(&Payer) -> BoxFuture<'static, bool> + Send + Sync>;

/// Tempo ID server options, as mppx's `TempoId.Server.create` config.
#[derive(Clone)]
pub struct Config {
    allow: Option<AllowFn>,
    chain_id: u64,
    client_ids: Vec<String>,
    store: Option<Arc<dyn Store>>,
    audience: Option<String>,
    issuer: String,
    origin: Option<String>,
    http: Option<reqwest::Client>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("chain_id", &self.chain_id)
            .field("client_ids", &self.client_ids)
            .field("audience", &self.audience)
            .field("issuer", &self.issuer)
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Accepts tokens of the app `client_id`.
    pub fn new(client_id: impl Into<String>) -> Self {
        Self {
            allow: None,
            chain_id: 4217,
            client_ids: vec![client_id.into()],
            store: None,
            audience: None,
            issuer: ISSUER.to_owned(),
            origin: None,
            http: None,
        }
    }

    /// Also accepts tokens of the app `client_id`.
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_ids.push(client_id.into());
        self
    }

    /// The chain payments settle on. Default: 4217 (Tempo mainnet).
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Accepts each DPoP proof once. Without it, a proof can be replayed for
    /// five minutes. The store must implement `put_if_absent_with_ttl` atomically.
    pub fn store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// The audience tokens must name. Default: the issuer's origin.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Tempo ID's origin. Default: `https://id.tempo.xyz`.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = issuer.into();
        self
    }

    /// This API's public origin, such as `https://api.example`, which a
    /// DPoP proof's `htu` names.
    ///
    /// mppx reads the full request URL; a Rust server often sees only the
    /// path. Without this the origin is the request URI's, and a request
    /// whose URI names none rejects DPoP-bound tokens: the `Host` header is
    /// the client's to choose, so it never stands in.
    pub fn origin(mut self, origin: impl Into<String>) -> Self {
        self.origin = Some(origin.into());
        self
    }

    /// The HTTP client that fetches Tempo ID's keys.
    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    /// Decides whether a verified user may call the API, such as by email or
    /// by the paying account's compliance state. On the paid retry it also
    /// receives the paying `account`.
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
}

/// A Tempo ID verifier from [`create`].
#[derive(Clone, Debug)]
pub struct TempoId {
    /// A request-stage verifier: requires a Tempo ID access token before any 402.
    pub verifier: Handle<TempoIdVerifier>,
    /// A payment check: requires a Tempo ID access token, and that the payer is one of its accounts.
    pub payment_check: Handle<TempoIdPaymentCheck>,
}

/// Creates a Tempo ID verifier for one API, as mppx's `TempoId.Server.create`.
///
/// - [`verifier`](TempoId::verifier) requires a valid Tempo ID access token from an allowed app.
/// - [`payment_check`](TempoId::payment_check) also requires a `tempo`
///   payment whose `source` is a Tempo Account the token grants to the app,
///   so one user's token cannot pay with another user's wallet. It refuses an
///   account that Tempo ID screened as anything but `clear`.
///
/// Tokens verify offline against Tempo ID's keys. A DPoP-bound token also
/// needs a proof of its key for the request, which the store accepts once.
pub fn create(config: Config) -> TempoId {
    let issuer = Url::parse(&config.issuer)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| config.issuer.trim_end_matches('/').to_owned());
    let audience = config.audience.clone().unwrap_or_else(|| issuer.clone());
    let keys = Keys::new(&issuer, config.http.clone().unwrap_or_default());
    let core = Arc::new(Core {
        requires: vec![Requirement::new(TYPE).with_issuer(issuer.clone())],
        issuer,
        audience,
        keys,
        memo: MemoKey::new(),
        config,
    });
    TempoId {
        verifier: Handle::new(TempoIdVerifier { core: core.clone() }),
        payment_check: Handle::new(TempoIdPaymentCheck { core }),
    }
}

struct Core {
    config: Config,
    issuer: String,
    audience: String,
    keys: Keys,
    requires: Vec<Requirement>,
    /// One verification per request, so a DPoP proof is spent once across both checks.
    memo: MemoKey,
}

/// The request-stage verifier of [`TempoId`].
pub struct TempoIdVerifier {
    core: Arc<Core>,
}

/// The payment check of [`TempoId`].
pub struct TempoIdPaymentCheck {
    core: Arc<Core>,
}

impl Verifier for TempoIdVerifier {
    type Value = Caller;

    // The token travels in Authorization, so the route's server needs requires_auth.
    fn reads_authorization(&self) -> bool {
        true
    }

    fn verify<'a>(&'a self, request: &'a IdentityRequest) -> BoxFuture<'a, Verification<Caller>> {
        Box::pin(async move {
            let caller = self.core.verify(request).await;
            let payer = caller.map(|caller| Payer {
                caller,
                account: None,
            });
            self.core.allowed(payer).await.map(|payer| payer.caller)
        })
    }
}

impl PaymentCheck for TempoIdPaymentCheck {
    type Value = Payer;

    // The token travels in Authorization, so the route's server needs requires_auth.
    fn reads_authorization(&self) -> bool {
        true
    }

    fn requires(&self) -> &[Requirement] {
        &self.core.requires
    }

    fn verify<'a>(&'a self, input: PaymentCheckInput<'a>) -> BoxFuture<'a, Verification<Payer>> {
        Box::pin(async move {
            let core = &self.core;
            let caller = core.verify(input.request).await;
            let (Verification::Valid(caller), Some(credential)) = (&caller, input.credential)
            else {
                return core
                    .allowed(caller.map(|caller| Payer {
                        caller,
                        account: None,
                    }))
                    .await;
            };
            // Only the tempo method checks the source against the transaction's sender.
            if input.challenge.method.as_str() != "tempo" {
                return Rejection::forbidden("Pay with the tempo method.").into();
            }
            // The source is a did:pkh:eip155:<chainId>:<address>.
            let parts: Vec<&str> = credential
                .source
                .as_deref()
                .unwrap_or_default()
                .split(':')
                .collect();
            let chain_id = core.config.chain_id;
            let account = match (
                parts.get(3),
                parts.get(4).and_then(|address| parse_address(address)),
            ) {
                (Some(chain), Some(account)) if *chain == chain_id.to_string() => account,
                _ => {
                    return Rejection::invalid(format!(
                        "The payment must name its source account on chain {chain_id}."
                    ))
                    .into()
                }
            };
            if !caller.accounts.contains(&account) {
                return Rejection::forbidden(
                    "The paying account is not one this user granted to the app.",
                )
                .into();
            }
            // Tempo ID screens the accounts in a registered app's realms; only a clear one pays.
            if caller
                .compliance
                .get(&account)
                .is_some_and(|state| *state != ComplianceState::Clear)
            {
                return Rejection::forbidden("The paying account is not cleared to pay.").into();
            }
            core.allowed(Verification::Valid(Payer {
                caller: caller.clone(),
                account: Some(account),
            }))
            .await
        })
    }
}

fn www_authenticate() -> HeaderValue {
    HeaderValue::from_static(r#"DPoP algs="ES256", Bearer"#)
}

fn invalid(reason: &str) -> Verification<Caller> {
    Rejection::invalid(reason)
        .with_header(WWW_AUTHENTICATE, www_authenticate())
        .into()
}

fn unavailable() -> Verification<Caller> {
    Rejection::unavailable("Tempo ID's signing keys are unavailable.").into()
}

/// Whether Tempo ID's RS256 keys signed a JWS.
enum Signed {
    Yes,
    No,
    Unavailable,
}

/// What the ID token adds to a caller.
enum IdToken {
    Email(Option<String>, Option<bool>),
    Invalid(&'static str),
    Unavailable,
}

impl Core {
    async fn verify(&self, request: &IdentityRequest) -> Verification<Caller> {
        request.memoize(&self.memo, self.check(request)).await
    }

    /// Runs `allow` on a verified user or payer.
    async fn allowed(&self, result: Verification<Payer>) -> Verification<Payer> {
        let (Verification::Valid(payer), Some(allow)) = (&result, &self.config.allow) else {
            return result;
        };
        if allow(payer).await {
            return result;
        }
        Rejection::forbidden("This user may not call this API.").into()
    }

    async fn check(&self, request: &IdentityRequest) -> Verification<Caller> {
        let authorization = request.header(AUTHORIZATION).unwrap_or_default();
        let mut words = authorization.split(' ');
        let (scheme, token) = (
            words.next().unwrap_or_default(),
            words.next().unwrap_or_default(),
        );
        let dpop = scheme.eq_ignore_ascii_case("dpop");
        if token.is_empty() || (!dpop && !scheme.eq_ignore_ascii_case("bearer")) {
            return Rejection::new(RejectionStatus::Missing)
                .with_reason("Sign in with Tempo ID.")
                .with_header(WWW_AUTHENTICATE, www_authenticate())
                .into();
        }

        let Some(jwt) =
            jwt::decode(token).filter(|jwt| str_claim(&jwt.header, "typ") == Some("at+jwt"))
        else {
            return invalid("The token is not a Tempo ID access token.");
        };
        match self.signed(&jwt).await {
            Signed::Unavailable => return unavailable(),
            Signed::No => return invalid("The access token signature is invalid."),
            Signed::Yes => {}
        }

        let claims = &jwt.claims;
        let now = now();
        let Some(sub) = str_claim(claims, "sub")
            .filter(|_| str_claim(claims, "iss") == Some(self.issuer.as_str()))
        else {
            return invalid("The access token is not from Tempo ID.");
        };
        // A token that also names another API is that API's too, so only our
        // audience (and Tempo ID's userinfo) passes.
        let audiences = audiences(claims);
        let userinfo = format!("{}/oauth2/userinfo", self.issuer);
        if !audiences.contains(&self.audience.as_str())
            || audiences
                .iter()
                .any(|aud| *aud != self.audience && *aud != userinfo)
        {
            return invalid("The access token is for another API.");
        }
        if !claims
            .get("exp")
            .and_then(Value::as_f64)
            .is_some_and(|exp| exp + CLOCK_TOLERANCE as f64 > now as f64)
        {
            return invalid("The access token has expired.");
        }
        let client_id = str_claim(claims, "client_id");
        let Some(client_id) =
            client_id.filter(|id| self.config.client_ids.iter().any(|allowed| allowed == id))
        else {
            return Rejection::forbidden("This app may not call this API.").into();
        };

        // RFC 9449: a DPoP-bound token is useless without a proof from its key,
        // and a Bearer token takes none.
        let jkt = claims.get("cnf").and_then(|cnf| cnf.get("jkt"));
        if dpop != jkt.is_some() {
            return invalid("The access token scheme does not match its binding.");
        }
        if dpop {
            let jkt = jkt.and_then(Value::as_str).unwrap_or_default();
            if let Err(reason) = self.check_proof(request, jkt, now, token).await {
                return invalid(reason);
            }
        }

        let chain_id = self.config.chain_id;
        let mut accounts: Vec<Address> = Vec::new();
        let granted = claims
            .get("access_keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|entry| entry.get("chain_id").and_then(Value::as_u64) == Some(chain_id))
            .filter_map(|entry| entry.get("account").and_then(Value::as_str))
            .chain(
                claims
                    .get("tempo_accounts")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str),
            )
            .filter_map(parse_address);
        for account in granted {
            if !accounts.contains(&account) {
                accounts.push(account);
            }
        }
        let compliance: HashMap<Address, ComplianceState> = claims
            .get("compliance")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter_map(|(address, state)| {
                Some((
                    parse_address(address)?,
                    ComplianceState::parse(state.as_str()?),
                ))
            })
            .collect();

        let (email, email_verified) = match self.check_id_token(request, client_id, now, sub).await
        {
            IdToken::Email(email, verified) => (email, verified),
            IdToken::Invalid(reason) => return invalid(reason),
            IdToken::Unavailable => return unavailable(),
        };

        Verification::Valid(Caller {
            user_id: sub.to_owned(),
            client_id: client_id.to_owned(),
            accounts,
            compliance,
            email,
            email_verified,
        })
    }

    async fn signed(&self, jwt: &Decoded) -> Signed {
        if str_claim(&jwt.header, "alg") != Some("RS256") {
            return Signed::No;
        }
        let kid = match jwt.header.get("kid") {
            Some(Value::String(kid)) => kid.clone(),
            Some(other) => other.to_string(),
            None => "undefined".to_owned(),
        };
        match self.keys.get(&kid).await {
            Err(_) => Signed::Unavailable,
            Ok(None) => Signed::No,
            Ok(Some(key)) if key.verify(&jwt.signing_input, &jwt.signature) => Signed::Yes,
            Ok(Some(_)) => Signed::No,
        }
    }

    /// Reads the email of the request's ID token, which Tempo ID issues to the
    /// same app for the same user.
    async fn check_id_token(
        &self,
        request: &IdentityRequest,
        client_id: &str,
        now: i64,
        sub: &str,
    ) -> IdToken {
        let Some(value) = request
            .header(ID_TOKEN_HEADER)
            .filter(|value| !value.is_empty())
        else {
            return IdToken::Email(None, None);
        };
        let Some(jwt) = jwt::decode(value) else {
            return IdToken::Invalid("The ID token is malformed.");
        };
        match self.signed(&jwt).await {
            Signed::Unavailable => return IdToken::Unavailable,
            Signed::No => return IdToken::Invalid("The ID token signature is invalid."),
            Signed::Yes => {}
        }
        let claims = &jwt.claims;
        if str_claim(claims, "iss") != Some(self.issuer.as_str())
            || !audiences(claims).contains(&client_id)
            || str_claim(claims, "sub") != Some(sub)
        {
            return IdToken::Invalid("The ID token is for another user or app.");
        }
        // An expired ID token names no email, so allow decides without it.
        let live = claims
            .get("exp")
            .and_then(Value::as_f64)
            .is_some_and(|exp| exp + CLOCK_TOLERANCE as f64 > now as f64);
        match str_claim(claims, "email") {
            Some(email) if live => IdToken::Email(
                Some(email.to_lowercase()),
                Some(claims.get("email_verified") == Some(&Value::Bool(true))),
            ),
            _ => IdToken::Email(None, None),
        }
    }

    /// Checks a request's DPoP proof, returning why it fails.
    async fn check_proof(
        &self,
        request: &IdentityRequest,
        jkt: &str,
        now: i64,
        token: &str,
    ) -> Result<(), &'static str> {
        let proof = jwt::decode(request.header("DPoP").unwrap_or_default())
            .filter(|proof| {
                str_claim(&proof.header, "alg") == Some("ES256")
                    && str_claim(&proof.header, "typ") == Some("dpop+jwt")
            })
            .ok_or("The DPoP proof is malformed.")?;
        let jwk = proof.header.get("jwk").and_then(Value::as_object);
        let member = |name: &str| jwk.and_then(|jwk| jwk.get(name)).and_then(Value::as_str);
        let (Some(crv), Some(kty), Some(x), Some(y)) =
            (member("crv"), member("kty"), member("x"), member("y"))
        else {
            return Err("The DPoP proof key does not bind the token.");
        };
        if jwk.is_some_and(|jwk| jwk.contains_key("d")) || jwt::thumbprint(crv, kty, x, y) != jkt {
            return Err("The DPoP proof key does not bind the token.");
        }
        if crv != "P-256"
            || kty != "EC"
            || !jwt::verify_es256(x, y, &proof.signing_input, &proof.signature)
        {
            return Err("The DPoP proof signature is invalid.");
        }

        let claims = &proof.claims;
        if self.htu(request).is_none() {
            return Err("This API needs a configured origin to accept DPoP-bound tokens.");
        }
        if str_claim(claims, "htm") != Some(request.method().as_str())
            || str_claim(claims, "htu") != self.htu(request).as_deref()
        {
            return Err("The DPoP proof is for another request.");
        }
        if str_claim(claims, "ath") != Some(jwt::sha256(token).as_str()) {
            return Err("The DPoP proof is for another token.");
        }
        let iat = claims
            .get("iat")
            .and_then(Value::as_f64)
            .ok_or("The DPoP proof has expired.")?;
        let expires = iat + (PROOF_MAX_AGE + CLOCK_TOLERANCE) as f64;
        if iat > (now + CLOCK_TOLERANCE) as f64 || expires < now as f64 {
            return Err("The DPoP proof has expired.");
        }
        let jti = str_claim(claims, "jti")
            .filter(|jti| !jti.is_empty())
            .ok_or("The DPoP proof has no ID.")?;
        if let Some(store) = &self.config.store {
            let key = format!(
                "mppx:tempo-id:dpop:{}",
                jwt::sha256(&format!("{jkt}:{jti}"))
            );
            let ttl = std::time::Duration::from_secs_f64((expires - now as f64).max(1.0));
            let claimed = store
                .put_if_absent_with_ttl(&key, Value::Bool(true), ttl)
                .await
                // A store that cannot claim the proof fails closed.
                .unwrap_or(false);
            if !claimed {
                return Err("The DPoP proof was already used.");
            }
        }
        Ok(())
    }

    /// The request URL without its query, as the proof's `htu` must name it.
    fn htu(&self, request: &IdentityRequest) -> Option<String> {
        htu(self.config.origin.as_deref(), request)
    }
}

/// The URL of `request` without its query, on `origin` when given, else on
/// the request URI's own scheme and host, as mppx's `Jwt.htu(request.url)`.
///
/// `None` when neither names an origin. mppx's request URL is absolute; a
/// Rust server often sees only the path, and the `Host` header is the
/// client's to choose, so it never stands in: a proof made for another origin
/// would then match.
fn htu(origin: Option<&str>, request: &IdentityRequest) -> Option<String> {
    let uri = request.uri();
    let origin = match (origin, uri.scheme_str(), uri.authority()) {
        (Some(origin), _, _) => origin.to_owned(),
        (None, Some(scheme), Some(authority)) => format!("{scheme}://{authority}"),
        (None, _, _) => return None,
    };
    let mut url = Url::parse(&origin).ok()?;
    // Set the path literally: resolved as a reference, a path such as
    // `//other.example/x` would replace the host.
    url.set_path(uri.path());
    Some(jwt::htu(&url))
}

fn str_claim<'a>(map: &'a serde_json::Map<String, Value>, name: &str) -> Option<&'a str> {
    map.get(name).and_then(Value::as_str)
}

fn audiences(claims: &serde_json::Map<String, Value>) -> Vec<&str> {
    match claims.get("aud") {
        Some(Value::String(aud)) => vec![aud.as_str()],
        Some(Value::Array(auds)) => auds.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    }
}

fn parse_address(value: &str) -> Option<Address> {
    let hex = value.strip_prefix("0x")?;
    if hex.len() != 40 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    value.parse().ok()
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests;
