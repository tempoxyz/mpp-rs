//! Issuer key resolution from a JSON Web Key Set.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;

use super::{trim_issuer, JWKS_PATH};

/// Future returned by [`KeyResolver::resolve`].
pub type KeyResolverFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<VerifyingKey>, KeyResolveError>> + Send + 'a>>;

/// The issuer's keys could not be fetched, so an attestation can be neither
/// accepted nor rejected: verifiers answer it with
/// [`RejectionStatus::Unavailable`](crate::identity::RejectionStatus::Unavailable).
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct KeyResolveError(pub String);

/// Resolves an issuer's public key by key ID.
pub trait KeyResolver: Send + Sync {
    /// Returns the Ed25519 key `issuer` publishes as `key_id`, `Ok(None)`
    /// when it publishes no such key, or an error when its keys could not be
    /// fetched.
    fn resolve<'a>(&'a self, issuer: &'a str, key_id: &'a str) -> KeyResolverFuture<'a>;
}

/// A key resolver that reads an issuer's JSON Web Key Set at
/// `<issuer>/.well-known/jwks.json`, as mppx's `Jwks.resolver`.
///
/// It caches an issuer's Ed25519 keys for `ttl` (5 minutes by default). An
/// unknown key ID refetches the set at most once every `refresh_interval`
/// (30 seconds) per issuer, and concurrent lookups share one fetch, so
/// callers cannot trigger a fetch per request. While the issuer is
/// unreachable, the last key set fetched successfully keeps verifying for up
/// to `max_stale` (1 hour) after it was fetched; after that, verification
/// fails closed. A redirect or non-2xx answer is a failed fetch.
#[derive(Clone)]
pub struct JwksResolver {
    client: reqwest::Client,
    ttl: Duration,
    refresh_interval: Duration,
    max_stale: Duration,
    timeout: Duration,
    state: Arc<State>,
}

#[derive(Default)]
struct State {
    /// The last set fetched successfully per issuer.
    good: Mutex<HashMap<String, KeySet>>,
    /// The newest fetch attempt per issuer, behind a lock concurrent lookups share.
    fetches: Mutex<HashMap<String, Arc<tokio::sync::Mutex<Attempt>>>>,
}

#[derive(Clone)]
struct KeySet {
    fetched_at: Instant,
    keys: HashMap<String, VerifyingKey>,
}

#[derive(Default)]
struct Attempt {
    started_at: Option<Instant>,
    failed: bool,
}

impl Default for JwksResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for JwksResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksResolver")
            .field("ttl", &self.ttl)
            .field("refresh_interval", &self.refresh_interval)
            .field("max_stale", &self.max_stale)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl JwksResolver {
    /// Creates a resolver with mppx's defaults and a client that follows no redirects.
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            client,
            ttl: Duration::from_secs(300),
            refresh_interval: Duration::from_secs(30),
            max_stale: Duration::from_secs(3_600),
            timeout: Duration::from_secs(5),
            state: Arc::default(),
        }
    }

    /// Fetches key sets with `client`. It should not follow redirects: a
    /// redirect it follows is read as the issuer's answer.
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// How long a fetched key set is used before it is fetched again.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Shortest time between two fetches of one issuer's keys after an
    /// unknown key ID or a failed fetch.
    pub fn with_refresh_interval(mut self, refresh_interval: Duration) -> Self {
        self.refresh_interval = refresh_interval;
        self
    }

    /// How long after it was fetched the last good key set keeps verifying
    /// while the issuer is unreachable.
    pub fn with_max_stale(mut self, max_stale: Duration) -> Self {
        self.max_stale = max_stale;
        self
    }

    /// Timeout of one key set request.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn good(&self, issuer: &str) -> Option<KeySet> {
        self.state
            .good
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(issuer)
            .cloned()
    }

    fn attempt_lock(&self, issuer: &str) -> Arc<tokio::sync::Mutex<Attempt>> {
        self.state
            .fetches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(issuer.to_string())
            .or_default()
            .clone()
    }

    async fn lookup(
        &self,
        issuer: &str,
        key_id: &str,
    ) -> Result<Option<VerifyingKey>, KeyResolveError> {
        // A known key in a set fetched within `ttl` is served at once, so a
        // refetch an unknown key ID started does not hold up other lookups.
        if let Some(set) = self.good(issuer) {
            if set.fetched_at.elapsed() <= self.ttl {
                if let Some(key) = set.keys.get(key_id) {
                    return Ok(Some(*key));
                }
            }
        }

        // Concurrent lookups for one issuer wait here and then see the fetch
        // the first one made.
        let lock = self.attempt_lock(issuer);
        let mut attempt = lock.lock().await;
        let good = self.good(issuer);
        let fresh = good
            .as_ref()
            .filter(|set| set.fetched_at.elapsed() <= self.ttl);
        let recent = attempt
            .started_at
            .is_some_and(|at| at.elapsed() <= self.refresh_interval);

        if let Some(set) = fresh {
            if let Some(key) = set.keys.get(key_id) {
                return Ok(Some(*key));
            }
            if recent && !attempt.failed {
                // Fetched moments ago and the key is not there: it is unknown.
                return Ok(None);
            }
        }
        if recent && attempt.failed {
            // A failed fetch is retried after `refresh_interval`, not on every lookup.
            return self.stale(good.as_ref(), key_id, "JWKS request failed recently.");
        }

        attempt.started_at = Some(Instant::now());
        match self.fetch(issuer).await {
            Ok(keys) => {
                attempt.failed = false;
                let key = keys.get(key_id).copied();
                self.state
                    .good
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(
                        issuer.to_string(),
                        KeySet {
                            fetched_at: attempt.started_at.unwrap_or_else(Instant::now),
                            keys,
                        },
                    );
                Ok(key)
            }
            Err(error) => {
                attempt.failed = true;
                self.stale(good.as_ref(), key_id, &error.0)
            }
        }
    }

    /// The key from the last good set while it is within `max_stale`. A stale
    /// set cannot say a key is unknown (it may be newly rotated in), so a
    /// missing key is the outage.
    fn stale(
        &self,
        good: Option<&KeySet>,
        key_id: &str,
        error: &str,
    ) -> Result<Option<VerifyingKey>, KeyResolveError> {
        good.filter(|set| set.fetched_at.elapsed() <= self.max_stale)
            .and_then(|set| set.keys.get(key_id).copied())
            .map(Some)
            .ok_or_else(|| KeyResolveError(error.to_string()))
    }

    async fn fetch(&self, issuer: &str) -> Result<HashMap<String, VerifyingKey>, KeyResolveError> {
        let url = format!("{}{JWKS_PATH}", trim_issuer(issuer));
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|_| KeyResolveError("JWKS request failed.".into()))?;
        if !response.status().is_success() {
            return Err(KeyResolveError(format!(
                "JWKS request failed with {}.",
                response.status().as_u16()
            )));
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| KeyResolveError("JWKS response is not JSON.".into()))?;
        // A body without a key list is a failed fetch, so it never replaces the last good set.
        let jwks = body
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| KeyResolveError("JWKS response has no keys list.".into()))?;
        Ok(jwks.iter().filter_map(parse_jwk).collect())
    }
}

impl KeyResolver for JwksResolver {
    fn resolve<'a>(&'a self, issuer: &'a str, key_id: &'a str) -> KeyResolverFuture<'a> {
        Box::pin(self.lookup(trim_issuer(issuer), key_id))
    }
}

/// Parses one JWK into an Ed25519 verifying key, skipping keys of other
/// types, keys the issuer restricts from verifying, and malformed keys, so
/// one cannot take the issuer's other keys down.
fn parse_jwk(jwk: &Value) -> Option<(String, VerifyingKey)> {
    let field = |name: &str| jwk.get(name);
    let text = |name: &str| field(name).and_then(Value::as_str);
    if text("kty") != Some("OKP") || text("crv") != Some("Ed25519") {
        return None;
    }
    let kid = text("kid")?;
    let x = text("x")?;
    // Honor the issuer's restrictions on what the key may do.
    if field("use").is_some() && text("use") != Some("sig") {
        return None;
    }
    if field("alg").is_some() && !matches!(text("alg"), Some("EdDSA" | "Ed25519")) {
        return None;
    }
    if let Some(ops) = field("key_ops") {
        let verifies = ops
            .as_array()
            .is_some_and(|ops| ops.iter().any(|op| op.as_str() == Some("verify")));
        if !verifies {
            return None;
        }
    }
    let bytes: [u8; 32] = URL_SAFE_NO_PAD.decode(x).ok()?.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&bytes).ok()?;
    Some((kid.to_string(), key))
}

/// A fixed set of keys, for tests.
#[cfg(test)]
pub(crate) struct StaticKeys(HashMap<String, VerifyingKey>);

#[cfg(test)]
impl StaticKeys {
    pub(crate) fn new(keys: impl IntoIterator<Item = (String, VerifyingKey)>) -> Self {
        Self(keys.into_iter().collect())
    }
}

#[cfg(test)]
impl KeyResolver for StaticKeys {
    fn resolve<'a>(&'a self, _issuer: &'a str, key_id: &'a str) -> KeyResolverFuture<'a> {
        let key = self.0.get(key_id).copied();
        Box::pin(async move { Ok(key) })
    }
}

/// A resolver whose issuer is always unreachable, for tests.
#[cfg(test)]
pub(crate) struct FailingKeys;

#[cfg(test)]
impl KeyResolver for FailingKeys {
    fn resolve<'a>(&'a self, _issuer: &'a str, _key_id: &'a str) -> KeyResolverFuture<'a> {
        Box::pin(async { Err(KeyResolveError("unreachable".into())) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ext::attestation::token::tests::{signing_key, KID};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn jwk(key: &VerifyingKey, extra: Value) -> Value {
        let mut jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": KID,
            "x": URL_SAFE_NO_PAD.encode(key.as_bytes()),
        });
        jwk.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        jwk
    }

    #[test]
    fn parses_ed25519_jwks_and_honors_restrictions() {
        let key = signing_key().verifying_key();
        assert!(parse_jwk(&jwk(&key, serde_json::json!({}))).is_some());
        assert!(parse_jwk(&jwk(
            &key,
            serde_json::json!({"use": "sig", "alg": "EdDSA", "key_ops": ["verify"]})
        ))
        .is_some());
        for extra in [
            serde_json::json!({"use": "enc"}),
            serde_json::json!({"alg": "ES256"}),
            serde_json::json!({"key_ops": ["sign"]}),
            serde_json::json!({"kty": "EC"}),
            serde_json::json!({"x": "AAAA"}),
        ] {
            assert!(parse_jwk(&jwk(&key, extra.clone())).is_none(), "{extra}");
        }
    }

    /// Serves `body` at `/.well-known/jwks.json` and counts requests.
    async fn serve(status: Arc<Mutex<u16>>, body: Arc<Mutex<Value>>) -> (String, Arc<AtomicUsize>) {
        use axum::routing::get;
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let app = axum::Router::new().route(
            "/.well-known/jwks.json",
            get(move || {
                let (status, body, counter) = (status.clone(), body.clone(), counter.clone());
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let status = *status.lock().unwrap();
                    let body = body.lock().unwrap().clone();
                    (
                        axum::http::StatusCode::from_u16(status).unwrap(),
                        axum::Json(body),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://127.0.0.1:{}", addr.port()), hits)
    }

    #[tokio::test]
    async fn caches_refetches_unknown_keys_and_serves_stale_sets() {
        let key = signing_key().verifying_key();
        let status = Arc::new(Mutex::new(200));
        let body = Arc::new(Mutex::new(
            serde_json::json!({ "keys": [jwk(&key, serde_json::json!({}))] }),
        ));
        let (issuer, hits) = serve(status.clone(), body.clone()).await;
        let resolver = JwksResolver::new().with_refresh_interval(Duration::from_millis(50));

        assert_eq!(resolver.resolve(&issuer, KID).await.unwrap(), Some(key));
        assert_eq!(resolver.resolve(&issuer, KID).await.unwrap(), Some(key));
        assert_eq!(hits.load(Ordering::SeqCst), 1, "a known key is cached");

        // An unknown key ID refetches once per refresh interval.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(resolver.resolve(&issuer, "rotated").await.unwrap(), None);
        assert_eq!(resolver.resolve(&issuer, "rotated").await.unwrap(), None);
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        // While the issuer is down, the last good set keeps verifying, and an
        // unknown key ID is an outage rather than unknown.
        *status.lock().unwrap() = 500;
        tokio::time::sleep(Duration::from_millis(60)).await;
        let stale = resolver.clone().with_ttl(Duration::ZERO);
        assert_eq!(stale.resolve(&issuer, KID).await.unwrap(), Some(key));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(stale.resolve(&issuer, "rotated").await.is_err());
    }

    #[tokio::test]
    async fn a_body_without_keys_is_a_failed_fetch() {
        let status = Arc::new(Mutex::new(200));
        let body = Arc::new(Mutex::new(serde_json::json!({ "nope": [] })));
        let (issuer, _) = serve(status, body).await;
        assert!(JwksResolver::new().resolve(&issuer, KID).await.is_err());
    }
}
