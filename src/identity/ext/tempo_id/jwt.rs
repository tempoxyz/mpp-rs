//! Compact JWS helpers and Tempo ID's key set.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use base64::engine::DecodePaddingMode;
use base64::Engine;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Base64url that accepts padded and unpadded input, as ox's decoder does.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Longest token accepted, in characters.
const MAX_TOKEN_LENGTH: usize = 16_384;

/// A decoded, unverified compact JWS.
pub(crate) struct Decoded {
    pub(crate) header: Map<String, Value>,
    pub(crate) claims: Map<String, Value>,
    pub(crate) signing_input: Vec<u8>,
    pub(crate) signature: Vec<u8>,
}

/// Decodes a compact JWS without verifying it, or `None` if it is malformed.
pub(crate) fn decode(token: &str) -> Option<Decoded> {
    if token.len() > MAX_TOKEN_LENGTH {
        return None;
    }
    let mut parts = token.split('.');
    let (Some(header), Some(claims), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let object =
        |part: &str| match serde_json::from_slice::<Value>(&LENIENT.decode(part).ok()?).ok()? {
            Value::Object(map) => Some(map),
            _ => None,
        };
    Some(Decoded {
        header: object(header)?,
        claims: object(claims)?,
        signing_input: format!("{header}.{claims}").into_bytes(),
        signature: LENIENT.decode(signature).ok()?,
    })
}

/// Encodes a JSON value as unpadded base64url.
#[cfg(any(feature = "client", test))]
pub(crate) fn encode(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(value.to_string())
}

/// Unpadded base64url SHA-256 of a string, as DPoP's `ath` uses.
pub(crate) fn sha256(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

/// RFC 7638 thumbprint of a P-256 public JWK, from its members in order.
pub(crate) fn thumbprint(crv: &str, kty: &str, x: &str, y: &str) -> String {
    let canonical = serde_json::json!({ "crv": crv, "kty": kty, "x": x, "y": y });
    sha256(&canonical.to_string())
}

/// A URL without its query and fragment, as DPoP's `htu` names it.
pub(crate) fn htu(url: &reqwest::Url) -> String {
    format!("{}{}", url.origin().ascii_serialization(), url.path())
}

/// Verifies an ES256 signature over `input` with a P-256 public JWK's coordinates.
pub(crate) fn verify_es256(x: &str, y: &str, input: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::{Signature, VerifyingKey};
    let (Ok(x), Ok(y)) = (LENIENT.decode(x), LENIENT.decode(y)) else {
        return false;
    };
    let (Ok(x), Ok(y)) = (<[u8; 32]>::try_from(x), <[u8; 32]>::try_from(y)) else {
        return false;
    };
    let point = p256::EncodedPoint::from_affine_coordinates(&x.into(), &y.into(), false);
    let (Ok(key), Ok(signature)) = (
        VerifyingKey::from_encoded_point(&point),
        Signature::from_slice(signature),
    ) else {
        return false;
    };
    key.verify(input, &signature).is_ok()
}

/// An issuer's RS256 key, ready to verify.
#[derive(Clone)]
pub(crate) struct RsaKey(rsa::PublicKey);

impl RsaKey {
    fn from_jwk(n: &str, e: &str) -> Option<Self> {
        let (n, e) = (LENIENT.decode(n).ok()?, LENIENT.decode(e).ok()?);
        let bits = |bytes: &[u8]| u32::try_from(bytes.len() * 8).ok();
        let n = rsa::BoxedUint::from_be_slice(&n, bits(&n)?).ok()?;
        let e = rsa::BoxedUint::from_be_slice(&e, bits(&e)?).ok()?;
        rsa::PublicKey::new(n, e).ok().map(Self)
    }

    /// Whether `signature` is this key's RSASSA-PKCS1-v1_5 SHA-256 signature of `input`.
    pub(crate) fn verify(&self, input: &[u8], signature: &[u8]) -> bool {
        let hashed = rsa::sha2::Sha256::digest(input);
        self.0
            .verify(
                rsa::Pkcs1v15Sign::new::<rsa::sha2::Sha256>(),
                &hashed,
                signature,
            )
            .is_ok()
    }
}

/// The key set could not be fetched and none was loaded before.
#[derive(Debug)]
pub(crate) struct KeysUnavailable;

struct Cached {
    at: Instant,
    keys: HashMap<String, RsaKey>,
}

#[derive(Default)]
struct KeyState {
    cached: Option<Cached>,
    attempted: Option<Instant>,
}

/// An issuer's RS256 keys by key ID, from `<issuer>/oauth2/jwks`, as mppx's
/// `Jwt.keys`. The set is cached for five minutes, an unknown key ID
/// refetches it at most every 30 seconds, and a failed fetch keeps the last
/// set that loaded.
pub(crate) struct Keys {
    url: String,
    http: reqwest::Client,
    state: tokio::sync::Mutex<KeyState>,
}

const MAX_AGE: Duration = Duration::from_secs(300);
const REFETCH: Duration = Duration::from_secs(30);

impl Keys {
    pub(crate) fn new(issuer: &str, http: reqwest::Client) -> Self {
        Self {
            url: format!("{issuer}/oauth2/jwks"),
            http,
            state: tokio::sync::Mutex::new(KeyState::default()),
        }
    }

    /// The key with `kid`, `None` for an unknown one, or
    /// [`KeysUnavailable`] when no key set ever loaded.
    pub(crate) async fn get(&self, kid: &str) -> Result<Option<RsaKey>, KeysUnavailable> {
        if let Some(key) = self.fresh(MAX_AGE).await?.remove(kid) {
            return Ok(Some(key));
        }
        Ok(self.fresh(REFETCH).await?.remove(kid))
    }

    async fn fresh(&self, max_age: Duration) -> Result<HashMap<String, RsaKey>, KeysUnavailable> {
        // One lock across the fetch, so concurrent requests share one fetch.
        let mut state = self.state.lock().await;
        // Within 30 seconds of the last attempt, the last loaded set serves,
        // and with none loaded the keys stay unavailable without another fetch.
        let cooling = state.attempted.is_some_and(|at| at.elapsed() < REFETCH);
        match &state.cached {
            Some(cached) if cached.at.elapsed() < max_age || cooling => {
                return Ok(cached.keys.clone());
            }
            None if cooling => return Err(KeysUnavailable),
            _ => {}
        }
        state.attempted = Some(Instant::now());
        match self.load().await {
            Some(keys) => {
                state.cached = Some(Cached {
                    at: Instant::now(),
                    keys: keys.clone(),
                });
                Ok(keys)
            }
            None => state
                .cached
                .as_ref()
                .map(|cached| cached.keys.clone())
                .ok_or(KeysUnavailable),
        }
    }

    async fn load(&self) -> Option<HashMap<String, RsaKey>> {
        let response = self
            .http
            .get(&self.url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let body: Value = response.json().await.ok()?;
        let mut keys = HashMap::new();
        for jwk in body
            .get("keys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let field = |name: &str| jwk.get(name).and_then(Value::as_str);
            let (Some("RSA"), Some(kid), Some(n), Some(e)) =
                (field("kty"), field("kid"), field("n"), field("e"))
            else {
                continue;
            };
            if let Some(key) = RsaKey::from_jwk(n, e) {
                keys.insert(kid.to_owned(), key);
            }
        }
        // A set with no usable key is a failed fetch: it never replaces the
        // last set that loaded.
        (!keys.is_empty()).then_some(keys)
    }
}
