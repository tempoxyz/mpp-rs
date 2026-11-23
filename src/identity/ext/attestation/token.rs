//! Attestation tokens: compact EdDSA JWS signing, decoding and verification.

use std::future::Future;
use std::pin::Pin;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::jwks::KeyResolver;
use super::{rejection, IdentityError};
use super::{ALGORITHM, CLOCK_TOLERANCE, MAX_LENGTH, TOKEN_TYPE};
use crate::identity::{Rejection, RejectionStatus};

/// Latest time, in Unix seconds, that a JavaScript `Date` can represent; mppx
/// rejects later times, so this does too.
const MAX_TIME: u64 = 8_640_000_000_000;

/// The verified claims of an attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationClaims {
    /// Issuer URL.
    pub iss: String,
    /// Audience: the origin the attestation is bound to.
    pub aud: String,
    /// Subject: the fact the issuer checked, such as an email address.
    pub sub: String,
    /// Attestation type, such as `email`.
    #[serde(rename = "type")]
    pub attestation_type: String,
    /// Issued at, in Unix seconds.
    pub iat: u64,
    /// Expires at, in Unix seconds.
    pub exp: u64,
    /// Attestation ID, if the issuer set one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Any other claims.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An attestation decoded without verification.
#[derive(Debug, Clone)]
pub struct DecodedAttestation {
    /// The JWS protected header.
    pub header: Map<String, Value>,
    /// The JWS payload.
    pub claims: Map<String, Value>,
    /// The bytes the signature covers: `<header>.<payload>`.
    pub signing_input: Vec<u8>,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// What [`verify`] checks an attestation against.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Trusted issuer; the `iss` claim must equal it.
    pub issuer: String,
    /// Expected audience (an origin); the `aud` claim must equal it.
    pub audience: String,
    /// Accepted attestation type; the `type` claim must equal it.
    pub attestation_type: String,
    /// Clock tolerance in seconds for `iat`, `exp` and `max_age`.
    /// Defaults to [`CLOCK_TOLERANCE`].
    pub clock_tolerance: Option<u64>,
    /// Longest accepted age since `iat`, in seconds.
    pub max_age: Option<u64>,
    /// The current Unix time in seconds; defaults to the system clock.
    pub now: Option<u64>,
}

/// Signs attestation claims as a compact JWS (EdDSA over Ed25519).
///
/// For issuers and tests. `key_id` should be the RFC 7638 thumbprint of the
/// public key published in the issuer's JSON Web Key Set (see [`thumbprint`]).
/// To sign with a key that stays in a KMS, an HSM or a wallet service, use
/// [`sign_with`].
pub fn sign<C: Serialize>(
    claims: &C,
    key: &SigningKey,
    key_id: &str,
) -> Result<String, IdentityError> {
    let input = signing_input(claims, key_id)?;
    let signature = key.sign(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

/// Error a [`RemoteSigner`] fails with.
pub type RemoteSignerError = Box<dyn std::error::Error + Send + Sync>;

/// Future returned by [`RemoteSigner::sign`].
pub type RemoteSignerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, RemoteSignerError>> + Send + 'a>>;

/// An Ed25519 key pair whose private key may stay outside this process, such
/// as in a cloud KMS, an HSM or a wallet service, as mppx's `Signer`.
///
/// [`sign_with`] checks every signature it returns against
/// [`public_key`](Self::public_key) before using it, so a wrong key, a
/// signature over a digest or a DER- or base64-encoded signature fails at the
/// issuer instead of at the verifier. A local [`SigningKey`] signs with
/// [`sign`] and [`thumbprint`] instead.
pub trait RemoteSigner: Send + Sync {
    /// The public key of the private key that signs.
    fn public_key(&self) -> VerifyingKey;

    /// Signs `payload` (the complete JWS signing input, not a digest) and
    /// returns the raw 64-byte Ed25519 signature.
    fn sign<'a>(&'a self, payload: &'a [u8]) -> RemoteSignerFuture<'a>;
}

/// Signs attestation claims as a compact JWS (EdDSA over Ed25519) with a
/// [`RemoteSigner`], as mppx's `Attestation.sign` does.
///
/// `key_id` defaults to the RFC 7638 thumbprint of the signer's public key
/// ([`thumbprint`]), the `kid` an issuer's JSON Web Key Set publishes for
/// it. The signer is called once, and its signature must verify with its
/// public key: otherwise this fails with [`IdentityError::InvalidSignature`].
/// A signer failure is returned as [`IdentityError::Signer`].
pub async fn sign_with<C: Serialize>(
    claims: &C,
    signer: &(impl RemoteSigner + ?Sized),
    key_id: Option<&str>,
) -> Result<String, IdentityError> {
    let public_key = signer.public_key();
    let key_id = match key_id {
        Some(key_id) => key_id.to_string(),
        None => thumbprint(&public_key),
    };
    let input = signing_input(claims, &key_id)?;
    let signature = signer
        .sign(input.as_bytes())
        .await
        .map_err(IdentityError::Signer)?;
    let valid = <[u8; 64]>::try_from(signature.as_slice())
        .map(|bytes| Signature::from_bytes(&bytes))
        .is_ok_and(|parsed| public_key.verify_strict(input.as_bytes(), &parsed).is_ok());
    if !valid {
        return Err(IdentityError::InvalidSignature);
    }
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

/// The RFC 7638 JWK thumbprint of an Ed25519 public key: the `kid` an issuer
/// publishes for it and [`sign_with`] uses by default.
pub fn thumbprint(key: &VerifyingKey) -> String {
    let jwk = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        URL_SAFE_NO_PAD.encode(key.as_bytes())
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(jwk.as_bytes()))
}

/// The JWS signing input `<header>.<payload>` for `claims`.
fn signing_input<C: Serialize>(claims: &C, key_id: &str) -> Result<String, IdentityError> {
    let header = serde_json::json!({ "alg": ALGORITHM, "kid": key_id, "typ": TOKEN_TYPE });
    let encode = |value: &serde_json::Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let claims = serde_json::to_value(claims)
        .map_err(|err| IdentityError::InvalidConfig(format!("claims: {err}")))?;
    Ok(format!("{}.{}", encode(&header), encode(&claims)))
}

/// Decodes an attestation without verifying it, or returns `None` if it is malformed.
pub fn decode(token: &str) -> Option<DecodedAttestation> {
    if token.len() > MAX_LENGTH {
        return None;
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return None;
    }
    let object = |part: &str| -> Option<Map<String, Value>> {
        match serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).ok()?).ok()? {
            Value::Object(map) => Some(map),
            _ => None,
        }
    };
    Some(DecodedAttestation {
        header: object(parts[0])?,
        claims: object(parts[1])?,
        signing_input: format!("{}.{}", parts[0], parts[1]).into_bytes(),
        signature: URL_SAFE_NO_PAD.decode(parts[2]).ok()?,
    })
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

/// Splits `Identity-Attestation` header values into their attestations.
pub fn parse_header<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    values
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(String::from)
        .collect()
}

/// Whether `value` is an acceptable issuer or attestation origin: an `https`
/// URL, or `http` only on `localhost` or `127.0.0.1` for development.
pub fn is_issuer(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    match url.scheme() {
        "https" => true,
        "http" => matches!(url.host_str(), Some("localhost" | "127.0.0.1")),
        _ => false,
    }
}

/// Verifies an attestation's signature and claims.
///
/// Checks the EdDSA algorithm and `typ`, the issuer, audience and type, and
/// the `iat` and `exp` times (with the clock tolerance), then the signature
/// with the key `resolver` returns for the header's `kid`. Rejects with
/// [`RejectionStatus::Invalid`], or [`RejectionStatus::Unavailable`] when the
/// issuer's keys could not be resolved, which says nothing about the token.
// Rejections are the cold path; keep the public type unboxed, as RouteIdentity::verify_request does.
#[allow(clippy::result_large_err)]
pub async fn verify(
    token: &str,
    options: &VerifyOptions,
    resolver: &dyn KeyResolver,
) -> Result<AttestationClaims, Rejection> {
    let invalid = |reason: &str| rejection(RejectionStatus::Invalid, reason);
    let decoded = decode(token).ok_or_else(|| invalid("The attestation is malformed."))?;
    let (header, claims) = (&decoded.header, &decoded.claims);

    if text(header, "alg") != Some(ALGORITHM) {
        return Err(invalid("The attestation algorithm is not EdDSA."));
    }
    if text(header, "typ") != Some(TOKEN_TYPE) {
        return Err(invalid("The attestation type header is wrong."));
    }
    let key_id = match text(header, "kid") {
        Some(kid) if !kid.is_empty() => kid,
        _ => return Err(invalid("The attestation has no key ID.")),
    };
    if text(claims, "iss") != Some(options.issuer.as_str()) {
        return Err(invalid("The attestation issuer is not trusted."));
    }
    if text(claims, "type") != Some(options.attestation_type.as_str()) {
        return Err(invalid("The attestation type is not accepted."));
    }
    if text(claims, "aud") != Some(options.audience.as_str()) {
        return Err(invalid("The attestation is for another audience."));
    }
    if text(claims, "sub").is_none_or(|sub| sub.is_empty()) {
        return Err(invalid("The attestation has no subject."));
    }
    if claims.get("jti").is_some_and(|jti| !jti.is_string()) {
        return Err(invalid("The attestation ID is malformed."));
    }
    let time = |key: &str| {
        claims
            .get(key)
            .and_then(Value::as_u64)
            .filter(|t| *t <= MAX_TIME)
    };
    let (Some(iat), Some(exp)) = (time("iat"), time("exp")) else {
        return Err(invalid("The attestation times are malformed."));
    };
    let now = options.now.unwrap_or_else(super::now);
    let tolerance = options.clock_tolerance.unwrap_or(CLOCK_TOLERANCE);
    if exp.saturating_add(tolerance) <= now {
        return Err(invalid("The attestation has expired."));
    }
    if iat > now.saturating_add(tolerance) {
        return Err(invalid("The attestation was issued in the future."));
    }
    if let Some(max_age) = options.max_age {
        if now.saturating_sub(iat) > max_age.saturating_add(tolerance) {
            return Err(invalid("The attestation is too old."));
        }
    }

    let key = match resolver.resolve(&options.issuer, key_id).await {
        Ok(Some(key)) => key,
        Ok(None) => {
            return Err(invalid(
                "No public key is available for the attestation key ID.",
            ))
        }
        Err(_) => {
            return Err(rejection(
                RejectionStatus::Unavailable,
                "The attestation key could not be resolved.",
            ))
        }
    };
    let signature = <[u8; 64]>::try_from(decoded.signature.as_slice())
        .map(|bytes| Signature::from_bytes(&bytes))
        .map_err(|_| invalid("The attestation signature is invalid."))?;
    key.verify_strict(&decoded.signing_input, &signature)
        .map_err(|_| invalid("The attestation signature is invalid."))?;

    serde_json::from_value(Value::Object(decoded.claims))
        .map_err(|_| invalid("The attestation is malformed."))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::identity::ext::attestation::jwks::StaticKeys;

    pub(crate) const ISSUER: &str = "https://issuer.example";
    pub(crate) const AUDIENCE: &str = "https://api.example";
    pub(crate) const KID: &str = "test-key";

    pub(crate) fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    pub(crate) fn claims(now: u64) -> Value {
        serde_json::json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "Alice@Example.com",
            "type": "email",
            "iat": now,
            "exp": now + 600,
            "jti": "att_1",
        })
    }

    pub(crate) fn token_with(now: u64, edit: impl FnOnce(&mut Value)) -> String {
        let mut claims = claims(now);
        edit(&mut claims);
        sign(&claims, &signing_key(), KID).unwrap()
    }

    pub(crate) fn keys() -> StaticKeys {
        StaticKeys::new([(KID.to_string(), signing_key().verifying_key())])
    }

    fn options(now: u64) -> VerifyOptions {
        VerifyOptions {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            attestation_type: "email".into(),
            clock_tolerance: None,
            max_age: None,
            now: Some(now),
        }
    }

    async fn reason(token: &str, options: &VerifyOptions) -> String {
        verify(token, options, &keys()).await.unwrap_err().reason
    }

    #[tokio::test]
    async fn verifies_a_signed_attestation() {
        let now = 1_800_000_000;
        let token = token_with(now, |_| {});
        let claims = verify(&token, &options(now), &keys()).await.unwrap();
        assert_eq!(claims.sub, "Alice@Example.com");
        assert_eq!(claims.attestation_type, "email");
        assert_eq!(claims.jti.as_deref(), Some("att_1"));
        assert_eq!(claims.exp, now + 600);
    }

    #[test]
    fn header_matches_mppx() {
        let token = token_with(1, |_| {});
        let decoded = decode(&token).unwrap();
        assert_eq!(
            Value::Object(decoded.header).to_string(),
            r#"{"alg":"EdDSA","kid":"test-key","typ":"mpp-attestation+jwt"}"#
        );
    }

    #[tokio::test]
    async fn rejects_bad_claims() {
        let now = 1_800_000_000;
        let cases: Vec<(String, &str)> = vec![
            (
                token_with(now, |c| c["iss"] = "https://evil.example".into()),
                "The attestation issuer is not trusted.",
            ),
            (
                token_with(now, |c| c["aud"] = "https://other.example".into()),
                "The attestation is for another audience.",
            ),
            (
                token_with(now, |c| c["type"] = "phone".into()),
                "The attestation type is not accepted.",
            ),
            (
                token_with(now, |c| c["sub"] = "".into()),
                "The attestation has no subject.",
            ),
            (
                token_with(now, |c| c["jti"] = 1.into()),
                "The attestation ID is malformed.",
            ),
            (
                token_with(now, |c| c["exp"] = (-1).into()),
                "The attestation times are malformed.",
            ),
            (
                token_with(now, |c| c["exp"] = (now - 61).into()),
                "The attestation has expired.",
            ),
            (
                token_with(now, |c| c["iat"] = (now + 61).into()),
                "The attestation was issued in the future.",
            ),
            ("a.b".into(), "The attestation is malformed."),
        ];
        for (token, expected) in cases {
            assert_eq!(reason(&token, &options(now)).await, expected);
        }
    }

    #[tokio::test]
    async fn clock_tolerance_and_max_age() {
        let now = 1_800_000_000;
        // Expired 30 s ago: inside the default 60 s tolerance.
        let token = token_with(now, |c| c["exp"] = (now - 30).into());
        assert!(verify(&token, &options(now), &keys()).await.is_ok());
        let strict = VerifyOptions {
            clock_tolerance: Some(0),
            ..options(now)
        };
        assert_eq!(
            reason(&token, &strict).await,
            "The attestation has expired."
        );

        let old = token_with(now, |c| c["iat"] = (now - 1_000).into());
        let max_age = VerifyOptions {
            max_age: Some(600),
            ..options(now)
        };
        assert_eq!(reason(&old, &max_age).await, "The attestation is too old.");
    }

    #[tokio::test]
    async fn rejects_tampered_and_unknown_keys() {
        let now = 1_800_000_000;
        let token = token_with(now, |_| {});
        let (input, _) = token.rsplit_once('.').unwrap();
        let other = SigningKey::from_bytes(&[9u8; 32]).sign(input.as_bytes());
        let forged = format!("{input}.{}", URL_SAFE_NO_PAD.encode(other.to_bytes()));
        assert_eq!(
            reason(&forged, &options(now)).await,
            "The attestation signature is invalid."
        );

        let unknown = sign(&claims(now), &signing_key(), "other").unwrap();
        assert_eq!(
            reason(&unknown, &options(now)).await,
            "No public key is available for the attestation key ID."
        );

        let header = URL_SAFE_NO_PAD
            .encode(r#"{"alg":"none","typ":"mpp-attestation+jwt","kid":"test-key"}"#);
        let (_, rest) = token.split_once('.').unwrap();
        assert_eq!(
            reason(&format!("{header}.{rest}"), &options(now)).await,
            "The attestation algorithm is not EdDSA."
        );
    }

    #[tokio::test]
    async fn unreachable_keys_are_unavailable() {
        let now = 1_800_000_000;
        let token = token_with(now, |_| {});
        let rejection = verify(
            &token,
            &options(now),
            &crate::identity::ext::attestation::jwks::FailingKeys,
        )
        .await
        .unwrap_err();
        assert_eq!(rejection.status, RejectionStatus::Unavailable);
    }

    #[test]
    fn decode_rejects_oversized_and_padded_tokens() {
        assert!(decode(&"a".repeat(MAX_LENGTH + 1)).is_none());
        let token = token_with(1, |_| {});
        assert!(decode(&format!("{token}=")).is_none());
    }

    #[test]
    fn issuers_require_https_except_localhost() {
        assert!(is_issuer("https://issuer.example"));
        assert!(is_issuer("http://localhost:8787"));
        assert!(is_issuer("http://127.0.0.1:8787"));
        assert!(!is_issuer("http://issuer.example"));
        assert!(!is_issuer("ftp://issuer.example"));
        assert!(!is_issuer("not a url"));
    }

    #[test]
    fn parse_header_splits_values() {
        assert_eq!(
            parse_header(["a.b.c, d.e.f", " ,g.h.i"]),
            vec!["a.b.c", "d.e.f", "g.h.i"]
        );
    }

    /// A remote signer backed by `key` that reports `public` as its public
    /// key, records each payload and returns `edit`'s change of the signature.
    struct TestSigner {
        key: SigningKey,
        public: VerifyingKey,
        calls: std::sync::Mutex<Vec<Vec<u8>>>,
        edit: fn(Vec<u8>) -> Result<Vec<u8>, RemoteSignerError>,
    }

    impl TestSigner {
        fn new(key: SigningKey) -> Self {
            Self {
                public: key.verifying_key(),
                key,
                calls: Default::default(),
                edit: Ok,
            }
        }
    }

    impl RemoteSigner for TestSigner {
        fn public_key(&self) -> VerifyingKey {
            self.public
        }

        fn sign<'a>(&'a self, payload: &'a [u8]) -> RemoteSignerFuture<'a> {
            self.calls.lock().unwrap().push(payload.to_vec());
            let signature = Signer::sign(&self.key, payload).to_bytes().to_vec();
            let result = (self.edit)(signature);
            Box::pin(async move { result })
        }
    }

    #[tokio::test]
    async fn remote_signer_signs_the_same_token_as_the_local_key() {
        // Ed25519 is deterministic, so the same key and claims give an identical token.
        let now = 1_800_000_000;
        let local = sign(&claims(now), &signing_key(), KID).unwrap();
        let signer = TestSigner::new(signing_key());
        let token = sign_with(&claims(now), &signer, Some(KID)).await.unwrap();
        assert_eq!(token, local);
        assert!(verify(&token, &options(now), &keys()).await.is_ok());
    }

    #[tokio::test]
    async fn remote_signer_gets_the_signing_input_once() {
        let signer = TestSigner::new(signing_key());
        let token = sign_with(&claims(1), &signer, None).await.unwrap();
        let calls = signer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], token.rsplit_once('.').unwrap().0.as_bytes());
    }

    #[tokio::test]
    async fn key_id_defaults_to_the_thumbprint() {
        let now = 1_800_000_000;
        let kid = thumbprint(&signing_key().verifying_key());
        let resolver = StaticKeys::new([(kid.clone(), signing_key().verifying_key())]);
        let remote = TestSigner::new(signing_key());
        for token in [
            sign(&claims(now), &signing_key(), &kid).unwrap(),
            sign_with(&claims(now), &remote, None).await.unwrap(),
        ] {
            assert_eq!(decode(&token).unwrap().header["kid"], kid.as_str());
            assert!(verify(&token, &options(now), &resolver).await.is_ok());
        }
        let explicit = sign_with(&claims(now), &remote, Some("issuer-key-1"))
            .await
            .unwrap();
        assert_eq!(decode(&explicit).unwrap().header["kid"], "issuer-key-1");
    }

    #[test]
    fn thumbprint_matches_rfc_8037() {
        // RFC 8037 Appendix A.2 and A.3.
        let x = URL_SAFE_NO_PAD
            .decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
            .unwrap();
        let key = VerifyingKey::from_bytes(&x.try_into().unwrap()).unwrap();
        assert_eq!(
            thumbprint(&key),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
    }

    #[tokio::test]
    async fn rejects_signatures_that_do_not_verify_with_the_public_key() {
        let mismatched = TestSigner {
            public: signing_key().verifying_key(),
            ..TestSigner::new(SigningKey::from_bytes(&[9u8; 32]))
        };
        let short = TestSigner {
            edit: |mut sig| {
                sig.pop();
                Ok(sig)
            },
            ..TestSigner::new(signing_key())
        };
        let long = TestSigner {
            edit: |mut sig| {
                sig.push(0);
                Ok(sig)
            },
            ..TestSigner::new(signing_key())
        };
        let prefixed = TestSigner {
            edit: |sig| Ok([&[0x30, 0x44][..], &sig].concat()),
            ..TestSigner::new(signing_key())
        };
        let digest = TestSigner {
            edit: |_| {
                let digest = Sha256::digest(b"payload");
                Ok(Signer::sign(&signing_key(), &digest).to_bytes().to_vec())
            },
            ..TestSigner::new(signing_key())
        };
        let empty = TestSigner {
            edit: |_| Ok(Vec::new()),
            ..TestSigner::new(signing_key())
        };
        for signer in [mismatched, short, long, prefixed, digest, empty] {
            let err = sign_with(&claims(1), &signer, None).await.unwrap_err();
            assert!(matches!(err, IdentityError::InvalidSignature), "{err}");
        }
    }

    #[tokio::test]
    async fn propagates_a_signer_failure() {
        let signer = TestSigner {
            edit: |_| Err("KMS unavailable.".into()),
            ..TestSigner::new(signing_key())
        };
        let err = sign_with(&claims(1), &signer, None).await.unwrap_err();
        match err {
            IdentityError::Signer(source) => assert_eq!(source.to_string(), "KMS unavailable."),
            other => panic!("unexpected error: {other}"),
        }
    }
}
