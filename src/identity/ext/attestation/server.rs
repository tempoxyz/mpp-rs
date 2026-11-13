//! Server verifier that requires an attestation.

use std::collections::HashSet;
use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

use super::jwks::{JwksResolver, KeyResolver};
use super::token::{decode, is_issuer, parse_header, verify, AttestationClaims, VerifyOptions};
use super::{decisive, rejection, IdentityError, HEADER};
use super::{trim_issuer, CLOCK_TOLERANCE};
use crate::identity::{
    requirements, BoxFuture, IdentityRequest, Rejection, RejectionStatus, Requirement,
    Verification, Verifier,
};

/// Most distinct attestations of one type and issuer verified per request.
const MAX_CANDIDATES: usize = 3;

/// The reason sent when `validate` rejects without one.
const DEFAULT_FORBIDDEN_REASON: &str = "This identity attestation is not allowed.";

type Validate = dyn Fn(&AttestationClaims) -> Result<(), String> + Send + Sync;

/// Verifies one type of identity attestation from one issuer, as mppx's
/// `Attestation.Server.verifier`.
///
/// As a [`Verifier`] (wrap it in a [`Handle`](crate::identity::Handle) to add
/// it to a [`RouteIdentity`](crate::identity::RouteIdentity)), it reads the
/// request's `Identity-Attestation` header and rejects with:
/// - [`Missing`](RejectionStatus::Missing) (401): no attestation of this type
///   and issuer, with an `Identity-Attestation-Required` header naming them,
///   which a client prover answers by obtaining one and retrying.
/// - [`Invalid`](RejectionStatus::Invalid) (401): none verified, with the same
///   header so the client can obtain a fresh one.
/// - [`Forbidden`](RejectionStatus::Forbidden) (403): one verified, but
///   `validate` rejected it.
/// - [`Unavailable`](RejectionStatus::Unavailable) (503): the issuer's keys
///   could not be fetched, so the client keeps its attestation instead of
///   asking for a new one.
///
/// Attestations of other types or issuers in the same header are left to
/// their own verifiers. An attestation is a bearer proof bound to this
/// server's origin until it expires; it says what the issuer checked, not
/// what the subject may do.
#[derive(Clone)]
pub struct AttestationVerifier {
    audience: String,
    issuer: String,
    attestation_type: String,
    clock_tolerance: u64,
    max_age: Option<u64>,
    resolver: Arc<dyn KeyResolver>,
    validate: Option<Arc<Validate>>,
    required: HeaderValue,
}

impl std::fmt::Debug for AttestationVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttestationVerifier")
            .field("audience", &self.audience)
            .field("issuer", &self.issuer)
            .field("attestation_type", &self.attestation_type)
            .field("clock_tolerance", &self.clock_tolerance)
            .field("max_age", &self.max_age)
            .finish_non_exhaustive()
    }
}

impl AttestationVerifier {
    /// Creates a verifier for attestations of `attestation_type` that
    /// `issuer` signs for `audience` (this server's origin, such as
    /// `https://api.example`). Keys are read from the issuer's JSON Web Key
    /// Set with a [`JwksResolver`].
    ///
    /// Fails when `issuer` is not an `https` URL (or `http` on localhost) or
    /// `attestation_type` is not a structured-field token.
    pub fn new(
        audience: impl Into<String>,
        issuer: impl Into<String>,
        attestation_type: impl Into<String>,
    ) -> Result<Self, IdentityError> {
        let issuer = trim_issuer(&issuer.into()).to_string();
        if !is_issuer(&issuer) {
            return Err(IdentityError::InvalidConfig(
                "Attestation issuer must be an https URL (http only on localhost).".into(),
            ));
        }
        let attestation_type = attestation_type.into();
        let requirement = Requirement::new(attestation_type.clone()).with_issuer(issuer.clone());
        let required = requirements::serialize(&[requirement])
            .ok()
            .and_then(|value| HeaderValue::from_str(&value).ok())
            .ok_or_else(|| {
                IdentityError::InvalidConfig(format!(
                    "attestation type {attestation_type:?} is not a structured-field token"
                ))
            })?;
        Ok(Self {
            audience: audience_origin(&audience.into()),
            issuer,
            attestation_type,
            clock_tolerance: CLOCK_TOLERANCE,
            max_age: None,
            resolver: Arc::new(JwksResolver::new()),
            validate: None,
            required,
        })
    }

    /// Clock tolerance in seconds for `iat`, `exp` and the maximum age.
    /// Defaults to [`CLOCK_TOLERANCE`].
    pub fn with_clock_tolerance(mut self, seconds: u64) -> Self {
        self.clock_tolerance = seconds;
        self
    }

    /// Rejects attestations issued more than `seconds` ago.
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    /// Resolves issuer keys with `resolver` instead of a default [`JwksResolver`].
    pub fn with_key_resolver(mut self, resolver: impl KeyResolver + 'static) -> Self {
        self.resolver = Arc::new(resolver);
        self
    }

    /// Accepts a verified attestation only when `validate` returns `Ok`.
    /// `Err(reason)` rejects it as [`Forbidden`](RejectionStatus::Forbidden)
    /// with `reason` (a default reason when empty); a later attestation in
    /// the same request may still be accepted.
    pub fn with_validate<F>(mut self, validate: F) -> Self
    where
        F: Fn(&AttestationClaims) -> Result<(), String> + Send + Sync + 'static,
    {
        self.validate = Some(Arc::new(validate));
        self
    }

    /// The `Identity-Attestation-Required` value this verifier sends, such as
    /// `email;issuer="https://issuer.example"`.
    pub fn required_header(&self) -> &HeaderValue {
        &self.required
    }

    /// The audience attestations must be bound to.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The trusted issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Verifies the `Identity-Attestation` attestations in a request's headers.
    ///
    /// At most three distinct attestations of this type and issuer are
    /// verified, latest expiry first, so repeated or forged ones cost a
    /// bounded number of signature checks. Without a usable one, the first is
    /// verified so its rejection says why.
    // Rejections are the cold path; keep the public type unboxed, as RouteIdentity::verify_request does.
    #[allow(clippy::result_large_err)]
    pub async fn verify_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<AttestationClaims, Rejection> {
        let now = super::now();
        let values = headers
            .get_all(HEADER)
            .iter()
            .filter_map(|value| value.to_str().ok());
        let candidates: Vec<(String, serde_json::Map<String, Value>)> = parse_header(values)
            .into_iter()
            .filter_map(|token| {
                let claims = decode(&token)?.claims;
                let matches = claims.get("iss").and_then(Value::as_str)
                    == Some(self.issuer.as_str())
                    && claims.get("type").and_then(Value::as_str)
                        == Some(self.attestation_type.as_str());
                matches.then_some((token, claims))
            })
            .collect();
        let exp = |claims: &serde_json::Map<String, Value>| {
            claims.get("exp").and_then(Value::as_u64).unwrap_or(0)
        };
        let mut usable: Vec<_> = candidates
            .iter()
            .filter(|(_, claims)| {
                claims.get("aud").and_then(Value::as_str) == Some(self.audience.as_str())
                    && exp(claims).saturating_add(self.clock_tolerance) > now
            })
            .collect();
        usable.sort_by_key(|(_, claims)| std::cmp::Reverse(exp(claims)));
        let (pool, limit) = if usable.is_empty() {
            (candidates.iter().collect::<Vec<_>>(), 1)
        } else {
            (usable, MAX_CANDIDATES)
        };
        let mut seen = HashSet::new();
        let tokens: Vec<&str> = pool
            .into_iter()
            .map(|(token, _)| token.as_str())
            .filter(|token| seen.insert(*token))
            .take(limit)
            .collect();

        if tokens.is_empty() {
            return Err(self.with_required(rejection(
                RejectionStatus::Missing,
                format!(
                    "An identity attestation of type \"{}\" is required.",
                    self.attestation_type
                ),
            )));
        }

        let options = VerifyOptions {
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            attestation_type: self.attestation_type.clone(),
            clock_tolerance: Some(self.clock_tolerance),
            max_age: self.max_age,
            now: Some(now),
        };
        let mut rejections = Vec::new();
        for token in tokens {
            let claims = match verify(token, &options, self.resolver.as_ref()).await {
                Ok(claims) => claims,
                Err(rejection) => {
                    rejections.push(rejection);
                    continue;
                }
            };
            if let Some(validate) = &self.validate {
                if let Err(reason) = validate(&claims) {
                    let reason = if reason.is_empty() {
                        DEFAULT_FORBIDDEN_REASON.to_string()
                    } else {
                        reason
                    };
                    rejections.push(rejection(RejectionStatus::Forbidden, reason));
                    continue;
                }
            }
            return Ok(claims);
        }
        let rejection = decisive(rejections)
            .unwrap_or_else(|| rejection(RejectionStatus::Invalid, "No attestation verified."));
        // Only an invalid attestation is worth replacing: the client may obtain a fresh one.
        Err(if rejection.status == RejectionStatus::Invalid {
            self.with_required(rejection)
        } else {
            rejection
        })
    }

    fn with_required(&self, mut rejection: Rejection) -> Rejection {
        rejection.headers.append(
            HeaderName::from_static("identity-attestation-required"),
            self.required.clone(),
        );
        rejection
    }
}

impl Verifier for AttestationVerifier {
    type Value = AttestationClaims;

    fn verify<'a>(
        &'a self,
        request: &'a IdentityRequest,
    ) -> BoxFuture<'a, Verification<AttestationClaims>> {
        Box::pin(async move {
            match self.verify_headers(request.headers()).await {
                Ok(claims) => Verification::Valid(claims),
                Err(rejection) => Verification::Rejected(rejection),
            }
        })
    }
}

/// An audience as the origin attestations carry, so `https://api.example/` matches.
fn audience_origin(audience: &str) -> String {
    match reqwest::Url::parse(audience) {
        Ok(url) if url.origin().is_tuple() => super::origin_of(&url),
        _ => audience.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ext::attestation::jwks::FailingKeys;
    use crate::identity::ext::attestation::token::tests::{keys, token_with, AUDIENCE, ISSUER};
    use crate::identity::ext::attestation::REQUIRED_HEADER;

    fn verifier() -> AttestationVerifier {
        AttestationVerifier::new(format!("{AUDIENCE}/"), ISSUER, "email")
            .unwrap()
            .with_key_resolver(keys())
    }

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER, value.parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn missing_asks_for_an_attestation() {
        let rejection = verifier()
            .verify_headers(&HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!(rejection.status, RejectionStatus::Missing);
        assert_eq!(rejection.status.code(), 401);
        assert_eq!(
            rejection.headers.get(REQUIRED_HEADER).unwrap(),
            r#"email;issuer="https://issuer.example""#
        );
        assert_eq!(
            rejection.reason,
            r#"An identity attestation of type "email" is required."#
        );
    }

    #[tokio::test]
    async fn accepts_a_valid_attestation_among_others() {
        let now = super::super::now();
        let phone = token_with(now, |c| c["type"] = "phone".into());
        let expired = token_with(now, |c| c["exp"] = (now - 3_600).into());
        let valid = token_with(now, |_| {});
        let claims = verifier()
            .verify_headers(&headers(&format!("{phone}, {expired}, garbage, {valid}")))
            .await
            .unwrap();
        assert_eq!(claims.sub, "Alice@Example.com");
    }

    #[tokio::test]
    async fn invalid_asks_for_a_fresh_attestation() {
        let now = super::super::now();
        let expired = token_with(now, |c| c["exp"] = (now - 3_600).into());
        let rejection = verifier()
            .verify_headers(&headers(&expired))
            .await
            .unwrap_err();
        assert_eq!(rejection.status, RejectionStatus::Invalid);
        assert_eq!(rejection.reason, "The attestation has expired.");
        assert!(rejection.headers.get(REQUIRED_HEADER).is_some());
    }

    #[tokio::test]
    async fn validate_rejects_as_forbidden_without_asking_again() {
        let now = super::super::now();
        let verifier = verifier().with_validate(|_| Err(String::new()));
        let rejection = verifier
            .verify_headers(&headers(&token_with(now, |_| {})))
            .await
            .unwrap_err();
        assert_eq!(rejection.status, RejectionStatus::Forbidden);
        assert_eq!(rejection.reason, DEFAULT_FORBIDDEN_REASON);
        assert!(rejection.headers.is_empty());
    }

    #[tokio::test]
    async fn unreachable_issuer_is_unavailable() {
        let now = super::super::now();
        let rejection = verifier()
            .with_key_resolver(FailingKeys)
            .verify_headers(&headers(&token_with(now, |_| {})))
            .await
            .unwrap_err();
        assert_eq!(rejection.status, RejectionStatus::Unavailable);
        assert_eq!(rejection.status.code(), 503);
        assert!(rejection.headers.is_empty());
    }

    #[test]
    fn rejects_untrusted_configuration() {
        assert!(AttestationVerifier::new(AUDIENCE, "http://issuer.example", "email").is_err());
        assert!(AttestationVerifier::new(AUDIENCE, ISSUER, "not a token").is_err());
        let verifier =
            AttestationVerifier::new(AUDIENCE, "https://issuer.example//", "email").unwrap();
        assert_eq!(verifier.issuer(), ISSUER);
    }
}
