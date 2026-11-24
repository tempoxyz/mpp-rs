//! Server verifier that requires a verified email address.

use std::sync::Arc;

use reqwest::header::HeaderMap;
use time::OffsetDateTime;

use super::ATTESTATION_TYPE;
use crate::identity::ext::attestation::IdentityError;
use crate::identity::ext::attestation::{AttestationVerifier, KeyResolver};
use crate::identity::{BoxFuture, IdentityRequest, Rejection, Verification, Verifier};

/// A verified email address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEmail {
    /// The address, lowercased.
    pub email: String,
    /// When the attestation expires.
    pub expires_at: OffsetDateTime,
    /// The attestation ID, if the issuer set one.
    pub id: Option<String>,
    /// The issuer that verified it.
    pub issuer: String,
}

/// Requires a verified email address, as mppx's `EmailOtp.Server.verifier`:
/// an [`AttestationVerifier`] of type `email` that only accepts addresses
/// [`with_allow`](Self::with_allow) allows.
///
/// A request without one is rejected as
/// [`Missing`](crate::identity::RejectionStatus::Missing) (401) with
/// `Identity-Attestation-Required: email;issuer="…"`; the client obtains an
/// attestation from the issuer with a one-time code sent to the address and
/// sends it in `Identity-Attestation`. An address `allow` rejects is
/// [`Forbidden`](crate::identity::RejectionStatus::Forbidden) (403).
///
/// Add it to a route as a verifier, so every request needs a verified address
/// before a Challenge is issued:
///
/// ```no_run
/// # fn example() -> Result<(), mpp::identity::ext::attestation::IdentityError> {
/// use mpp::identity::ext::email_otp::EmailOtpVerifier;
/// use mpp::identity::{Handle, RouteIdentity};
///
/// let email = Handle::new(
///     EmailOtpVerifier::new("https://api.example", "https://issuer.example")?
///         .with_allow(|email| email.ends_with("@example.com")),
/// );
/// let identity = RouteIdentity::new().verifier(&email);
/// // Router::new().route("/paid", get(handler)).layer(axum::Extension(identity))
/// // In the handler, `charge.identity.get(&email)` is the `VerifiedEmail`.
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct EmailOtpVerifier {
    inner: AttestationVerifier,
}

impl EmailOtpVerifier {
    /// Creates a verifier for email attestations `issuer` signs for
    /// `audience`, this server's origin.
    pub fn new(
        audience: impl Into<String>,
        issuer: impl Into<String>,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            inner: AttestationVerifier::new(audience, issuer, ATTESTATION_TYPE)?,
        })
    }

    /// Accepts only addresses for which `allow` returns `true`. It receives
    /// the address lowercased.
    pub fn with_allow<F>(self, allow: F) -> Self
    where
        F: Fn(&str) -> bool + Send + Sync + 'static,
    {
        let allow = Arc::new(allow);
        Self {
            inner: self.inner.with_validate(move |claims| {
                if allow(&claims.sub.to_lowercase()) {
                    Ok(())
                } else {
                    Err("This email address is not allowed.".into())
                }
            }),
        }
    }

    /// Clock tolerance in seconds for `iat`, `exp` and the maximum age.
    pub fn with_clock_tolerance(self, seconds: u64) -> Self {
        Self {
            inner: self.inner.with_clock_tolerance(seconds),
        }
    }

    /// Rejects attestations issued more than `seconds` ago.
    pub fn with_max_age(self, seconds: u64) -> Self {
        Self {
            inner: self.inner.with_max_age(seconds),
        }
    }

    /// Resolves issuer keys with `resolver` instead of a default
    /// [`JwksResolver`](crate::identity::ext::attestation::JwksResolver).
    pub fn with_key_resolver(self, resolver: impl KeyResolver + 'static) -> Self {
        Self {
            inner: self.inner.with_key_resolver(resolver),
        }
    }

    /// The underlying attestation verifier.
    pub fn attestation_verifier(&self) -> &AttestationVerifier {
        &self.inner
    }

    /// Verifies the email attestation in a request's headers.
    // Rejections are the cold path; keep the public type unboxed, as RouteIdentity::verify_request does.
    #[allow(clippy::result_large_err)]
    pub async fn verify_headers(&self, headers: &HeaderMap) -> Result<VerifiedEmail, Rejection> {
        let claims = self.inner.verify_headers(headers).await?;
        Ok(VerifiedEmail {
            email: claims.sub.to_lowercase(),
            expires_at: i64::try_from(claims.exp)
                .ok()
                .and_then(|exp| OffsetDateTime::from_unix_timestamp(exp).ok())
                // Past what `time` represents (year 9999): the latest it can.
                .unwrap_or_else(|| time::PrimitiveDateTime::MAX.assume_utc()),
            id: claims.jti,
            issuer: claims.iss,
        })
    }
}

impl Verifier for EmailOtpVerifier {
    type Value = VerifiedEmail;

    fn verify<'a>(
        &'a self,
        request: &'a IdentityRequest,
    ) -> BoxFuture<'a, Verification<VerifiedEmail>> {
        Box::pin(async move {
            match self.verify_headers(request.headers()).await {
                Ok(verified) => Verification::Valid(verified),
                Err(rejection) => Verification::Rejected(rejection),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ext::attestation::token::tests::{keys, token_with, AUDIENCE, ISSUER};
    use crate::identity::ext::attestation::HEADER;
    use crate::identity::RejectionStatus;

    fn headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HEADER, token.parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn returns_the_lowercased_email() {
        let now = crate::identity::ext::attestation::now();
        let verifier = EmailOtpVerifier::new(AUDIENCE, ISSUER)
            .unwrap()
            .with_key_resolver(keys());
        let verified = verifier
            .verify_headers(&headers(&token_with(now, |_| {})))
            .await
            .unwrap();
        assert_eq!(verified.email, "alice@example.com");
        assert_eq!(verified.id.as_deref(), Some("att_1"));
        assert_eq!(verified.issuer, ISSUER);
        assert_eq!(verified.expires_at.unix_timestamp(), (now + 600) as i64);
    }

    #[tokio::test]
    async fn allow_rejects_as_forbidden() {
        let now = crate::identity::ext::attestation::now();
        let verifier = EmailOtpVerifier::new(AUDIENCE, ISSUER)
            .unwrap()
            .with_key_resolver(keys())
            .with_allow(|email| email.ends_with("@corp.example"));
        let rejection = verifier
            .verify_headers(&headers(&token_with(now, |_| {})))
            .await
            .unwrap_err();
        assert_eq!(rejection.status, RejectionStatus::Forbidden);
        assert_eq!(rejection.reason, "This email address is not allowed.");
    }
}
