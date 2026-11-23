//! Identity attestations, as mppx's `mppx/extensions/identity/attestation`.
//!
//! An attestation is a compact EdDSA JWS that a trusted issuer signs after
//! checking one fact about the subject (such as an email address), bound to
//! the origin it is presented to and sent in the `Identity-Attestation`
//! request header. See [mpp.dev/extensions/identity](https://mpp.dev/extensions/identity).
//!
//! - **Server:** [`AttestationVerifier`] is a [`Verifier`](crate::identity::Verifier)
//!   that requires one type of attestation from one issuer, with the issuer's
//!   keys read from its JSON Web Key Set by a [`JwksResolver`].
//! - **Client:** [`AttestationProver`] is a [`Prover`](crate::identity::client::Prover)
//!   that presents cached attestations and, when a server answers with
//!   `Identity-Attestation-Required`, obtains one and resends the request.
//! - **Issuers** sign attestations and serve their key with an
//!   [`AttestationIssuer`], or sign them directly with [`sign`], or with
//!   [`sign_with`] and a [`RemoteSigner`] whose private key stays in a KMS,
//!   an HSM or a wallet service.
//!
//! [`email_otp`](super::email_otp) builds on it.
//!
//! ```no_run
//! # fn example() -> Result<(), mpp::identity::ext::attestation::IdentityError> {
//! use mpp::identity::ext::attestation::AttestationVerifier;
//! use mpp::identity::{Handle, RouteIdentity};
//!
//! let phone = Handle::new(
//!     AttestationVerifier::new("https://api.example", "https://issuer.example", "phone")?,
//! );
//! let identity = RouteIdentity::new().verifier(&phone);
//! // Router::new().route("/paid", get(handler)).layer(axum::Extension(identity))
//! # Ok(())
//! # }
//! ```

mod error;
pub(crate) mod issuer;
pub(crate) mod jwks;
mod server;
pub(crate) mod token;

#[cfg(feature = "client")]
mod client;

pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use error::IdentityError;
pub use issuer::{AttestationIssuer, SignParameters, DEFAULT_TTL};
pub use jwks::{JwksResolver, KeyResolveError, KeyResolver, KeyResolverFuture};
pub use server::AttestationVerifier;
pub use token::{
    decode, is_issuer, parse_header, sign, sign_with, thumbprint, verify, AttestationClaims,
    Confirmation, DecodedAttestation, RemoteSigner, RemoteSignerError, RemoteSignerFuture,
    VerifyOptions,
};

#[cfg(feature = "client")]
pub use client::{requirements, AttestationProver, AttestationRequest, AttestationRequirement};

/// Request header carrying one or more attestations, separated by commas.
pub const HEADER: &str = "Identity-Attestation";

/// Response header listing the attestations a route requires, as a
/// structured-field list.
pub const REQUIRED_HEADER: &str = "Identity-Attestation-Required";

/// JWS `typ` header of an attestation.
pub const TOKEN_TYPE: &str = "mpp-attestation+jwt";

/// JWS algorithm of an attestation: EdDSA over Ed25519.
pub const ALGORITHM: &str = "EdDSA";

/// Path of the issuer's JSON Web Key Set, relative to the issuer URL.
pub const JWKS_PATH: &str = "/.well-known/jwks.json";

/// Default clock tolerance, in seconds, applied to `iat` and `exp`.
pub const CLOCK_TOLERANCE: u64 = 60;

/// Seconds before expiry at which a client stops sending an attestation on
/// unpaid attempts and replaces it, capped at half the attestation's lifetime.
pub const REFRESH_MARGIN: u64 = 300;

/// Longest attestation accepted, in characters.
pub const MAX_LENGTH: usize = 8_192;

/// A rejection with `status` and `reason`.
pub(crate) fn rejection(
    status: crate::identity::RejectionStatus,
    reason: impl Into<String>,
) -> crate::identity::Rejection {
    crate::identity::Rejection::new(status).with_reason(reason)
}

/// The first rejection of the status with the highest precedence in
/// [`status::PRECEDENCE`](crate::identity::status::PRECEDENCE), or `None`
/// when `rejections` is empty.
pub(crate) fn decisive(
    rejections: Vec<crate::identity::Rejection>,
) -> Option<crate::identity::Rejection> {
    crate::identity::status::PRECEDENCE
        .iter()
        .find_map(|status| rejections.iter().find(|r| r.status == *status).cloned())
}

/// The current Unix time, in seconds.
pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// `value` without trailing slashes, as issuers are compared.
pub(crate) fn trim_issuer(value: &str) -> &str {
    value.trim_end_matches('/')
}

/// The canonical form of an issuer URL, or `None` when it is not one.
///
/// It must be an `https` URL (`http` only on localhost) without userinfo,
/// a query, a fragment, whitespace or a backslash. The URL parser's
/// serialization, without trailing slashes, is returned, so the `iss` an
/// issuer signs, the key set path it serves and the paths clients build from
/// it all name the same URL.
pub(crate) fn canonical_issuer(value: &str) -> Option<String> {
    if value
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '\\' | '?' | '#'))
    {
        return None;
    }
    let url = reqwest::Url::parse(value).ok()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let canonical = trim_issuer(url.as_str()).to_owned();
    token::is_issuer(&canonical).then_some(canonical)
}

/// Whether `url` names this host (`localhost` or `127.0.0.1`).
#[cfg(feature = "client")]
pub(crate) fn is_loopback(url: &str) -> bool {
    reqwest::Url::parse(url)
        .is_ok_and(|url| matches!(url.host_str(), Some("localhost" | "127.0.0.1")))
}

/// The origin of `url`, as `new URL(url).origin` serializes it.
pub(crate) fn origin_of(url: &reqwest::Url) -> String {
    url.origin().ascii_serialization()
}
