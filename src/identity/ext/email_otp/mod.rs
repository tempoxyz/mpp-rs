//! Email OTP identity: an issuer emails a one-time code and signs an `email`
//! attestation the client sends in `Identity-Attestation`.
//!
//! A server requires a verified email address with [`EmailOtpVerifier`], a
//! [`Verifier`](crate::identity::Verifier). A client obtains one with
//! [`EmailOtpProver`] (with the `client` feature), which builds an
//! [`AttestationProver`](super::attestation::AttestationProver) that asks a trusted issuer to
//! email a code, gets the code from a callback (a terminal prompt or a form)
//! and exchanges it for an attestation bound to the server's origin.
//!
//! The issuer protocol, as Tempo's `mpp-identity` issuer serves it:
//!
//! - `POST {issuer}/email/otp` with `{"email", "audience"}` answers
//!   `{"id", "expires_at"}` ([`send_code`]).
//! - `POST {issuer}/email/verify` with `{"id", "code"}` answers
//!   `{"attestation", "expires_at"}` ([`verify_code`]).
//! - `GET {issuer}/.well-known/jwks.json` publishes the Ed25519 keys
//!   ([`JwksResolver`](super::attestation::JwksResolver)).
//!
//! Ported from mppx's `mppx/extensions/identity/email-otp`.

#[cfg(feature = "client")]
mod client;
mod server;

#[cfg(all(test, feature = "client", feature = "axum"))]
mod tests;

#[cfg(feature = "client")]
pub use client::{send_code, verify_code, CodeContext, CodeRequest, EmailOtpProver, VerifiedCode};
pub use server::{EmailOtpVerifier, VerifiedEmail};

/// Attestation type for a verified email address.
pub const ATTESTATION_TYPE: &str = "email";

/// Issuer path that emails a one-time code.
pub const OTP_PATH: &str = "/email/otp";

/// Issuer path that exchanges a one-time code for an attestation.
pub const VERIFY_PATH: &str = "/email/verify";

/// Times the prover asks for a code before giving up.
pub const CODE_ATTEMPTS: u32 = 3;
