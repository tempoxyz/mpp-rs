//! Identity providers built on the [identity](super) primitives.
//!
//! mppx ships more providers under `mppx/extensions/identity`. They are not
//! ported yet:
//!
//! - TODO: attestation (`Identity-Attestation` EdDSA tokens, `Attestation.Server.verifier`,
//!   `Attestation.Client.prover` and issuer JWKS), the base of email OTP.
//! - TODO: email OTP (email address verification with a one-time code).
//! - TODO: Link (agent identity: attestation tokens and Link-signed claims).
//! - TODO: Persona (a payment check that requires an approved Persona inquiry).
//! - TODO: RFC 9421 HTTP message signatures, then TAP and Web Bot Auth on top.

#[cfg(feature = "identity-tempo-id")]
pub mod tempo_id;
