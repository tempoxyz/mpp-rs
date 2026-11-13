//! Identity providers built on the [identity](super) primitives.
//!
//! mppx ships more providers under `mppx/extensions/identity`. They are not
//! ported yet:
//!
//! - TODO: Link (agent identity: attestation tokens and Link-signed claims).
//! - TODO: Persona (a payment check that requires an approved Persona inquiry).
//! - TODO: RFC 9421 HTTP message signatures, then TAP and Web Bot Auth on top.

#[cfg(feature = "identity-attestation")]
pub mod attestation;

#[cfg(feature = "identity-email-otp")]
pub mod email_otp;

#[cfg(feature = "identity-tempo-id")]
pub mod tempo_id;
