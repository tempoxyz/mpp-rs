//! Identity: who calls a paid route, checked beside what they pay.
//!
//! A port of mppx's `mppx/identity` and `mppx/extensions/identity`, with the
//! same statuses, headers and behavior:
//!
//! - On a server, a [`Verifier`] checks one identity
//!   protocol on every request, before any payment Challenge is issued, and a
//!   [`PaymentCheck`] checks the payer's identity on the
//!   paid retry, after the Credential's HMAC and pinned fields are checked and
//!   before it settles. A [`RouteIdentity`] holds a
//!   route's verifiers and payment check; the Axum extractors run it when a
//!   route carries one as a request extension.
//! - On a client, a [`Prover`](client::Prover) adds one identity protocol to
//!   outbound requests, and [`ChargeClient::with_identity`](crate::client::ChargeClient::with_identity)
//!   applies provers to every attempt of a paid request.
//! - [`ext`] holds identity providers: [Tempo ID](ext::tempo_id) so far.
//!
//! A rejected identity has one of four fixed statuses ([`RejectionStatus`]),
//! each with one HTTP status code: `missing` and `invalid` (401),
//! `forbidden` (403) and `unavailable` (503).

pub mod ext;
pub mod headers;
pub mod requirements;
pub mod server;
pub mod status;
mod types;

#[cfg(feature = "client")]
pub mod client;

pub use server::{
    any_of, from_fn, from_fn_with_challenge, AnyOf, AnyOfMatch, ErasedCheck, ErasedVerifier,
    Handle, IdentityContext, IdentityRejection, IdentityRequest, IdentityResults, MemoKey,
    PaymentCheck, PaymentCheckInput, PaymentGate, RejectionStage, RouteIdentity, Verifier,
};
pub use types::{Rejection, RejectionStatus, Requirement, Verification};

/// A boxed, sendable future, as identity verifiers, payment checks and provers return.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
