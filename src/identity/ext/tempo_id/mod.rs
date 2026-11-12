//! Tempo ID (`id.tempo.xyz`) as an identity method, as mppx's
//! `mppx/extensions/identity/tempo`.
//!
//! - **Server:** [`server::create`] returns a [`verifier`](server::TempoId::verifier)
//!   and a [`payment_check`](server::TempoId::payment_check). Both check a
//!   Tempo ID access token offline against Tempo ID's keys (issuer, audience,
//!   expiry, allowed client ID, and the DPoP proof when the token is
//!   DPoP-bound). The payment check also refuses, before settlement, a payment
//!   that does not use the `tempo` method, whose `source` is not a Tempo
//!   Account the token grants to the app, or whose account Tempo ID screened
//!   as anything but `clear`. The optional `allow` callback receives the
//!   verified user and decides.
//! - **Client:** [`client::prover`] sends the access token as `Bearer`, or as
//!   `DPoP` with a new ES256 proof for each request, plus the optional ID
//!   token in `Tempo-Id-Token`.
//!
//! The token uses `Authorization`, so create the server with
//! `requires_auth`, so Payment Credentials travel in `Payment-Authorization`.
//!
//! ```no_run
//! # #[cfg(all(feature = "server", feature = "axum"))]
//! # fn example() {
//! use std::sync::Arc;
//! use mpp::identity::ext::tempo_id::server::{self, Config};
//! use mpp::identity::RouteIdentity;
//! use mpp::store::MemoryStore;
//!
//! let tempo_id = server::create(
//!     Config::new("app_123")
//!         .origin("https://api.example")
//!         .store(Arc::new(MemoryStore::new()))
//!         .allow(|user| user.email_verified == Some(true)),
//! );
//! let identity = RouteIdentity::new().payment(&tempo_id.payment_check);
//! // Router::new().route("/haiku", get(handler)).layer(axum::Extension(identity))
//! # }
//! ```

mod jwt;
mod types;

pub mod server;

#[cfg(feature = "client")]
pub mod client;

pub use types::{Caller, ComplianceState, DpopKey, Payer};

/// Tempo ID values.
pub mod constants {
    /// Identity type advertised in the 402's `Identity-Required` header.
    pub const TYPE: &str = "tempo-id";
    /// Tempo ID in production: the issuer of every access token.
    pub const ISSUER: &str = "https://id.tempo.xyz";
    /// Header that carries the user's ID token, for their email address.
    pub const ID_TOKEN_HEADER: &str = "Tempo-Id-Token";
    /// Seconds a DPoP proof is accepted after its `iat`.
    pub const PROOF_MAX_AGE: i64 = 300;
    /// Seconds of clock skew allowed on token and proof times.
    pub const CLOCK_TOLERANCE: i64 = 60;
}
