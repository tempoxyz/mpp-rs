//! Persona KYC as an identity method, as mppx's `mppx/extensions/identity/persona`.
//!
//! Link a person's wallet to a [Persona](https://withpersona.com) inquiry,
//! then require an approved inquiry before serving a paid request:
//!
//! - [`verify_wallet`] checks that the signer of a message owns a wallet and
//!   returns the wallet's reference ID ([`did`]), to start an inquiry with.
//! - [`Persona::start_inquiry`] starts an inquiry for a reference ID and
//!   returns a one-time link to Persona's hosted flow.
//! - [`Persona::payment_check`] requires an approved inquiry on a route's paid
//!   retry, keyed by the payer, and [`Persona::verifier`] requires one before
//!   any 402, keyed by your own session.
//!
//! Every 402 of a route with the payment check advertises
//! `Identity-Required: kyc;issuer="https://api.withpersona.com"`. No payer is
//! `missing` (401) and no accepted inquiry `forbidden` (403), both with the
//! onboarding URL in `Link: <url>; rel="kyc"`; a Persona API failure is
//! `unavailable` (503), without the upstream body.
//!
//! ```no_run
//! # fn example() -> Result<(), mpp::identity::ext::persona::PersonaError> {
//! use std::sync::Arc;
//! use mpp::identity::ext::persona::{normalize, Config, LookupOptions, Persona};
//! use mpp::identity::{Handle, RouteIdentity};
//! use mpp::store::MemoryStore;
//!
//! let persona = Persona::new(Config::new("persona_api_key").template_id("itmpl_123"))?;
//! // Derive the reference ID from something the server authenticated, such as
//! // your own session: a Credential's `source` is client-supplied.
//! let kyc = Handle::new(persona.payment_check(
//!     |input| input.request.header("x-session-wallet").map(normalize),
//!     LookupOptions::new()
//!         .onboarding("https://api.example/kyc")
//!         .cache(Arc::new(MemoryStore::new())),
//! ));
//! let identity = RouteIdentity::new().payment(&kyc);
//! // Router::new().route("/paid", get(handler)).layer(axum::Extension(identity))
//! # Ok(())
//! # }
//! ```

mod server;

#[cfg(test)]
mod tests;

pub use server::{
    verify_wallet, verify_wallet_with, Config, InquiryStatus, LookupOptions, Persona, PersonaError,
    PersonaPaymentCheck, PersonaVerifier, StartInquiry, StartedInquiry, VerifiedInquiry,
    WalletProof,
};

/// Persona KYC values.
pub mod constants {
    /// Identity type advertised in the 402's `Identity-Required` header.
    pub const TYPE: &str = "kyc";
    /// Issuer advertised in the 402's `Identity-Required` header: Persona's API origin.
    pub const ISSUER: &str = "https://api.withpersona.com";
    /// Persona API origin.
    pub const API_URL: &str = "https://api.withpersona.com";
    /// Persona API path for inquiries.
    pub const INQUIRIES_PATH: &str = "/api/v1/inquiries";
    /// Persona API version sent in `Persona-Version` by default.
    pub const API_VERSION: &str = "2023-01-05";
    /// Link relation of the onboarding URL sent with a rejection.
    pub const REL: &str = "kyc";
    /// Seconds before a Persona API call is abandoned as `unavailable`.
    pub const TIMEOUT_SECS: u64 = 5;
    /// Seconds an approval stays cached when a cache is set.
    pub const CACHE_TTL_SECS: u64 = 300;
    /// Most inquiry pages read per lookup.
    pub const MAX_PAGES: usize = 3;
}

/// Returns the reference ID for an EVM wallet: its `did:pkh` DID, the form a
/// Credential's `source` takes, with the address lowercased.
///
/// ```
/// use mpp::identity::ext::persona::did;
///
/// assert_eq!(did("0xAbC", 4217), "did:pkh:eip155:4217:0xabc");
/// ```
pub fn did(address: &str, chain_id: impl std::fmt::Display) -> String {
    did_in("eip155", chain_id, address)
}

/// Returns the reference ID for a wallet in a CAIP-2 `namespace`. Only EVM
/// (`eip155`) addresses are lowercased, since they are case-insensitive;
/// addresses on other chains, such as base58 Solana addresses, are kept as
/// they are.
pub fn did_in(namespace: &str, chain_id: impl std::fmt::Display, address: &str) -> String {
    normalize(&format!("did:pkh:{namespace}:{chain_id}:{address}"))
}

/// Normalizes a `did:pkh` DID: lowercases the scheme, the namespace and an
/// EVM address, and keeps the rest. Any other value is returned as it is.
pub fn normalize(value: &str) -> String {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 5
        || !parts[0].eq_ignore_ascii_case("did")
        || !parts[1].eq_ignore_ascii_case("pkh")
    {
        return value.to_owned();
    }
    let namespace = parts[2].to_lowercase();
    let address = if namespace == "eip155" {
        parts[4].to_lowercase()
    } else {
        parts[4].to_owned()
    };
    format!("did:pkh:{namespace}:{}:{address}", parts[3])
}
