//! Identity headers as data, lowercased, for code that must handle them
//! without knowing each protocol: the client's redirect handling and a
//! proxy's header scrubbing. As mppx's `Identity.Headers`.

/// Bearer identity request headers. Anyone holding one can replay it until it
/// expires, so it is never sent across origins or forwarded upstream by a
/// proxy. Provers declare their own extra sensitive headers in
/// [`Prover::headers`](super::client::Prover::headers).
pub const REQUEST: &[&str] = &["identity-attestation", "identity-presentation"];

/// `WWW-Authenticate` schemes that ask for an identity, lowercased. A proxy
/// removes them from upstream responses: the proxy, not the upstream, decides
/// which identity the client presents.
pub const CHALLENGES: &[&str] = &["privatetoken", "identity-presentation"];

/// Identity response headers a proxy must not pass on from upstream.
pub const RESPONSE: &[&str] = &["identity-attestation-required", "identity-required"];
