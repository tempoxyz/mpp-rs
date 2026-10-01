//! HMAC challenge-id binding.
//!
//! - A challenge signed with a secret verifies under it, also after a trip
//!   through the header and through its credential echo, and under no other
//!   secret.
//! - Changing a bound field (`realm`, `method`, `intent`, `request`,
//!   `expires`, `digest`, `opaque`, advertised `header`) or the `id` makes
//!   verification fail. `description` is not bound.
//!
//! The second property is asserted for slots without a `|`: the HMAC input
//! joins the slots with `|` and does not escape them, so slots containing
//! the separator can be re-split into a different challenge with the same
//! id (e.g. realm `a|b`, method `m`, intent `i` and realm `a`, method `b`,
//! intent `m|i`).

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mpp::{
    compute_challenge_id_with_header, format_www_authenticate, parse_www_authenticate,
    PaymentChallenge,
};
use mpp_fuzz::{
    wire_header, ChallengeInput, DigestInput, ExpiresInput, HeaderInput, Method, OpaqueInput,
    RequestInput, Text, SECRET,
};

#[derive(Debug, Arbitrary)]
enum Mutation {
    Id(Text),
    Realm(Text),
    Method(Method),
    Intent(Text),
    Request(RequestInput),
    Expires(Option<ExpiresInput>),
    Description(Option<Text>),
    Digest(Option<DigestInput>),
    Opaque(Option<OpaqueInput>),
    Header(Option<HeaderInput>),
}

impl Mutation {
    fn apply(&self, challenge: &mut PaymentChallenge) {
        match self {
            Self::Id(id) => challenge.id = id.0.clone(),
            Self::Realm(realm) => challenge.realm = realm.0.clone(),
            Self::Method(method) => challenge.method = method.0.as_str().into(),
            Self::Intent(intent) => challenge.intent = intent.0.as_str().into(),
            Self::Request(request) => challenge.request = request.build(),
            Self::Expires(expires) => challenge.expires = expires.as_ref().map(|e| e.build()),
            Self::Description(text) => challenge.description = text.as_ref().map(|t| t.0.clone()),
            Self::Digest(digest) => challenge.digest = digest.as_ref().map(|d| d.build()),
            Self::Opaque(opaque) => challenge.opaque = opaque.as_ref().map(|o| o.build()),
            Self::Header(header) => challenge.header = header.as_ref().map(|h| h.build()),
        }
    }
}

/// The values the id commits to. An absent optional field and an empty one
/// share a slot, as do the spellings of the default `Authorization` header.
fn slots(challenge: &PaymentChallenge) -> [String; 8] {
    [
        challenge.realm.clone(),
        challenge.method.to_string(),
        challenge.intent.to_string(),
        challenge.request.raw().to_owned(),
        challenge.expires.clone().unwrap_or_default(),
        challenge.digest.clone().unwrap_or_default(),
        wire_header(challenge.header.as_deref()).unwrap_or_default(),
        challenge
            .opaque
            .as_ref()
            .map(|opaque| opaque.raw().to_owned())
            .unwrap_or_default(),
    ]
}

fuzz_target!(|input: (ChallengeInput, Vec<Mutation>)| {
    let (input, mutations) = input;
    let challenge = input.build_signed();

    assert!(challenge.verify(SECRET));
    assert!(!challenge.verify("another-secret-key-0123456789abcdef"));
    assert_eq!(
        mpp::base64url_decode(&challenge.id)
            .map(|mac| mac.len())
            .ok(),
        Some(32),
        "id is not a base64url HMAC-SHA256"
    );

    let echo = challenge.to_echo();
    let echoed_id = compute_challenge_id_with_header(
        SECRET,
        &echo.realm,
        &echo.method,
        &echo.intent,
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(|opaque| opaque.raw()),
        echo.header.as_deref(),
    );
    assert_eq!(
        echoed_id, challenge.id,
        "the echo does not carry the binding"
    );

    if let Ok(parsed) = format_www_authenticate(&challenge).and_then(|h| parse_www_authenticate(&h))
    {
        assert!(
            parsed.verify(SECRET),
            "the header does not carry the binding"
        );
    }

    let mut mutated = challenge.clone();
    for mutation in &mutations {
        mutation.apply(&mut mutated);
    }
    let unchanged = slots(&mutated) == slots(&challenge) && mutated.id == challenge.id;
    let separator_free = slots(&challenge)
        .iter()
        .chain(&slots(&mutated))
        .all(|slot| !slot.contains('|'));
    if unchanged || separator_free {
        assert_eq!(
            mutated.verify(SECRET),
            unchanged,
            "{challenge:?}\n{mutated:?}"
        );
    }
});
