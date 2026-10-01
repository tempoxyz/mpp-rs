//! Format → parse round trip over structured challenges.
//!
//! - The formatter refuses only an empty `id` and an unsupported `header`.
//! - Formatted headers are printable ASCII, so they survive any HTTP stack.
//! - Every challenge the formatter accepts parses back field for field.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::{format_www_authenticate, parse_www_authenticate};
use mpp_fuzz::{
    assert_same, has_supported_header, has_unparseable_optionals, is_header_safe, wire_header,
    ChallengeInput,
};

fuzz_target!(|input: ChallengeInput| {
    let mut challenge = input.build();

    let Ok(header) = format_www_authenticate(&challenge) else {
        assert!(challenge.id.is_empty() || !has_supported_header(challenge.header.as_deref()));
        return;
    };
    assert!(is_header_safe(&header), "not a portable header: {header:?}");

    let parsed = match parse_www_authenticate(&header) {
        Ok(parsed) => parsed,
        Err(error) => {
            assert!(
                has_unparseable_optionals(
                    challenge.expires.as_deref(),
                    challenge.digest.as_deref()
                ),
                "{error}: {header}"
            );
            return;
        }
    };
    challenge.header = wire_header(challenge.header.as_deref());
    assert_same(&parsed, &challenge);
    assert_eq!(format_www_authenticate(&parsed).unwrap(), header);
});
