//! Format → parse round trip over structured challenges.
//!
//! - The formatter accepts exactly the challenges whose `id` and bound
//!   fields have their wire form and whose `header` can be emitted.
//! - Formatted headers are printable ASCII, so they survive any HTTP stack.
//! - Every challenge the formatter accepts parses back field for field, but
//!   for `description` characters written as `\uXXXX`, which read back as
//!   the text `uXXXX`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::{format_www_authenticate, parse_www_authenticate};
use mpp_fuzz::{
    assert_same, has_formattable_header, has_quoted_text_values, is_header_safe, is_well_formed,
    read_back, wire_header, ChallengeInput,
};

fuzz_target!(|input: ChallengeInput| {
    let mut challenge = input.build();
    let formattable = is_well_formed(&challenge)
        && has_formattable_header(challenge.header.as_deref())
        && has_quoted_text_values(&challenge);

    let Ok(header) = format_www_authenticate(&challenge) else {
        assert!(!formattable, "cannot format {challenge:?}");
        return;
    };
    assert!(formattable, "formatted {challenge:?}");
    assert!(is_header_safe(&header), "not a portable header: {header:?}");

    let parsed = parse_www_authenticate(&header).unwrap_or_else(|e| panic!("{e}: {header}"));
    challenge.header = wire_header(challenge.header.as_deref());
    let expected = read_back(&challenge);
    assert_same(&parsed, &expected);
    let again = format_www_authenticate(&parsed).unwrap();
    if expected.description == challenge.description {
        assert_eq!(again, header);
    } else {
        assert_same(&parse_www_authenticate(&again).unwrap(), &parsed);
    }
});
