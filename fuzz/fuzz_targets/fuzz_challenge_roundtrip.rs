//! Format → parse round trip over structured challenges.
//!
//! - The formatter accepts exactly the challenges whose `id` and bound
//!   fields have their wire form and whose `header` is supported.
//! - Formatted headers are printable ASCII, so they survive any HTTP stack.
//! - Every challenge the formatter accepts parses back field for field.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::{format_www_authenticate, parse_www_authenticate};
use mpp_fuzz::{
    assert_same, has_supported_header, is_header_safe, is_well_formed, wire_header, ChallengeInput,
};

fuzz_target!(|input: ChallengeInput| {
    let mut challenge = input.build();
    let formattable =
        is_well_formed(&challenge) && has_supported_header(challenge.header.as_deref());

    let Ok(header) = format_www_authenticate(&challenge) else {
        assert!(!formattable, "cannot format {challenge:?}");
        return;
    };
    assert!(formattable, "formatted {challenge:?}");
    assert!(is_header_safe(&header), "not a portable header: {header:?}");

    let parsed = parse_www_authenticate(&header).unwrap_or_else(|e| panic!("{e}: {header}"));
    challenge.header = wire_header(challenge.header.as_deref());
    assert_same(&parsed, &challenge);
    assert_eq!(format_www_authenticate(&parsed).unwrap(), header);
});
