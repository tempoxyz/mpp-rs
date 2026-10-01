//! `WWW-Authenticate` parsing over arbitrary text.
//!
//! - Neither parser panics.
//! - Parsing normalizes once: an accepted header formats, and the formatted
//!   header parses back to the same challenge.
//! - The single and list parsers agree on a header that names the scheme once.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::{
    format_www_authenticate, parse_www_authenticate, parse_www_authenticate_all, PaymentChallenge,
    PaymentProtocol,
};
use mpp_fuzz::{assert_same, is_header_safe, quoted_values};

fuzz_target!(|header: &str| {
    let single = parse_www_authenticate(header);
    let list = parse_www_authenticate_all([header]);
    let detected = PaymentProtocol::detect(Some(header)).is_some();

    let Ok(challenge) = single else { return };
    assert!(detected, "parsed a challenge the detector does not see");
    assert!(!challenge.id.is_empty());

    match format_www_authenticate(&challenge) {
        Ok(formatted) => {
            let reparsed = parse_www_authenticate(&formatted).expect("formatted header parses");
            assert_same(&reparsed, &challenge);
            assert_eq!(format_www_authenticate(&reparsed).unwrap(), formatted);
        }
        // The parser decodes `\u000a` and friends; the formatter refuses to
        // emit them.
        Err(_) => assert!(has_line_break(&challenge), "cannot format {challenge:?}"),
    }

    // The parsers disagree in two corners, both left out here: the single
    // parser trims Unicode whitespace (VT, NBSP, ...) before the scheme while
    // the list parser only skips SP and HTAB, and an auth-param that is
    // itself named `Payment` is a scheme boundary to the list parser.
    if is_header_safe(header) && scheme_count(header) == 1 {
        assert_eq!(list.len(), 1, "list parser disagrees on {header:?}");
        assert_same(list[0].as_ref().expect("list parser accepts"), &challenge);
    }
});

fn has_line_break(challenge: &PaymentChallenge) -> bool {
    quoted_values(challenge)
        .iter()
        .any(|value| value.contains(['\r', '\n']))
}

fn scheme_count(header: &str) -> usize {
    header.to_ascii_lowercase().matches("payment").count()
}
