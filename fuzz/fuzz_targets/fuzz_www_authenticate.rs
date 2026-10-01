//! `WWW-Authenticate` parsing over arbitrary text.
//!
//! - Neither parser panics.
//! - The single parser, the list parser and `PaymentProtocol::detect` agree
//!   on the first challenge of a header.
//! - Parsing normalizes once: an accepted header formats, and the formatted
//!   header parses back to the same challenge.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::{
    format_www_authenticate, parse_www_authenticate, parse_www_authenticate_all, PaymentChallenge,
    PaymentProtocol,
};
use mpp_fuzz::{assert_same, quoted_values};

fuzz_target!(|header: &str| {
    let single = parse_www_authenticate(header);
    let list = parse_www_authenticate_all([header]);
    let detected = PaymentProtocol::detect(Some(header)).is_some();

    if detected {
        match (&single, list.first()) {
            (Ok(challenge), Some(Ok(listed))) => assert_same(listed, challenge),
            (Err(_), Some(Err(_))) => {}
            _ => panic!("the parsers disagree on {header:?}"),
        }
    } else {
        assert!(single.is_err(), "parsed a challenge the detector does not see");
    }

    let Ok(challenge) = single else { return };
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
});

fn has_line_break(challenge: &PaymentChallenge) -> bool {
    quoted_values(challenge)
        .iter()
        .any(|value| value.contains(['\r', '\n']))
}
