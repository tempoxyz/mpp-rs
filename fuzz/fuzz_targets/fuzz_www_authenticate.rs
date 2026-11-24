//! `WWW-Authenticate` parsing over arbitrary text.
//!
//! - Neither parser panics.
//! - The single parser, the list parser and `PaymentProtocol::detect` agree
//!   on the first challenge of a header.
//! - Parsing normalizes once: an accepted header formats unless a value
//!   holds a line break or a bound value holds text outside printable ASCII,
//!   and the formatted header parses back to the same challenge, but for
//!   `description` characters written as `\uXXXX`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::{
    format_www_authenticate, parse_www_authenticate, parse_www_authenticate_all, PaymentChallenge,
    PaymentProtocol,
};
use mpp_fuzz::{assert_same, has_quoted_text_values, quoted_values, read_back};

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
        assert!(
            single.is_err(),
            "parsed a challenge the detector does not see"
        );
    }

    let Ok(challenge) = single else { return };
    assert!(!challenge.id.is_empty());

    match format_www_authenticate(&challenge) {
        Ok(formatted) => {
            let reparsed = parse_www_authenticate(&formatted).expect("formatted header parses");
            let expected = read_back(&challenge);
            assert_same(&reparsed, &expected);
            let again = format_www_authenticate(&reparsed).unwrap();
            if expected.description == challenge.description {
                assert_eq!(again, formatted);
            } else {
                // `description` lost its `\uXXXX` escapes once; it reads
                // back the same from now on.
                assert_same(&parse_www_authenticate(&again).unwrap(), &reparsed);
            }
        }
        // A quoted string may hold raw line breaks, and raw text outside
        // printable ASCII; the formatter refuses both outside `description`
        // and line breaks in it. It also refuses a Challenge flagged as
        // carrying the legacy `\uXXXX` escape.
        Err(_) => assert!(
            challenge.legacy_unicode_escape
                || has_line_break(&challenge)
                || !has_quoted_text_values(&challenge),
            "cannot format {challenge:?}"
        ),
    }
});

fn has_line_break(challenge: &PaymentChallenge) -> bool {
    quoted_values(challenge)
        .iter()
        .any(|value| value.contains(['\r', '\n']))
}
