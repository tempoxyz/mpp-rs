//! Multi-challenge parsing among other auth schemes.
//!
//! Builds `WWW-Authenticate` values from 1–5 formatted challenges, each
//! optionally preceded by a `Basic`/`Bearer`/`Digest` challenge whose quoted
//! parameter contains scheme-like text, with varied scheme casing and list
//! whitespace. `parse_www_authenticate_all` must return exactly the Payment
//! challenges, in order and intact. Mirrors mppx `Challenge.fuzz.test.ts`.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mpp::{format_www_authenticate, parse_www_authenticate, parse_www_authenticate_all};
use mpp_fuzz::{assert_same, ChallengeInput, Text};

#[derive(Debug, Arbitrary)]
struct Input {
    entries: Vec<Entry>,
    trailing_decoy: Option<Decoy>,
}

#[derive(Debug, Arbitrary)]
struct Entry {
    challenge: ChallengeInput,
    scheme: Scheme,
    decoy: Option<Decoy>,
    separator: Separator,
    /// Start a new header line instead of continuing the current one.
    new_line: bool,
}

#[derive(Debug, Arbitrary)]
enum Scheme {
    Canonical,
    Lower,
    UpperTwoSpaces,
    MixedTab,
}

impl Scheme {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Canonical => "Payment ",
            Self::Lower => "payment ",
            Self::UpperTwoSpaces => "PAYMENT  ",
            Self::MixedTab => "pAyMeNt\t",
        }
    }
}

#[derive(Debug, Arbitrary)]
enum Separator {
    CommaSpace,
    Comma,
    SpaceCommaSpace,
    CommaTab,
    EmptyElement,
}

impl Separator {
    fn as_str(&self) -> &'static str {
        match self {
            Self::CommaSpace => ", ",
            Self::Comma => ",",
            Self::SpaceCommaSpace => " , ",
            Self::CommaTab => ",\t",
            Self::EmptyElement => ", , ",
        }
    }
}

/// Another scheme's challenge whose quoted parameter looks like a Payment one.
#[derive(Debug, Arbitrary)]
struct Decoy {
    scheme: DecoyScheme,
    prefix: Text,
    token: Scheme,
    suffix: Text,
}

#[derive(Debug, Arbitrary)]
enum DecoyScheme {
    Basic,
    Bearer,
    Digest,
}

impl Decoy {
    fn build(&self) -> String {
        let text = format!("{}{}{}", self.prefix.0, self.token.as_str(), self.suffix.0);
        let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
        format!("{:?} realm=\"{escaped}\"", self.scheme)
    }
}

fuzz_target!(|input: Input| {
    let mut lines: Vec<String> = Vec::new();
    let mut expected = Vec::new();

    for entry in input.entries.iter().take(5) {
        let challenge = entry.challenge.build();
        let Ok(header) = format_www_authenticate(&challenge) else {
            return;
        };
        // Skip challenges the single parser rejects; see `fuzz_challenge_roundtrip`.
        let Ok(parsed) = parse_www_authenticate(&header) else {
            return;
        };
        expected.push(parsed);

        let payment = header.replacen("Payment ", entry.scheme.as_str(), 1);
        let mut members = entry.decoy.iter().map(Decoy::build).collect::<Vec<_>>();
        members.push(payment);
        let members = members.join(entry.separator.as_str());

        match lines.last_mut() {
            Some(line) if !entry.new_line => {
                line.push_str(entry.separator.as_str());
                line.push_str(&members);
            }
            _ => lines.push(members),
        }
    }
    if let (Some(decoy), Some(line)) = (&input.trailing_decoy, lines.last_mut()) {
        line.push_str(", ");
        line.push_str(&decoy.build());
    }

    let parsed = parse_www_authenticate_all(lines.iter().map(String::as_str));
    assert_eq!(parsed.len(), expected.len(), "{lines:#?}");
    for (parsed, expected) in parsed.iter().zip(&expected) {
        let parsed = parsed
            .as_ref()
            .unwrap_or_else(|e| panic!("{e}: {lines:#?}"));
        assert_same(parsed, expected);
    }
});
