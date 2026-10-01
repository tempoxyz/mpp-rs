//! Tokenizer for `WWW-Authenticate` and `Authorization` field values
//! (RFC 9110 §11), and the quoted-string escaping of the formatter.

use super::headers::PAYMENT_SCHEME;
use crate::error::{MppError, Result};
use std::borrow::Cow;

/// A lexical element of a list of challenges or credentials.
#[derive(Debug, PartialEq)]
pub(super) enum Token<'a> {
    /// An auth-scheme: the first word of a list element, followed by SP or HTAB.
    Scheme(&'a str),
    /// An auth-param, with a quoted value unescaped.
    Param { name: &'a str, value: Cow<'a, str> },
    /// Any other word, such as the token68 of a scheme.
    Word(&'a str),
}

impl Token<'_> {
    /// Whether this is the `Payment` auth-scheme (case-insensitive).
    pub(super) fn is_payment_scheme(&self) -> bool {
        matches!(self, Self::Scheme(scheme) if scheme.eq_ignore_ascii_case(PAYMENT_SCHEME))
    }
}

/// Splits a field value into auth-schemes and their auth-params.
///
/// Every header parser reads through this type, so they all agree on where a
/// scheme starts and on how a value is delimited and unquoted.
///
/// The grammar is RFC 9110 §11, read as leniently as mppx reads it:
///
/// - Whitespace is ASCII whitespace, list elements may be empty, and
///   auth-params need no comma between them.
/// - A name is the text up to `=` or whitespace. An unquoted value is the
///   text up to a comma or whitespace.
/// - A word followed by `=` is an auth-param, also where it could start a list
///   element: in `a b=c, d = e` the scheme `a` has two auth-params. Only the
///   first word of the field value is a scheme whatever follows it.
pub(super) struct Tokenizer<'a> {
    input: &'a str,
    pos: usize,
    /// Where the token returned last starts.
    start: usize,
}

impl<'a> Tokenizer<'a> {
    pub(super) fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            start: 0,
        }
    }

    /// The next token if it is an auth-param. Any other token is left for
    /// [`Iterator::next`].
    pub(super) fn param(&mut self) -> Result<Option<(&'a str, Cow<'a, str>)>> {
        let pos = self.pos;
        match self.next().transpose()? {
            Some(Token::Param { name, value }) => Ok(Some((name, value))),
            _ => {
                self.pos = pos;
                Ok(None)
            }
        }
    }

    /// The credentials that the scheme just returned starts: the scheme and
    /// the text up to the next comma. `None` if nothing follows the scheme.
    ///
    /// The token68 of credentials can end in `=`, which makes it look like an
    /// auth-param, so it is not read as tokens.
    pub(super) fn credentials(&mut self) -> Option<&'a str> {
        let scheme_len = self.pos - self.start;
        let rest = &self.input[self.pos..];
        self.pos += rest.find(',').unwrap_or(rest.len());
        let credentials = self.input[self.start..self.pos].trim_ascii_end();
        (credentials.len() > scheme_len).then_some(credentials)
    }

    /// Index of the first byte from `from` on that satisfies `stop`, or the
    /// length of the input.
    fn seek(&self, from: usize, stop: impl Fn(u8) -> bool) -> usize {
        self.input.as_bytes()[from..]
            .iter()
            .position(|byte| stop(*byte))
            .map_or(self.input.len(), |offset| from + offset)
    }

    /// Reads the value of an auth-param: a quoted-string, or the text up to a
    /// comma or whitespace.
    fn value(&mut self) -> Result<Cow<'a, str>> {
        let bytes = self.input.as_bytes();
        let start = self.seek(self.pos, |byte| !byte.is_ascii_whitespace());
        if bytes.get(start) != Some(&b'"') {
            self.pos = self.seek(start, |byte| byte == b',' || byte.is_ascii_whitespace());
            return Ok(Cow::Borrowed(&self.input[start..self.pos]));
        }

        let start = start + 1;
        let mut unescaped = String::new();
        let mut segment_start = start;
        let mut i = start;
        loop {
            match bytes.get(i) {
                Some(b'"') => break,
                Some(b'\\') => {
                    unescaped.push_str(&self.input[segment_start..i]);
                    i += 1;
                    if let Some((decoded, next)) = read_unicode_escape(self.input, i) {
                        unescaped.push(decoded);
                        i = next;
                    } else if let Some(escaped) = self.input[i..].chars().next() {
                        unescaped.push(escaped);
                        i += escaped.len_utf8();
                    }
                    segment_start = i;
                }
                Some(_) => i += 1,
                None => {
                    self.pos = bytes.len();
                    return Err(MppError::invalid_challenge_reason(
                        "Unterminated quoted-string",
                    ));
                }
            }
        }
        self.pos = i + 1;

        let tail = &self.input[segment_start..i];
        if segment_start == start {
            return Ok(Cow::Borrowed(tail));
        }
        unescaped.push_str(tail);
        Ok(Cow::Owned(unescaped))
    }
}

impl<'a> Iterator for Tokenizer<'a> {
    type Item = Result<Token<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.input.as_bytes();
        let first = self.pos == 0;
        // A list element starts at the beginning of the value and after a comma.
        let mut element_start = first;
        while let Some(&byte) = bytes.get(self.pos) {
            if byte == b',' {
                element_start = true;
            } else if !byte.is_ascii_whitespace() {
                break;
            }
            self.pos += 1;
        }
        if self.pos == bytes.len() {
            return None;
        }

        self.start = self.pos;
        let is_separator = |at| matches!(bytes.get(at), Some(b' ' | b'\t'));
        let end = self.seek(self.start, |byte| {
            byte == b'=' || byte.is_ascii_whitespace()
        });
        let equals = self.seek(end, |byte| !byte.is_ascii_whitespace());

        if bytes.get(equals) == Some(&b'=') && !(first && is_separator(end)) {
            let name = &self.input[self.start..end];
            self.pos = equals + 1;
            return Some(self.value().map(|value| Token::Param { name, value }));
        }

        // Not an auth-param, so the word ends at a comma too.
        let end = self.seek(self.start, |byte| byte == b',').min(end);
        let word = &self.input[self.start..end];
        self.pos = end;
        Some(Ok(if element_start && is_separator(end) {
            Token::Scheme(word)
        } else {
            Token::Word(word)
        }))
    }
}

/// Whether a field value starts with the `Payment` auth-scheme.
pub(super) fn starts_with_payment_scheme(input: &str) -> bool {
    matches!(Tokenizer::new(input).next(), Some(Ok(token)) if token.is_payment_scheme())
}

fn read_unicode_escape(input: &str, at: usize) -> Option<(char, usize)> {
    let (unit, next) = read_escaped_code_unit(input, at)?;

    if !(0xD800..=0xDFFF).contains(&unit) {
        return char::from_u32(u32::from(unit)).map(|decoded| (decoded, next));
    }

    if (0xD800..=0xDBFF).contains(&unit) && input.as_bytes().get(next) == Some(&b'\\') {
        if let Some((low, after)) = read_escaped_code_unit(input, next + 1) {
            if (0xDC00..=0xDFFF).contains(&low) {
                let code =
                    0x1_0000 + ((u32::from(unit) - 0xD800) << 10) + (u32::from(low) - 0xDC00);
                return char::from_u32(code).map(|decoded| (decoded, after));
            }
        }
    }

    Some((char::REPLACEMENT_CHARACTER, next))
}

fn read_escaped_code_unit(input: &str, at: usize) -> Option<(u16, usize)> {
    if input.as_bytes().get(at) != Some(&b'u') {
        return None;
    }
    let digits = input.get(at + 1..at + 5)?;
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(digits, 16)
        .ok()
        .map(|unit| (unit, at + 5))
}

/// Escape a string for use in a quoted-string header value.
///
/// Only printable ASCII and HTAB are emitted as-is. Everything else is written
/// as `\uXXXX` UTF-16 code units, so the result is always a valid header value.
/// Rejects CRLF to prevent header injection attacks.
pub(super) fn escape_quoted_value(s: &str) -> Result<String> {
    if s.contains('\r') || s.contains('\n') {
        return Err(MppError::invalid_challenge_reason(
            "Header value contains invalid CRLF characters",
        ));
    }
    let mut escaped = String::with_capacity(s.len());
    for unit in s.encode_utf16() {
        match unit {
            0x005c => escaped.push_str("\\\\"),
            0x0022 => escaped.push_str("\\\""),
            0x0009 | 0x0020..=0x007e => {
                escaped.push(char::from_u32(u32::from(unit)).expect("ASCII is valid Unicode"))
            }
            _ => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{unit:04x}").expect("writing to String cannot fail");
            }
        }
    }
    Ok(escaped)
}

#[cfg(test)]
mod tests {
    use super::Token::{Scheme, Word};
    use super::*;

    fn tokens(input: &str) -> Vec<Token<'_>> {
        Tokenizer::new(input).map(Result::unwrap).collect()
    }

    fn param<'a>(name: &'a str, value: &'a str) -> Token<'a> {
        Token::Param {
            name,
            value: value.into(),
        }
    }

    fn payment_schemes(input: &str) -> usize {
        let tokens = tokens(input);
        tokens.iter().filter(|t| t.is_payment_scheme()).count()
    }

    #[test]
    fn test_tokenizer_ignores_scheme_in_quoted_value() {
        // "Payment" inside a quoted value should NOT be treated as a boundary
        let header = r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30", description="Payment required""#;
        assert_eq!(payment_schemes(header), 1);
    }

    #[test]
    fn test_tokenizer_skips_leading_whitespace() {
        // Headers with leading whitespace must still be recognized
        let header =
            r#"  Payment id="a", realm="api", method="tempo", intent="charge", request="e30""#;
        assert_eq!(tokens(header)[..2], [Scheme("Payment"), param("id", "a")]);
    }

    #[test]
    fn test_tokenizer_finds_each_challenge() {
        // single challenge
        let single =
            r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30""#;
        assert_eq!(payment_schemes(single), 1);

        // two challenges, normal spacing
        let two = concat!(
            r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30", "#,
            r#"Payment id="b", realm="api", method="stripe", intent="charge", request="e30""#,
        );
        let tokens = tokens(two);
        assert_eq!(tokens.len(), 12);
        assert_eq!(tokens[..2], [Scheme("Payment"), param("id", "a")]);
        assert_eq!(tokens[6..8], [Scheme("Payment"), param("id", "b")]);

        // no whitespace after comma, mixed case scheme
        let compact = concat!(
            r#"PAYMENT id="a", realm="api", method="tempo", intent="charge", request="e30","#,
            r#"payment id="b", realm="api", method="stripe", intent="charge", request="e30""#,
        );
        assert_eq!(payment_schemes(compact), 2);

        // non-Payment scheme
        assert_eq!(payment_schemes("Bearer token123"), 0);
    }

    #[test]
    fn test_tokenizer_tokens() {
        assert_eq!(
            tokens("Bearer abc,Payment id = \"a\" realm=\tapi ,empty=, Basic dXNlcg==,x y"),
            [
                Scheme("Bearer"),
                Word("abc"),
                Scheme("Payment"),
                param("id", "a"),
                param("realm", "api"),
                param("empty", ""),
                Scheme("Basic"),
                param("dXNlcg", "="),
                Scheme("x"),
                Word("y"),
            ]
        );
        assert_eq!(tokens(" ,\t, "), []);
    }

    #[test]
    fn test_tokenizer_tells_schemes_from_params() {
        // A word followed by `=` is an auth-param, also after a comma.
        assert_eq!(
            tokens(r#"Payment id="a", payment ="x""#),
            [Scheme("Payment"), param("id", "a"), param("payment", "x")]
        );
        // The first word of the value is a scheme whatever follows.
        assert_eq!(
            tokens(r#"Payment ="x""#),
            [Scheme("Payment"), param("", "x")]
        );
        // A scheme starts a list element and is followed by SP or HTAB.
        assert_eq!(tokens("Payment"), [Word("Payment")]);
        assert_eq!(
            tokens("a b Payment c"),
            [Scheme("a"), Word("b"), Word("Payment"), Word("c")]
        );
        assert_eq!(
            tokens("a b,Payment\tc"),
            [Scheme("a"), Word("b"), Scheme("Payment"), Word("c")]
        );
    }

    #[test]
    fn test_tokenizer_unescapes_quoted_values() {
        let input = "Payment a=\"x, Payment y\", b=\"\\\"q\\\" \\\\ \u{e9} \u{1f600}\"";
        let mut tokens = Tokenizer::new(input);
        assert_eq!(tokens.next().unwrap().unwrap(), Scheme("Payment"));
        let (_, plain) = tokens.param().unwrap().unwrap();
        assert!(matches!(plain, Cow::Borrowed("x, Payment y")));
        let (_, escaped) = tokens.param().unwrap().unwrap();
        assert_eq!(escaped, "\"q\" \\ \u{e9} \u{1f600}");
        assert!(tokens.next().is_none());
    }

    #[test]
    fn test_tokenizer_ends_at_unterminated_quoted_string() {
        for input in [
            r#"Payment id="a", realm="oops, Payment id=b"#,
            r#"Payment id="a", realm="oops\"#,
        ] {
            let mut tokens = Tokenizer::new(input);
            assert_eq!(tokens.next().unwrap().unwrap(), Scheme("Payment"));
            assert_eq!(tokens.next().unwrap().unwrap(), param("id", "a"));
            assert!(tokens.next().unwrap().is_err());
            assert!(tokens.next().is_none());
        }
    }

    #[test]
    fn test_param_leaves_other_tokens() {
        let mut tokens = Tokenizer::new("Payment a=1 b=2, Bearer c=3");
        assert_eq!(tokens.next().unwrap().unwrap(), Scheme("Payment"));
        assert_eq!(tokens.param().unwrap(), Some(("a", "1".into())));
        assert_eq!(tokens.param().unwrap(), Some(("b", "2".into())));
        assert_eq!(tokens.param().unwrap(), None);
        assert_eq!(tokens.next().unwrap().unwrap(), Scheme("Bearer"));
    }

    #[test]
    fn test_credentials() {
        let mut tokens = Tokenizer::new("Payment  abc== , Payment\t, x");
        assert_eq!(tokens.next().unwrap().unwrap(), Scheme("Payment"));
        assert_eq!(tokens.credentials(), Some("Payment  abc=="));
        assert_eq!(tokens.next().unwrap().unwrap(), Scheme("Payment"));
        assert_eq!(tokens.credentials(), None);
        assert_eq!(tokens.next().unwrap().unwrap(), Word("x"));
    }
}
