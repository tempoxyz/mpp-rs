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
    /// `(from, stop)`: the first `=` or whitespace at or after `from`, so a
    /// long run of comma-separated words is scanned once, not once per word.
    name_end: Option<(usize, usize)>,
    /// The first non-whitespace byte at or after `name_end`, cached for the
    /// same reason.
    name_equals: Option<(usize, usize)>,
    /// Whether a comma separates the token returned last from the one before.
    after_comma: bool,
    /// Whether the auth-param value read last was a quoted-string.
    quoted: bool,
    /// Whether the value read last was quoted and held a quoted-pair `\u`
    /// followed by four hex digits: the `\uXXXX` escape that older servers
    /// wrote for characters above U+00FF, which a quoted-pair reads as
    /// `uXXXX`.
    unicode_escape: bool,
}

impl<'a> Tokenizer<'a> {
    pub(super) fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            start: 0,
            name_end: None,
            name_equals: None,
            after_comma: false,
            quoted: false,
            unicode_escape: false,
        }
    }

    /// Whether a comma separates the token returned last from the token
    /// before it.
    pub(super) fn after_comma(&self) -> bool {
        self.after_comma
    }

    /// Whether the value of the auth-param returned last was a quoted-string
    /// rather than a token.
    pub(super) fn quoted(&self) -> bool {
        self.quoted
    }

    /// Whether the auth-param value returned last was quoted and held a
    /// legacy `\uXXXX` escape.
    pub(super) fn read_unicode_escape(&self) -> bool {
        self.unicode_escape
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
        self.unicode_escape = false;
        let bytes = self.input.as_bytes();
        let start = self.seek(self.pos, |byte| !byte.is_ascii_whitespace());
        self.quoted = bytes.get(start) == Some(&b'"');
        if !self.quoted {
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
                    // A quoted-pair (RFC 9110 §5.6.4) stands for the character
                    // after the backslash, so \u2014 is the text "u2014".
                    i += 1;
                    if bytes.get(i) == Some(&b'u')
                        && bytes
                            .get(i + 1..i + 5)
                            .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
                    {
                        self.unicode_escape = true;
                    }
                    if let Some(escaped) = self.input[i..].chars().next() {
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
        self.after_comma = false;
        while let Some(&byte) = bytes.get(self.pos) {
            if byte == b',' {
                element_start = true;
                self.after_comma = true;
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
        // A stop found from an earlier start is still the first one from any
        // start between the two: reuse it to keep the scan linear in the
        // length of the value.
        let end = match self.name_end {
            Some((from, end)) if (from..=end).contains(&self.start) => end,
            _ => {
                let end = self.seek(self.start, |byte| {
                    byte == b'=' || byte.is_ascii_whitespace()
                });
                self.name_end = Some((self.start, end));
                end
            }
        };
        let equals = match self.name_equals {
            Some((cached_end, equals)) if cached_end == end => equals,
            _ => {
                let equals = self.seek(end, |byte| !byte.is_ascii_whitespace());
                self.name_equals = Some((end, equals));
                equals
            }
        };

        if bytes.get(equals) == Some(&b'=') && !(first && is_separator(end)) {
            let name = &self.input[self.start..end];
            self.pos = equals + 1;
            return Some(self.value().map(|value| Token::Param { name, value }));
        }

        // Not an auth-param, so the word ends at a comma too.
        let end = bytes[self.start..end]
            .iter()
            .position(|byte| *byte == b',')
            .map_or(end, |offset| self.start + offset);
        let word = &self.input[self.start..end];
        self.pos = end;
        Some(Ok(if element_start && is_separator(end) {
            Token::Scheme(word)
        } else {
            Token::Word(word)
        }))
    }
}

/// Whether `value` is an RFC 9110 token (§5.6.2): one or more tchar.
pub(super) fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || is_tchar_symbol(byte))
}

/// Whether `byte` is one of the non-alphanumeric tchar.
fn is_tchar_symbol(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
    )
}

/// Whether a field value starts with the `Payment` auth-scheme.
pub(super) fn starts_with_payment_scheme(input: &str) -> bool {
    matches!(Tokenizer::new(input).next(), Some(Ok(token)) if token.is_payment_scheme())
}

/// Escape a string for use in a quoted-string header value.
///
/// Only printable ASCII and HTAB can be written: a quoted-pair (RFC 9110
/// §5.6.4) escapes a single character, so nothing else survives a round trip.
/// Rejects other characters, such as CR and LF, which would allow header
/// injection, and text that a parser would read back differently.
pub(super) fn escape_quoted_value(s: &str) -> Result<String> {
    reject_line_breaks(s)?;
    if let Some(c) = s.chars().find(|c| !is_quoted_text(*c)) {
        return Err(MppError::invalid_challenge_reason(format!(
            "Header value contains a character outside printable ASCII: {:?}",
            c
        )));
    }
    Ok(escape_quoted_text(s))
}

/// Check that a server realm can be written into a Challenge header.
///
/// The realm is bound into the Challenge ID, so [`escape_quoted_value`]
/// refuses it on every request when it holds a character outside printable
/// ASCII; checking it once when the server is configured reports that early.
#[cfg(all(feature = "server", any(feature = "tempo", feature = "stripe")))]
pub(crate) fn validate_realm(realm: &str) -> Result<()> {
    escape_quoted_value(realm).map(|_| ()).map_err(|_| {
        MppError::InvalidConfig(format!(
            "Invalid realm {realm:?}: a realm must be printable ASCII, since a Challenge header can't carry other characters."
        ))
    })
}

/// Escape free text, such as a description, for a quoted-string header value.
///
/// Like [`escape_quoted_value`], but writes any other character as `\uXXXX`
/// UTF-16 code units instead of rejecting it, as mppx does, so a server can
/// always send its Challenge. Parsers read the escape as the text `uXXXX`, so
/// use this only for values that are not bound into the Challenge ID.
pub(super) fn escape_quoted_description(s: &str) -> Result<String> {
    reject_line_breaks(s)?;
    let mut escaped = String::with_capacity(s.len());
    for unit in s.encode_utf16() {
        match char::from_u32(u32::from(unit)) {
            Some(c) if is_quoted_text(c) => push_quoted_char(&mut escaped, c),
            _ => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{unit:04x}").expect("writing to String cannot fail");
            }
        }
    }
    Ok(escaped)
}

fn reject_line_breaks(s: &str) -> Result<()> {
    if s.contains('\r') || s.contains('\n') {
        return Err(MppError::invalid_challenge_reason(
            "Header value contains invalid CRLF characters",
        ));
    }
    Ok(())
}

/// Whether `c` can appear in a quoted-string, either as itself or after a
/// backslash.
fn is_quoted_text(c: char) -> bool {
    c == '\t' || (' '..='~').contains(&c)
}

fn escape_quoted_text(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        push_quoted_char(&mut escaped, c);
    }
    escaped
}

fn push_quoted_char(escaped: &mut String, c: char) {
    if matches!(c, '\\' | '"') {
        escaped.push('\\');
    }
    escaped.push(c);
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
    fn test_tokenizer_reads_quoted_pairs() {
        // Every quoted-pair drops its backslash; \uXXXX is not decoded.
        let input = r#"Payment a="\u2014 \ud83d\ude00 \\u0041 \x\"""#;
        let mut tokens = Tokenizer::new(input);
        assert_eq!(tokens.next().unwrap().unwrap(), Scheme("Payment"));
        let (_, value) = tokens.param().unwrap().unwrap();
        assert_eq!(value, r#"u2014 ud83dude00 \u0041 x""#);
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
    fn test_tokenizer_reports_commas_and_quoting() {
        let mut tokens = Tokenizer::new(r#"Payment a="1" b=2 ,c=3"#);
        assert_eq!(tokens.next().unwrap().unwrap(), Scheme("Payment"));
        tokens.param().unwrap().unwrap();
        assert!(!tokens.after_comma());
        assert!(tokens.quoted());
        tokens.param().unwrap().unwrap();
        assert!(!tokens.after_comma());
        assert!(!tokens.quoted());
        tokens.param().unwrap().unwrap();
        assert!(tokens.after_comma());
    }

    #[test]
    fn test_is_token() {
        for token in ["a", "e30", "Payment", "a!#$%&'*+-.^_`|~9"] {
            assert!(is_token(token), "{token}");
        }
        for not_token in [
            "",
            "\\",
            "a b",
            "d\"escription",
            "a=b",
            "a,b",
            "a:b",
            "caf\u{e9}",
        ] {
            assert!(!is_token(not_token), "{not_token}");
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
