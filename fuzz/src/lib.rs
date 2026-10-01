//! Input generators and comparison helpers shared by the fuzz targets.

use arbitrary::{Arbitrary, Result, Unstructured};
use mpp::protocol::core::{
    advertised_credential_header, is_default_credential_header, Base64UrlJson, ChallengeEcho,
    MethodName, PaymentChallenge,
};
use serde::Serialize;
use serde_json::Value;

/// HMAC secret used by every target that binds a challenge id.
pub const SECRET: &str = "fuzz-secret-key-0123456789abcdef";

/// A string without CR or LF, the only characters `format_www_authenticate`
/// refuses in a quoted value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Text(pub String);

impl<'a> Arbitrary<'a> for Text {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        let mut text = String::arbitrary(u)?;
        text.retain(|c| c != '\r' && c != '\n');
        Ok(Self(text))
    }
}

/// A method name matching `[a-z][a-z0-9:_-]*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Method(pub String);

impl<'a> Arbitrary<'a> for Method {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789:_-";
        let mut name = String::from(*u.choose(&ALPHABET[..26])? as char);
        for _ in 0..u.int_in_range(0..=11)? {
            name.push(*u.choose(ALPHABET)? as char);
        }
        Ok(Self(name))
    }
}

/// An intent name matching `1*( ALPHA / DIGIT / "-" / "_" )`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent(pub String);

impl<'a> Arbitrary<'a> for Intent {
    fn arbitrary(u: &mut Unstructured<'a>) -> Result<Self> {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
        let mut name = String::new();
        for _ in 0..u.int_in_range(1..=12)? {
            name.push(*u.choose(ALPHABET)? as char);
        }
        Ok(Self(name))
    }
}

#[derive(Debug, Clone, Arbitrary)]
pub enum IntentInput {
    Name(Intent),
    Raw(Text),
}

impl IntentInput {
    pub fn build(&self) -> &str {
        match self {
            Self::Name(name) => &name.0,
            Self::Raw(text) => &text.0,
        }
    }
}

/// An arbitrary JSON document.
#[derive(Debug, Clone, Arbitrary)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Array(Vec<Json>),
    Object(JsonObject),
}

impl Json {
    /// Nesting beyond this is cut off. `serde_json` refuses to parse more
    /// than 128 levels, so deeper values cannot arrive over the wire and
    /// would only make the formatters reject their own input.
    const MAX_DEPTH: usize = 32;

    pub fn to_value(&self) -> Value {
        self.to_value_at(0)
    }

    fn to_value_at(&self, depth: usize) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::Bool(b) => Value::Bool(*b),
            Self::Int(n) => Value::from(*n),
            // Non-finite floats have no JSON form and become `null`.
            Self::Float(f) => Value::from(*f),
            Self::String(s) => Value::String(s.clone()),
            Self::Array(_) | Self::Object(_) if depth == Self::MAX_DEPTH => Value::Null,
            Self::Array(items) => {
                Value::Array(items.iter().map(|i| i.to_value_at(depth + 1)).collect())
            }
            Self::Object(object) => object.to_value_at(depth + 1),
        }
    }
}

/// An arbitrary JSON object.
#[derive(Debug, Clone, Arbitrary)]
pub struct JsonObject(pub Vec<(String, Json)>);

impl JsonObject {
    pub fn to_value(&self) -> Value {
        self.to_value_at(1)
    }

    fn to_value_at(&self, depth: usize) -> Value {
        Value::Object(
            self.0
                .iter()
                .map(|(key, value)| (key.clone(), value.to_value_at(depth)))
                .collect(),
        )
    }
}

/// The `request` auth-param: canonical (what `Base64UrlJson::from_value`
/// emits) or the same JSON in the padded standard alphabet, which the parser
/// also accepts.
#[derive(Debug, Clone, Arbitrary)]
pub enum RequestInput {
    Canonical(JsonObject),
    Padded(JsonObject),
}

impl RequestInput {
    pub fn is_canonical(&self) -> bool {
        matches!(self, Self::Canonical(_))
    }

    pub fn build(&self) -> Base64UrlJson {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        match self {
            Self::Canonical(object) => {
                Base64UrlJson::from_value(&object.to_value()).expect("JSON objects canonicalize")
            }
            Self::Padded(object) => {
                Base64UrlJson::from_raw(STANDARD.encode(object.to_value().to_string()))
            }
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
pub enum ExpiresInput {
    /// Seconds since the Unix epoch, formatted as RFC 3339.
    Timestamp(u32),
    Raw(Text),
}

impl ExpiresInput {
    pub fn build(&self) -> String {
        match self {
            Self::Timestamp(seconds) => time::OffsetDateTime::from_unix_timestamp(*seconds as i64)
                .expect("u32 seconds are in range")
                .format(&time::format_description::well_known::Rfc3339)
                .expect("RFC 3339 formatting cannot fail"),
            Self::Raw(text) => text.0.clone(),
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
pub enum DigestInput {
    /// `sha-256=<base64>`, as mppx emits it.
    Bare([u8; 32]),
    /// `sha-256=:<base64>:`, the RFC 9530 byte sequence.
    ByteSequence([u8; 32]),
    Raw(Text),
}

impl DigestInput {
    pub fn build(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        match self {
            Self::Bare(hash) => format!("sha-256={}", STANDARD.encode(hash)),
            Self::ByteSequence(hash) => format!("sha-256=:{}:", STANDARD.encode(hash)),
            Self::Raw(text) => text.0.clone(),
        }
    }
}

#[derive(Debug, Clone, Arbitrary)]
pub enum OpaqueInput {
    Json(JsonObject),
    Raw(Text),
}

impl OpaqueInput {
    pub fn build(&self) -> Base64UrlJson {
        match self {
            Self::Json(object) => {
                Base64UrlJson::from_value(&object.to_value()).expect("JSON objects canonicalize")
            }
            Self::Raw(text) => Base64UrlJson::from_raw(text.0.clone()),
        }
    }
}

/// The `header` auth-param. The masks flip the case of individual letters,
/// since header names are case-insensitive.
#[derive(Debug, Clone, Arbitrary)]
pub enum HeaderInput {
    Empty,
    Authorization(u32),
    PaymentAuthorization(u32),
    Other(Text),
}

impl HeaderInput {
    pub fn build(&self) -> String {
        match self {
            Self::Empty => String::new(),
            Self::Authorization(mask) => flip_case("Authorization", *mask),
            Self::PaymentAuthorization(mask) => flip_case("Payment-Authorization", *mask),
            Self::Other(text) => text.0.clone(),
        }
    }
}

fn flip_case(name: &str, mask: u32) -> String {
    name.chars()
        .enumerate()
        .map(|(i, c)| match mask >> (i % 32) & 1 {
            1 if c.is_ascii_uppercase() => c.to_ascii_lowercase(),
            1 => c.to_ascii_uppercase(),
            _ => c,
        })
        .collect()
}

/// Every field of a `PaymentChallenge`.
#[derive(Debug, Clone, Arbitrary)]
pub struct ChallengeInput {
    pub id: Text,
    pub realm: Text,
    pub method: Method,
    pub intent: IntentInput,
    pub request: RequestInput,
    pub expires: Option<ExpiresInput>,
    pub description: Option<Text>,
    pub digest: Option<DigestInput>,
    pub opaque: Option<OpaqueInput>,
    pub header: Option<HeaderInput>,
}

impl ChallengeInput {
    /// The challenge with the generated `id`.
    pub fn build(&self) -> PaymentChallenge {
        PaymentChallenge {
            id: self.id.0.clone(),
            realm: self.realm.0.clone(),
            method: MethodName::new(&self.method.0),
            intent: self.intent.build().into(),
            request: self.request.build(),
            expires: self.expires.as_ref().map(ExpiresInput::build),
            description: self.description.as_ref().map(|text| text.0.clone()),
            digest: self.digest.as_ref().map(DigestInput::build),
            opaque: self.opaque.as_ref().map(OpaqueInput::build),
            header: self.header.as_ref().map(HeaderInput::build),
        }
    }

    /// The challenge with an `id` bound to its fields under [`SECRET`].
    pub fn build_signed(&self) -> PaymentChallenge {
        let challenge = self.build();
        PaymentChallenge::with_secret_key_full(
            SECRET,
            challenge.realm,
            challenge.method,
            challenge.intent,
            challenge.request,
            challenge.expires.as_deref(),
            challenge.digest.as_deref(),
            challenge.description.as_deref(),
            challenge.opaque,
            challenge.header.as_deref(),
        )
    }
}

/// Every value `format_www_authenticate` writes as a quoted-string.
pub fn quoted_values(challenge: &PaymentChallenge) -> Vec<&str> {
    let optional = [
        challenge.expires.as_deref(),
        challenge.description.as_deref(),
        challenge.digest.as_deref(),
        challenge.opaque.as_ref().map(Base64UrlJson::raw),
        challenge.header.as_deref(),
    ];
    let mut values = vec![
        challenge.id.as_str(),
        challenge.realm.as_str(),
        challenge.method.as_str(),
        challenge.intent.as_str(),
        challenge.request.raw(),
    ];
    values.extend(optional.into_iter().flatten());
    values
}

/// Whether the `header` field names a credential header the SDK supports.
pub fn has_supported_header(header: Option<&str>) -> bool {
    is_default_credential_header(header) || advertised_credential_header(header).is_some()
}

/// The `header` field as the wire carries it: `Authorization` is the implicit
/// default and is never emitted.
pub fn wire_header(header: Option<&str>) -> Option<String> {
    advertised_credential_header(header)
}

/// Whether the `id` and the fields it binds have the wire form that the
/// formatters and parsers require: a non-empty `id`, an intent name, an
/// RFC 3339 `expires`, a `sha-256=` digest and a base64url `opaque`.
///
/// `method` and `request` are valid in every generated challenge.
pub fn is_well_formed(challenge: &PaymentChallenge) -> bool {
    is_well_formed_echo(&challenge.to_echo())
}

/// [`is_well_formed`] for the challenge a credential echoes.
pub fn is_well_formed_echo(echo: &ChallengeEcho) -> bool {
    let intent = echo.intent.as_str();
    !echo.id.is_empty()
        && !intent.is_empty()
        && intent
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && echo.expires.as_deref().is_none_or(is_rfc3339)
        && echo.digest.as_deref().is_none_or(is_sha256_digest)
        && echo
            .opaque
            .as_ref()
            .is_none_or(|opaque| mpp::base64url_decode(opaque.raw()).is_ok())
}

/// `sha-256=` followed by base64 text, bare or between colons.
fn is_sha256_digest(digest: &str) -> bool {
    let Some(value) = digest.strip_prefix("sha-256=") else {
        return false;
    };
    let value = value
        .strip_prefix(':')
        .and_then(|value| value.strip_suffix(':'))
        .unwrap_or(value);
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/-_=".contains(&b))
}

pub fn is_rfc3339(timestamp: &str) -> bool {
    time::OffsetDateTime::parse(timestamp, &time::format_description::well_known::Rfc3339).is_ok()
}

/// Whether `value` consists only of the bytes `HeaderValue::to_str` accepts:
/// printable ASCII and HTAB.
pub fn is_header_safe(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
}

/// Assert that two values serialize to the same JSON.
///
/// None of the protocol types implement `PartialEq`; their serde form covers
/// every field.
#[track_caller]
pub fn assert_same<T: Serialize>(left: &T, right: &T) {
    let left = serde_json::to_value(left).expect("left value serializes");
    let right = serde_json::to_value(right).expect("right value serializes");
    assert!(json_eq(&left, &right), "\n left: {left}\nright: {right}");
}

/// JSON equality up to number spelling: `1.0` equals `1`, and floats may
/// differ by the last-digit error `serde_json` allows itself when it parses
/// them without the `float_roundtrip` feature.
pub fn json_eq(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(l), Value::Number(r)) if l != r => match (l.as_f64(), r.as_f64()) {
            (Some(l), Some(r)) => (l - r).abs() <= l.abs().max(r.abs()) * 4.0 * f64::EPSILON,
            _ => false,
        },
        (Value::Array(l), Value::Array(r)) => {
            l.len() == r.len() && l.iter().zip(r).all(|(l, r)| json_eq(l, r))
        }
        (Value::Object(l), Value::Object(r)) => {
            l.len() == r.len()
                && l.iter()
                    .all(|(key, l)| r.get(key).is_some_and(|r| json_eq(l, r)))
        }
        _ => left == right,
    }
}
