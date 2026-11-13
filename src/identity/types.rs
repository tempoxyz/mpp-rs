//! Identity outcomes and requirements.

use std::fmt;

use http_types::{HeaderMap, HeaderName, HeaderValue, StatusCode};

/// The fixed status of a rejected identity outcome, as mppx's `RejectionStatus`.
///
/// Each maps to one HTTP status code ([`code`](Self::code)), and the highest
/// in [`status::PRECEDENCE`](super::status::PRECEDENCE) decides when several
/// verifiers reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectionStatus {
    /// No proof was presented (401).
    Missing,
    /// A proof was presented but did not verify (401).
    Invalid,
    /// The proof verified, but the identity is not allowed (403).
    Forbidden,
    /// The proof could not be checked right now, such as an issuer outage (503).
    Unavailable,
}

impl RejectionStatus {
    /// The HTTP status code a rejection with this status is sent with.
    pub fn code(self) -> StatusCode {
        match self {
            Self::Missing | Self::Invalid => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// The status as mppx names it: `missing`, `invalid`, `forbidden` or `unavailable`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Invalid => "invalid",
            Self::Forbidden => "forbidden",
            Self::Unavailable => "unavailable",
        }
    }

    /// The reason sent when an outcome gives none, as mppx's.
    pub fn default_reason(self) -> &'static str {
        match self {
            Self::Missing => "Identity verification is required.",
            Self::Invalid => "The identity proof is invalid.",
            Self::Forbidden => "This identity is not allowed.",
            Self::Unavailable => "Identity verification is unavailable.",
        }
    }

    /// Index in [`status::PRECEDENCE`](super::status::PRECEDENCE): lower wins.
    pub(crate) fn rank(self) -> usize {
        super::status::PRECEDENCE
            .iter()
            .position(|status| *status == self)
            .unwrap_or(usize::MAX)
    }
}

impl fmt::Display for RejectionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A rejected identity outcome: its fixed status, a human-readable reason
/// (also the rejection response's body) and headers returned to the client,
/// such as a protocol challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// Fixed status of the rejection.
    pub status: RejectionStatus,
    /// Human-readable reason.
    pub reason: String,
    /// Headers returned to the client.
    pub headers: HeaderMap,
}

impl Rejection {
    /// A rejection with `status` and its default reason.
    pub fn new(status: RejectionStatus) -> Self {
        Self {
            status,
            reason: status.default_reason().to_owned(),
            headers: HeaderMap::new(),
        }
    }

    /// No proof was presented (401).
    pub fn missing() -> Self {
        Self::new(RejectionStatus::Missing)
    }

    /// A proof was presented but did not verify (401).
    pub fn invalid(reason: impl Into<String>) -> Self {
        Self::new(RejectionStatus::Invalid).with_reason(reason)
    }

    /// The proof verified, but the identity is not allowed (403).
    pub fn forbidden(reason: impl Into<String>) -> Self {
        Self::new(RejectionStatus::Forbidden).with_reason(reason)
    }

    /// The proof could not be checked right now (503).
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::new(RejectionStatus::Unavailable).with_reason(reason)
    }

    /// Replaces the reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// Appends a header returned to the client.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.append(name, value);
        self
    }

    /// Appends headers returned to the client.
    pub fn with_headers(mut self, headers: &HeaderMap) -> Self {
        for (name, value) in headers {
            self.headers.append(name.clone(), value.clone());
        }
        self
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "identity {}: {}", self.status, self.reason)
    }
}

impl std::error::Error for Rejection {}

/// The outcome of one identity verifier or payment check, as mppx's `Verification`.
///
/// `Valid` carries the verified value. A rejection rejects the request with
/// its fixed HTTP status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification<T> {
    /// The identity verified.
    Valid(T),
    /// The identity was rejected.
    Rejected(Rejection),
}

impl<T> Verification<T> {
    /// Maps the verified value.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Verification<U> {
        match self {
            Self::Valid(value) => Verification::Valid(f(value)),
            Self::Rejected(rejection) => Verification::Rejected(rejection),
        }
    }

    /// Whether the identity verified.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }
}

impl<T> From<Rejection> for Verification<T> {
    fn from(rejection: Rejection) -> Self {
        Self::Rejected(rejection)
    }
}

/// One identity a payment check requires, sent in the 402's
/// `Identity-Required` header as a structured-field list item: the type token
/// with an `issuer` string parameter when set.
///
/// mppx names the type `type`, a Rust keyword, so it is `kind` here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Requirement {
    /// Identity type, a structured-field token such as `tempo-id`.
    pub kind: String,
    /// Issuer the identity must come from, such as `https://id.tempo.xyz`.
    pub issuer: Option<String>,
}

impl Requirement {
    /// A requirement for an identity of `kind`, from any issuer.
    pub fn new(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            issuer: None,
        }
    }

    /// Requires the identity to come from `issuer`.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }
}
