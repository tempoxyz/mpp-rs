//! HTTP-specific error types.

use crate::error::MppError;
use std::fmt;

/// Error type for HTTP payment operations.
#[derive(Debug)]
pub enum HttpError {
    /// Missing WWW-Authenticate header on 402 response
    MissingChallenge,

    /// No challenge in the 402 response matches the provider's supported methods
    NoSupportedChallenge(String),

    /// Failed to parse challenge from WWW-Authenticate header
    InvalidChallenge(String),

    /// Failed to format credential for Authorization header
    InvalidCredential(String),

    /// Request could not be cloned (required for retry)
    CloneFailed,

    /// Payment provider error
    Payment(MppError),

    /// HTTP request error
    #[cfg(feature = "client")]
    Request(reqwest::Error),
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingChallenge => {
                write!(f, "402 response missing WWW-Authenticate header")
            }
            Self::NoSupportedChallenge(msg) => {
                write!(f, "no supported challenge: {}", msg)
            }
            Self::InvalidChallenge(msg) => write!(f, "invalid challenge: {}", msg),
            Self::InvalidCredential(msg) => write!(f, "invalid credential: {}", msg),
            Self::CloneFailed => write!(f, "request could not be cloned for retry"),
            Self::Payment(e) => write!(f, "payment failed: {}", e),
            #[cfg(feature = "client")]
            Self::Request(e) => write!(f, "HTTP request failed: {}", e),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Payment(e) => Some(e),
            #[cfg(feature = "client")]
            Self::Request(e) => Some(e),
            _ => None,
        }
    }
}

impl From<MppError> for HttpError {
    fn from(e: MppError) -> Self {
        Self::Payment(e)
    }
}

#[cfg(feature = "client")]
impl From<reqwest::Error> for HttpError {
    fn from(e: reqwest::Error) -> Self {
        Self::Request(e)
    }
}
