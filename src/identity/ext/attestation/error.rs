//! Identity errors.

/// Error of an identity prover, verifier or issuer request.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentityError {
    /// A prover, verifier or resolver was configured with an invalid value.
    #[error("invalid identity configuration: {0}")]
    InvalidConfig(String),

    /// An attestation could not be decoded.
    #[error("Identity attestation is malformed.")]
    MalformedAttestation,

    /// An email OTP issuer rejected a request or answered with a malformed body.
    #[error("{message}")]
    EmailOtp {
        /// What went wrong, from the issuer's `error` field when it sent one.
        message: String,
        /// HTTP status the issuer answered with, if any.
        status: Option<u16>,
    },

    /// An issuer or attestation-bearing request could not be sent.
    #[error("identity request failed")]
    Request(#[source] reqwest::Error),

    /// An attestation could not be acquired for another reason.
    #[error("{0}")]
    Acquire(String),
}

impl IdentityError {
    pub(crate) fn email_otp(message: impl Into<String>, status: Option<u16>) -> Self {
        Self::EmailOtp {
            message: message.into(),
            status,
        }
    }
}
