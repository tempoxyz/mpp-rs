//! Error types for the mpp library.
//!
//! This module provides:
//! - [`MppError`]: The main error enum for all mpp operations
//! - [`PaymentErrorDetails`]: RFC 9457 Problem Details format for HTTP error responses
//! - [`PaymentError`]: Trait for converting errors to Problem Details

use thiserror::Error;

/// Result type alias for mpp operations.
pub type Result<T> = std::result::Result<T, MppError>;

// ==================== RFC 9457 Problem Details ====================

/// Base URI for payment-related problem types.
pub const PROBLEM_TYPE_BASE: &str = "https://paymentauth.org/problems";

/// RFC 9457 Problem Details structure for payment errors.
///
/// This struct provides a standardized format for HTTP error responses,
/// following [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html).
///
/// # Example
///
/// ```
/// use mpay::error::PaymentErrorDetails;
///
/// let problem = PaymentErrorDetails::new("verification-failed")
///     .with_title("VerificationFailedError")
///     .with_status(402)
///     .with_detail("Payment verification failed: insufficient amount.");
///
/// // Serialize to JSON for HTTP response body
/// let json = serde_json::to_string(&problem).unwrap();
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PaymentErrorDetails {
    /// A URI reference that identifies the problem type.
    #[serde(rename = "type")]
    pub problem_type: String,

    /// A short, human-readable summary of the problem type.
    pub title: String,

    /// The HTTP status code for this problem.
    pub status: u16,

    /// A human-readable explanation specific to this occurrence.
    pub detail: String,

    /// The challenge ID associated with this error, if applicable.
    #[serde(rename = "challengeId", skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
}

impl PaymentErrorDetails {
    /// Create a new PaymentErrorDetails with the given problem type suffix.
    ///
    /// The full type URI will be constructed as `{PROBLEM_TYPE_BASE}/{suffix}`.
    pub fn new(type_suffix: impl Into<String>) -> Self {
        let suffix = type_suffix.into();
        Self {
            problem_type: format!("{}/{}", PROBLEM_TYPE_BASE, suffix),
            title: String::new(),
            status: 402,
            detail: String::new(),
            challenge_id: None,
        }
    }

    /// Set the title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Set the HTTP status code.
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// Set the detail message.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Set the associated challenge ID.
    pub fn with_challenge_id(mut self, id: impl Into<String>) -> Self {
        self.challenge_id = Some(id.into());
        self
    }
}

/// Trait for errors that can be converted to RFC 9457 Problem Details.
///
/// Implement this trait to enable automatic conversion of payment errors
/// to standardized HTTP error responses.
///
/// # Example
///
/// ```
/// use mpay::error::{PaymentError, PaymentErrorDetails};
///
/// struct MyError {
///     reason: String,
/// }
///
/// impl PaymentError for MyError {
///     fn to_problem_details(&self, challenge_id: Option<&str>) -> PaymentErrorDetails {
///         PaymentErrorDetails::new("my-error")
///             .with_title("MyError")
///             .with_status(402)
///             .with_detail(&self.reason)
///     }
/// }
/// ```
pub trait PaymentError {
    /// Convert this error to RFC 9457 Problem Details format.
    ///
    /// # Arguments
    ///
    /// * `challenge_id` - Optional challenge ID to include in the response
    fn to_problem_details(&self, challenge_id: Option<&str>) -> PaymentErrorDetails;
}

#[derive(Error, Debug)]
pub enum MppError {
    /// Required amount exceeds user's maximum allowed
    #[error("Required amount ({required}) exceeds maximum allowed ({max})")]
    AmountExceedsMax { required: u128, max: u128 },

    /// Invalid amount format
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Configuration is invalid
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    // ==================== HTTP Errors ====================
    /// HTTP request/response error
    #[error("HTTP error: {0}")]
    Http(String),

    /// Chain ID mismatch between challenge and provider
    #[error("Chain ID mismatch: challenge requires {expected}, provider connected to {got}")]
    ChainIdMismatch { expected: u64, got: u64 },

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Hex decoding error
    #[cfg(feature = "utils")]
    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Base64 decoding error
    #[cfg(feature = "utils")]
    #[error("Base64 decoding error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    // ==================== Web Payment Auth Errors ====================
    /// Unsupported payment method
    #[error("Unsupported payment method: {0}")]
    UnsupportedPaymentMethod(String),

    /// Missing required header
    #[error("Missing required header: {0}")]
    MissingHeader(String),

    /// Invalid base64url encoding
    #[error("Invalid base64url: {0}")]
    InvalidBase64Url(String),

    // ==================== RFC 9457 Payment Problems ====================
    // These variants can be converted to RFC 9457 Problem Details format.
    /// Credential is malformed (invalid base64url, bad JSON structure).
    #[error("{}", format_malformed_credential(.0))]
    MalformedCredential(Option<String>),

    /// Challenge ID is unknown, expired, or already used.
    #[error("{}", format_invalid_challenge(.id, .reason))]
    InvalidChallenge {
        id: Option<String>,
        reason: Option<String>,
    },

    /// Payment proof is invalid or verification failed.
    #[error("{}", format_verification_failed(.0))]
    VerificationFailed(Option<String>),

    /// Payment has expired.
    #[error("{}", format_payment_expired(.0))]
    PaymentExpired(Option<String>),

    /// No credential was provided but payment is required.
    #[error("{}", format_payment_required(.realm, .description))]
    PaymentRequired {
        realm: Option<String>,
        description: Option<String>,
    },

    /// Credential payload does not match the expected schema.
    #[error("{}", format_invalid_payload(.0))]
    InvalidPayload(Option<String>),

    // ==================== External Library Errors ====================
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid UTF-8 in response
    #[error("Invalid UTF-8 in response body")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    /// System time error
    #[error("System time error: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
}

// ==================== RFC 9457 Format Helpers ====================

fn format_malformed_credential(reason: &Option<String>) -> String {
    match reason {
        Some(r) => format!("Credential is malformed: {}.", r),
        None => "Credential is malformed.".to_string(),
    }
}

fn format_invalid_challenge(id: &Option<String>, reason: &Option<String>) -> String {
    let id_part = id
        .as_ref()
        .map(|id| format!(" \"{}\"", id))
        .unwrap_or_default();
    let reason_part = reason
        .as_ref()
        .map(|r| format!(": {}", r))
        .unwrap_or_default();
    format!("Challenge{} is invalid{}.", id_part, reason_part)
}

fn format_verification_failed(reason: &Option<String>) -> String {
    match reason {
        Some(r) => format!("Payment verification failed: {}.", r),
        None => "Payment verification failed.".to_string(),
    }
}

fn format_payment_expired(expires: &Option<String>) -> String {
    match expires {
        Some(e) => format!("Payment expired at {}.", e),
        None => "Payment has expired.".to_string(),
    }
}

fn format_payment_required(realm: &Option<String>, description: &Option<String>) -> String {
    let mut s = "Payment is required".to_string();
    if let Some(r) = realm {
        s.push_str(&format!(" for \"{}\"", r));
    }
    if let Some(d) = description {
        s.push_str(&format!(" ({})", d));
    }
    s.push('.');
    s
}

fn format_invalid_payload(reason: &Option<String>) -> String {
    match reason {
        Some(r) => format!("Credential payload is invalid: {}.", r),
        None => "Credential payload is invalid.".to_string(),
    }
}

impl MppError {
    /// Create an unsupported payment method error
    pub fn unsupported_method(method: &impl std::fmt::Display) -> Self {
        Self::UnsupportedPaymentMethod(format!("Payment method '{}' is not supported", method))
    }

    // ==================== RFC 9457 Payment Problem Constructors ====================

    /// Create a malformed credential error.
    pub fn malformed_credential(reason: impl Into<String>) -> Self {
        Self::MalformedCredential(Some(reason.into()))
    }

    /// Create a malformed credential error without a reason.
    pub fn malformed_credential_default() -> Self {
        Self::MalformedCredential(None)
    }

    /// Create an invalid challenge error with ID.
    pub fn invalid_challenge_id(id: impl Into<String>) -> Self {
        Self::InvalidChallenge {
            id: Some(id.into()),
            reason: None,
        }
    }

    /// Create an invalid challenge error with reason.
    pub fn invalid_challenge_reason(reason: impl Into<String>) -> Self {
        Self::InvalidChallenge {
            id: None,
            reason: Some(reason.into()),
        }
    }

    /// Create an invalid challenge error with ID and reason.
    pub fn invalid_challenge(id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidChallenge {
            id: Some(id.into()),
            reason: Some(reason.into()),
        }
    }

    /// Create an invalid challenge error without details.
    pub fn invalid_challenge_default() -> Self {
        Self::InvalidChallenge {
            id: None,
            reason: None,
        }
    }

    /// Create a verification failed error.
    pub fn verification_failed(reason: impl Into<String>) -> Self {
        Self::VerificationFailed(Some(reason.into()))
    }

    /// Create a verification failed error without a reason.
    pub fn verification_failed_default() -> Self {
        Self::VerificationFailed(None)
    }

    /// Create a payment expired error with expiration timestamp.
    pub fn payment_expired(expires: impl Into<String>) -> Self {
        Self::PaymentExpired(Some(expires.into()))
    }

    /// Create a payment expired error without timestamp.
    pub fn payment_expired_default() -> Self {
        Self::PaymentExpired(None)
    }

    /// Create a payment required error with realm.
    pub fn payment_required_realm(realm: impl Into<String>) -> Self {
        Self::PaymentRequired {
            realm: Some(realm.into()),
            description: None,
        }
    }

    /// Create a payment required error with description.
    pub fn payment_required_description(description: impl Into<String>) -> Self {
        Self::PaymentRequired {
            realm: None,
            description: Some(description.into()),
        }
    }

    /// Create a payment required error with realm and description.
    pub fn payment_required(realm: impl Into<String>, description: impl Into<String>) -> Self {
        Self::PaymentRequired {
            realm: Some(realm.into()),
            description: Some(description.into()),
        }
    }

    /// Create a payment required error without details.
    pub fn payment_required_default() -> Self {
        Self::PaymentRequired {
            realm: None,
            description: None,
        }
    }

    /// Create an invalid payload error.
    pub fn invalid_payload(reason: impl Into<String>) -> Self {
        Self::InvalidPayload(Some(reason.into()))
    }

    /// Create an invalid payload error without a reason.
    pub fn invalid_payload_default() -> Self {
        Self::InvalidPayload(None)
    }

    /// Returns the RFC 9457 problem type suffix if this is a payment problem.
    pub fn problem_type_suffix(&self) -> Option<&'static str> {
        match self {
            Self::MalformedCredential(_) => Some("malformed-credential"),
            Self::InvalidChallenge { .. } => Some("invalid-challenge"),
            Self::VerificationFailed(_) => Some("verification-failed"),
            Self::PaymentExpired(_) => Some("payment-expired"),
            Self::PaymentRequired { .. } => Some("payment-required"),
            Self::InvalidPayload(_) => Some("invalid-payload"),
            _ => None,
        }
    }

    /// Returns true if this error is an RFC 9457 payment problem.
    pub fn is_payment_problem(&self) -> bool {
        self.problem_type_suffix().is_some()
    }
}

impl PaymentError for MppError {
    fn to_problem_details(&self, challenge_id: Option<&str>) -> PaymentErrorDetails {
        let (suffix, title) = match self {
            Self::MalformedCredential(_) => ("malformed-credential", "MalformedCredentialError"),
            Self::InvalidChallenge { .. } => ("invalid-challenge", "InvalidChallengeError"),
            Self::VerificationFailed(_) => ("verification-failed", "VerificationFailedError"),
            Self::PaymentExpired(_) => ("payment-expired", "PaymentExpiredError"),
            Self::PaymentRequired { .. } => ("payment-required", "PaymentRequiredError"),
            Self::InvalidPayload(_) => ("invalid-payload", "InvalidPayloadError"),
            // Non-payment-problem errors get a generic problem type
            _ => ("internal-error", "InternalError"),
        };

        let mut problem = PaymentErrorDetails::new(suffix)
            .with_title(title)
            .with_status(402)
            .with_detail(self.to_string());

        // Use embedded challenge ID from InvalidChallenge, or the provided one
        let embedded_id = match self {
            Self::InvalidChallenge { id, .. } => id.as_deref(),
            _ => None,
        };
        if let Some(id) = challenge_id.or(embedded_id) {
            problem = problem.with_challenge_id(id);
        }
        problem
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amount_exceeds_max_display() {
        let err = MppError::AmountExceedsMax {
            required: 1000,
            max: 500,
        };
        let display = err.to_string();
        assert!(display.contains("Required amount (1000) exceeds maximum allowed (500)"));
    }

    #[test]
    fn test_invalid_amount_display() {
        let err = MppError::InvalidAmount("not a number".to_string());
        assert_eq!(err.to_string(), "Invalid amount: not a number");
    }

    #[test]
    fn test_invalid_config_display() {
        let err = MppError::InvalidConfig("invalid rpc url".to_string());
        assert_eq!(err.to_string(), "Invalid configuration: invalid rpc url");
    }

    #[test]
    fn test_http_display() {
        let err = MppError::Http("404 Not Found".to_string());
        assert_eq!(err.to_string(), "HTTP error: 404 Not Found");
    }

    #[test]
    fn test_unsupported_payment_method_display() {
        let err = MppError::UnsupportedPaymentMethod("bitcoin".to_string());
        assert_eq!(err.to_string(), "Unsupported payment method: bitcoin");
    }

    #[test]
    fn test_invalid_challenge_display() {
        let err = MppError::invalid_challenge_reason("Malformed challenge");
        assert_eq!(
            err.to_string(),
            "Challenge is invalid: Malformed challenge."
        );
    }

    #[test]
    fn test_missing_header_display() {
        let err = MppError::MissingHeader("WWW-Authenticate".to_string());
        assert_eq!(err.to_string(), "Missing required header: WWW-Authenticate");
    }

    #[test]
    fn test_invalid_base64_url_display() {
        let err = MppError::InvalidBase64Url("Invalid padding".to_string());
        assert_eq!(err.to_string(), "Invalid base64url: Invalid padding");
    }

    #[test]
    fn test_challenge_expired_display() {
        let err = MppError::payment_expired("2025-01-15T12:00:00Z");
        assert_eq!(err.to_string(), "Payment expired at 2025-01-15T12:00:00Z.");
    }

    #[test]
    fn test_unsupported_method_constructor() {
        let err = MppError::unsupported_method(&"bitcoin");
        assert!(matches!(err, MppError::UnsupportedPaymentMethod(_)));
        assert!(err.to_string().contains("bitcoin"));
        assert!(err.to_string().contains("not supported"));
    }

    // ==================== RFC 9457 Problem Details Tests ====================

    #[test]
    fn test_problem_details_new() {
        let problem = PaymentErrorDetails::new("test-error")
            .with_title("TestError")
            .with_status(400)
            .with_detail("Something went wrong");

        assert_eq!(
            problem.problem_type,
            "https://paymentauth.org/problems/test-error"
        );
        assert_eq!(problem.title, "TestError");
        assert_eq!(problem.status, 400);
        assert_eq!(problem.detail, "Something went wrong");
        assert!(problem.challenge_id.is_none());
    }

    #[test]
    fn test_problem_details_with_challenge_id() {
        let problem = PaymentErrorDetails::new("test-error")
            .with_title("TestError")
            .with_challenge_id("abc123");

        assert_eq!(problem.challenge_id, Some("abc123".to_string()));
    }

    #[test]
    fn test_problem_details_serialize() {
        let problem = PaymentErrorDetails::new("verification-failed")
            .with_title("VerificationFailedError")
            .with_status(402)
            .with_detail("Payment verification failed.")
            .with_challenge_id("abc123");

        let json = serde_json::to_string(&problem).unwrap();
        assert!(json.contains("\"type\":"));
        assert!(json.contains("verification-failed"));
        assert!(json.contains("\"challengeId\":\"abc123\""));
    }

    #[test]
    fn test_malformed_credential_error() {
        let err = MppError::malformed_credential_default();
        assert_eq!(err.to_string(), "Credential is malformed.");

        let err = MppError::malformed_credential("invalid base64url");
        assert_eq!(
            err.to_string(),
            "Credential is malformed: invalid base64url."
        );

        let problem = err.to_problem_details(Some("test-id"));
        assert!(problem.problem_type.contains("malformed-credential"));
        assert_eq!(problem.title, "MalformedCredentialError");
        assert_eq!(problem.challenge_id, Some("test-id".to_string()));
    }

    #[test]
    fn test_invalid_challenge_error() {
        let err = MppError::invalid_challenge_default();
        assert_eq!(err.to_string(), "Challenge is invalid.");

        let err = MppError::invalid_challenge_id("abc123");
        assert_eq!(err.to_string(), "Challenge \"abc123\" is invalid.");

        let err = MppError::invalid_challenge_reason("expired");
        assert_eq!(err.to_string(), "Challenge is invalid: expired.");

        let err = MppError::invalid_challenge("abc123", "already used");
        assert_eq!(
            err.to_string(),
            "Challenge \"abc123\" is invalid: already used."
        );

        let problem = err.to_problem_details(None);
        assert!(problem.problem_type.contains("invalid-challenge"));
        assert_eq!(problem.challenge_id, Some("abc123".to_string()));
    }

    #[test]
    fn test_verification_failed_error() {
        let err = MppError::verification_failed_default();
        assert_eq!(err.to_string(), "Payment verification failed.");

        let err = MppError::verification_failed("insufficient amount");
        assert_eq!(
            err.to_string(),
            "Payment verification failed: insufficient amount."
        );

        let problem = err.to_problem_details(None);
        assert!(problem.problem_type.contains("verification-failed"));
        assert_eq!(problem.title, "VerificationFailedError");
    }

    #[test]
    fn test_payment_expired_error() {
        let err = MppError::payment_expired_default();
        assert_eq!(err.to_string(), "Payment has expired.");

        let err = MppError::payment_expired("2025-01-15T12:00:00Z");
        assert_eq!(err.to_string(), "Payment expired at 2025-01-15T12:00:00Z.");

        let problem = err.to_problem_details(None);
        assert!(problem.problem_type.contains("payment-expired"));
    }

    #[test]
    fn test_payment_required_error() {
        let err = MppError::payment_required_default();
        assert_eq!(err.to_string(), "Payment is required.");

        let err = MppError::payment_required_realm("api.example.com");
        assert_eq!(
            err.to_string(),
            "Payment is required for \"api.example.com\"."
        );

        let err = MppError::payment_required_description("Premium content access");
        assert_eq!(
            err.to_string(),
            "Payment is required (Premium content access)."
        );

        let err = MppError::payment_required("api.example.com", "Premium access");
        assert_eq!(
            err.to_string(),
            "Payment is required for \"api.example.com\" (Premium access)."
        );

        let problem = err.to_problem_details(Some("chal-id"));
        assert!(problem.problem_type.contains("payment-required"));
        assert_eq!(problem.challenge_id, Some("chal-id".to_string()));
    }

    #[test]
    fn test_invalid_payload_error() {
        let err = MppError::invalid_payload_default();
        assert_eq!(err.to_string(), "Credential payload is invalid.");

        let err = MppError::invalid_payload("missing signature field");
        assert_eq!(
            err.to_string(),
            "Credential payload is invalid: missing signature field."
        );

        let problem = err.to_problem_details(None);
        assert!(problem.problem_type.contains("invalid-payload"));
        assert_eq!(problem.title, "InvalidPayloadError");
    }
}
