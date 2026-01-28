//! Error types for the mpp library.
//!
//! This module provides:
//! - [`MppError`]: The main error enum for all mpp operations
//! - [`PaymentErrorDetails`]: RFC 9457 Problem Details format for HTTP error responses
//! - [`PaymentError`]: Trait for converting errors to Problem Details

use std::error::Error as StdError;
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

/// Context for signing errors
#[derive(Debug, Clone)]
pub struct SigningContext {
    pub network: Option<String>,
    pub address: Option<String>,
    pub operation: &'static str,
}

impl Default for SigningContext {
    fn default() -> Self {
        Self {
            network: None,
            address: None,
            operation: "sign",
        }
    }
}

impl std::fmt::Display for SigningContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "operation: {}", self.operation)?;
        if let Some(ref network) = self.network {
            write!(f, ", network: {}", network)?;
        }
        if let Some(ref address) = self.address {
            write!(f, ", address: {}", address)?;
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum MppError {
    #[error("Payment provider not found for network: {0}")]
    ProviderNotFound(String),

    /// No payment methods are configured
    #[error("No payment methods configured")]
    NoPaymentMethods,

    /// No compatible payment method for the server's requirements
    #[error("No compatible payment method found. Available networks: {networks:?}")]
    NoCompatibleMethod { networks: Vec<String> },

    /// Required amount exceeds user's maximum allowed
    #[error("Required amount ({required}) exceeds maximum allowed ({max})")]
    AmountExceedsMax { required: u128, max: u128 },

    /// Invalid amount format
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Missing required field
    #[error("Missing payment requirement: {0}")]
    MissingRequirement(String),

    /// Configuration file or value is missing
    #[error("Configuration missing: {0}")]
    ConfigMissing(String),

    /// Configuration is invalid
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Invalid private key format
    #[error("Invalid private key: {0}")]
    InvalidKey(String),

    /// Failed to determine config directory
    #[error("Failed to determine config directory")]
    NoConfigDir,

    /// Unknown network identifier
    #[error("Unknown network: {0}")]
    UnknownNetwork(String),

    /// Token not configured for network
    #[error("Token configuration not found for asset {asset} on network {network}")]
    TokenConfigNotFound { asset: String, network: String },

    /// Unsupported token type
    #[error("Unsupported token: {0}")]
    UnsupportedToken(String),

    /// Balance query failed
    #[error("Balance query failed: {0}")]
    BalanceQuery(String),

    // ==================== HTTP Errors ====================
    /// HTTP request/response error
    #[error("HTTP error: {0}")]
    Http(String),

    /// Chain ID mismatch between challenge and provider
    #[error("Chain ID mismatch: challenge requires {expected}, provider connected to {got}")]
    ChainIdMismatch { expected: u64, got: u64 },

    /// Transaction was confirmed but reverted
    #[error("Transaction reverted: {0}")]
    TransactionReverted(String),

    /// Failed to format credential for Authorization header
    #[error("Failed to format credential: {0}")]
    CredentialFormat(String),

    /// Unsupported HTTP method
    #[error("Unsupported HTTP method: {0}")]
    UnsupportedHttpMethod(String),

    /// Signing error with context and source chain
    #[error("signing failed ({context})")]
    Signing {
        #[source]
        source: Box<dyn StdError + Send + Sync>,
        context: SigningContext,
    },

    /// Address parsing error
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

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

    /// Unsupported payment intent
    #[error("Unsupported payment intent: {0}")]
    UnsupportedPaymentIntent(String),

    /// Missing required header
    #[error("Missing required header: {0}")]
    MissingHeader(String),

    /// Invalid base64url encoding
    #[error("Invalid base64url: {0}")]
    InvalidBase64Url(String),

    /// Invalid DID format
    #[error("Invalid DID: {0}")]
    InvalidDid(String),

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
    /// Create a signing error with context and source chain
    pub fn signing_with_context(
        source: impl StdError + Send + Sync + 'static,
        context: SigningContext,
    ) -> Self {
        Self::Signing {
            source: Box::new(source),
            context,
        }
    }

    /// Add network context to an existing error
    pub fn with_network(self, network: impl Into<String>) -> Self {
        match self {
            Self::Signing {
                source,
                mut context,
            } => {
                context.network = Some(network.into());
                Self::Signing { source, context }
            }
            other => other,
        }
    }

    /// Create an invalid address error
    pub fn invalid_address(msg: impl Into<String>) -> Self {
        Self::InvalidAddress(msg.into())
    }

    /// Create a config missing error
    pub fn config_missing(msg: impl Into<String>) -> Self {
        Self::ConfigMissing(msg.into())
    }

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

/// Extension trait for adding context to Results
pub trait ResultExt<T> {
    /// Add signing context to an error
    fn with_signing_context(self, context: SigningContext) -> Result<T>;

    /// Add network context to an error
    fn with_network(self, network: &str) -> Result<T>;
}

impl<T, E: StdError + Send + Sync + 'static> ResultExt<T> for std::result::Result<T, E> {
    fn with_signing_context(self, context: SigningContext) -> Result<T> {
        self.map_err(|e| MppError::signing_with_context(e, context))
    }

    fn with_network(self, network: &str) -> Result<T> {
        self.map_err(|e| {
            MppError::signing_with_context(
                e,
                SigningContext {
                    network: Some(network.to_string()),
                    address: None,
                    operation: "sign",
                },
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_compatible_method_display() {
        let err = MppError::NoCompatibleMethod {
            networks: vec!["ethereum".to_string(), "tempo".to_string()],
        };
        let display = err.to_string();
        assert!(display.contains("No compatible payment method"));
        assert!(display.contains("ethereum"));
        assert!(display.contains("tempo"));
    }

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
    fn test_missing_requirement_display() {
        let err = MppError::MissingRequirement("network".to_string());
        assert_eq!(err.to_string(), "Missing payment requirement: network");
    }

    #[test]
    fn test_config_missing_display() {
        let err = MppError::ConfigMissing("wallet not configured".to_string());
        assert_eq!(
            err.to_string(),
            "Configuration missing: wallet not configured"
        );
    }

    #[test]
    fn test_invalid_config_display() {
        let err = MppError::InvalidConfig("invalid rpc url".to_string());
        assert_eq!(err.to_string(), "Invalid configuration: invalid rpc url");
    }

    #[test]
    fn test_invalid_key_display() {
        let err = MppError::InvalidKey("wrong format".to_string());
        assert_eq!(err.to_string(), "Invalid private key: wrong format");
    }

    #[test]
    fn test_no_config_dir_display() {
        let err = MppError::NoConfigDir;
        assert_eq!(err.to_string(), "Failed to determine config directory");
    }

    #[test]
    fn test_unknown_network_display() {
        let err = MppError::UnknownNetwork("custom-chain".to_string());
        assert_eq!(err.to_string(), "Unknown network: custom-chain");
    }

    #[test]
    fn test_token_config_not_found_display() {
        let err = MppError::TokenConfigNotFound {
            asset: "USDC".to_string(),
            network: "ethereum".to_string(),
        };
        let display = err.to_string();
        assert!(
            display.contains("Token configuration not found for asset USDC on network ethereum")
        );
    }

    #[test]
    fn test_unsupported_token_display() {
        let err = MppError::UnsupportedToken("UNKNOWN".to_string());
        assert_eq!(err.to_string(), "Unsupported token: UNKNOWN");
    }

    #[test]
    fn test_balance_query_display() {
        let err = MppError::BalanceQuery("RPC timeout".to_string());
        assert_eq!(err.to_string(), "Balance query failed: RPC timeout");
    }

    #[test]
    fn test_http_display() {
        let err = MppError::Http("404 Not Found".to_string());
        assert_eq!(err.to_string(), "HTTP error: 404 Not Found");
    }

    #[test]
    fn test_unsupported_http_method_display() {
        let err = MppError::UnsupportedHttpMethod("TRACE".to_string());
        assert_eq!(err.to_string(), "Unsupported HTTP method: TRACE");
    }

    #[test]
    fn test_invalid_address_display() {
        let err = MppError::InvalidAddress("Not a valid address".to_string());
        assert_eq!(err.to_string(), "Invalid address: Not a valid address");
    }

    #[test]
    fn test_unsupported_payment_method_display() {
        let err = MppError::UnsupportedPaymentMethod("bitcoin".to_string());
        assert_eq!(err.to_string(), "Unsupported payment method: bitcoin");
    }

    #[test]
    fn test_unsupported_payment_intent_display() {
        let err = MppError::UnsupportedPaymentIntent("subscription".to_string());
        assert_eq!(err.to_string(), "Unsupported payment intent: subscription");
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
    fn test_invalid_did_display() {
        let err = MppError::InvalidDid("Not a valid DID".to_string());
        assert_eq!(err.to_string(), "Invalid DID: Not a valid DID");
    }

    #[test]
    fn test_signing_with_context() {
        use std::io::{Error as IoError, ErrorKind};
        let source = IoError::new(ErrorKind::Other, "underlying error");
        let ctx = SigningContext {
            network: Some("tempo".to_string()),
            address: Some("0x123".to_string()),
            operation: "sign_transaction",
        };
        let err = MppError::signing_with_context(source, ctx);
        let display = err.to_string();
        assert!(display.contains("signing failed"));
        assert!(display.contains("sign_transaction"));
        assert!(display.contains("tempo"));
        assert!(display.contains("0x123"));
    }

    #[test]
    fn test_signing_context_display() {
        let ctx = SigningContext {
            network: Some("ethereum".to_string()),
            address: Some("0xabc".to_string()),
            operation: "get_nonce",
        };
        let display = ctx.to_string();
        assert!(display.contains("operation: get_nonce"));
        assert!(display.contains("network: ethereum"));
        assert!(display.contains("address: 0xabc"));
    }

    #[test]
    fn test_signing_context_default() {
        let ctx = SigningContext::default();
        assert_eq!(ctx.operation, "sign");
        assert!(ctx.network.is_none());
        assert!(ctx.address.is_none());
    }

    #[test]
    fn test_result_ext_with_signing_context() {
        use std::io::{Error as IoError, ErrorKind};
        let result: std::result::Result<(), IoError> = Err(IoError::new(ErrorKind::Other, "test"));
        let ctx = SigningContext {
            network: Some("tempo".to_string()),
            address: None,
            operation: "test_op",
        };
        let mpp_result = result.with_signing_context(ctx);
        assert!(mpp_result.is_err());
        let err = mpp_result.unwrap_err();
        assert!(err.to_string().contains("signing failed"));
    }

    #[test]
    fn test_result_ext_with_network() {
        use std::io::{Error as IoError, ErrorKind};
        let result: std::result::Result<(), IoError> = Err(IoError::new(ErrorKind::Other, "test"));
        let mpp_result = result.with_network("base-sepolia");
        assert!(mpp_result.is_err());
        let err = mpp_result.unwrap_err();
        assert!(err.to_string().contains("base-sepolia"));
    }

    #[test]
    fn test_with_network_on_signing_error() {
        use std::io::{Error as IoError, ErrorKind};
        let source = IoError::new(ErrorKind::Other, "test");
        let err = MppError::signing_with_context(source, SigningContext::default());
        let err_with_network = err.with_network("optimism");
        assert!(err_with_network.to_string().contains("optimism"));
    }

    #[test]
    fn test_invalid_address_constructor() {
        let err = MppError::invalid_address("test address");
        assert!(matches!(err, MppError::InvalidAddress(_)));
        assert_eq!(err.to_string(), "Invalid address: test address");
    }

    #[test]
    fn test_config_missing_constructor() {
        let err = MppError::config_missing("test config");
        assert!(matches!(err, MppError::ConfigMissing(_)));
        assert_eq!(err.to_string(), "Configuration missing: test config");
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
