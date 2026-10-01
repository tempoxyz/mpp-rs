//! Payment challenge and its credential echo.
//!
//! These types represent the protocol envelope - they work with any payment
//! method and intent. Method-specific interpretation happens in the methods layer.

use serde::{Deserialize, Serialize};

use super::binding::is_payment_authorization_header;
use super::types::{Base64UrlJson, IntentName, MethodName};

// These lived in this module before it was split; the paths stay valid.
pub(crate) use super::binding::constant_time_eq;
pub use super::binding::{
    advertised_credential_header, compute_challenge_id, compute_challenge_id_with_header,
    is_default_credential_header, parse_advertised_credential_header,
};
pub use super::credential::{PaymentCredential, PaymentPayload};
pub use super::receipt::{extract_tx_hash, Receipt};

/// Payment challenge from server (parsed from WWW-Authenticate header).
///
/// This is the core challenge envelope. The `request` field contains
/// intent-specific data encoded as base64url JSON. Use the intents layer
/// to decode it to a typed struct (e.g., ChargeRequest).
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::{PaymentChallenge, parse_www_authenticate};
/// use mpp::protocol::intents::ChargeRequest;
///
/// let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QifQ""#;
/// let challenge = parse_www_authenticate(header).unwrap();
/// if challenge.intent.is_charge() {
///     let req: ChargeRequest = challenge.request.decode().unwrap();
///     println!("Amount: {}", req.amount);
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "WireChallenge")]
pub struct PaymentChallenge {
    /// Unique challenge identifier (128+ bits entropy)
    pub id: String,

    /// Protection space / realm
    pub realm: String,

    /// Payment method identifier
    pub method: MethodName,

    /// Payment intent identifier
    pub intent: IntentName,

    /// Method+intent specific request data (base64url-encoded JSON).
    /// This is the source of truth - don't re-serialize.
    pub request: Base64UrlJson,

    /// Challenge expiration time (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Request body digest for body binding (RFC 9530 Content-Digest)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// Server-defined correlation data (base64url-encoded JSON, flat string-to-string map).
    ///
    /// Stored as `Base64UrlJson` matching mppx's `Record<string, string>`.
    /// On the wire (WWW-Authenticate header) it appears as a base64url-encoded
    /// JCS-serialized JSON object. Clients MUST NOT modify.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque: Option<Base64UrlJson>,

    /// HTTP field that must carry the Payment credential.
    ///
    /// When omitted, clients send the credential in `Authorization`. When
    /// present, the value is `Payment-Authorization` so `Authorization` can
    /// remain in use for ordinary application authentication.
    /// `Authorization` is the implicit default and is never advertised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

/// Serde shape of [`PaymentChallenge`]. Deserialized challenges get the same
/// validation as ones parsed from a `WWW-Authenticate` header.
#[derive(Deserialize)]
struct WireChallenge {
    id: String,
    realm: String,
    method: MethodName,
    intent: IntentName,
    request: Base64UrlJson,
    expires: Option<String>,
    description: Option<String>,
    digest: Option<String>,
    opaque: Option<Base64UrlJson>,
    header: Option<String>,
}

impl TryFrom<WireChallenge> for PaymentChallenge {
    type Error = crate::error::MppError;

    fn try_from(wire: WireChallenge) -> crate::error::Result<Self> {
        super::headers::validate_challenge_fields(
            &wire.id,
            wire.intent.as_str(),
            wire.request.raw(),
            wire.expires.as_deref(),
            wire.digest.as_deref(),
            wire.opaque.as_ref().map(Base64UrlJson::raw),
        )?;
        Ok(Self {
            id: wire.id,
            realm: wire.realm,
            method: wire.method,
            intent: wire.intent,
            request: wire.request,
            expires: wire.expires,
            description: wire.description,
            digest: wire.digest,
            opaque: wire.opaque,
            header: parse_advertised_credential_header(wire.header.as_deref())?,
        })
    }
}

impl PaymentChallenge {
    /// Create a new payment challenge with an explicit ID.
    ///
    /// For HMAC-bound IDs (recommended for servers), use [`PaymentChallenge::with_secret_key`].
    ///
    /// # Examples
    ///
    /// ```
    /// use mpp::PaymentChallenge;
    /// use mpp::protocol::core::Base64UrlJson;
    ///
    /// let challenge = PaymentChallenge::new(
    ///     "explicit-id-123",
    ///     "api.example.com",
    ///     "tempo",
    ///     "charge",
    ///     Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
    /// );
    /// assert_eq!(challenge.id, "explicit-id-123");
    /// assert_eq!(challenge.method.as_str(), "tempo");
    /// ```
    pub fn new(
        id: impl Into<String>,
        realm: impl Into<String>,
        method: impl Into<MethodName>,
        intent: impl Into<IntentName>,
        request: Base64UrlJson,
    ) -> Self {
        Self {
            id: id.into(),
            realm: realm.into(),
            method: method.into(),
            intent: intent.into(),
            request,
            expires: None,
            description: None,
            digest: None,
            opaque: None,
            header: None,
        }
    }

    /// Create a new payment challenge with an HMAC-bound ID.
    ///
    /// The challenge ID is computed as HMAC-SHA256 over the challenge parameters,
    /// cryptographically binding the ID to its contents. This enables stateless
    /// verification without storing challenge state.
    ///
    /// This is the Rust equivalent of `Challenge.from({ secretKey, ... })` in the TS SDK.
    ///
    /// `secret_key` must be at least 32 bytes. This constructor cannot fail and
    /// does not check the length.
    ///
    /// # Examples
    ///
    /// ```
    /// use mpp::PaymentChallenge;
    /// use mpp::protocol::core::Base64UrlJson;
    ///
    /// let challenge = PaymentChallenge::with_secret_key(
    ///     "my-server-secret-of-at-least-32-bytes",
    ///     "api.example.com",
    ///     "tempo",
    ///     "charge",
    ///     Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
    /// );
    ///
    /// // ID is HMAC-bound — can be verified later
    /// assert!(challenge.verify("my-server-secret-of-at-least-32-bytes"));
    /// ```
    pub fn with_secret_key(
        secret_key: &str,
        realm: impl Into<String>,
        method: impl Into<MethodName>,
        intent: impl Into<IntentName>,
        request: Base64UrlJson,
    ) -> Self {
        let realm = realm.into();
        let method = method.into();
        let intent = intent.into();
        let id = compute_challenge_id(
            secret_key,
            &realm,
            method.as_str(),
            intent.as_str(),
            request.raw(),
            None,
            None,
            None,
        );
        Self {
            id,
            realm,
            method,
            intent,
            request,
            expires: None,
            description: None,
            digest: None,
            opaque: None,
            header: None,
        }
    }

    /// Create a new payment challenge with HMAC-bound ID including all optional fields.
    ///
    /// Unlike [`with_secret_key`], this includes `expires` and `digest` in the HMAC
    /// computation, matching the full TS SDK `Challenge.from()` behavior.
    ///
    /// The `opaque` parameter accepts a `Base64UrlJson` value (use
    /// `Base64UrlJson::from_value()` to create from a JSON object). This matches
    /// the mppx SDK where opaque is `Record<string, string>`.
    ///
    /// `secret_key` must be at least 32 bytes. This constructor cannot fail and
    /// does not check the length.
    #[allow(clippy::too_many_arguments)]
    pub fn with_secret_key_full(
        secret_key: &str,
        realm: impl Into<String>,
        method: impl Into<MethodName>,
        intent: impl Into<IntentName>,
        request: Base64UrlJson,
        expires: Option<&str>,
        digest: Option<&str>,
        description: Option<&str>,
        opaque: Option<Base64UrlJson>,
        header: Option<&str>,
    ) -> Self {
        let realm = realm.into();
        let method = method.into();
        let intent = intent.into();
        let header = advertised_credential_header(header);
        let id = compute_challenge_id_with_header(
            secret_key,
            &realm,
            method.as_str(),
            intent.as_str(),
            request.raw(),
            expires,
            digest,
            opaque.as_ref().map(|o| o.raw()),
            header.as_deref(),
        );
        Self {
            id,
            realm,
            method,
            intent,
            request,
            expires: expires.map(String::from),
            description: description.map(String::from),
            digest: digest.map(String::from),
            opaque,
            header,
        }
    }

    /// Set the expiration time (ISO 8601).
    ///
    /// Note: When using `with_secret_key`, set expires BEFORE creating the challenge
    /// since it affects the HMAC. For post-creation use, the HMAC won't include the
    /// expires. Use [`with_secret_key_full`] instead if expires is needed in the HMAC.
    pub fn with_expires(mut self, expires: impl Into<String>) -> Self {
        self.expires = Some(expires.into());
        self
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the digest.
    pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
        self.digest = Some(digest.into());
        self
    }

    /// Set the opaque correlation data from a JSON value.
    ///
    /// Note: When using `with_secret_key`, set opaque BEFORE creating the challenge
    /// since it affects the HMAC. Use [`with_secret_key_full`] instead if opaque
    /// is needed in the HMAC.
    pub fn with_opaque(mut self, opaque: Base64UrlJson) -> Self {
        self.opaque = Some(opaque);
        self
    }

    /// Set the HTTP field that must carry the Payment credential.
    ///
    /// `Payment-Authorization` is the only field a challenge can select.
    /// `Authorization` is the implicit default and is stored as `None`, as is
    /// any other value.
    /// Note: When using `with_secret_key`, set header BEFORE creating the
    /// challenge since it affects the HMAC. Use [`with_secret_key_full`]
    /// instead if header is needed in the HMAC.
    pub fn with_header(mut self, header: impl Into<String>) -> Self {
        let header = header.into();
        self.header = advertised_credential_header(Some(&header));
        self
    }

    /// HTTP field a client must use for the payment credential.
    ///
    /// Returns `header` when it selects `Payment-Authorization`, otherwise
    /// `Authorization`.
    pub fn credential_header(&self) -> &str {
        match self.header.as_deref() {
            Some(header) if is_payment_authorization_header(header) => header,
            _ => "Authorization",
        }
    }

    /// Get the effective expiration time for this payment challenge.
    ///
    /// Returns `challenge.expires` if set. Expiry is a property of
    /// the challenge lifecycle, not the payment request content.
    pub fn effective_expires(&self) -> Option<&str> {
        self.expires.as_deref()
    }

    /// Create a challenge echo for use in credentials.
    pub fn to_echo(&self) -> ChallengeEcho {
        ChallengeEcho {
            id: self.id.clone(),
            realm: self.realm.clone(),
            method: self.method.clone(),
            intent: self.intent.clone(),
            request: self.request.clone(),
            expires: self.expires.clone(),
            description: self.description.clone(),
            digest: self.digest.clone(),
            opaque: self.opaque.clone(),
            header: self.header.clone(),
        }
    }

    /// Format as WWW-Authenticate header value.
    pub fn to_header(&self) -> crate::error::Result<String> {
        super::format_www_authenticate(self)
    }

    /// Parse a PaymentChallenge from a WWW-Authenticate header value.
    ///
    /// This is a convenience method equivalent to [`parse_www_authenticate`](super::parse_www_authenticate).
    pub fn from_header(header: &str) -> crate::error::Result<Self> {
        super::parse_www_authenticate(header)
    }

    /// Parse all Payment challenges from multiple WWW-Authenticate header values.
    ///
    /// This is a convenience method equivalent to [`parse_www_authenticate_all`](super::parse_www_authenticate_all).
    pub fn from_headers<'a>(
        headers: impl IntoIterator<Item = &'a str>,
    ) -> Vec<crate::error::Result<Self>> {
        super::parse_www_authenticate_all(headers)
    }

    /// Parse a PaymentChallenge from a 402 response's WWW-Authenticate header.
    ///
    /// This is a convenience method that validates the status code and parses the challenge.
    ///
    /// # Arguments
    /// * `status_code` - HTTP status code (must be 402)
    /// * `www_authenticate` - The WWW-Authenticate header value
    pub fn from_response(status_code: u16, www_authenticate: &str) -> crate::error::Result<Self> {
        if status_code != 402 {
            return Err(crate::error::MppError::invalid_challenge_reason(format!(
                "Expected 402 status, got {}",
                status_code
            )));
        }
        Self::from_header(www_authenticate)
    }

    /// Verify that this challenge's ID matches the expected HMAC for the given secret key.
    ///
    /// Recomputes HMAC-SHA256 over `realm|method|intent|request|expires|digest|opaque`,
    /// inserting `header` immediately before `opaque` when advertised,
    /// and performs a constant-time comparison against the challenge ID.
    ///
    /// This is the Rust equivalent of `Challenge.verify(challenge, { secretKey })` in the TS SDK.
    ///
    /// # Examples
    ///
    /// ```
    /// use mpp::PaymentChallenge;
    ///
    /// # let challenge = PaymentChallenge::from_header(
    /// #     r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="e30""#
    /// # ).unwrap();
    /// let is_valid = challenge.verify("my-server-secret");
    /// ```
    pub fn verify(&self, secret_key: &str) -> bool {
        let expected_id = compute_challenge_id_with_header(
            secret_key,
            &self.realm,
            self.method.as_str(),
            self.intent.as_str(),
            self.request.raw(),
            self.expires.as_deref(),
            self.digest.as_deref(),
            self.opaque.as_ref().map(|o| o.raw()),
            self.header.as_deref(),
        );
        constant_time_eq(&self.id, &expected_id)
    }

    /// Returns true if the challenge has expired.
    ///
    /// Parses the `expires` field as RFC 3339. If `expires` is `None`,
    /// returns `false`. If set but unparseable, returns `true` (fail-closed).
    pub fn is_expired(&self) -> bool {
        match &self.expires {
            None => false,
            Some(s) => {
                match time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                {
                    Ok(expires) => expires <= time::OffsetDateTime::now_utc(),
                    Err(_) => true, // fail-closed: unparseable timestamps are treated as expired
                }
            }
        }
    }

    /// Returns the parsed expiry timestamp if present and valid, `None` otherwise.
    pub fn expires_at(&self) -> Option<time::OffsetDateTime> {
        self.expires.as_ref().and_then(|s| {
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()
        })
    }

    /// Validate that this challenge can be used for a charge payment with the given method.
    ///
    /// Checks that:
    /// - The payment method matches (case-insensitive)
    /// - The intent is "charge"
    /// - The challenge has not expired
    pub fn validate_for_charge(&self, method: &str) -> crate::error::Result<()> {
        if !self.method.eq_ignore_ascii_case(method) {
            return Err(crate::error::MppError::UnsupportedPaymentMethod(format!(
                "Payment method '{}' is not supported. Supported methods: {}",
                self.method, method
            )));
        }

        if !self.intent.is_charge() {
            return Err(crate::error::MppError::InvalidChallenge {
                id: Some(self.id.clone()),
                reason: Some(format!(
                    "Only 'charge' intent is supported, got: {}",
                    self.intent
                )),
            });
        }

        if self.is_expired() {
            return Err(crate::error::MppError::PaymentExpired(self.expires.clone()));
        }

        Ok(())
    }

    /// Validate that this challenge can be used for a session with the given method.
    ///
    /// Checks that:
    /// - The payment method matches (case-insensitive)
    /// - The intent is "session"
    /// - The challenge has not expired
    pub fn validate_for_session(&self, method: &str) -> crate::error::Result<()> {
        if !self.method.eq_ignore_ascii_case(method) {
            return Err(crate::error::MppError::UnsupportedPaymentMethod(format!(
                "Payment method '{}' is not supported. Supported methods: {}",
                self.method, method
            )));
        }

        if !self.intent.is_session() {
            return Err(crate::error::MppError::InvalidChallenge {
                id: Some(self.id.clone()),
                reason: Some(format!("Expected 'session' intent, got: {}", self.intent)),
            });
        }

        if self.is_expired() {
            return Err(crate::error::MppError::PaymentExpired(self.expires.clone()));
        }

        Ok(())
    }
}

/// Challenge echo in credential (echoes server challenge parameters).
///
/// This is included in the credential to bind the payment to the original challenge.
/// The `request` field is the raw base64url string (not re-encoded).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeEcho {
    /// Challenge identifier
    pub id: String,

    /// Protection space / realm
    pub realm: String,

    /// Payment method
    pub method: MethodName,

    /// Payment intent
    pub intent: IntentName,

    /// Base64url-encoded request (as received from server)
    pub request: Base64UrlJson,

    /// Challenge expiration time (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Human-readable description, echoed from the challenge when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Request body digest for body binding (RFC 9530 Content-Digest)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// Server-defined correlation data (base64url-encoded JSON).
    ///
    /// The legacy object form sent by older mppx clients is accepted and
    /// normalized to the base64url string.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_echo_opaque"
    )]
    pub opaque: Option<Base64UrlJson>,

    /// HTTP field that must carry the Payment credential.
    ///
    /// Echoed from the challenge when present. Omitted when the challenge
    /// used the default `Authorization` field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
}

fn deserialize_echo_opaque<'de, D>(deserializer: D) -> Result<Option<Base64UrlJson>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Opaque {
        Raw(String),
        Legacy(std::collections::BTreeMap<String, String>),
    }

    match Option::<Opaque>::deserialize(deserializer)? {
        None => Ok(None),
        Some(Opaque::Raw(raw)) => Ok(Some(Base64UrlJson::from_raw(raw))),
        Some(Opaque::Legacy(meta)) => Base64UrlJson::from_typed(&meta)
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(in crate::protocol::core) fn test_challenge() -> PaymentChallenge {
        PaymentChallenge {
            id: "abc123".to_string(),
            realm: "api".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "10000",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: Some("2024-01-01T00:00:00Z".to_string()),
            description: None,
            digest: None,
            opaque: None,
            header: None,
        }
    }

    #[test]
    fn test_challenge_to_echo() {
        let challenge = test_challenge();
        let echo = challenge.to_echo();

        assert_eq!(echo.id, "abc123");
        assert_eq!(echo.realm, "api");
        assert_eq!(echo.method.as_str(), "tempo");
        assert_eq!(echo.intent.as_str(), "charge");
        assert_eq!(echo.request.raw(), challenge.request.raw());
    }

    #[test]
    fn test_challenge_from_header() {
        let header = r#"Payment id="abc123", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIn0""#;
        let challenge = PaymentChallenge::from_header(header).unwrap();
        assert_eq!(challenge.id, "abc123");
        assert_eq!(challenge.method.as_str(), "tempo");
    }

    #[test]
    fn test_challenge_from_headers() {
        let headers = vec![
            "Bearer token",
            r#"Payment id="a", realm="api", method="tempo", intent="charge", request="e30""#,
            r#"Payment id="b", realm="api", method="base", intent="charge", request="e30""#,
        ];
        let results = PaymentChallenge::from_headers(headers);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_challenge_verify_valid() {
        let secret = "test-secret";
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000"
        }))
        .unwrap();

        let id = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );

        let challenge = PaymentChallenge {
            id,
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request,
            expires: None,
            description: None,
            digest: None,
            opaque: None,
            header: None,
        };

        assert!(challenge.verify(secret));
    }

    #[test]
    fn test_challenge_verify_wrong_secret() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let id = compute_challenge_id(
            "correct-secret",
            "api",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );

        let challenge = PaymentChallenge {
            id,
            realm: "api".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request,
            expires: None,
            description: None,
            digest: None,
            opaque: None,
            header: None,
        };

        assert!(!challenge.verify("wrong-secret"));
    }

    #[test]
    fn test_challenge_verify_tampered_id() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();

        let challenge = PaymentChallenge {
            id: "tampered-id".to_string(),
            realm: "api".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request,
            expires: None,
            description: None,
            digest: None,
            opaque: None,
            header: None,
        };

        assert!(!challenge.verify("any-secret"));
    }

    #[test]
    fn test_challenge_verify_with_expires_and_digest() {
        let secret = "my-secret";
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "500"})).unwrap();
        let expires = Some("2026-01-01T00:00:00Z");
        let digest = Some("sha-256=abc123");

        let id = compute_challenge_id(
            secret,
            "payments.example.org",
            "tempo",
            "charge",
            request.raw(),
            expires,
            digest,
            None,
        );

        let challenge = PaymentChallenge {
            id,
            realm: "payments.example.org".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request,
            expires: expires.map(String::from),
            description: Some("test payment".to_string()),
            digest: digest.map(String::from),
            opaque: None,
            header: None,
        };

        assert!(challenge.verify(secret));
    }

    #[test]
    fn test_challenge_serialize_includes_digest() {
        let mut challenge = test_challenge();
        challenge.digest = Some("sha-256=abc".to_string());

        let header = challenge.to_header().unwrap();
        assert!(header.contains(r#"digest="sha-256=abc""#));
        assert!(header.contains("expires="));
    }

    #[test]
    fn test_challenge_roundtrip_with_digest() {
        let mut challenge = test_challenge();
        challenge.digest = Some("sha-256=abc".to_string());

        let header = challenge.to_header().unwrap();
        let parsed = PaymentChallenge::from_header(&header).unwrap();

        assert_eq!(parsed.digest.as_deref(), Some("sha-256=abc"));
        assert_eq!(parsed.expires, challenge.expires);
    }

    #[test]
    fn test_challenge_from_response_402() {
        let challenge = test_challenge();
        let header = challenge.to_header().unwrap();

        let parsed = PaymentChallenge::from_response(402, &header).unwrap();
        assert_eq!(parsed.id, challenge.id);
        assert_eq!(parsed.realm, challenge.realm);
        assert_eq!(parsed.method.as_str(), challenge.method.as_str());
        assert_eq!(parsed.intent.as_str(), challenge.intent.as_str());
    }

    #[test]
    fn test_challenge_from_response_non_402() {
        let challenge = test_challenge();
        let header = challenge.to_header().unwrap();

        let result = PaymentChallenge::from_response(401, &header);
        assert!(result.is_err());
    }

    #[test]
    fn test_challenge_verify_tampered_request() {
        let secret = "test-secret";
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();

        let id = compute_challenge_id(
            secret,
            "api",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );

        // Build challenge with the valid HMAC ID but tampered request data
        let tampered_request =
            Base64UrlJson::from_value(&serde_json::json!({"amount": "9999"})).unwrap();
        let challenge = PaymentChallenge {
            id,
            realm: "api".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: tampered_request,
            expires: None,
            description: None,
            digest: None,
            opaque: None,
            header: None,
        };

        assert!(!challenge.verify(secret));
    }

    #[test]
    fn test_challenge_new() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge =
            PaymentChallenge::new("my-id", "api.example.com", "tempo", "charge", request);
        assert_eq!(challenge.id, "my-id");
        assert_eq!(challenge.realm, "api.example.com");
        assert_eq!(challenge.method.as_str(), "tempo");
        assert_eq!(challenge.intent.as_str(), "charge");
        assert!(challenge.expires.is_none());
        assert!(challenge.description.is_none());
        assert!(challenge.digest.is_none());
    }

    #[test]
    fn test_challenge_with_secret_key() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::with_secret_key(
            "my-secret",
            "api.example.com",
            "tempo",
            "charge",
            request,
        );
        assert!(challenge.verify("my-secret"));
        assert!(!challenge.verify("wrong-secret"));
    }

    #[test]
    fn test_challenge_with_secret_key_full() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::with_secret_key_full(
            "my-secret",
            "api.example.com",
            "tempo",
            "charge",
            request,
            Some("2026-01-01T00:00:00Z"),
            Some("sha-256=abc"),
            Some("test payment"),
            None,
            None,
        );
        assert!(challenge.verify("my-secret"));
        assert_eq!(challenge.expires.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(challenge.digest.as_deref(), Some("sha-256=abc"));
        assert_eq!(challenge.description.as_deref(), Some("test payment"));
    }

    #[test]
    fn test_opaque_verify_roundtrip() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();
        let opaque =
            Base64UrlJson::from_value(&serde_json::json!({"pi": "pi_3abc123XYZ"})).unwrap();
        let opaque_raw = opaque.raw().to_string();
        let challenge = PaymentChallenge::with_secret_key_full(
            "my-secret",
            "api.example.com",
            "tempo",
            "charge",
            request,
            None,
            None,
            None,
            Some(opaque),
            None,
        );
        assert_eq!(challenge.opaque.as_ref().unwrap().raw(), opaque_raw);
        assert!(challenge.verify("my-secret"));
    }

    #[test]
    fn test_opaque_tamper_fails_verify() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();
        let opaque =
            Base64UrlJson::from_value(&serde_json::json!({"pi": "pi_3abc123XYZ"})).unwrap();
        let mut challenge = PaymentChallenge::with_secret_key_full(
            "my-secret",
            "api.example.com",
            "tempo",
            "charge",
            request,
            None,
            None,
            None,
            Some(opaque),
            None,
        );
        let tampered =
            Base64UrlJson::from_value(&serde_json::json!({"pi": "pi_TAMPERED"})).unwrap();
        challenge.opaque = Some(tampered);
        assert!(!challenge.verify("my-secret"));
    }

    #[test]
    fn test_opaque_echo_roundtrip() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();
        let opaque =
            Base64UrlJson::from_value(&serde_json::json!({"pi": "pi_3abc123XYZ"})).unwrap();
        let opaque_raw = opaque.raw().to_string();
        let challenge = PaymentChallenge::with_secret_key_full(
            "my-secret",
            "api.example.com",
            "tempo",
            "charge",
            request,
            None,
            None,
            None,
            Some(opaque),
            None,
        );
        let echo = challenge.to_echo();
        assert_eq!(
            echo.opaque.as_ref().map(|o| o.raw()),
            Some(opaque_raw.as_str())
        );
    }

    /// Verify that opaque roundtrips through header serialize/deserialize
    /// and still passes HMAC verification — the critical cross-SDK path.
    #[test]
    fn test_opaque_header_roundtrip_with_hmac() {
        let opaque =
            Base64UrlJson::from_value(&serde_json::json!({"pi": "pi_3abc123XYZ"})).unwrap();
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();
        let challenge = PaymentChallenge::with_secret_key_full(
            "test-secret",
            "api.example.com",
            "tempo",
            "charge",
            request,
            Some("2025-01-06T12:00:00Z"),
            None,
            None,
            Some(opaque),
            None,
        );
        assert!(challenge.verify("test-secret"));

        // Serialize to header, parse back, verify HMAC still holds
        let header = challenge.to_header().unwrap();
        assert!(header.contains("opaque="));
        let parsed = PaymentChallenge::from_header(&header).unwrap();
        assert!(parsed.opaque.is_some());
        assert_eq!(
            parsed.opaque.as_ref().unwrap().raw(),
            challenge.opaque.as_ref().unwrap().raw()
        );

        // Decoded opaque should match original
        let decoded: std::collections::HashMap<String, String> =
            parsed.opaque.unwrap().decode().unwrap();
        assert_eq!(decoded.get("pi").unwrap(), "pi_3abc123XYZ");
    }

    /// Verify opaque value can be decoded to a typed HashMap.
    #[test]
    fn test_opaque_decode_to_hashmap() {
        let opaque = Base64UrlJson::from_value(
            &serde_json::json!({"deposit": "dep_456", "pi": "pi_3abc123XYZ"}),
        )
        .unwrap();
        let decoded: std::collections::HashMap<String, String> = opaque.decode().unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded.get("pi").unwrap(), "pi_3abc123XYZ");
        assert_eq!(decoded.get("deposit").unwrap(), "dep_456");
    }

    /// Verify with_opaque builder method works and affects HMAC.
    #[test]
    fn test_with_opaque_builder() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let opaque = Base64UrlJson::from_value(&serde_json::json!({"key": "val"})).unwrap();
        let challenge =
            PaymentChallenge::new("id", "api", "tempo", "charge", request).with_opaque(opaque);
        assert!(challenge.opaque.is_some());
        let decoded: std::collections::HashMap<String, String> =
            challenge.opaque.unwrap().decode().unwrap();
        assert_eq!(decoded.get("key").unwrap(), "val");
    }

    #[test]
    fn test_challenge_builder_methods() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2026-01-01T00:00:00Z")
            .with_description("test")
            .with_digest("sha-256=abc");
        assert_eq!(challenge.expires.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(challenge.description.as_deref(), Some("test"));
        assert_eq!(challenge.digest.as_deref(), Some("sha-256=abc"));
    }

    #[test]
    fn test_is_expired_no_expires() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request);
        assert!(!challenge.is_expired());
    }

    #[test]
    fn test_is_expired_future() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2099-01-01T00:00:00Z");
        assert!(!challenge.is_expired());
    }

    #[test]
    fn test_is_expired_past() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2020-01-01T00:00:00Z");
        assert!(challenge.is_expired());
    }

    #[test]
    fn test_is_expired_unparseable() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("not-a-date");
        assert!(challenge.is_expired()); // fail-closed: unparseable → expired
    }

    #[test]
    fn test_expires_at_valid() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2099-01-01T00:00:00Z");
        assert!(challenge.expires_at().is_some());
    }

    #[test]
    fn test_expires_at_missing() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request);
        assert!(challenge.expires_at().is_none());
    }

    #[test]
    fn test_expires_at_invalid() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge =
            PaymentChallenge::new("id", "api", "tempo", "charge", request).with_expires("garbage");
        assert!(challenge.expires_at().is_none());
    }

    #[test]
    fn test_is_expired_positive_timezone_offset_future() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2099-01-01T00:00:00+05:00");
        assert!(!challenge.is_expired());
        assert!(challenge.expires_at().is_some());
    }

    #[test]
    fn test_is_expired_negative_timezone_offset_past() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2020-01-01T00:00:00-07:00");
        assert!(challenge.is_expired());
    }

    #[test]
    fn test_is_expired_fractional_seconds_millis() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2099-01-01T00:00:00.123Z");
        assert!(!challenge.is_expired());
        assert!(challenge.expires_at().is_some());
    }

    #[test]
    fn test_is_expired_fractional_seconds_micros() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2099-01-01T00:00:00.123456Z");
        assert!(!challenge.is_expired());
    }

    #[test]
    fn test_is_expired_empty_string() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge =
            PaymentChallenge::new("id", "api", "tempo", "charge", request).with_expires("");
        assert!(challenge.is_expired()); // fail-closed: unparseable → expired
        assert!(challenge.expires_at().is_none());
    }

    #[test]
    fn test_is_expired_whitespace_only() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge =
            PaymentChallenge::new("id", "api", "tempo", "charge", request).with_expires("   ");
        assert!(challenge.is_expired()); // fail-closed: unparseable → expired
        assert!(challenge.expires_at().is_none());
    }

    #[test]
    fn test_is_expired_unix_epoch() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("1970-01-01T00:00:00Z");
        assert!(challenge.is_expired());
    }

    #[test]
    fn test_is_expired_invalid_month() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2099-13-01T00:00:00Z");
        assert!(challenge.is_expired()); // fail-closed: unparseable → expired
    }

    #[test]
    fn test_is_expired_invalid_day() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2099-01-32T00:00:00Z");
        assert!(challenge.is_expired()); // fail-closed: unparseable → expired
    }

    #[test]
    fn test_is_expired_plain_text() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("just some text");
        assert!(challenge.is_expired()); // fail-closed: unparseable → expired
    }

    #[test]
    fn test_is_expired_numeric_string() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge =
            PaymentChallenge::new("id", "api", "tempo", "charge", request).with_expires("12345");
        assert!(challenge.is_expired()); // fail-closed: unparseable → expired
    }

    #[test]
    fn test_validate_for_charge_valid() {
        let request = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request);
        assert!(challenge.validate_for_charge("tempo").is_ok());
    }

    #[test]
    fn test_validate_for_charge_case_insensitive() {
        let request = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request);
        assert!(challenge.validate_for_charge("TEMPO").is_ok());
        assert!(challenge.validate_for_charge("Tempo").is_ok());
    }

    #[test]
    fn test_validate_for_charge_wrong_method() {
        let request = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request);
        assert!(challenge.validate_for_charge("stripe").is_err());
    }

    #[test]
    fn test_validate_for_charge_wrong_intent() {
        let request = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "session", request);
        assert!(challenge.validate_for_charge("tempo").is_err());
    }

    #[test]
    fn test_validate_for_charge_expired() {
        let request = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_expires("2020-01-01T00:00:00Z");
        assert!(challenge.validate_for_charge("tempo").is_err());
    }

    #[test]
    fn test_validate_for_session_valid() {
        let request = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "session", request);
        assert!(challenge.validate_for_session("tempo").is_ok());
    }

    #[test]
    fn test_validate_for_session_wrong_intent() {
        let request = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request);
        assert!(challenge.validate_for_session("tempo").is_err());
    }

    #[test]
    fn test_validate_for_session_expired() {
        let request = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "session", request)
            .with_expires("2020-01-01T00:00:00Z");
        assert!(challenge.validate_for_session("tempo").is_err());
    }

    #[test]
    fn test_authorization_header_does_not_change_challenge_id() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();
        let implicit = PaymentChallenge::with_secret_key_full(
            "test-secret-key-12345",
            "api.example.com",
            "tempo",
            "charge",
            request.clone(),
            None,
            None,
            None,
            None,
            None,
        );
        let explicit = PaymentChallenge::with_secret_key_full(
            "test-secret-key-12345",
            "api.example.com",
            "tempo",
            "charge",
            request,
            None,
            None,
            None,
            None,
            Some("Authorization"),
        );

        assert!(implicit.header.is_none());
        assert!(explicit.header.is_none());
        assert_eq!(implicit.id, explicit.id);
        assert!(!implicit.to_header().unwrap().contains("header="));
        assert_eq!(implicit.credential_header(), "Authorization");
    }

    #[test]
    fn test_payment_authorization_header_is_bound_into_id() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();
        let implicit = PaymentChallenge::with_secret_key_full(
            "test-secret-key-12345",
            "api.example.com",
            "tempo",
            "charge",
            request.clone(),
            None,
            None,
            None,
            None,
            None,
        );
        let advertised = PaymentChallenge::with_secret_key_full(
            "test-secret-key-12345",
            "api.example.com",
            "tempo",
            "charge",
            request,
            None,
            None,
            None,
            None,
            Some("Payment-Authorization"),
        );

        assert_ne!(implicit.id, advertised.id);
        assert_eq!(advertised.header.as_deref(), Some("Payment-Authorization"));
        assert!(advertised.verify("test-secret-key-12345"));
        assert_eq!(advertised.credential_header(), "Payment-Authorization");
        assert!(advertised
            .to_header()
            .unwrap()
            .contains(r#"header="Payment-Authorization""#));
        assert_eq!(
            advertised.to_echo().header.as_deref(),
            Some("Payment-Authorization")
        );
    }

    #[test]
    fn test_credential_header_spelling_is_bound_as_given() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();
        let build = |header| {
            PaymentChallenge::with_secret_key_full(
                "test-secret-key-12345",
                "api.example.com",
                "tempo",
                "charge",
                request.clone(),
                None,
                None,
                None,
                None,
                Some(header),
            )
        };
        let canonical = build("Payment-Authorization");
        let lowercase = build("payment-authorization");

        assert_eq!(lowercase.header.as_deref(), Some("payment-authorization"));
        assert_ne!(lowercase.id, canonical.id);
        assert!(lowercase.verify("test-secret-key-12345"));
    }

    #[test]
    fn test_unsupported_credential_header_is_never_advertised() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();
        let implicit = PaymentChallenge::with_secret_key(
            "test-secret-key-12345",
            "api.example.com",
            "tempo",
            "charge",
            request.clone(),
        );
        let bound = PaymentChallenge::with_secret_key_full(
            "test-secret-key-12345",
            "api.example.com",
            "tempo",
            "charge",
            request.clone(),
            None,
            None,
            None,
            None,
            Some("Cookie"),
        );
        assert!(bound.header.is_none());
        assert_eq!(bound.id, implicit.id);

        let built = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_header("X-Anything");
        assert!(built.header.is_none());
        assert!(!built.to_header().unwrap().contains("header="));

        let mut assigned = built;
        assigned.header = Some("Cookie".to_string());
        assert_eq!(assigned.credential_header(), "Authorization");
        assert!(assigned.to_header().is_err());
    }

    #[test]
    fn test_header_roundtrip_through_www_authenticate() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "charge", request)
            .with_header("Payment-Authorization");
        let header = challenge.to_header().unwrap();
        let parsed = PaymentChallenge::from_header(&header).unwrap();
        assert_eq!(parsed.header.as_deref(), Some("Payment-Authorization"));
        assert_eq!(parsed.credential_header(), "Payment-Authorization");
    }
}
