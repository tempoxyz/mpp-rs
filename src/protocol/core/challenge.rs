//! Core challenge, credential, and receipt types.
//!
//! These types represent the protocol envelope - they work with any payment
//! method and intent. Method-specific interpretation happens in the methods layer.

use serde::{Deserialize, Serialize};

use super::types::{Base64UrlJson, IntentName, MethodName, PayloadType, ReceiptStatus};

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
    /// # Examples
    ///
    /// ```
    /// use mpp::PaymentChallenge;
    /// use mpp::protocol::core::Base64UrlJson;
    ///
    /// let challenge = PaymentChallenge::with_secret_key(
    ///     "my-server-secret",
    ///     "api.example.com",
    ///     "tempo",
    ///     "charge",
    ///     Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
    /// );
    ///
    /// // ID is HMAC-bound — can be verified later
    /// assert!(challenge.verify("my-server-secret"));
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
            expires,
            digest,
            opaque.as_ref().map(|o| o.raw()),
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
            digest: self.digest.clone(),
            opaque: self.opaque.clone(),
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
    /// Recomputes HMAC-SHA256 over `realm|method|intent|request|expires|digest|opaque`
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
        let expected_id = compute_challenge_id(
            secret_key,
            &self.realm,
            self.method.as_str(),
            self.intent.as_str(),
            self.request.raw(),
            self.expires.as_deref(),
            self.digest.as_deref(),
            self.opaque.as_ref().map(|o| o.raw()),
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

/// Compute an HMAC-SHA256 challenge ID from challenge parameters.
///
/// This is the canonical implementation used by both `PaymentChallenge::verify()`
/// and challenge creation. The algorithm matches the TypeScript and Python SDKs:
///
/// 1. Concatenate all fields `realm|method|intent|request|expires|digest|opaque` with `|` (empty string for absent optional fields)
/// 2. Compute HMAC-SHA256 with the secret key
/// 3. Base64url-encode the result (no padding)
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::compute_challenge_id;
///
/// let id = compute_challenge_id(
///     "my-secret-key",
///     "api.example.com",
///     "tempo",
///     "charge",
///     "eyJhbW91bnQiOiIxMDAwMDAwIn0",
///     None,
///     None,
///     None,
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn compute_challenge_id(
    secret_key: &str,
    realm: &str,
    method: &str,
    intent: &str,
    request: &str,
    expires: Option<&str>,
    digest: Option<&str>,
    opaque: Option<&str>,
) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // All fields are always included in the pipe-delimited HMAC input,
    // with empty string for absent optional fields. This ensures challenges
    // with vs without expires/digest/opaque produce different HMACs.
    let hmac_input = [
        realm,
        method,
        intent,
        request,
        expires.unwrap_or(""),
        digest.unwrap_or(""),
        opaque.unwrap_or(""),
    ]
    .join("|");

    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(hmac_input.as_bytes());
    let result = mac.finalize();

    super::base64url_encode(&result.into_bytes())
}

/// Constant-time string comparison to prevent timing attacks.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
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

    /// Request body digest for body binding (RFC 9530 Content-Digest)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// Server-defined correlation data (base64url-encoded JSON).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opaque: Option<Base64UrlJson>,
}

/// Payment payload in credential.
///
/// Contains the signed transaction or transaction hash.
///
/// Per IETF spec (Tempo §5.1-5.2):
/// - `type="transaction"` uses field `signature` containing the signed transaction
/// - `type="hash"` uses field `hash` containing the transaction hash
#[derive(Debug, Clone)]
pub struct PaymentPayload {
    /// Payload type: "transaction" or "hash"
    pub payload_type: PayloadType,

    /// Hex-encoded signed data.
    ///
    /// For `type="transaction"`: the RLP-encoded signed transaction to broadcast.
    /// For `type="hash"`: the transaction hash (0x-prefixed) of an already-broadcast tx.
    data: String,
}

impl serde::Serialize for PaymentPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("PaymentPayload", 2)?;
        state.serialize_field("type", &self.payload_type)?;

        match self.payload_type {
            PayloadType::Transaction => state.serialize_field("signature", &self.data)?,
            PayloadType::Hash => state.serialize_field("hash", &self.data)?,
        }

        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for PaymentPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawPayload {
            #[serde(rename = "type")]
            payload_type: PayloadType,
            signature: Option<String>,
            hash: Option<String>,
        }

        let raw = RawPayload::deserialize(deserializer)?;

        let data = match raw.payload_type {
            PayloadType::Transaction => raw.signature.ok_or_else(|| {
                serde::de::Error::custom("transaction payload requires 'signature' field")
            })?,
            PayloadType::Hash => raw
                .hash
                .ok_or_else(|| serde::de::Error::custom("hash payload requires 'hash' field"))?,
        };

        Ok(PaymentPayload {
            payload_type: raw.payload_type,
            data,
        })
    }
}

impl PaymentPayload {
    /// Create a new transaction payload.
    pub fn transaction(signature: impl Into<String>) -> Self {
        Self {
            payload_type: PayloadType::Transaction,
            data: signature.into(),
        }
    }

    /// Create a new hash payload (already broadcast).
    pub fn hash(tx_hash: impl Into<String>) -> Self {
        Self {
            payload_type: PayloadType::Hash,
            data: tx_hash.into(),
        }
    }

    /// Get the payload type.
    pub fn payload_type(&self) -> PayloadType {
        self.payload_type.clone()
    }

    /// Get the underlying data (works for both transaction and hash payloads).
    ///
    /// For transaction payloads, this is the signed transaction bytes.
    /// For hash payloads, this is the transaction hash.
    ///
    /// Prefer using `tx_hash()` or `signed_tx()` for type-safe access.
    pub fn data(&self) -> &str {
        &self.data
    }

    /// Get the hash (for hash payloads).
    ///
    /// Returns the transaction hash if this is a hash payload, None otherwise.
    pub fn tx_hash(&self) -> Option<&str> {
        if self.payload_type == PayloadType::Hash {
            Some(&self.data)
        } else {
            None
        }
    }

    /// Get the signed transaction (for transaction payloads).
    ///
    /// Returns the signed transaction if this is a transaction payload, None otherwise.
    pub fn signed_tx(&self) -> Option<&str> {
        if self.payload_type == PayloadType::Transaction {
            Some(&self.data)
        } else {
            None
        }
    }

    /// Check if this is a transaction payload.
    pub fn is_transaction(&self) -> bool {
        self.payload_type == PayloadType::Transaction
    }

    /// Check if this is a hash payload.
    pub fn is_hash(&self) -> bool {
        self.payload_type == PayloadType::Hash
    }

    /// Get the transaction reference (hash or signature data).
    ///
    /// Returns the underlying data, which contains either:
    /// - The transaction hash for hash payloads
    /// - The signed transaction for transaction payloads
    pub fn reference(&self) -> &str {
        &self.data
    }
}

/// Payment credential from client (sent in Authorization header).
///
/// Contains the challenge echo and the payment proof.
///
/// The `payload` field is stored as a generic JSON value to support
/// different payload formats across intents (e.g., charge uses
/// `PaymentPayload` with type/signature/hash, while session uses
/// `SessionCredentialPayload` with action/channelId/etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCredential {
    /// Echo of challenge parameters from server
    pub challenge: ChallengeEcho,

    /// Payer identifier (DID format: did:pkh:eip155:chainId:address)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Payment payload (method/intent-specific JSON).
    ///
    /// For charge intents, use [`charge_payload()`](Self::charge_payload) to
    /// deserialize as [`PaymentPayload`].
    pub payload: serde_json::Value,
}

impl PaymentCredential {
    /// Create a new payment credential with a serializable payload.
    ///
    /// The payload is serialized to a JSON value. For charge intents, pass a
    /// [`PaymentPayload`]. For session intents, pass a `SessionCredentialPayload`.
    pub fn new(challenge: ChallengeEcho, payload: impl Serialize) -> Self {
        Self {
            challenge,
            source: None,
            payload: serde_json::to_value(payload).expect("payload must be serializable"),
        }
    }

    /// Create a new payment credential with a source DID and serializable payload.
    pub fn with_source(
        challenge: ChallengeEcho,
        source: impl Into<String>,
        payload: impl Serialize,
    ) -> Self {
        Self {
            challenge,
            source: Some(source.into()),
            payload: serde_json::to_value(payload).expect("payload must be serializable"),
        }
    }

    /// Deserialize the payload as a charge [`PaymentPayload`].
    ///
    /// Returns `Ok` if the payload has the expected `type`/`signature`/`hash` structure.
    pub fn charge_payload(&self) -> crate::error::Result<PaymentPayload> {
        serde_json::from_value(self.payload.clone()).map_err(|e| {
            crate::error::MppError::invalid_payload(format!("not a charge payload: {}", e))
        })
    }

    /// Parse a PaymentCredential from an Authorization header value.
    ///
    /// This is a convenience method equivalent to [`parse_authorization`](super::parse_authorization).
    pub fn from_header(header: &str) -> crate::error::Result<Self> {
        super::parse_authorization(header)
    }

    /// Deserialize the payload as a specific type.
    ///
    /// This is a generic accessor for method/intent-specific payload types.
    pub fn payload_as<T: serde::de::DeserializeOwned>(&self) -> crate::error::Result<T> {
        serde_json::from_value(self.payload.clone()).map_err(|e| {
            crate::error::MppError::invalid_payload(format!(
                "payload deserialization failed: {}",
                e
            ))
        })
    }

    /// Create a DID for an EVM address.
    ///
    /// Format: `did:pkh:eip155:{chain_id}:{address}`
    pub fn evm_did(chain_id: u64, address: &str) -> String {
        format!("did:pkh:eip155:{}:{}", chain_id, address)
    }
}

/// Payment receipt from server (parsed from Payment-Receipt header).
///
/// Per IETF spec, contains: status, method, timestamp, reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Receipt status ("success" or "failed")
    pub status: ReceiptStatus,

    /// Payment method used
    pub method: MethodName,

    /// Timestamp (ISO 8601)
    pub timestamp: String,

    /// Transaction hash or reference
    pub reference: String,
}

impl Receipt {
    /// Create a successful payment receipt.
    #[must_use]
    pub fn success(method: impl Into<MethodName>, reference: impl Into<String>) -> Self {
        Self {
            status: ReceiptStatus::Success,
            method: method.into(),
            timestamp: now_iso8601(),
            reference: reference.into(),
        }
    }

    /// Check if the payment was successful.
    pub fn is_success(&self) -> bool {
        self.status == ReceiptStatus::Success
    }

    /// Format as Payment-Receipt header value.
    pub fn to_header(&self) -> crate::error::Result<String> {
        super::format_receipt(self)
    }

    /// Parse a Receipt from a Payment-Receipt header value.
    ///
    /// This is a convenience method equivalent to [`parse_receipt`](super::parse_receipt).
    pub fn from_header(header: &str) -> crate::error::Result<Self> {
        super::parse_receipt(header)
    }

    /// Parse a Receipt from a response's Payment-Receipt header.
    ///
    /// Extracts the `Payment-Receipt` header value and parses it.
    ///
    /// # Arguments
    /// * `receipt_header` - The value of the Payment-Receipt header
    /// * `status_code` - The HTTP status code (must be 2xx for receipt)
    pub fn from_response(receipt_header: &str) -> crate::error::Result<Self> {
        Self::from_header(receipt_header)
    }
}

fn now_iso8601() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Extract the `txHash` field from a base64url-encoded receipt JSON.
///
/// The receipt is base64url-encoded JSON that may contain a `txHash` field
/// with the on-chain transaction hash.
pub fn extract_tx_hash(receipt_b64: &str) -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let decoded = URL_SAFE_NO_PAD.decode(receipt_b64.trim()).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    json.get("txHash")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_challenge() -> PaymentChallenge {
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
    fn test_payment_payload_constructors() {
        let tx = PaymentPayload::transaction("0xabc");
        assert_eq!(tx.payload_type(), PayloadType::Transaction);
        assert!(tx.is_transaction());
        assert_eq!(tx.data(), "0xabc");
        assert_eq!(tx.signed_tx(), Some("0xabc"));
        assert_eq!(tx.tx_hash(), None);

        let hash = PaymentPayload::hash("0xdef");
        assert_eq!(hash.payload_type(), PayloadType::Hash);
        assert!(hash.is_hash());
        assert_eq!(hash.tx_hash(), Some("0xdef"));
        assert_eq!(hash.data(), "0xdef");
        assert_eq!(hash.signed_tx(), None);
    }

    #[test]
    fn test_payment_payload_serialization() {
        // Transaction payload serializes with "signature" field per spec
        let tx = PaymentPayload::transaction("0xabc");
        let json = serde_json::to_string(&tx).unwrap();
        assert!(json.contains("\"signature\":\"0xabc\""));
        assert!(json.contains("\"type\":\"transaction\""));
        assert!(!json.contains("\"hash\""));

        // Hash payload serializes with "hash" field per spec
        let hash = PaymentPayload::hash("0xdef");
        let json = serde_json::to_string(&hash).unwrap();
        assert!(json.contains("\"hash\":\"0xdef\""));
        assert!(json.contains("\"type\":\"hash\""));
        assert!(!json.contains("\"signature\""));
    }

    #[test]
    fn test_payment_payload_deserialization() {
        // Hash payload requires "hash" field per IETF spec
        let hash_json = r#"{"type":"hash","hash":"0xdef123"}"#;
        let payload: PaymentPayload = serde_json::from_str(hash_json).unwrap();
        assert!(payload.is_hash());
        assert_eq!(payload.tx_hash(), Some("0xdef123"));

        // Transaction payload requires "signature" field per IETF spec
        let tx_json = r#"{"type":"transaction","signature":"0xabc456"}"#;
        let payload: PaymentPayload = serde_json::from_str(tx_json).unwrap();
        assert!(payload.is_transaction());
        assert_eq!(payload.signed_tx(), Some("0xabc456"));
    }

    #[test]
    fn test_payment_payload_strict_field_enforcement() {
        // hash payload with "signature" field should fail
        let bad_hash = r#"{"type":"hash","signature":"0xdef123"}"#;
        let result: Result<PaymentPayload, _> = serde_json::from_str(bad_hash);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash"));

        // transaction payload with "hash" field should fail
        let bad_tx = r#"{"type":"transaction","hash":"0xabc456"}"#;
        let result: Result<PaymentPayload, _> = serde_json::from_str(bad_tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }

    #[test]
    fn test_payment_credential_serialization() {
        let challenge = test_challenge();
        let credential = PaymentCredential::with_source(
            challenge.to_echo(),
            "did:pkh:eip155:42431:0x123",
            PaymentPayload::transaction("0xabc"),
        );

        let json = serde_json::to_string(&credential).unwrap();
        assert!(json.contains("\"id\":\"abc123\""));
        assert!(json.contains("did:pkh:eip155:42431:0x123"));
        assert!(json.contains("\"type\":\"transaction\""));
    }

    #[test]
    fn test_payment_credential_charge_payload() {
        let challenge = test_challenge();
        let credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdef"));

        let payload = credential.charge_payload().unwrap();
        assert!(payload.is_hash());
        assert_eq!(payload.tx_hash(), Some("0xdef"));
    }

    #[test]
    fn test_payment_credential_arbitrary_json_payload() {
        let challenge = test_challenge();
        let payload_json = serde_json::json!({
            "action": "voucher",
            "channelId": "0xabc",
            "cumulativeAmount": "5000",
            "signature": "0xdef"
        });
        let credential = PaymentCredential::new(challenge.to_echo(), payload_json.clone());

        assert_eq!(credential.payload, payload_json);

        // charge_payload should fail for non-charge payloads
        assert!(credential.charge_payload().is_err());
    }

    #[test]
    fn test_payment_credential_payload_as() {
        let challenge = test_challenge();
        let credential =
            PaymentCredential::new(challenge.to_echo(), PaymentPayload::transaction("0xabc"));

        let payload: PaymentPayload = credential.payload_as().unwrap();
        assert!(payload.is_transaction());
        assert_eq!(payload.signed_tx(), Some("0xabc"));
    }

    #[test]
    fn test_evm_did() {
        let did = PaymentCredential::evm_did(42431, "0x1234abcd");
        assert_eq!(did, "did:pkh:eip155:42431:0x1234abcd");
    }

    #[test]
    fn test_payment_receipt_status() {
        let success = Receipt {
            status: ReceiptStatus::Success,
            method: "tempo".into(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            reference: "0xabc".to_string(),
        };
        assert!(success.is_success());
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
    fn test_credential_from_header() {
        let challenge = test_challenge();
        let credential = PaymentCredential::with_source(
            challenge.to_echo(),
            "did:pkh:eip155:42431:0x123",
            PaymentPayload::transaction("0xabc"),
        );
        let header = crate::protocol::core::format_authorization(&credential).unwrap();
        let parsed = PaymentCredential::from_header(&header).unwrap();
        assert_eq!(parsed.challenge.id, "abc123");
    }

    #[test]
    fn test_receipt_from_header() {
        let receipt = Receipt::success("tempo", "0xabc123");
        let header = receipt.to_header().unwrap();
        let parsed = Receipt::from_header(&header).unwrap();
        assert!(parsed.is_success());
        assert_eq!(parsed.reference, "0xabc123");
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
        };

        assert!(challenge.verify(secret));
    }

    #[test]
    fn test_compute_challenge_id_cross_sdk() {
        // This test vector matches the cross-SDK conformance tests
        let id = compute_challenge_id(
            "test-secret-key-12345",
            "api.example.com",
            "tempo",
            "charge",
            &crate::protocol::core::base64url_encode(
                br#"{"amount":"1000000","currency":"0x20c0000000000000000000000000000000000000","recipient":"0x1234567890abcdef1234567890abcdef12345678"}"#,
            ),
            None,
            None,
            None,
        );
        assert_eq!(id, "XmJ98SdsAdzwP9Oa-8In322Uh6yweMO6rywdomWk_V4");
    }

    /// Cross-SDK golden vectors (shared with mppx and pympp).
    ///
    /// HMAC input: realm | method | intent | base64url(canonicalize(request)) | expires | digest | opaque
    /// HMAC key:   UTF-8 bytes of secret_key ("test-vector-secret")
    /// Output:     base64url(HMAC-SHA256(key, input), no padding)
    ///
    /// These vectors cover every combination of optional HMAC fields (expires, digest)
    /// and variations in each required field (realm, method, intent, request).
    #[test]
    fn test_golden_vectors() {
        use crate::protocol::core::base64url_encode as b64;
        let secret = "test-vector-secret";

        let req_amount = b64(br#"{"amount":"1000000"}"#);
        let req_multi = b64(br#"{"amount":"1000000","currency":"0x1234","recipient":"0xabcd"}"#);
        let req_nested =
            b64(br#"{"amount":"1000000","currency":"0x1234","methodDetails":{"chainId":42431}}"#);
        let req_empty = b64(br#"{}"#);

        #[allow(clippy::type_complexity)]
        let vectors: Vec<(
            &str,
            &str,
            &str,
            &str,
            &str,
            Option<&str>,
            Option<&str>,
            &str,
        )> = vec![
            (
                "required fields only",
                "api.example.com",
                "tempo",
                "charge",
                &req_amount,
                None,
                None,
                "X6v1eo7fJ76gAxqY0xN9Jd__4lUyDDYmriryOM-5FO4",
            ),
            (
                "with expires",
                "api.example.com",
                "tempo",
                "charge",
                &req_amount,
                Some("2025-01-06T12:00:00Z"),
                None,
                "ChPX33RkKSZoSUyZcu8ai4hhkvjZJFkZVnvWs5s0iXI",
            ),
            (
                "with digest",
                "api.example.com",
                "tempo",
                "charge",
                &req_amount,
                None,
                Some("sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE"),
                "JHB7EFsPVb-xsYCo8LHcOzeX1gfXWVoUSzQsZhKAfKM",
            ),
            (
                "with expires and digest",
                "api.example.com",
                "tempo",
                "charge",
                &req_amount,
                Some("2025-01-06T12:00:00Z"),
                Some("sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE"),
                "m39jbWWCIfmfJZSwCfvKFFtBl0Qwf9X4nOmDb21peLA",
            ),
            (
                "multi-field request",
                "api.example.com",
                "tempo",
                "charge",
                &req_multi,
                None,
                None,
                "_H5TOnnlW0zduQ5OhQ3EyLVze_TqxLDPda2CGZPZxOc",
            ),
            (
                "nested methodDetails",
                "api.example.com",
                "tempo",
                "charge",
                &req_nested,
                None,
                None,
                "TqujwpuDDg_zsWGINAd5XObO2rRe6uYufpqvtDmr6N8",
            ),
            (
                "empty request",
                "api.example.com",
                "tempo",
                "charge",
                &req_empty,
                None,
                None,
                "yLN7yChAejW9WNmb54HpJIWpdb1WWXeA3_aCx4dxmkU",
            ),
            (
                "different realm",
                "payments.other.com",
                "tempo",
                "charge",
                &req_amount,
                None,
                None,
                "3F5bOo2a9RUihdwKk4hGRvBvzQmVPBMDvW0YM-8GD00",
            ),
            (
                "different method",
                "api.example.com",
                "stripe",
                "charge",
                &req_amount,
                None,
                None,
                "o0ra2sd7HcB4Ph0Vns69gRDUhSj5WNOnUopcDqKPLz4",
            ),
            (
                "different intent",
                "api.example.com",
                "tempo",
                "session",
                &req_amount,
                None,
                None,
                "aAY7_IEDzsznNYplhOSE8cERQxvjFcT4Lcn-7FHjLVE",
            ),
        ];

        for (label, realm, method, intent, request, expires, digest, expected) in &vectors {
            let id = compute_challenge_id(
                secret, realm, method, intent, request, *expires, *digest, None,
            );
            assert_eq!(&id, expected, "golden vector failed: {}", label);
        }
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
    fn test_compute_challenge_id_deterministic() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();

        let id1 = compute_challenge_id(
            "secret",
            "api",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );
        let id2 = compute_challenge_id(
            "secret",
            "api",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_challenge_id_different_secrets() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();

        let id1 = compute_challenge_id(
            "secret-a",
            "api",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );
        let id2 = compute_challenge_id(
            "secret-b",
            "api",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );

        assert_ne!(id1, id2);
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
        );
        assert!(challenge.verify("my-secret"));
        assert_eq!(challenge.expires.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(challenge.digest.as_deref(), Some("sha-256=abc"));
        assert_eq!(challenge.description.as_deref(), Some("test payment"));
    }

    #[test]
    fn test_opaque_affects_challenge_id() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();
        let id_without = compute_challenge_id(
            "test-secret",
            "api.example.com",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );
        let opaque =
            Base64UrlJson::from_value(&serde_json::json!({"pi": "pi_3abc123XYZ"})).unwrap();
        let id_with = compute_challenge_id(
            "test-secret",
            "api.example.com",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            Some(opaque.raw()),
        );
        assert_ne!(id_without, id_with);
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
        );
        let echo = challenge.to_echo();
        assert_eq!(
            echo.opaque.as_ref().map(|o| o.raw()),
            Some(opaque_raw.as_str())
        );
    }

    /// Cross-SDK opaque golden vectors (computed from mppx reference SDK).
    ///
    /// These vectors verify that opaque (meta) data produces identical HMAC
    /// challenge IDs across mpp-rs and mppx. The opaque value is JCS-serialized
    /// then base64url-encoded before entering the HMAC computation.
    #[test]
    fn test_opaque_golden_vectors() {
        let secret = "test-vector-secret";
        let req = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();

        // Vector 1: with opaque {pi: "pi_3abc123XYZ"}
        let opaque1 =
            Base64UrlJson::from_value(&serde_json::json!({"pi": "pi_3abc123XYZ"})).unwrap();
        let id1 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            req.raw(),
            None,
            None,
            Some(opaque1.raw()),
        );
        assert_eq!(
            id1, "rxzKZ2qjXvinqCH96RORTZEPs1KXsA-0AUjrCAPFOWc",
            "opaque golden vector failed: with opaque"
        );

        // Vector 2: with opaque and expires
        let id2 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            req.raw(),
            Some("2025-01-06T12:00:00Z"),
            None,
            Some(opaque1.raw()),
        );
        assert_eq!(
            id2, "KAfoMrA4fnzS1DPWN_cUv_b3_yHxCizdp6OhH7gluMY",
            "opaque golden vector failed: with opaque and expires"
        );

        // Vector 3: with empty opaque {}
        let opaque_empty = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let id3 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            req.raw(),
            None,
            None,
            Some(opaque_empty.raw()),
        );
        assert_eq!(
            id3, "vb4IyH-0LdJ3s7L0QAw8jIzcZkyxksPhIvEfmHmzA9k",
            "opaque golden vector failed: with empty opaque"
        );

        // Vector 4: with multi-key opaque (JCS sorts keys alphabetically)
        let opaque_multi = Base64UrlJson::from_value(
            &serde_json::json!({"deposit": "dep_456", "pi": "pi_3abc123XYZ"}),
        )
        .unwrap();
        let id4 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            req.raw(),
            None,
            None,
            Some(opaque_multi.raw()),
        );
        assert_eq!(
            id4, "aKskU8sadR5ZuFbUCsIwhO-ENxuVpTw17FdwHEXsJDk",
            "opaque golden vector failed: with multi-key opaque"
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
    fn test_extract_tx_hash_valid() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let json = serde_json::json!({"txHash": "0xabc123", "status": "success"});
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        assert_eq!(extract_tx_hash(&encoded), Some("0xabc123".to_string()));
    }

    #[test]
    fn test_extract_tx_hash_missing() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let json = serde_json::json!({"status": "success"});
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        assert_eq!(extract_tx_hash(&encoded), None);
    }

    #[test]
    fn test_extract_tx_hash_empty() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let json = serde_json::json!({"txHash": ""});
        let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json).unwrap());
        assert_eq!(extract_tx_hash(&encoded), None);
    }

    #[test]
    fn test_extract_tx_hash_invalid_base64() {
        assert_eq!(extract_tx_hash("not-valid-base64!!!"), None);
    }

    #[test]
    fn test_extract_tx_hash_invalid_json() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let encoded = URL_SAFE_NO_PAD.encode(b"not json");
        assert_eq!(extract_tx_hash(&encoded), None);
    }
}
