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
/// use mpay::protocol::core::{PaymentChallenge, parse_www_authenticate};
/// use mpay::protocol::intents::ChargeRequest;
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
}

impl PaymentChallenge {
    /// Get the effective expiration time for this payment challenge.
    ///
    /// Returns `challenge.expires` if set. Callers should also check
    /// the intent-specific request (e.g., `ChargeRequest.expires`).
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
            request: self.request.raw().to_string(),
            expires: self.expires.clone(),
            digest: self.digest.clone(),
        }
    }

    /// Format as WWW-Authenticate header value.
    pub fn to_header(&self) -> crate::error::Result<String> {
        super::format_www_authenticate(self)
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
    pub request: String,

    /// Challenge expiration time (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,

    /// Request body digest for body binding (RFC 9530 Content-Digest)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentCredential {
    /// Echo of challenge parameters from server
    pub challenge: ChallengeEcho,

    /// Payer identifier (DID format: did:pkh:eip155:chainId:address)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Payment payload
    pub payload: PaymentPayload,
}

impl PaymentCredential {
    /// Create a new payment credential.
    pub fn new(challenge: ChallengeEcho, payload: PaymentPayload) -> Self {
        Self {
            challenge,
            source: None,
            payload,
        }
    }

    /// Create a new payment credential with a source DID.
    pub fn with_source(
        challenge: ChallengeEcho,
        source: impl Into<String>,
        payload: PaymentPayload,
    ) -> Self {
        Self {
            challenge,
            source: Some(source.into()),
            payload,
        }
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

    /// Error message (optional, for failed payments)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Receipt {
    /// Create a successful payment receipt.
    pub fn success(method: impl Into<MethodName>, reference: impl Into<String>) -> Self {
        Self {
            status: ReceiptStatus::Success,
            method: method.into(),
            timestamp: now_iso8601(),
            reference: reference.into(),
            error: None,
        }
    }

    /// Create a failed payment receipt.
    pub fn failed(method: impl Into<MethodName>, error_msg: &str) -> Self {
        Self {
            status: ReceiptStatus::Failed,
            method: method.into(),
            timestamp: now_iso8601(),
            reference: String::new(),
            error: Some(error_msg.to_string()),
        }
    }

    /// Check if the payment was successful.
    pub fn is_success(&self) -> bool {
        self.status == ReceiptStatus::Success
    }

    /// Check if the payment failed.
    pub fn is_failed(&self) -> bool {
        self.status == ReceiptStatus::Failed
    }

    /// Format as Payment-Receipt header value.
    pub fn to_header(&self) -> crate::error::Result<String> {
        super::format_receipt(self)
    }
}

fn now_iso8601() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    OffsetDateTime::now_utc()
        .format(&Iso8601::DEFAULT)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
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
        assert_eq!(echo.request, challenge.request.raw());
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
            error: None,
        };
        assert!(success.is_success());
        assert!(!success.is_failed());

        let failed = Receipt {
            status: ReceiptStatus::Failed,
            method: "tempo".into(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            reference: "".to_string(),
            error: Some("Payment failed".to_string()),
        };
        assert!(!failed.is_success());
        assert!(failed.is_failed());
    }
}
