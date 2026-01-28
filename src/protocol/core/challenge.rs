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
}

/// Payment payload in credential.
///
/// Contains the signed transaction or transaction hash. Per the IETF spec,
/// the field name depends on the payload type:
/// - `type="transaction"`: uses `signature` field (hex-encoded signed transaction)
/// - `type="hash"`: uses `hash` field (transaction hash, already broadcast)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PaymentPayload {
    /// Signed transaction payload (to be broadcast by server)
    Transaction {
        /// Hex-encoded signed transaction
        signature: String,
        /// Payload type
        #[serde(rename = "type")]
        payload_type: PayloadType,
    },
    /// Transaction hash payload (already broadcast by client)
    Hash {
        /// Transaction hash with 0x prefix
        hash: String,
        /// Payload type
        #[serde(rename = "type")]
        payload_type: PayloadType,
    },
}

impl PaymentPayload {
    /// Create a new transaction payload.
    pub fn transaction(signature: impl Into<String>) -> Self {
        Self::Transaction {
            signature: signature.into(),
            payload_type: PayloadType::Transaction,
        }
    }

    /// Create a new hash payload (already broadcast).
    pub fn hash(tx_hash: impl Into<String>) -> Self {
        Self::Hash {
            hash: tx_hash.into(),
            payload_type: PayloadType::Hash,
        }
    }

    /// Get the payload type.
    pub fn payload_type(&self) -> PayloadType {
        match self {
            Self::Transaction { payload_type, .. } => payload_type.clone(),
            Self::Hash { payload_type, .. } => payload_type.clone(),
        }
    }

    /// Get the signature (for transaction payloads).
    pub fn signature(&self) -> Option<&str> {
        match self {
            Self::Transaction { signature, .. } => Some(signature),
            Self::Hash { .. } => None,
        }
    }

    /// Get the hash (for hash payloads).
    pub fn tx_hash(&self) -> Option<&str> {
        match self {
            Self::Transaction { .. } => None,
            Self::Hash { hash, .. } => Some(hash),
        }
    }

    /// Check if this is a transaction payload.
    pub fn is_transaction(&self) -> bool {
        matches!(self, Self::Transaction { .. })
    }

    /// Check if this is a hash payload.
    pub fn is_hash(&self) -> bool {
        matches!(self, Self::Hash { .. })
    }

    /// Get the transaction reference (hash or signature).
    ///
    /// Returns the tx hash for hash payloads, or the signature for transaction payloads.
    pub fn reference(&self) -> &str {
        match self {
            Self::Hash { hash, .. } => hash,
            Self::Transaction { signature, .. } => signature,
        }
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
        assert_eq!(tx.signature(), Some("0xabc"));
        assert_eq!(tx.tx_hash(), None);

        let hash = PaymentPayload::hash("0xdef");
        assert_eq!(hash.payload_type(), PayloadType::Hash);
        assert!(hash.is_hash());
        assert_eq!(hash.tx_hash(), Some("0xdef"));
        assert_eq!(hash.signature(), None);
    }

    #[test]
    fn test_payment_payload_serialization() {
        // Transaction payload should serialize with "signature" field
        let tx = PaymentPayload::transaction("0xabc");
        let json = serde_json::to_string(&tx).unwrap();
        assert!(json.contains("\"signature\":\"0xabc\""));
        assert!(json.contains("\"type\":\"transaction\""));
        assert!(!json.contains("\"hash\""));

        // Hash payload should serialize with "hash" field (per IETF spec)
        let hash = PaymentPayload::hash("0xdef");
        let json = serde_json::to_string(&hash).unwrap();
        assert!(json.contains("\"hash\":\"0xdef\""));
        assert!(json.contains("\"type\":\"hash\""));
        assert!(!json.contains("\"signature\""));
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
