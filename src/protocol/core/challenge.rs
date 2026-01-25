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

    /// Content digest for body binding (RFC 9530)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

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
            digest: self.digest.clone(),
            expires: self.expires.clone(),
        }
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

    /// Content digest for body binding (RFC 9530)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// Challenge expiration time (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

/// Payment payload in credential.
///
/// Contains the signed transaction or authorization signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPayload {
    /// Signature (hex-encoded signed transaction or authorization)
    pub signature: String,

    /// Payload type (defaults to "transaction" if not specified)
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub payload_type: Option<PayloadType>,
}

impl PaymentPayload {
    /// Create a new transaction payload.
    pub fn transaction(signature: impl Into<String>) -> Self {
        Self {
            signature: signature.into(),
            payload_type: Some(PayloadType::Transaction),
        }
    }

    /// Create a new hash payload (already broadcast).
    pub fn hash(tx_hash: impl Into<String>) -> Self {
        Self {
            signature: tx_hash.into(),
            payload_type: Some(PayloadType::Hash),
        }
    }

    /// Get the effective payload type.
    pub fn effective_type(&self) -> PayloadType {
        self.payload_type.clone().unwrap_or_default()
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// Receipt status
    pub status: ReceiptStatus,

    /// Payment method used
    pub method: MethodName,

    /// Timestamp (ISO 8601)
    pub timestamp: String,

    /// Transaction hash or reference
    pub reference: String,

    /// Block number (optional)
    #[serde(rename = "blockNumber", skip_serializing_if = "Option::is_none")]
    pub block_number: Option<String>,

    /// Error message if failed (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl PaymentReceipt {
    /// Check if the payment was successful.
    pub fn is_success(&self) -> bool {
        self.status == ReceiptStatus::Success
    }

    /// Check if the payment failed.
    pub fn is_failed(&self) -> bool {
        self.status == ReceiptStatus::Failed
    }
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
            digest: None,
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
        assert_eq!(tx.effective_type(), PayloadType::Transaction);

        let hash = PaymentPayload::hash("0xdef");
        assert_eq!(hash.effective_type(), PayloadType::Hash);
    }

    #[test]
    fn test_payment_credential_serialization() {
        let challenge = test_challenge();
        let credential = PaymentCredential::with_source(
            challenge.to_echo(),
            "did:pkh:eip155:88153:0x123",
            PaymentPayload::transaction("0xabc"),
        );

        let json = serde_json::to_string(&credential).unwrap();
        assert!(json.contains("\"id\":\"abc123\""));
        assert!(json.contains("did:pkh:eip155:88153:0x123"));
        assert!(json.contains("\"type\":\"transaction\""));
    }

    #[test]
    fn test_evm_did() {
        let did = PaymentCredential::evm_did(88153, "0x1234abcd");
        assert_eq!(did, "did:pkh:eip155:88153:0x1234abcd");
    }

    #[test]
    fn test_payment_receipt_status() {
        let success = PaymentReceipt {
            status: ReceiptStatus::Success,
            method: "tempo".into(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            reference: "0xabc".to_string(),
            block_number: Some("12345".to_string()),
            error: None,
        };
        assert!(success.is_success());
        assert!(!success.is_failed());

        let failed = PaymentReceipt {
            status: ReceiptStatus::Failed,
            method: "tempo".into(),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            reference: "".to_string(),
            block_number: None,
            error: Some("Insufficient funds".to_string()),
        };
        assert!(!failed.is_success());
        assert!(failed.is_failed());
    }
}
