//! Payment credential and charge payload.

use serde::{Deserialize, Serialize};

use super::challenge::ChallengeEcho;
use super::types::PayloadType;

/// Payment payload in credential.
///
/// Contains the signed transaction, typed proof, or transaction hash.
///
/// Per IETF spec (Tempo §5.1-5.2):
/// - `type="transaction"` uses field `signature` containing the signed transaction
/// - `type="proof"` uses field `signature` containing the signed typed proof
/// - `type="hash"` uses field `hash` containing the transaction hash
#[derive(Debug, Clone)]
pub struct PaymentPayload {
    /// Payload type: "transaction", "proof", or "hash"
    pub payload_type: PayloadType,

    /// Hex-encoded signed data.
    ///
    /// For `type="transaction"`: the RLP-encoded signed transaction to broadcast.
    /// For `type="proof"`: the EIP-712 signature for the challenge proof.
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
            PayloadType::Transaction | PayloadType::Proof => {
                state.serialize_field("signature", &self.data)?
            }
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
            PayloadType::Transaction | PayloadType::Proof => raw.signature.ok_or_else(|| {
                serde::de::Error::custom(format!(
                    "{} payload requires 'signature' field",
                    raw.payload_type
                ))
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

    /// Create a new proof payload.
    pub fn proof(signature: impl Into<String>) -> Self {
        Self {
            payload_type: PayloadType::Proof,
            data: signature.into(),
        }
    }

    /// Get the payload type.
    pub fn payload_type(&self) -> PayloadType {
        self.payload_type.clone()
    }

    /// Get the underlying data (works for both transaction and hash payloads).
    ///
    /// For transaction payloads, this is the signed transaction bytes.
    /// For proof payloads, this is the proof signature.
    /// For hash payloads, this is the transaction hash.
    ///
    /// Prefer using `tx_hash()`, `signed_tx()`, or `proof_signature()` for type-safe access.
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

    /// Get the proof signature (for proof payloads).
    ///
    /// Returns the proof signature if this is a proof payload, None otherwise.
    pub fn proof_signature(&self) -> Option<&str> {
        if self.payload_type == PayloadType::Proof {
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

    /// Check if this is a proof payload.
    pub fn is_proof(&self) -> bool {
        self.payload_type == PayloadType::Proof
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::challenge::tests::test_challenge;

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

        let proof = PaymentPayload::proof("0x123");
        assert_eq!(proof.payload_type(), PayloadType::Proof);
        assert!(proof.is_proof());
        assert_eq!(proof.proof_signature(), Some("0x123"));
        assert_eq!(proof.data(), "0x123");
        assert_eq!(proof.signed_tx(), None);
        assert_eq!(proof.tx_hash(), None);
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

        let proof = PaymentPayload::proof("0x123");
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"signature\":\"0x123\""));
        assert!(json.contains("\"type\":\"proof\""));
        assert!(!json.contains("\"hash\""));
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

        let proof_json = r#"{"type":"proof","signature":"0x123456"}"#;
        let payload: PaymentPayload = serde_json::from_str(proof_json).unwrap();
        assert!(payload.is_proof());
        assert_eq!(payload.proof_signature(), Some("0x123456"));
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

        let bad_proof = r#"{"type":"proof","hash":"0x123456"}"#;
        let result: Result<PaymentPayload, _> = serde_json::from_str(bad_proof);
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
}
