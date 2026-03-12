//! MCP (Model Context Protocol) support for Web Payment Auth.
//!
//! Provides types and helpers for integrating payment challenges and credentials
//! into MCP JSON-RPC messages. Works with any MCP SDK — uses `serde_json::Value`
//! for maximum flexibility.
//!
//! # Constants
//!
//! - [`PAYMENT_REQUIRED_CODE`]: JSON-RPC error code for payment required (-32042)
//! - [`PAYMENT_VERIFICATION_FAILED_CODE`]: JSON-RPC error code for verification failed (-32043)
//! - [`CREDENTIAL_META_KEY`]: Metadata key for credentials in `_meta`
//! - [`RECEIPT_META_KEY`]: Metadata key for receipts in `_meta`
//!
//! # Server-side
//!
//! - [`extract_credential`]: Extract a payment credential from MCP request `_meta`
//! - [`payment_required_error`]: Create an MCP payment-required error
//! - [`attach_receipt`]: Attach a receipt to an MCP result's `_meta`
//!
//! # Client-side
//!
//! - [`is_payment_required`]: Check if a JSON-RPC error indicates payment required
//! - [`extract_challenges`]: Extract challenges from a payment-required error
//! - [`attach_credential`]: Attach a credential to MCP request params `_meta`
//!
//! # Example (server)
//!
//! ```
//! use mpp::mcp;
//! use mpp::{PaymentChallenge, Receipt};
//! use serde_json::json;
//!
//! // Extract credential from incoming request
//! let meta = json!({});
//! let credential = mcp::extract_credential(&meta);
//! assert!(credential.is_none());
//!
//! // Build a payment-required error
//! let challenge = PaymentChallenge::new(
//!     "ch_123", "api.example.com", "tempo", "charge",
//!     mpp::Base64UrlJson::from_value(&json!({"amount": "1000"})).unwrap(),
//! );
//! let error = mcp::payment_required_error(&challenge);
//! assert_eq!(error.code, mcp::PAYMENT_REQUIRED_CODE);
//! ```

use serde::{Deserialize, Serialize};

use crate::protocol::core::challenge::{PaymentChallenge, PaymentCredential, Receipt};

// ==================== Constants ====================

/// MCP JSON-RPC error code for payment required.
pub const PAYMENT_REQUIRED_CODE: i32 = -32042;

/// MCP JSON-RPC error code for payment verification failed.
pub const PAYMENT_VERIFICATION_FAILED_CODE: i32 = -32043;

/// MCP metadata key for credentials.
pub const CREDENTIAL_META_KEY: &str = "org.paymentauth/credential";

/// MCP metadata key for receipts.
pub const RECEIPT_META_KEY: &str = "org.paymentauth/receipt";

// ==================== Types ====================

/// MCP receipt (extends core Receipt with MCP-specific fields).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpReceipt {
    #[serde(flatten)]
    pub receipt: Receipt,
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
}

/// MCP error object for payment-required responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPaymentError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<McpPaymentErrorData>,
}

/// Data payload within an MCP payment-required error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPaymentErrorData {
    #[serde(rename = "httpStatus")]
    pub http_status: u16,
    pub challenges: Vec<PaymentChallenge>,
    /// RFC 9457 Problem Details for rich error context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<crate::error::PaymentErrorDetails>,
}

// ==================== Server-side helpers ====================

/// Extract a payment credential from MCP request metadata (`_meta`).
///
/// Expects the `_meta` object (not the full params). Returns `None` if the
/// credential key is missing or the value cannot be deserialized.
pub fn extract_credential(meta: &serde_json::Value) -> Option<PaymentCredential> {
    let cred_value = meta.get(CREDENTIAL_META_KEY)?;
    serde_json::from_value(cred_value.clone()).ok()
}

/// Create an MCP payment-required error response.
pub fn payment_required_error(challenge: &PaymentChallenge) -> McpPaymentError {
    McpPaymentError {
        code: PAYMENT_REQUIRED_CODE,
        message: "Payment Required".to_string(),
        data: Some(McpPaymentErrorData {
            http_status: 402,
            challenges: vec![challenge.clone()],
            problem: None,
        }),
    }
}

/// Attach a receipt to an MCP result's `_meta`.
///
/// Inserts (or creates) the `_meta` object on `result` and sets
/// the receipt under [`RECEIPT_META_KEY`].
pub fn attach_receipt(result: &mut serde_json::Value, receipt: &Receipt, challenge_id: &str) {
    let mcp_receipt = McpReceipt {
        receipt: receipt.clone(),
        challenge_id: challenge_id.to_string(),
    };
    let receipt_value =
        serde_json::to_value(&mcp_receipt).expect("McpReceipt must be serializable");

    let meta = result
        .as_object_mut()
        .expect("result must be a JSON object")
        .entry("_meta")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

    meta.as_object_mut()
        .expect("_meta must be a JSON object")
        .insert(RECEIPT_META_KEY.to_string(), receipt_value);
}

// ==================== Client-side helpers ====================

/// Check if an MCP JSON-RPC error response indicates payment required.
///
/// Returns `true` if `error.code` equals [`PAYMENT_REQUIRED_CODE`].
pub fn is_payment_required(error: &serde_json::Value) -> bool {
    error
        .get("code")
        .and_then(|c| c.as_i64())
        .is_some_and(|c| c == PAYMENT_REQUIRED_CODE as i64)
}

/// Extract challenges from an MCP payment-required error.
///
/// Returns `None` if the error has no `data.challenges` array or
/// if deserialization fails.
pub fn extract_challenges(error: &serde_json::Value) -> Option<Vec<PaymentChallenge>> {
    let challenges_value = error.get("data")?.get("challenges")?;
    serde_json::from_value(challenges_value.clone()).ok()
}

/// Attach a credential to MCP request `params._meta`.
///
/// Inserts (or creates) `params._meta` and sets the credential
/// under [`CREDENTIAL_META_KEY`].
pub fn attach_credential(params: &mut serde_json::Value, credential: &PaymentCredential) {
    let cred_value =
        serde_json::to_value(credential).expect("PaymentCredential must be serializable");

    let meta = params
        .as_object_mut()
        .expect("params must be a JSON object")
        .entry("_meta")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));

    meta.as_object_mut()
        .expect("_meta must be a JSON object")
        .insert(CREDENTIAL_META_KEY.to_string(), cred_value);
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::challenge::{ChallengeEcho, PaymentPayload};
    use crate::protocol::core::types::Base64UrlJson;
    use serde_json::json;

    fn test_challenge() -> PaymentChallenge {
        PaymentChallenge::new(
            "ch_test_123",
            "api.example.com",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&json!({"amount": "1000", "currency": "USD"})).unwrap(),
        )
    }

    fn test_credential() -> PaymentCredential {
        PaymentCredential::with_source(
            ChallengeEcho {
                id: "ch_test_123".to_string(),
                realm: "api.example.com".to_string(),
                method: "tempo".into(),
                intent: "charge".into(),
                request: Base64UrlJson::from_raw("eyJhbW91bnQiOiIxMDAwIn0"),
                expires: None,
                digest: None,
                opaque: None,
            },
            "did:pkh:eip155:42161:0xabc",
            PaymentPayload::transaction("0xdeadbeef"),
        )
    }

    fn test_receipt() -> Receipt {
        Receipt::success("tempo", "0xtxhash123")
    }

    // ---- McpPaymentError serde round-trip ----

    #[test]
    fn test_mcp_payment_error_roundtrip() {
        let challenge = test_challenge();
        let error = payment_required_error(&challenge);

        let json = serde_json::to_string(&error).unwrap();
        let parsed: McpPaymentError = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.code, PAYMENT_REQUIRED_CODE);
        assert_eq!(parsed.message, "Payment Required");
        let data = parsed.data.unwrap();
        assert_eq!(data.http_status, 402);
        assert_eq!(data.challenges.len(), 1);
        assert_eq!(data.challenges[0].id, "ch_test_123");
    }

    #[test]
    fn test_mcp_payment_error_without_data() {
        let error = McpPaymentError {
            code: PAYMENT_REQUIRED_CODE,
            message: "Payment Required".to_string(),
            data: None,
        };
        let json = serde_json::to_string(&error).unwrap();
        let parsed: McpPaymentError = serde_json::from_str(&json).unwrap();
        assert!(parsed.data.is_none());
    }

    // ---- extract_credential ----

    #[test]
    fn test_extract_credential_valid() {
        let cred = test_credential();
        let meta = json!({
            CREDENTIAL_META_KEY: cred,
        });
        let extracted = extract_credential(&meta).unwrap();
        assert_eq!(extracted.challenge.id, "ch_test_123");
        assert_eq!(
            extracted.source.as_deref(),
            Some("did:pkh:eip155:42161:0xabc")
        );
    }

    #[test]
    fn test_extract_credential_missing() {
        let meta = json!({});
        assert!(extract_credential(&meta).is_none());
    }

    #[test]
    fn test_extract_credential_malformed() {
        let meta = json!({
            CREDENTIAL_META_KEY: "not-a-valid-credential",
        });
        assert!(extract_credential(&meta).is_none());
    }

    #[test]
    fn test_extract_credential_null_value() {
        let meta = json!({
            CREDENTIAL_META_KEY: null,
        });
        assert!(extract_credential(&meta).is_none());
    }

    // ---- payment_required_error ----

    #[test]
    fn test_payment_required_error_construction() {
        let challenge = test_challenge();
        let error = payment_required_error(&challenge);

        assert_eq!(error.code, PAYMENT_REQUIRED_CODE);
        assert_eq!(error.message, "Payment Required");
        let data = error.data.as_ref().unwrap();
        assert_eq!(data.http_status, 402);
        assert_eq!(data.challenges.len(), 1);
        assert_eq!(data.challenges[0].method.as_str(), "tempo");
        assert_eq!(data.challenges[0].intent.as_str(), "charge");
    }

    // ---- attach_receipt ----

    #[test]
    fn test_attach_receipt_to_empty_result() {
        let receipt = test_receipt();
        let mut result = json!({});
        attach_receipt(&mut result, &receipt, "ch_test_123");

        let meta = result.get("_meta").unwrap();
        let mcp_receipt = meta.get(RECEIPT_META_KEY).unwrap();
        assert_eq!(mcp_receipt["status"], "success");
        assert_eq!(mcp_receipt["method"], "tempo");
        assert_eq!(mcp_receipt["reference"], "0xtxhash123");
        assert_eq!(mcp_receipt["challengeId"], "ch_test_123");
    }

    #[test]
    fn test_attach_receipt_preserves_existing_meta() {
        let receipt = test_receipt();
        let mut result = json!({
            "_meta": {
                "other_key": "other_value"
            },
            "content": [{"type": "text", "text": "hello"}]
        });
        attach_receipt(&mut result, &receipt, "ch_456");

        let meta = result.get("_meta").unwrap();
        assert_eq!(meta["other_key"], "other_value");
        assert!(meta.get(RECEIPT_META_KEY).is_some());
        // Original content preserved
        assert_eq!(result["content"][0]["text"], "hello");
    }

    #[test]
    fn test_attach_receipt_deserializes_as_mcp_receipt() {
        let receipt = test_receipt();
        let mut result = json!({});
        attach_receipt(&mut result, &receipt, "ch_789");

        let receipt_value = result["_meta"][RECEIPT_META_KEY].clone();
        let mcp_receipt: McpReceipt = serde_json::from_value(receipt_value).unwrap();
        assert_eq!(mcp_receipt.challenge_id, "ch_789");
        assert!(mcp_receipt.receipt.is_success());
    }

    // ---- is_payment_required ----

    #[test]
    fn test_is_payment_required_matching() {
        let error = json!({
            "code": PAYMENT_REQUIRED_CODE,
            "message": "Payment Required"
        });
        assert!(is_payment_required(&error));
    }

    #[test]
    fn test_is_payment_required_wrong_code() {
        let error = json!({
            "code": -32600,
            "message": "Invalid Request"
        });
        assert!(!is_payment_required(&error));
    }

    #[test]
    fn test_is_payment_required_verification_failed_code() {
        let error = json!({
            "code": PAYMENT_VERIFICATION_FAILED_CODE,
            "message": "Payment Verification Failed"
        });
        assert!(!is_payment_required(&error));
    }

    #[test]
    fn test_is_payment_required_no_code() {
        let error = json!({"message": "something"});
        assert!(!is_payment_required(&error));
    }

    // ---- extract_challenges ----

    #[test]
    fn test_extract_challenges_valid() {
        let challenge = test_challenge();
        let error = json!({
            "code": PAYMENT_REQUIRED_CODE,
            "message": "Payment Required",
            "data": {
                "httpStatus": 402,
                "challenges": [challenge]
            }
        });
        let challenges = extract_challenges(&error).unwrap();
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].id, "ch_test_123");
    }

    #[test]
    fn test_extract_challenges_no_data() {
        let error = json!({
            "code": PAYMENT_REQUIRED_CODE,
            "message": "Payment Required"
        });
        assert!(extract_challenges(&error).is_none());
    }

    #[test]
    fn test_extract_challenges_no_challenges_field() {
        let error = json!({
            "code": PAYMENT_REQUIRED_CODE,
            "data": {"httpStatus": 402}
        });
        assert!(extract_challenges(&error).is_none());
    }

    #[test]
    fn test_extract_challenges_multiple() {
        let c1 = test_challenge();
        let mut c2 = test_challenge();
        c2.id = "ch_test_456".to_string();
        c2.method = "base".into();

        let error = json!({
            "code": PAYMENT_REQUIRED_CODE,
            "data": {
                "httpStatus": 402,
                "challenges": [c1, c2]
            }
        });
        let challenges = extract_challenges(&error).unwrap();
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[1].method.as_str(), "base");
    }

    // ---- attach_credential ----

    #[test]
    fn test_attach_credential_to_empty_params() {
        let cred = test_credential();
        let mut params = json!({"name": "premium_tool"});
        attach_credential(&mut params, &cred);

        let meta = params.get("_meta").unwrap();
        let cred_value = meta.get(CREDENTIAL_META_KEY).unwrap();
        assert_eq!(cred_value["challenge"]["id"], "ch_test_123");
    }

    #[test]
    fn test_attach_credential_preserves_existing_meta() {
        let cred = test_credential();
        let mut params = json!({
            "name": "tool",
            "_meta": {"progressToken": 42}
        });
        attach_credential(&mut params, &cred);

        let meta = params.get("_meta").unwrap();
        assert_eq!(meta["progressToken"], 42);
        assert!(meta.get(CREDENTIAL_META_KEY).is_some());
    }

    #[test]
    fn test_attach_credential_preserves_params() {
        let cred = test_credential();
        let mut params = json!({
            "name": "tool",
            "arguments": {"query": "test"}
        });
        attach_credential(&mut params, &cred);

        assert_eq!(params["name"], "tool");
        assert_eq!(params["arguments"]["query"], "test");
    }

    // ---- McpReceipt serde ----

    #[test]
    fn test_mcp_receipt_serde_roundtrip() {
        let mcp_receipt = McpReceipt {
            receipt: test_receipt(),
            challenge_id: "ch_abc".to_string(),
        };
        let json = serde_json::to_value(&mcp_receipt).unwrap();

        // Flattened fields
        assert_eq!(json["status"], "success");
        assert_eq!(json["method"], "tempo");
        assert_eq!(json["challengeId"], "ch_abc");

        let parsed: McpReceipt = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.challenge_id, "ch_abc");
        assert!(parsed.receipt.is_success());
    }

    // ---- Full MCP payment roundtrip ----

    #[test]
    fn test_mcp_payment_roundtrip() {
        let secret = "mcp-test-secret";

        // 1. Server creates an HMAC-bound challenge
        let challenge = PaymentChallenge::with_secret_key(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&json!({"amount": "1000", "currency": "USD"})).unwrap(),
        );
        assert!(challenge.verify(secret));

        // 2. Server builds MCP payment-required error
        let error = payment_required_error(&challenge);
        let error_json = serde_json::to_value(&error).unwrap();

        // 3. Client detects payment required
        assert!(is_payment_required(&error_json));

        // 4. Client extracts challenges
        let challenges = extract_challenges(&error_json).unwrap();
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].id, challenge.id);
        assert_eq!(challenges[0].method.as_str(), "tempo");
        assert_eq!(challenges[0].intent.as_str(), "charge");

        // 5. Client "pays" — build credential from echoed challenge
        let received = &challenges[0];
        let credential = PaymentCredential::with_source(
            received.to_echo(),
            "did:pkh:eip155:42161:0xabc",
            PaymentPayload::hash("0xtxhash_roundtrip"),
        );

        // 6. Client attaches credential to request params
        let mut params = json!({"name": "premium_tool", "arguments": {"query": "test"}});
        attach_credential(&mut params, &credential);
        assert!(params["_meta"][CREDENTIAL_META_KEY].is_object());

        // 7. Server extracts credential from params._meta
        let meta = params.get("_meta").unwrap();
        let extracted = extract_credential(meta).unwrap();
        assert_eq!(extracted.challenge.id, challenge.id);
        assert_eq!(extracted.challenge.realm, "api.example.com");
        assert_eq!(
            extracted.source.as_deref(),
            Some("did:pkh:eip155:42161:0xabc")
        );

        // 8. Server verifies the HMAC-bound challenge ID
        let echoed_challenge = PaymentChallenge {
            id: extracted.challenge.id.clone(),
            realm: extracted.challenge.realm.clone(),
            method: extracted.challenge.method.clone(),
            intent: extracted.challenge.intent.clone(),
            request: extracted.challenge.request.clone(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };
        assert!(echoed_challenge.verify(secret));

        // 9. Server creates receipt and attaches to result
        let receipt = Receipt::success("tempo", "0xtxhash_roundtrip");
        let mut result = json!({"content": [{"type": "text", "text": "paid response"}]});
        attach_receipt(&mut result, &receipt, &challenge.id);

        // 10. Assert final result has receipt in _meta
        let receipt_value = &result["_meta"][RECEIPT_META_KEY];
        assert_eq!(receipt_value["status"], "success");
        assert_eq!(receipt_value["method"], "tempo");
        assert_eq!(receipt_value["reference"], "0xtxhash_roundtrip");
        assert_eq!(receipt_value["challengeId"], challenge.id);
        // Original content preserved
        assert_eq!(result["content"][0]["text"], "paid response");

        // Deserialize as McpReceipt to verify structure
        let mcp_receipt: McpReceipt = serde_json::from_value(receipt_value.clone()).unwrap();
        assert_eq!(mcp_receipt.challenge_id, challenge.id);
        assert!(mcp_receipt.receipt.is_success());
    }

    // ---- Verification-failed error code ----

    #[test]
    fn test_verification_failed_code_not_payment_required() {
        let error = json!({
            "code": PAYMENT_VERIFICATION_FAILED_CODE,
            "message": "Payment Verification Failed",
            "data": {
                "httpStatus": 403,
                "reason": "invalid signature"
            }
        });
        // -32043 is NOT -32042, so is_payment_required must return false
        assert!(!is_payment_required(&error));
        // extract_challenges should still work if data.challenges is present
        assert!(extract_challenges(&error).is_none());
    }
}
