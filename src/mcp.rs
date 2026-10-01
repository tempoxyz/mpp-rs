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
//! - [`PAYMENT_REQUIRED_META_KEY`]: Metadata key for payment-required tool results
//! - [`RECEIPT_META_KEY`]: Metadata key for receipts in `_meta`
//!
//! # Server-side
//!
//! - [`extract_credential`]: Extract a payment credential from MCP request `_meta`
//! - [`payment_required_error`]: Create an MCP payment-required error
//! - [`payment_required_error_with_problem`]: Create an MCP payment error with RFC 9457 problem details
//! - [`attach_receipt`] / [`try_attach_receipt`]: Attach a receipt to an MCP result's `_meta`
//!
//! # Client-side
//!
//! - [`is_payment_required`]: Check if a JSON-RPC error requires a (new) payment attempt
//! - [`extract_challenges`]: Extract challenges from a payment-required error
//! - [`extract_challenges_from_data`]: Extract challenges from a payment-required payload
//! - [`attach_credential`] / [`try_attach_credential`]: Attach a credential to MCP request params `_meta`
//! - [`client::McpClient`]: Wrap an MCP SDK adapter with automatic payment handling
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

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    protocol::core::{
        challenge::{PaymentChallenge, PaymentCredential, Receipt},
        Base64UrlJson,
    },
    MppError,
};

#[cfg(feature = "client")]
pub mod client;

// ==================== Constants ====================

/// MCP JSON-RPC error code for payment required.
pub const PAYMENT_REQUIRED_CODE: i32 = -32042;

/// MCP JSON-RPC error code for payment verification failed.
pub const PAYMENT_VERIFICATION_FAILED_CODE: i32 = -32043;

/// JSON-RPC error code for invalid params, used for malformed credentials.
const INVALID_PARAMS_CODE: i32 = -32602;

/// JSON-RPC error code for internal errors, used for internal payment errors.
const INTERNAL_ERROR_CODE: i32 = -32603;

/// MCP metadata key for credentials.
pub const CREDENTIAL_META_KEY: &str = "org.paymentauth/credential";

/// MCP metadata key for payment-required tool results.
pub const PAYMENT_REQUIRED_META_KEY: &str = "org.paymentauth/payment-required";

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
    /// Serialized with `request` as a native JSON object, as the MCP
    /// transport requires. Deserialization also accepts the base64url form
    /// and skips malformed entries.
    #[serde(
        serialize_with = "serialize_wire_challenges",
        deserialize_with = "deserialize_wire_challenges"
    )]
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
    let mut credential = meta.get(CREDENTIAL_META_KEY)?.clone();
    normalize_wire_challenge(credential.get_mut("challenge")?)?;
    serde_json::from_value(credential).ok()
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

/// Create an MCP payment-required error with RFC 9457 problem details.
///
/// Use when a credential was rejected. Sets `message` to `problem.detail`
/// and automatically binds `problem.challenge_id` to the challenge ID.
///
/// The JSON-RPC code follows the problem type: [`PAYMENT_REQUIRED_CODE`] for
/// `payment-required`, `-32602` for `malformed-credential` and
/// `invalid-payload`, `-32603` for `internal-payment-error`, and
/// [`PAYMENT_VERIFICATION_FAILED_CODE`] for every other problem. `httpStatus`
/// is taken from `problem.status`.
pub fn payment_required_error_with_problem(
    challenge: &PaymentChallenge,
    mut problem: crate::error::PaymentErrorDetails,
) -> McpPaymentError {
    problem.challenge_id = Some(challenge.id.clone());
    McpPaymentError {
        code: error_code(&problem),
        message: problem.detail.clone(),
        data: Some(McpPaymentErrorData {
            http_status: problem.status,
            challenges: vec![challenge.clone()],
            problem: Some(problem),
        }),
    }
}

fn error_code(problem: &crate::error::PaymentErrorDetails) -> i32 {
    let core_problem = problem
        .problem_type
        .strip_prefix(crate::error::CORE_PROBLEM_TYPE_BASE)
        .and_then(|suffix| suffix.strip_prefix('/'));
    match core_problem {
        Some("payment-required") => PAYMENT_REQUIRED_CODE,
        Some("malformed-credential" | "invalid-payload") => INVALID_PARAMS_CODE,
        Some("internal-payment-error") => INTERNAL_ERROR_CODE,
        _ => PAYMENT_VERIFICATION_FAILED_CODE,
    }
}

/// Attach a receipt to an MCP result's `_meta`.
///
/// Inserts (or creates) the `_meta` object on `result` and sets
/// the receipt under [`RECEIPT_META_KEY`].
///
/// Leaves `result` unchanged if it or its `_meta` is not a JSON object. Use
/// [`try_attach_receipt`] to observe that failure.
pub fn attach_receipt(result: &mut serde_json::Value, receipt: &Receipt, challenge_id: &str) {
    let _ = try_attach_receipt(result, receipt, challenge_id);
}

/// Attach a receipt to an MCP result's `_meta`.
///
/// Like [`attach_receipt`], but returns an error and leaves `result`
/// unchanged if it or its `_meta` is not a JSON object.
pub fn try_attach_receipt(
    result: &mut serde_json::Value,
    receipt: &Receipt,
    challenge_id: &str,
) -> Result<(), MppError> {
    let mcp_receipt = McpReceipt {
        receipt: receipt.clone(),
        challenge_id: challenge_id.to_string(),
    };
    let receipt_value = serde_json::to_value(&mcp_receipt)
        .map_err(|error| MppError::InvalidConfig(error.to_string()))?;
    insert_meta(result, "result", RECEIPT_META_KEY, receipt_value)
}

fn insert_meta(
    target: &mut serde_json::Value,
    name: &str,
    key: &str,
    value: serde_json::Value,
) -> Result<(), MppError> {
    target
        .as_object_mut()
        .ok_or_else(|| MppError::InvalidConfig(format!("{name} must be a JSON object")))?
        .entry("_meta")
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| MppError::InvalidConfig(format!("{name}._meta must be a JSON object")))?
        .insert(key.to_owned(), value);
    Ok(())
}

// ==================== Client-side helpers ====================

/// Check if an MCP JSON-RPC error response indicates payment required.
///
/// Returns `true` if `error.code` equals [`PAYMENT_REQUIRED_CODE`] or
/// [`PAYMENT_VERIFICATION_FAILED_CODE`]: a failed verification carries a
/// fresh challenge and requires a new payment attempt.
pub fn is_payment_required(error: &serde_json::Value) -> bool {
    error.get("code").and_then(|c| c.as_i64()).is_some_and(|c| {
        c == PAYMENT_REQUIRED_CODE as i64 || c == PAYMENT_VERIFICATION_FAILED_CODE as i64
    })
}

/// Extract challenges from an MCP payment-required error.
///
/// Returns `None` if the error has no `data.challenges` array or
/// none of its entries is a valid challenge.
pub fn extract_challenges(error: &serde_json::Value) -> Option<Vec<PaymentChallenge>> {
    extract_challenges_from_data(error.get("data")?)
}

/// Extracts challenges from an MCP payment-required data payload.
///
/// Accepts MCP's expanded JSON `request` object and normalizes it to the
/// base64url representation retained by the core protocol types. Malformed
/// entries are skipped so that the remaining alternatives stay usable.
pub fn extract_challenges_from_data(
    payment_required: &serde_json::Value,
) -> Option<Vec<PaymentChallenge>> {
    let challenges_value = payment_required.get("challenges")?;
    extract_wire_challenges(challenges_value)
}

/// Extract challenges from an MCP tool result's payment-required metadata.
///
/// Expects the result `_meta` object (not the complete tool result). Returns
/// `None` when the metadata key is absent or it lists no valid challenge.
pub fn extract_result_challenges(meta: &serde_json::Value) -> Option<Vec<PaymentChallenge>> {
    extract_challenges_from_data(meta.get(PAYMENT_REQUIRED_META_KEY)?)
}

fn extract_wire_challenges(value: &serde_json::Value) -> Option<Vec<PaymentChallenge>> {
    let challenges: Vec<_> = value
        .as_array()?
        .iter()
        .cloned()
        .filter_map(parse_wire_challenge)
        .collect();
    (!challenges.is_empty()).then_some(challenges)
}

fn parse_wire_challenge(mut challenge: serde_json::Value) -> Option<PaymentChallenge> {
    normalize_wire_challenge(&mut challenge)?;
    serde_json::from_value(challenge).ok()
}

fn deserialize_wire_challenges<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<PaymentChallenge>, D::Error> {
    let challenges = Vec::<serde_json::Value>::deserialize(deserializer)?;
    Ok(challenges
        .into_iter()
        .filter_map(parse_wire_challenge)
        .collect())
}

fn serialize_wire_challenges<S: Serializer>(
    challenges: &[PaymentChallenge],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    challenges
        .iter()
        .map(wire_challenge)
        .collect::<Result<Vec<_>, _>>()
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
}

fn wire_challenge(challenge: &PaymentChallenge) -> Result<serde_json::Value, MppError> {
    let mut value = serde_json::to_value(challenge)
        .map_err(|error| MppError::InvalidConfig(error.to_string()))?;
    value["request"] = challenge.request.decode_value()?;
    Ok(value)
}

fn normalize_wire_challenge(challenge: &mut serde_json::Value) -> Option<()> {
    let object = challenge.as_object_mut()?;
    let request = object.get("request")?;
    if !request.is_string() {
        let request = Base64UrlJson::from_value(request).ok()?;
        object.insert(
            "request".to_owned(),
            serde_json::Value::String(request.raw().to_owned()),
        );
    }
    if !object.contains_key("opaque") {
        if let Some(meta) = object.get("meta") {
            let opaque = Base64UrlJson::from_value(meta).ok()?;
            object.insert(
                "opaque".to_owned(),
                serde_json::Value::String(opaque.raw().to_owned()),
            );
        }
    }
    Some(())
}

/// Encodes a credential for MCP request metadata.
///
/// MCP carries the challenge request as expanded JSON, unlike the base64url
/// representation used by HTTP Payment authentication.
pub fn credential_value(credential: &PaymentCredential) -> Result<serde_json::Value, MppError> {
    let mut value = serde_json::to_value(credential)
        .map_err(|error| MppError::InvalidConfig(error.to_string()))?;
    let challenge = value
        .get_mut("challenge")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| MppError::InvalidConfig("credential challenge is invalid".to_owned()))?;
    challenge.insert(
        "request".to_owned(),
        credential.challenge.request.decode_value()?,
    );
    if let Some(opaque) = &credential.challenge.opaque {
        challenge.insert("meta".to_owned(), opaque.decode_value()?);
    }
    Ok(value)
}

/// Attach a credential to MCP request `params._meta`.
///
/// Inserts (or creates) `params._meta` and sets the credential
/// under [`CREDENTIAL_META_KEY`].
///
/// Leaves `params` unchanged if it or its `_meta` is not a JSON object, or if
/// the credential's challenge is not valid base64url JSON. Use
/// [`try_attach_credential`] to observe that failure.
pub fn attach_credential(params: &mut serde_json::Value, credential: &PaymentCredential) {
    let _ = try_attach_credential(params, credential);
}

/// Attach a credential to MCP request `params._meta`.
///
/// Like [`attach_credential`], but returns an error and leaves `params`
/// unchanged if it or its `_meta` is not a JSON object, or if the
/// credential's challenge is not valid base64url JSON.
pub fn try_attach_credential(
    params: &mut serde_json::Value,
    credential: &PaymentCredential,
) -> Result<(), MppError> {
    let cred_value = credential_value(credential)?;
    insert_meta(params, "params", CREDENTIAL_META_KEY, cred_value)
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
            Base64UrlJson::from_value(&json!({"amount": "1000", "currency": "USD"}))
                .expect("test request should serialize"),
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
                description: None,
                digest: None,
                opaque: None,
                header: None,
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

        let json = serde_json::to_string(&error).expect("test error should serialize");
        let parsed: McpPaymentError =
            serde_json::from_str(&json).expect("test error should deserialize");

        assert_eq!(parsed.code, PAYMENT_REQUIRED_CODE);
        assert_eq!(parsed.message, "Payment Required");
        let data = parsed.data.expect("test error should contain data");
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
        let json = serde_json::to_string(&error).expect("test error should serialize");
        let parsed: McpPaymentError =
            serde_json::from_str(&json).expect("test error should deserialize");
        assert!(parsed.data.is_none());
    }

    #[test]
    fn test_mcp_payment_error_with_problem() {
        use crate::error::PaymentErrorDetails;

        let challenge = test_challenge();
        // Caller does NOT set challenge_id — the function binds it automatically.
        let problem = PaymentErrorDetails::core("verification-failed")
            .with_title("VerificationFailedError")
            .with_status(402)
            .with_detail("Payment verification failed: bad signature.");

        let error = payment_required_error_with_problem(&challenge, problem);

        // Top-level: code is -32043, message mirrors problem.detail.
        assert_eq!(error.code, PAYMENT_VERIFICATION_FAILED_CODE);
        assert_eq!(error.message, "Payment verification failed: bad signature.");

        // Survives JSON round-trip (matches mppx McpError wire format).
        let json = serde_json::to_string(&error).expect("test error should serialize");
        let parsed: McpPaymentError =
            serde_json::from_str(&json).expect("test error should deserialize");
        let data = parsed.data.expect("test error should contain data");

        // Challenge is present in data.challenges.
        assert_eq!(data.challenges[0].id, "ch_test_123");

        // Problem details: type URI, title, status, detail, and auto-bound challengeId.
        let p = data
            .problem
            .expect("test error should contain problem details");
        assert_eq!(
            p.problem_type,
            "https://paymentauth.org/problems/verification-failed"
        );
        assert_eq!(p.title, "VerificationFailedError");
        assert_eq!(p.status, 402);
        assert_eq!(p.detail, "Payment verification failed: bad signature.");
        assert_eq!(p.challenge_id.as_deref(), Some("ch_test_123"));
    }

    #[test]
    fn test_payment_required_error_with_problem_maps_error_code() {
        use crate::error::PaymentErrorDetails;

        let cases = [
            (PaymentErrorDetails::core("payment-required"), -32042, 402),
            (
                PaymentErrorDetails::core("verification-failed"),
                -32043,
                402,
            ),
            (PaymentErrorDetails::core("payment-expired"), -32043, 402),
            (
                PaymentErrorDetails::session("invalid-signature"),
                -32043,
                402,
            ),
            (
                PaymentErrorDetails::core("malformed-credential"),
                -32602,
                402,
            ),
            (PaymentErrorDetails::core("invalid-payload"), -32602, 402),
            (
                PaymentErrorDetails::core("internal-payment-error").with_status(500),
                -32603,
                500,
            ),
        ];

        for (problem, code, http_status) in cases {
            let problem_type = problem.problem_type.clone();
            let error = payment_required_error_with_problem(&test_challenge(), problem);
            assert_eq!(error.code, code, "{problem_type}");
            assert_eq!(
                error.data.unwrap().http_status,
                http_status,
                "{problem_type}"
            );
        }
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

    #[test]
    fn test_payment_required_error_serializes_expanded_request() {
        let challenge = test_challenge()
            .with_opaque(Base64UrlJson::from_value(&json!({"scope": "job:123"})).unwrap());
        let error = serde_json::to_value(payment_required_error(&challenge)).unwrap();

        let wire = &error["data"]["challenges"][0];
        assert_eq!(
            wire["request"],
            json!({"amount": "1000", "currency": "USD"})
        );
        assert_eq!(wire["opaque"], challenge.opaque.as_ref().unwrap().raw());

        let extracted = extract_challenges(&error).unwrap();
        assert_eq!(extracted[0].request.raw(), challenge.request.raw());
        assert_eq!(extracted[0].opaque, challenge.opaque);
    }

    #[test]
    fn test_payment_required_error_rejects_undecodable_request() {
        let mut challenge = test_challenge();
        challenge.request = Base64UrlJson::from_raw("not json");

        assert!(serde_json::to_value(payment_required_error(&challenge)).is_err());
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
        assert!(is_payment_required(&error));
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
    fn test_extract_challenges_accepts_expanded_mcp_request() {
        let error = json!({
            "code": PAYMENT_REQUIRED_CODE,
            "message": "Payment Required",
            "data": {
                "httpStatus": 402,
                "challenges": [{
                    "id": "mercator-challenge",
                    "realm": "mercator.example",
                    "method": "tempo",
                    "intent": "charge",
                    "request": {
                        "amount": "6000",
                        "currency": "0x20c000000000000000000000b9537d11c60e8b50",
                        "methodDetails": {"chainId": 4217}
                    },
                    "meta": {"scope": "job:123"}
                }]
            }
        });

        let challenges = extract_challenges(&error).unwrap();

        assert_eq!(challenges[0].id, "mercator-challenge");
        assert_eq!(
            challenges[0].request.decode_value().unwrap()["amount"],
            "6000"
        );
        assert_eq!(
            challenges[0]
                .opaque
                .as_ref()
                .unwrap()
                .decode_value()
                .unwrap()["scope"],
            "job:123"
        );
    }

    #[test]
    fn test_extract_challenges_rejects_invalid_method_name() {
        let mut challenge = serde_json::to_value(test_challenge()).unwrap();
        challenge["method"] = json!("123");
        let error = json!({
            "code": PAYMENT_REQUIRED_CODE,
            "message": "Payment Required",
            "data": {
                "httpStatus": 402,
                "challenges": [challenge]
            }
        });

        assert!(extract_challenges(&error).is_none());
    }

    #[test]
    fn test_extract_challenges_skips_malformed_entries() {
        let mut invalid_method = serde_json::to_value(test_challenge()).unwrap();
        invalid_method["method"] = json!("123");
        let mut second = test_challenge();
        second.id = "ch_test_456".to_string();
        let data = json!({
            "httpStatus": 402,
            "challenges": [
                test_challenge(),
                invalid_method,
                {"id": "missing-fields"},
                "not-an-object",
                second
            ]
        });

        let challenges = extract_challenges_from_data(&data).unwrap();
        let ids: Vec<_> = challenges.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["ch_test_123", "ch_test_456"]);

        let typed: McpPaymentErrorData = serde_json::from_value(data).unwrap();
        assert_eq!(typed.challenges.len(), 2);
    }

    #[test]
    fn test_extract_challenges_empty_list() {
        let error = json!({
            "code": PAYMENT_REQUIRED_CODE,
            "data": {"httpStatus": 402, "challenges": []}
        });
        assert!(extract_challenges(&error).is_none());
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
        assert_eq!(cred_value["challenge"]["request"]["amount"], "1000");
    }

    #[test]
    fn test_mcp_credential_wire_roundtrip_preserves_opaque_meta() {
        let mut credential = test_credential();
        credential.challenge.opaque =
            Some(Base64UrlJson::from_value(&json!({"scope": "job:123"})).unwrap());
        let encoded = credential_value(&credential).unwrap();
        assert_eq!(encoded["challenge"]["request"]["amount"], "1000");
        assert_eq!(encoded["challenge"]["meta"]["scope"], "job:123");

        let decoded = extract_credential(&json!({CREDENTIAL_META_KEY: encoded})).unwrap();
        assert_eq!(
            decoded.challenge.request.raw(),
            credential.challenge.request.raw()
        );
        assert_eq!(
            decoded.challenge.opaque.unwrap().raw(),
            credential.challenge.opaque.unwrap().raw()
        );
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
            header: None,
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
    fn test_verification_failed_error_carries_fresh_challenge() {
        // Example from the MCP transport spec, "Payment Verification Failure".
        let error = json!({
            "code": -32043,
            "message": "Payment Verification Failed",
            "data": {
                "httpStatus": 402,
                "challenges": [{
                    "id": "retry-challenge-abc",
                    "realm": "api.example.com",
                    "method": "tempo",
                    "intent": "charge",
                    "request": {"amount": "1000", "currency": "usd"}
                }],
                "failure": {
                    "reason": "signature-invalid",
                    "detail": "Signature verification failed"
                }
            }
        });

        assert!(is_payment_required(&error));
        let challenges = extract_challenges(&error).unwrap();
        assert_eq!(challenges[0].id, "retry-challenge-abc");
    }

    // ---- mppx interop ----

    // `Transport.mcp().respondChallenge` output for the challenge in mppx's
    // `src/server/Transport.test.ts`.
    const MPPX_SECRET_KEY: &str = "test-secret-key-test-secret-key-32";
    const MPPX_CHALLENGE_ID: &str = "ITdnfSy5EVxmsDHMll-mcEbGENBvnz3jfySVS8uFS7Y";
    const MPPX_REQUEST: &str = "eyJhbW91bnQiOiIxMDAwMDAwMDAwIiwiY3VycmVuY3kiOiIweDIwYzAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDEiLCJyZWNpcGllbnQiOiIweDc0MmQzNUNjNjYzNEMwNTMyOTI1YTNiODQ0QmM5ZTc1OTVmOGZFMDAifQ";

    fn mppx_challenge() -> serde_json::Value {
        json!({
            "expires": "2025-01-01T00:00:00.000Z",
            "id": MPPX_CHALLENGE_ID,
            "intent": "charge",
            "method": "tempo",
            "realm": "api.example.com",
            "request": {
                "amount": "1000000000",
                "currency": "0x20c0000000000000000000000000000000000001",
                "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f8fE00"
            }
        })
    }

    #[test]
    fn test_mppx_payment_required_error_roundtrip() {
        let wire = json!({
            "code": -32042,
            "message": "Payment Required",
            "data": {
                "httpStatus": 402,
                "challenges": [mppx_challenge()]
            }
        });

        assert!(is_payment_required(&wire));
        let challenges = extract_challenges(&wire).unwrap();
        assert_eq!(challenges.len(), 1);
        assert_eq!(challenges[0].request.raw(), MPPX_REQUEST);
        assert!(challenges[0].verify(MPPX_SECRET_KEY));

        assert_eq!(
            serde_json::to_value(payment_required_error(&challenges[0])).unwrap(),
            wire
        );
        let typed: McpPaymentError = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(typed).unwrap(), wire);
    }

    #[test]
    fn test_mppx_verification_failed_error_roundtrip() {
        let wire = json!({
            "code": -32043,
            "message": "Payment verification failed: bad signature.",
            "data": {
                "httpStatus": 402,
                "challenges": [mppx_challenge()],
                "problem": {
                    "type": "https://paymentauth.org/problems/verification-failed",
                    "title": "Verification Failed",
                    "status": 402,
                    "detail": "Payment verification failed: bad signature.",
                    "challengeId": MPPX_CHALLENGE_ID
                }
            }
        });

        assert!(is_payment_required(&wire));
        let challenges = extract_challenges(&wire).unwrap();
        assert!(challenges[0].verify(MPPX_SECRET_KEY));

        let problem = crate::error::PaymentErrorDetails::core("verification-failed")
            .with_title("Verification Failed")
            .with_detail("Payment verification failed: bad signature.");
        assert_eq!(
            serde_json::to_value(payment_required_error_with_problem(&challenges[0], problem))
                .unwrap(),
            wire
        );
        let typed: McpPaymentError = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(typed).unwrap(), wire);
    }

    #[test]
    fn test_mppx_challenge_with_meta_keeps_raw_opaque() {
        // mppx emits both the parsed `meta` and the raw `opaque` it is bound to.
        let mut challenge = mppx_challenge();
        challenge["meta"] = json!({"scope": "job:123"});
        challenge["opaque"] = json!("eyJzY29wZSI6ImpvYjoxMjMifQ");
        let data = json!({"httpStatus": 402, "challenges": [challenge]});

        let challenges = extract_challenges_from_data(&data).unwrap();

        let opaque = challenges[0].opaque.as_ref().unwrap();
        assert_eq!(opaque.raw(), "eyJzY29wZSI6ImpvYjoxMjMifQ");
        assert_eq!(opaque.decode_value().unwrap(), json!({"scope": "job:123"}));
    }

    // ---- attach helpers on non-object input ----

    #[test]
    fn test_attach_credential_rejects_non_object_params() {
        for params in [json!(["latest", false]), json!(null), json!({"_meta": "x"})] {
            let mut attached = params.clone();
            attach_credential(&mut attached, &test_credential());
            assert_eq!(attached, params);
            assert!(try_attach_credential(&mut attached, &test_credential()).is_err());
            assert_eq!(attached, params);
        }
    }

    #[test]
    fn test_attach_credential_rejects_undecodable_challenge() {
        let mut credential = test_credential();
        credential.challenge.request = Base64UrlJson::from_raw("not json");
        let mut params = json!({"name": "tool"});

        attach_credential(&mut params, &credential);
        assert!(try_attach_credential(&mut params, &credential).is_err());
        assert_eq!(params, json!({"name": "tool"}));
    }

    #[test]
    fn test_attach_receipt_rejects_non_object_result() {
        for result in [json!("0x1"), json!([1, 2]), json!({"_meta": []})] {
            let mut attached = result.clone();
            attach_receipt(&mut attached, &test_receipt(), "ch_test_123");
            assert_eq!(attached, result);
            assert!(try_attach_receipt(&mut attached, &test_receipt(), "ch_test_123").is_err());
            assert_eq!(attached, result);
        }
    }
}
