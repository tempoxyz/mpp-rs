//! Tempo API MPP relay adapter.

use alloy::primitives::keccak256;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;

use crate::error::MppError;
use crate::protocol::core::{PaymentCredential, Receipt, ReceiptStatus};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeValidation, VerificationError};

const DEFAULT_API_BASE_URL: &str = "https://api.tempo.xyz";

/// Configuration for Tempo API's MPP relay.
#[derive(Clone)]
pub struct RelayConfig {
    api_key: String,
    api_base_url: String,
    client: Client,
}

impl RelayConfig {
    /// Create relay configuration using `https://api.tempo.xyz`.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: api_key.into(),
            api_base_url: DEFAULT_API_BASE_URL.to_string(),
            client: Client::new(),
        }
    }

    /// Override the Tempo API base URL, including an optional path prefix.
    #[must_use]
    pub fn api_base_url(mut self, api_base_url: impl Into<String>) -> Self {
        self.api_base_url = api_base_url.into();
        self
    }

    /// Use a custom HTTP client.
    #[must_use]
    pub fn client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }
}

impl std::fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayConfig")
            .field("api_key", &"[REDACTED]")
            .field("api_base_url", &self.api_base_url)
            .finish_non_exhaustive()
    }
}

/// Stable machine-readable failure codes returned by Tempo API's MPP relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayErrorCode {
    AlreadyUsed,
    BroadcastFailed,
    Expired,
    InvalidPayment,
    InsufficientFunds,
    PolicyDenied,
    ScreenRejected,
    SimulationFailed,
    TemporarilyUnavailable,
    Unsupported,
    Unknown,
}

impl RelayErrorCode {
    /// Return the relay's wire-format code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AlreadyUsed => "already_used",
            Self::BroadcastFailed => "broadcast_failed",
            Self::Expired => "expired",
            Self::InvalidPayment => "invalid_payment",
            Self::InsufficientFunds => "insufficient_funds",
            Self::PolicyDenied => "policy_denied",
            Self::ScreenRejected => "screen_rejected",
            Self::SimulationFailed => "simulation_failed",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "already_used" => Self::AlreadyUsed,
            "broadcast_failed" => Self::BroadcastFailed,
            "expired" => Self::Expired,
            "invalid_payment" => Self::InvalidPayment,
            "insufficient_funds" => Self::InsufficientFunds,
            "policy_denied" => Self::PolicyDenied,
            "screen_rejected" => Self::ScreenRejected,
            "simulation_failed" => Self::SimulationFailed,
            "temporarily_unavailable" => Self::TemporarilyUnavailable,
            "unsupported" => Self::Unsupported,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }

    fn is_safe(self) -> bool {
        matches!(
            self,
            Self::AlreadyUsed
                | Self::BroadcastFailed
                | Self::InvalidPayment
                | Self::InsufficientFunds
                | Self::SimulationFailed
                | Self::TemporarilyUnavailable
                | Self::Unsupported
        )
    }
}

impl std::fmt::Display for RelayErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone)]
pub(crate) struct Relay {
    api_key: String,
    api_base_url: Url,
    client: Client,
}

impl Relay {
    pub(crate) fn new(config: RelayConfig) -> crate::error::Result<Self> {
        if config.api_key.trim().is_empty() {
            return Err(MppError::InvalidConfig(
                "Tempo relay API key must not be empty".to_string(),
            ));
        }

        let mut api_base_url = Url::parse(&config.api_base_url).map_err(|error| {
            MppError::InvalidConfig(format!("invalid Tempo relay API base URL: {error}"))
        })?;
        if !api_base_url.path().ends_with('/') {
            let path = format!("{}/", api_base_url.path());
            api_base_url.set_path(&path);
        }

        Ok(Self {
            api_key: config.api_key,
            api_base_url,
            client: config.client,
        })
    }

    pub(crate) async fn validate(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> Result<ChargeValidation, VerificationError> {
        let input = RelayInput::try_from(credential)?;
        let response = self.post("v1/mpp/validate", &input, None).await?;
        if !is_success(&response) {
            return Err(failure(Some(&response)));
        }

        Ok(ChargeValidation::new(
            credential,
            request,
            serde_json::json!({}),
        ))
    }

    pub(crate) async fn broadcast(
        &self,
        credential: &PaymentCredential,
        expected_method: &str,
    ) -> Result<Receipt, VerificationError> {
        let input = RelayInput::try_from(credential)?;
        let key = idempotency_key(&input)?;
        let broadcast = self.post("v1/mpp/broadcast", &input, Some(&key)).await?;
        let response: BroadcastSuccess =
            serde_json::from_value(broadcast.clone()).map_err(|_| failure(Some(&broadcast)))?;
        if !response.success || response.receipt.method != expected_method {
            return Err(failure(Some(&broadcast)));
        }
        time::OffsetDateTime::parse(&response.receipt.timestamp, &Rfc3339)
            .map_err(|_| failure(Some(&broadcast)))?;

        Ok(Receipt {
            status: ReceiptStatus::Success,
            method: response.receipt.method.into(),
            timestamp: response.receipt.timestamp,
            reference: response.receipt.reference,
            external_id: response.receipt.external_id,
        })
    }

    async fn post(
        &self,
        path: &str,
        input: &RelayInput<'_>,
        idempotency_key: Option<&str>,
    ) -> Result<serde_json::Value, VerificationError> {
        let url = self.api_base_url.join(path).map_err(|_| failure(None))?;
        let mut request = self
            .client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .header("tempo-api-key", &self.api_key)
            .json(input);
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("idempotency-key", idempotency_key);
        }

        let response = request.send().await.map_err(|_| failure(None))?;
        if !response.status().is_success() {
            return Err(failure(None));
        }
        response
            .json::<serde_json::Value>()
            .await
            .map_err(|_| failure(None))
    }
}

#[derive(Serialize)]
struct RelayInput<'a> {
    challenge: RelayChallenge<'a>,
    payload: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<&'a str>,
}

#[derive(Serialize)]
struct RelayChallenge<'a> {
    id: &'a str,
    realm: &'a str,
    method: &'a crate::protocol::core::MethodName,
    intent: &'a crate::protocol::core::IntentName,
    request: serde_json::Map<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    opaque: Option<&'a str>,
}

impl<'a> TryFrom<&'a PaymentCredential> for RelayInput<'a> {
    type Error = VerificationError;

    fn try_from(credential: &'a PaymentCredential) -> Result<Self, Self::Error> {
        let request = credential
            .challenge
            .request
            .decode_value()
            .map_err(|_| failure(None))?
            .as_object()
            .cloned()
            .ok_or_else(|| failure(None))?;

        Ok(Self {
            challenge: RelayChallenge {
                id: &credential.challenge.id,
                realm: &credential.challenge.realm,
                method: &credential.challenge.method,
                intent: &credential.challenge.intent,
                request,
                expires: credential.challenge.expires.as_deref(),
                digest: credential.challenge.digest.as_deref(),
                opaque: credential
                    .challenge
                    .opaque
                    .as_ref()
                    .map(|value| value.raw()),
            },
            payload: &credential.payload,
            source: credential.source.as_deref(),
        })
    }
}

#[derive(Deserialize)]
struct BroadcastSuccess {
    success: bool,
    receipt: RelayReceipt,
}

#[derive(Deserialize)]
struct RelayReceipt {
    #[serde(rename = "externalId")]
    external_id: Option<String>,
    method: String,
    reference: String,
    timestamp: String,
}

fn is_success(value: &serde_json::Value) -> bool {
    value.get("success").and_then(serde_json::Value::as_bool) == Some(true)
}

fn relay_error_code(value: &serde_json::Value) -> Option<RelayErrorCode> {
    value
        .get("error")?
        .get("code")?
        .as_str()
        .and_then(RelayErrorCode::parse)
}

fn failure(value: Option<&serde_json::Value>) -> VerificationError {
    let code = value.and_then(relay_error_code);
    match code {
        Some(RelayErrorCode::Expired) => VerificationError::expired("Payment has expired."),
        Some(RelayErrorCode::TemporarilyUnavailable) => {
            VerificationError::network_error("Tempo API relay temporarily unavailable")
        }
        Some(code) if code.is_safe() => VerificationError::new(format!(
            "Tempo API relay rejected credential ({})",
            code.as_str()
        )),
        _ => VerificationError::new("Tempo API relay rejected credential"),
    }
}

fn idempotency_key(input: &RelayInput<'_>) -> Result<String, VerificationError> {
    if input
        .payload
        .get("type")
        .and_then(serde_json::Value::as_str)
        == Some("transaction")
    {
        if let Some(signature) = input
            .payload
            .get("signature")
            .and_then(serde_json::Value::as_str)
        {
            if let Ok(bytes) = hex::decode(signature.strip_prefix("0x").unwrap_or(signature)) {
                return Ok(format!("mppx_{:#x}", keccak256(bytes)));
            }
        }
    }

    let canonical = serde_json_canonicalizer::to_string(input).map_err(|_| failure(None))?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(format!("mppx_0x{}", hex::encode(digest)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{Base64UrlJson, ChallengeEcho, PaymentPayload};
    use crate::protocol::methods::tempo::ChargeMethod as TempoChargeMethod;
    use crate::protocol::traits::ChargeMethod as _;
    use crate::server::Mpp;
    use axum::{
        extract::{OriginalUri, State},
        http::{HeaderMap, StatusCode},
        routing::post,
        Json, Router,
    };
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone)]
    struct MockState {
        calls: Arc<Mutex<Vec<MockCall>>>,
        responses: Arc<Mutex<VecDeque<(StatusCode, serde_json::Value)>>>,
    }

    struct MockCall {
        body: serde_json::Value,
        headers: HeaderMap,
        path: String,
    }

    fn credential(payload: PaymentPayload) -> PaymentCredential {
        PaymentCredential::new(
            ChallengeEcho {
                id: "challenge-id".into(),
                realm: "relay.example".into(),
                method: "tempo".into(),
                intent: "charge".into(),
                request: Base64UrlJson::from_raw("e30"),
                expires: Some("2099-01-01T00:00:00Z".into()),
                digest: None,
                opaque: None,
            },
            payload,
        )
    }

    fn bound_credential(secret_key: &str, payload: PaymentPayload) -> PaymentCredential {
        let request = ChargeRequest {
            amount: "1".into(),
            currency: "0x1".into(),
            ..Default::default()
        };
        let encoded = Base64UrlJson::from_typed(&request).unwrap();
        let expires = "2099-01-01T00:00:00Z";
        let id = crate::protocol::core::compute_challenge_id(
            secret_key,
            "relay.example",
            "tempo",
            "charge",
            encoded.raw(),
            Some(expires),
            None,
            None,
        );
        PaymentCredential::new(
            ChallengeEcho {
                id,
                realm: "relay.example".into(),
                method: "tempo".into(),
                intent: "charge".into(),
                request: encoded,
                expires: Some(expires.into()),
                digest: None,
                opaque: None,
            },
            payload,
        )
    }

    #[test]
    fn transaction_idempotency_key_uses_transaction_hash() {
        let credential = credential(PaymentPayload::transaction("0x1234"));
        let input = RelayInput::try_from(&credential).unwrap();
        assert_eq!(
            idempotency_key(&input).unwrap(),
            format!("mppx_{:#x}", keccak256([0x12, 0x34]))
        );
    }

    #[test]
    fn non_transaction_idempotency_key_is_canonical_and_deterministic() {
        let credential = credential(PaymentPayload::hash("0x1234"));
        let input = RelayInput::try_from(&credential).unwrap();
        let first = idempotency_key(&input).unwrap();
        let second = idempotency_key(&input).unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("mppx_0x"));
        assert_eq!(first.len(), "mppx_0x".len() + 64);
    }

    #[test]
    fn invalid_transaction_signature_uses_canonical_idempotency_fallback() {
        let credential = credential(PaymentPayload::transaction("not-hex"));
        let input = RelayInput::try_from(&credential).unwrap();
        let key = idempotency_key(&input).unwrap();

        assert!(key.starts_with("mppx_0x"));
        assert_eq!(key.len(), "mppx_0x".len() + 64);
    }

    #[test]
    fn relay_input_rejects_invalid_or_non_object_challenge_requests() {
        for request in ["not-base64", "W10"] {
            let mut credential = credential(PaymentPayload::hash("0x1234"));
            credential.challenge.request = Base64UrlJson::from_raw(request);

            assert!(RelayInput::try_from(&credential).is_err(), "{request}");
        }
    }

    #[test]
    fn relay_configuration_redacts_api_key() {
        let debug = format!("{:?}", RelayConfig::new("top-secret"));
        assert!(!debug.contains("top-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn relay_configuration_accepts_custom_client() {
        let config = RelayConfig::new("key").client(Client::new());

        assert!(Relay::new(config).is_ok());
    }

    #[test]
    fn relay_error_codes_round_trip_through_public_strings() {
        let cases = [
            (RelayErrorCode::AlreadyUsed, "already_used"),
            (RelayErrorCode::BroadcastFailed, "broadcast_failed"),
            (RelayErrorCode::Expired, "expired"),
            (RelayErrorCode::InvalidPayment, "invalid_payment"),
            (RelayErrorCode::InsufficientFunds, "insufficient_funds"),
            (RelayErrorCode::PolicyDenied, "policy_denied"),
            (RelayErrorCode::ScreenRejected, "screen_rejected"),
            (RelayErrorCode::SimulationFailed, "simulation_failed"),
            (
                RelayErrorCode::TemporarilyUnavailable,
                "temporarily_unavailable",
            ),
            (RelayErrorCode::Unsupported, "unsupported"),
            (RelayErrorCode::Unknown, "unknown"),
        ];

        for (code, wire) in cases {
            assert_eq!(code.as_str(), wire);
            assert_eq!(code.to_string(), wire);
            assert_eq!(RelayErrorCode::parse(wire), Some(code));
        }
        assert_eq!(RelayErrorCode::parse("future_code"), None);
    }

    #[test]
    fn relay_input_normalizes_a_valid_credential() {
        let credential = credential(PaymentPayload::hash("0x1234"));

        let input = RelayInput::try_from(&credential).unwrap();

        assert_eq!(input.challenge.id, "challenge-id");
        assert!(input.challenge.request.is_empty());
        assert_eq!(input.payload["type"], "hash");
        assert!(input.source.is_none());
    }

    #[test]
    fn relay_configuration_rejects_invalid_values() {
        for config in [
            RelayConfig::new(""),
            RelayConfig::new("key").api_base_url("://bad"),
        ] {
            assert!(Relay::new(config).is_err());
        }
    }

    #[test]
    fn relay_error_mapping_hides_private_messages() {
        let cases = [
            ("already_used", true, false),
            ("broadcast_failed", true, false),
            ("expired", true, false),
            ("invalid_payment", true, false),
            ("insufficient_funds", true, false),
            ("policy_denied", false, false),
            ("screen_rejected", false, false),
            ("simulation_failed", true, false),
            ("temporarily_unavailable", false, true),
            ("unsupported", true, false),
            ("unknown", false, false),
            ("future_private_code", false, false),
        ];

        for (code, exposes_code, retryable) in cases {
            let value = serde_json::json!({
                "success": false,
                "error": { "code": code, "message": "private detail" }
            });
            let error = failure(Some(&value));

            assert_eq!(error.retryable, retryable, "{code}");
            assert_eq!(error.message.contains(code), exposes_code, "{code}");
            assert!(!error.message.contains("private detail"), "{code}");
            if code == "expired" {
                assert_eq!(
                    error.code,
                    Some(crate::protocol::traits::ErrorCode::Expired)
                );
            }
        }
    }

    #[tokio::test]
    async fn relay_validate_and_broadcast_are_separate() {
        let (base_url, calls) = spawn_relay([
            (StatusCode::OK, serde_json::json!({ "success": true })),
            (
                StatusCode::OK,
                serde_json::json!({
                    "success": true,
                    "receipt": {
                        "externalId": "invoice-1",
                        "method": "tempo",
                        "reference": "0xreceipt",
                        "timestamp": "2026-08-03T12:00:00Z"
                    }
                }),
            ),
        ])
        .await;
        let relay =
            Relay::new(RelayConfig::new("test-api-key").api_base_url(format!("{base_url}/prefix")))
                .unwrap();
        let mut credential = credential(PaymentPayload::transaction("0x1234"));
        credential.source = Some("did:pkh:eip155:42431:0x1234".into());

        let request = ChargeRequest {
            amount: "1".into(),
            currency: "0x1".into(),
            ..Default::default()
        };
        relay.validate(&credential, &request).await.unwrap();
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].path, "/prefix/v1/mpp/validate");
        }
        let receipt = relay.broadcast(&credential, "tempo").await.unwrap();
        assert_eq!(receipt.reference, "0xreceipt");
        assert_eq!(receipt.external_id.as_deref(), Some("invoice-1"));

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].path, "/prefix/v1/mpp/validate");
        assert_eq!(calls[1].path, "/prefix/v1/mpp/broadcast");
        for call in calls.iter() {
            assert_eq!(call.headers["tempo-api-key"], "test-api-key");
            assert_eq!(call.body["challenge"]["id"], "challenge-id");
            assert!(call.body["challenge"]["request"].is_object());
            assert_eq!(call.body["payload"]["type"], "transaction");
            assert_eq!(call.body["source"], "did:pkh:eip155:42431:0x1234");
        }
        assert!(calls[0].headers.get("idempotency-key").is_none());
        assert_eq!(
            calls[1].headers["idempotency-key"],
            format!("mppx_{:#x}", keccak256([0x12, 0x34]))
        );
    }

    #[tokio::test]
    async fn relay_omits_absent_source_and_forwards_all_challenge_bindings() {
        let (base_url, calls) =
            spawn_relay([(StatusCode::OK, serde_json::json!({ "success": true }))]).await;
        let relay = Relay::new(RelayConfig::new("key").api_base_url(base_url)).unwrap();
        let mut credential = credential(PaymentPayload::proof("0x1234"));
        credential.challenge.digest = Some("sha-256=:digest:".into());
        credential.challenge.opaque = Some(Base64UrlJson::from_raw("eyJyb3V0ZSI6MX0"));

        relay
            .validate(&credential, &ChargeRequest::default())
            .await
            .unwrap();

        let calls = calls.lock().unwrap();
        let body = &calls[0].body;
        assert!(body.get("source").is_none());
        assert_eq!(body["challenge"]["expires"], "2099-01-01T00:00:00Z");
        assert_eq!(body["challenge"]["digest"], "sha-256=:digest:");
        assert_eq!(body["challenge"]["opaque"], "eyJyb3V0ZSI6MX0");
    }

    #[tokio::test]
    async fn relay_legacy_verify_preserves_combined_lifecycle() {
        let (base_url, calls) = spawn_relay([
            (StatusCode::OK, serde_json::json!({ "success": true })),
            (
                StatusCode::OK,
                serde_json::json!({
                    "success": true,
                    "receipt": {
                        "method": "tempo",
                        "reference": "0xreceipt",
                        "timestamp": "2026-08-03T12:00:00Z"
                    }
                }),
            ),
        ])
        .await;
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = TempoChargeMethod::new(provider)
            .with_relay(RelayConfig::new("test-key").api_base_url(base_url))
            .unwrap();
        let credential = credential(PaymentPayload::transaction("0x1234"));

        let receipt = method
            .verify(&credential, &ChargeRequest::default())
            .await
            .unwrap();

        assert_eq!(receipt.reference, "0xreceipt");
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].path, "/v1/mpp/validate");
        assert_eq!(calls[1].path, "/v1/mpp/broadcast");
    }

    #[tokio::test]
    async fn mpp_broadcast_validates_through_relay_before_finalizing() {
        let (base_url, calls) = spawn_relay([
            (StatusCode::OK, serde_json::json!({ "success": true })),
            (
                StatusCode::OK,
                serde_json::json!({
                    "success": true,
                    "receipt": {
                        "method": "tempo",
                        "reference": "0xreceipt",
                        "timestamp": "2026-08-03T12:00:00Z"
                    }
                }),
            ),
        ])
        .await;
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = TempoChargeMethod::new(provider)
            .with_relay(RelayConfig::new("test-key").api_base_url(base_url))
            .unwrap();
        let payment = Mpp::new(method, "relay.example", "test-secret");
        let credential = bound_credential("test-secret", PaymentPayload::transaction("0x1234"));

        let receipt = payment.broadcast_credential(&credential).await.unwrap();

        assert_eq!(receipt.reference, "0xreceipt");
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].path, "/v1/mpp/validate");
        assert_eq!(calls[1].path, "/v1/mpp/broadcast");
    }

    #[tokio::test]
    async fn mpp_broadcast_does_not_finalize_when_relay_validation_fails() {
        let (base_url, calls) = spawn_relay([(
            StatusCode::OK,
            serde_json::json!({
                "success": false,
                "error": { "code": "policy_denied", "message": "private detail" }
            }),
        )])
        .await;
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = TempoChargeMethod::new(provider)
            .with_relay(RelayConfig::new("test-key").api_base_url(base_url))
            .unwrap();
        let payment = Mpp::new(method, "relay.example", "test-secret");
        let credential = bound_credential("test-secret", PaymentPayload::transaction("0x1234"));

        let error = payment.broadcast_credential(&credential).await.unwrap_err();

        assert_eq!(error.message, "Tempo API relay rejected credential");
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].path, "/v1/mpp/validate");
    }

    #[tokio::test]
    async fn relay_stops_after_validation_failure_and_hides_details() {
        let (base_url, calls) = spawn_relay([(
            StatusCode::OK,
            serde_json::json!({
                "success": false,
                "error": { "code": "policy_denied", "message": "private detail" }
            }),
        )])
        .await;
        let relay = Relay::new(RelayConfig::new("key").api_base_url(base_url)).unwrap();

        let error = relay
            .validate(
                &credential(PaymentPayload::transaction("0x1234")),
                &ChargeRequest::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.message, "Tempo API relay rejected credential");
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn relay_non_success_http_status_keeps_response_body_opaque() {
        let (base_url, calls) = spawn_relay([(
            StatusCode::FORBIDDEN,
            serde_json::json!({
                "success": false,
                "error": { "code": "insufficient_funds", "message": "private detail" }
            }),
        )])
        .await;
        let relay = Relay::new(RelayConfig::new("key").api_base_url(base_url)).unwrap();

        let error = relay
            .validate(
                &credential(PaymentPayload::transaction("0x1234")),
                &ChargeRequest::default(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.message, "Tempo API relay rejected credential");
        assert!(!error.message.contains("insufficient_funds"));
        assert!(!error.message.contains("private detail"));
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn relay_malformed_json_response_is_opaque() {
        let base_url = spawn_raw_relay("not-json").await;
        let relay = Relay::new(RelayConfig::new("key").api_base_url(base_url)).unwrap();

        let error = relay
            .validate(
                &credential(PaymentPayload::transaction("0x1234")),
                &ChargeRequest::default(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.message, "Tempo API relay rejected credential");
    }

    #[tokio::test]
    async fn relay_network_failure_is_opaque_and_does_not_leak_configuration() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let relay =
            Relay::new(RelayConfig::new("top-secret-key").api_base_url(base_url.clone())).unwrap();

        let error = relay
            .validate(
                &credential(PaymentPayload::transaction("0x1234")),
                &ChargeRequest::default(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.message, "Tempo API relay rejected credential");
        assert!(!error.message.contains("top-secret-key"));
        assert!(!error.message.contains(&base_url));
    }

    #[tokio::test]
    async fn relay_rejects_invalid_receipts() {
        for receipt in [
            serde_json::json!({
                "method": "tempo",
                "timestamp": "2026-08-03T12:00:00Z"
            }),
            serde_json::json!({
                "method": "stripe",
                "reference": "0xreceipt",
                "timestamp": "2026-08-03T12:00:00Z"
            }),
            serde_json::json!({
                "method": "tempo",
                "reference": "0xreceipt",
                "timestamp": "not-a-timestamp"
            }),
        ] {
            let (base_url, calls) = spawn_relay([(
                StatusCode::OK,
                serde_json::json!({ "success": true, "receipt": receipt }),
            )])
            .await;
            let relay = Relay::new(RelayConfig::new("key").api_base_url(base_url)).unwrap();
            let error = relay
                .broadcast(&credential(PaymentPayload::transaction("0x1234")), "tempo")
                .await
                .unwrap_err();
            assert_eq!(error.message, "Tempo API relay rejected credential");
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].path, "/v1/mpp/broadcast");
        }
    }

    #[tokio::test]
    async fn relay_rejects_false_success_even_with_a_valid_receipt() {
        let (base_url, calls) = spawn_relay([(
            StatusCode::OK,
            serde_json::json!({
                "success": false,
                "receipt": {
                    "method": "tempo",
                    "reference": "0xreceipt",
                    "timestamp": "2026-08-03T12:00:00Z"
                }
            }),
        )])
        .await;
        let relay = Relay::new(RelayConfig::new("key").api_base_url(base_url)).unwrap();

        let error = relay
            .broadcast(&credential(PaymentPayload::transaction("0x1234")), "tempo")
            .await
            .unwrap_err();

        assert_eq!(error.message, "Tempo API relay rejected credential");
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    async fn spawn_relay(
        responses: impl IntoIterator<Item = (StatusCode, serde_json::Value)>,
    ) -> (String, Arc<Mutex<Vec<MockCall>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let state = MockState {
            calls: Arc::clone(&calls),
            responses: Arc::new(Mutex::new(responses.into_iter().collect())),
        };
        let app = Router::new()
            .route("/{*path}", post(relay_endpoint))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), calls)
    }

    async fn spawn_raw_relay(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        format!("http://{address}")
    }

    async fn relay_endpoint(
        State(state): State<MockState>,
        OriginalUri(uri): OriginalUri,
        headers: HeaderMap,
        Json(body): Json<serde_json::Value>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        state.calls.lock().unwrap().push(MockCall {
            body,
            headers,
            path: uri.path().to_string(),
        });
        let (status, body) = state.responses.lock().unwrap().pop_front().unwrap();
        (status, Json(body))
    }
}
