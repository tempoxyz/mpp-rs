//! Tempo stream method for server-side streaming payment verification.
//!
//! This module provides [`StreamMethod`] which implements the [`StreamMethod`]
//! trait for **Tempo blockchain** streaming payments.
//!
//! # Tempo-Specific
//!
//! This verifier is designed specifically for the Tempo network.
//! It validates stream credential payloads (open, topUp, voucher, close)
//! and verifies challenge ID integrity.
//!
//! # Example
//!
//! ```ignore
//! use mpay::server::{tempo_provider, TempoStreamMethod};
//! use mpay::protocol::traits::StreamMethod as StreamMethodTrait;
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
//! let method = TempoStreamMethod::new(provider);
//!
//! // In your server handler:
//! let receipt = method.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use alloy::providers::Provider;
use std::future::Future;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::StreamRequest;
use crate::protocol::traits::{StreamMethod as StreamMethodTrait, VerificationError};

use super::stream::StreamCredentialPayload;
use super::{INTENT_STREAM, METHOD_NAME};

/// Tempo stream method for payment channel verification.
///
/// This is a **Tempo-specific** streaming payment verifier. It expects:
/// - `method="tempo"` in the credential
/// - `intent="stream"` in the credential
/// - A provider configured for `TempoNetwork`
///
/// # Verification Flow
///
/// 1. Validate method and intent match
/// 2. Parse the raw_payload as a `StreamCredentialPayload`
/// 3. Validate the action is known (open, topUp, voucher, close)
/// 4. Return a Receipt with the channelId as reference
///
/// # TODO
///
/// On-chain verification (escrow contract calls, voucher signature verification,
/// storage) requires a storage trait and escrow contract bindings that don't
/// exist in the Rust SDK yet. For now, this performs basic credential validation.
#[derive(Clone)]
pub struct StreamMethod<P> {
    provider: Arc<P>,
}

impl<P> StreamMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Create a new Tempo stream method with the given alloy Provider.
    ///
    /// The provider must be configured for `TempoNetwork`. Use
    /// [`tempo_provider`](crate::server::tempo_provider) to create one.
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
        }
    }

    /// Get a reference to the underlying provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }
}

impl<P> StreamMethodTrait for StreamMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        _request: &StreamRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let credential = credential.clone();

        async move {
            if credential.challenge.method.as_str() != METHOD_NAME {
                return Err(VerificationError::credential_mismatch(format!(
                    "Method mismatch: expected {}, got {}",
                    METHOD_NAME, credential.challenge.method
                )));
            }
            if credential.challenge.intent.as_str() != INTENT_STREAM {
                return Err(VerificationError::credential_mismatch(format!(
                    "Intent mismatch: expected {}, got {}",
                    INTENT_STREAM, credential.challenge.intent
                )));
            }

            let raw_payload = credential.raw_payload().ok_or_else(|| {
                VerificationError::new(
                    "Stream credential missing raw_payload — expected a JSON payload with an 'action' field",
                )
            })?;

            let stream_payload: StreamCredentialPayload =
                serde_json::from_value(raw_payload.clone()).map_err(|e| {
                    VerificationError::new(format!(
                        "Failed to parse stream credential payload: {}",
                        e
                    ))
                })?;

            let channel_id = match &stream_payload {
                StreamCredentialPayload::Open { channel_id, .. } => channel_id.clone(),
                StreamCredentialPayload::TopUp { channel_id, .. } => channel_id.clone(),
                StreamCredentialPayload::Voucher { channel_id, .. } => channel_id.clone(),
                StreamCredentialPayload::Close { channel_id, .. } => channel_id.clone(),
            };

            // TODO: On-chain verification steps (per TypeScript SDK Stream.ts):
            // - open: broadcast open transaction, verify on-chain channel, verify voucher signature
            // - topUp: broadcast topUp transaction, update channel deposit
            // - voucher: verify voucher signature, check delta >= minVoucherDelta, update session
            // - close: verify final voucher, settle on-chain, finalize channel
            //
            // These require:
            // - ChannelStorage trait (getChannel, updateChannel, getSession, updateSession)
            // - Escrow contract bindings (getOnChainChannel, broadcastOpenTransaction, etc.)
            // - Voucher signature verification (verifyVoucher)
            //
            // For now, return success with the channelId as the reference.

            Ok(Receipt::success(METHOD_NAME, channel_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{ChallengeEcho, PaymentCredential, PaymentPayload};

    fn stream_credential(action: &str) -> PaymentCredential {
        let echo = ChallengeEcho {
            id: "test-id".into(),
            realm: "test.com".into(),
            method: "tempo".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjoidmFsdWUifQ".into(),
            expires: None,
            digest: None,
        };
        let raw = match action {
            "open" => serde_json::json!({
                "action": "open",
                "type": "transaction",
                "channelId": "0xchannel123",
                "transaction": "0xtx",
                "signature": "0xsig",
                "cumulativeAmount": "5000"
            }),
            "topUp" => serde_json::json!({
                "action": "topUp",
                "type": "transaction",
                "channelId": "0xchannel123",
                "transaction": "0xtx",
                "additionalDeposit": "10000"
            }),
            "voucher" => serde_json::json!({
                "action": "voucher",
                "channelId": "0xchannel123",
                "cumulativeAmount": "15000",
                "signature": "0xsig"
            }),
            "close" => serde_json::json!({
                "action": "close",
                "channelId": "0xchannel123",
                "cumulativeAmount": "20000",
                "signature": "0xsig"
            }),
            _ => panic!("unknown action"),
        };
        PaymentCredential::with_raw_payload(echo, "did:test", raw)
    }

    fn stream_request() -> StreamRequest {
        StreamRequest {
            amount: "1000".into(),
            unit_type: "llm_token".into(),
            currency: "0x123".into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_method_mismatch() {
        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "test.com".into(),
            method: "other".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjoidmFsdWUifQ".into(),
            expires: None,
            digest: None,
        };
        let raw = serde_json::json!({"action": "voucher", "channelId": "0x1", "cumulativeAmount": "1", "signature": "0x"});
        let credential = PaymentCredential::with_raw_payload(echo, "did:test", raw);
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http("https://rpc.example.com".parse().unwrap());
        let method = StreamMethod::new(provider);
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Method mismatch"));
    }

    #[test]
    fn test_intent_mismatch() {
        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "test.com".into(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: "eyJ0ZXN0IjoidmFsdWUifQ".into(),
            expires: None,
            digest: None,
        };
        let raw = serde_json::json!({"action": "voucher", "channelId": "0x1", "cumulativeAmount": "1", "signature": "0x"});
        let credential = PaymentCredential::with_raw_payload(echo, "did:test", raw);
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http("https://rpc.example.com".parse().unwrap());
        let method = StreamMethod::new(provider);
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Intent mismatch"));
    }

    #[test]
    fn test_missing_raw_payload() {
        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "test.com".into(),
            method: "tempo".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjoidmFsdWUifQ".into(),
            expires: None,
            digest: None,
        };
        let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http("https://rpc.example.com".parse().unwrap());
        let method = StreamMethod::new(provider);
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .message
            .contains("missing raw_payload"));
    }

    #[test]
    fn test_invalid_payload_json() {
        let echo = ChallengeEcho {
            id: "test".into(),
            realm: "test.com".into(),
            method: "tempo".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjoidmFsdWUifQ".into(),
            expires: None,
            digest: None,
        };
        let raw = serde_json::json!({"action": "unknown_action", "channelId": "0x1"});
        let credential = PaymentCredential::with_raw_payload(echo, "did:test", raw);
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http("https://rpc.example.com".parse().unwrap());
        let method = StreamMethod::new(provider);
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Failed to parse"));
    }

    #[test]
    fn test_open_returns_channel_id() {
        let credential = stream_credential("open");
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http("https://rpc.example.com".parse().unwrap());
        let method = StreamMethod::new(provider);
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_ok());
        let receipt = result.unwrap();
        assert!(receipt.is_success());
        assert_eq!(receipt.reference, "0xchannel123");
    }

    #[test]
    fn test_voucher_returns_channel_id() {
        let credential = stream_credential("voucher");
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http("https://rpc.example.com".parse().unwrap());
        let method = StreamMethod::new(provider);
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().reference, "0xchannel123");
    }

    #[test]
    fn test_top_up_returns_channel_id() {
        let credential = stream_credential("topUp");
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http("https://rpc.example.com".parse().unwrap());
        let method = StreamMethod::new(provider);
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().reference, "0xchannel123");
    }

    #[test]
    fn test_close_returns_channel_id() {
        let credential = stream_credential("close");
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http("https://rpc.example.com".parse().unwrap());
        let method = StreamMethod::new(provider);
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().reference, "0xchannel123");
    }
}
