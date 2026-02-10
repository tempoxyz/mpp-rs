//! Tempo stream method for server-side streaming payment verification.
//!
//! This module provides [`StreamMethod`] which implements the [`StreamMethod`]
//! trait for **Tempo blockchain** streaming payments.
//!
//! # Tempo-Specific
//!
//! This verifier is designed specifically for the Tempo network.
//! It validates stream credential payloads (open, topUp, voucher, close),
//! verifies EIP-712 voucher signatures, and enforces cumulative monotonicity
//! via injectable [`ChannelStorage`].
//!
//! # Example
//!
//! ```ignore
//! use mpay::server::{tempo_provider, TempoStreamMethod, InMemoryChannelStorage};
//! use mpay::protocol::traits::StreamMethod as StreamMethodTrait;
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
//! let storage = InMemoryChannelStorage::new();
//! let method = TempoStreamMethod::new(provider, storage);
//!
//! // In your server handler:
//! let receipt = method.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use alloy::primitives::{Address, B256};
use alloy::providers::Provider;
use std::future::Future;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::StreamRequest;
use crate::protocol::traits::{StreamMethod as StreamMethodTrait, VerificationError};

use super::stream::{StreamCredentialPayload, TempoStreamExt};
use super::stream_storage::{ChannelState, ChannelStatus, ChannelStorage, SessionState};
use super::stream_verify::verify_voucher_signature;
use super::{INTENT_STREAM, METHOD_NAME};

/// Tempo stream method for payment channel verification.
///
/// Expects:
/// - `method="tempo"` in the credential
/// - `intent="stream"` in the credential
/// - A provider configured for `TempoNetwork`
/// - A [`ChannelStorage`] implementation for state tracking
///
/// # Verification Flow
///
/// - **open**: Store channel with authorized signer, optionally verify initial voucher
/// - **topUp**: Require channel exists and is open, update deposit
/// - **voucher**: Verify EIP-712 signature, enforce cumulative monotonicity
/// - **close**: Verify final voucher signature, mark channel closed
#[derive(Clone)]
pub struct StreamMethod<P, S> {
    provider: Arc<P>,
    storage: S,
}

impl<P, S> StreamMethod<P, S>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
    S: ChannelStorage,
{
    /// Create a new Tempo stream method with the given provider and storage.
    pub fn new(provider: P, storage: S) -> Self {
        Self {
            provider: Arc::new(provider),
            storage,
        }
    }

    /// Get a reference to the underlying provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Get a reference to the storage.
    pub fn storage(&self) -> &S {
        &self.storage
    }
}

impl<P, S> StreamMethodTrait for StreamMethod<P, S>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
    S: ChannelStorage,
{
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &StreamRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let credential = credential.clone();
        let request = request.clone();
        let storage = self.storage.clone();

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

            let escrow_contract_str = request.escrow_contract().map_err(|e| {
                VerificationError::new(format!(
                    "Stream request missing escrowContract in methodDetails: {}",
                    e
                ))
            })?;
            let escrow_contract: Address = escrow_contract_str.parse().map_err(|e| {
                VerificationError::new(format!("Invalid escrow contract address: {}", e))
            })?;
            let chain_id = request.chain_id().ok_or_else(|| {
                VerificationError::new(
                    "Stream request missing chainId in methodDetails — required for EIP-712 verification",
                )
            })?;

            match stream_payload {
                StreamCredentialPayload::Open {
                    channel_id,
                    authorized_signer,
                    cumulative_amount,
                    signature,
                    ..
                } => {
                    let auth_signer_str = authorized_signer.ok_or_else(|| {
                        VerificationError::new("open action missing authorizedSigner")
                    })?;
                    let auth_signer: Address = auth_signer_str.parse().map_err(|e| {
                        VerificationError::new(format!("Invalid authorizedSigner address: {}", e))
                    })?;
                    let channel_id_b256: B256 = channel_id
                        .parse()
                        .map_err(|e| VerificationError::new(format!("Invalid channelId: {}", e)))?;

                    let channel = ChannelState {
                        channel_id: channel_id_b256,
                        authorized_signer: auth_signer,
                        status: ChannelStatus::Open,
                        deposit: None,
                    };
                    storage.put_channel(channel).await.map_err(|e| {
                        VerificationError::new(format!("Failed to store channel: {}", e))
                    })?;

                    let cumulative: u128 = cumulative_amount.parse().unwrap_or(0);
                    if cumulative > 0 {
                        verify_voucher_signature(
                            channel_id_b256,
                            cumulative,
                            escrow_contract,
                            chain_id,
                            signature.signature(),
                            auth_signer,
                        )
                        .map_err(|e| {
                            VerificationError::new(format!(
                                "Open initial voucher signature invalid: {}",
                                e
                            ))
                        })?;

                        let payer_address = signature
                            .user_address()
                            .and_then(|s| s.parse::<Address>().ok());
                        let session = SessionState {
                            channel_id: channel_id_b256,
                            last_cumulative: cumulative,
                            payer_address,
                        };
                        storage.put_session(session).await.map_err(|e| {
                            VerificationError::new(format!("Failed to store session: {}", e))
                        })?;
                    }

                    Ok(Receipt::success(METHOD_NAME, channel_id))
                }

                StreamCredentialPayload::TopUp {
                    channel_id,
                    additional_deposit,
                    ..
                } => {
                    let channel_id_b256: B256 = channel_id
                        .parse()
                        .map_err(|e| VerificationError::new(format!("Invalid channelId: {}", e)))?;

                    let mut channel = storage
                        .get_channel(channel_id_b256)
                        .await
                        .map_err(|e| {
                            VerificationError::new(format!("Failed to load channel: {}", e))
                        })?
                        .ok_or_else(|| {
                            VerificationError::not_found("Channel not found for topUp")
                        })?;

                    if channel.status == ChannelStatus::Closed {
                        return Err(VerificationError::new("Cannot topUp a closed channel"));
                    }

                    let additional: u128 = additional_deposit.parse().map_err(|e| {
                        VerificationError::new(format!("Invalid additionalDeposit: {}", e))
                    })?;
                    channel.deposit = Some(channel.deposit.unwrap_or(0) + additional);
                    storage.put_channel(channel).await.map_err(|e| {
                        VerificationError::new(format!("Failed to update channel: {}", e))
                    })?;

                    Ok(Receipt::success(METHOD_NAME, channel_id))
                }

                StreamCredentialPayload::Voucher {
                    channel_id,
                    cumulative_amount,
                    signature,
                } => {
                    let channel_id_b256: B256 = channel_id
                        .parse()
                        .map_err(|e| VerificationError::new(format!("Invalid channelId: {}", e)))?;

                    let channel = storage
                        .get_channel(channel_id_b256)
                        .await
                        .map_err(|e| {
                            VerificationError::new(format!("Failed to load channel: {}", e))
                        })?
                        .ok_or_else(|| {
                            VerificationError::not_found("Channel not found for voucher")
                        })?;

                    if channel.status == ChannelStatus::Closed {
                        return Err(VerificationError::new(
                            "Cannot submit voucher for a closed channel",
                        ));
                    }

                    let cumulative: u128 = cumulative_amount.parse().map_err(|e| {
                        VerificationError::new(format!("Invalid cumulativeAmount: {}", e))
                    })?;

                    verify_voucher_signature(
                        channel_id_b256,
                        cumulative,
                        escrow_contract,
                        chain_id,
                        signature.signature(),
                        channel.authorized_signer,
                    )
                    .map_err(|e| {
                        VerificationError::new(format!("Voucher signature invalid: {}", e))
                    })?;

                    let payer_address = signature
                        .user_address()
                        .and_then(|s| s.parse::<Address>().ok());
                    let session = SessionState {
                        channel_id: channel_id_b256,
                        last_cumulative: cumulative,
                        payer_address,
                    };
                    storage.put_session(session).await.map_err(|e| {
                        VerificationError::new(format!("Voucher rejected (monotonicity): {}", e))
                    })?;

                    Ok(Receipt::success(METHOD_NAME, channel_id))
                }

                StreamCredentialPayload::Close {
                    channel_id,
                    cumulative_amount,
                    signature,
                } => {
                    let channel_id_b256: B256 = channel_id
                        .parse()
                        .map_err(|e| VerificationError::new(format!("Invalid channelId: {}", e)))?;

                    let mut channel = storage
                        .get_channel(channel_id_b256)
                        .await
                        .map_err(|e| {
                            VerificationError::new(format!("Failed to load channel: {}", e))
                        })?
                        .ok_or_else(|| {
                            VerificationError::not_found("Channel not found for close")
                        })?;

                    if channel.status == ChannelStatus::Closed {
                        return Err(VerificationError::new("Channel is already closed"));
                    }

                    let cumulative: u128 = cumulative_amount.parse().map_err(|e| {
                        VerificationError::new(format!("Invalid cumulativeAmount: {}", e))
                    })?;

                    verify_voucher_signature(
                        channel_id_b256,
                        cumulative,
                        escrow_contract,
                        chain_id,
                        signature.signature(),
                        channel.authorized_signer,
                    )
                    .map_err(|e| {
                        VerificationError::new(format!("Close voucher signature invalid: {}", e))
                    })?;

                    let payer_address = signature
                        .user_address()
                        .and_then(|s| s.parse::<Address>().ok());
                    let session = SessionState {
                        channel_id: channel_id_b256,
                        last_cumulative: cumulative,
                        payer_address,
                    };
                    // Allow equal cumulative for close (final voucher may be same as last)
                    let _ = storage.put_session(session).await;

                    channel.status = ChannelStatus::Closed;
                    storage.put_channel(channel).await.map_err(|e| {
                        VerificationError::new(format!("Failed to close channel: {}", e))
                    })?;

                    Ok(Receipt::success(METHOD_NAME, channel_id))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::{ChallengeEcho, PaymentCredential, PaymentPayload};
    use crate::protocol::methods::tempo::stream::VoucherSignature;
    use crate::protocol::methods::tempo::stream_storage::InMemoryChannelStorage;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use alloy::sol;
    use alloy::sol_types::{eip712_domain, SolStruct};

    const TEST_ESCROW: &str = "0x9d136eEa063eDE5418A6BC7bEafF009bBb6CFa70";
    const TEST_CHAIN_ID: u64 = 42431;

    fn test_signer() -> PrivateKeySigner {
        "0x1234567890123456789012345678901234567890123456789012345678901234"
            .parse()
            .unwrap()
    }

    fn sign_voucher(
        signer: &PrivateKeySigner,
        channel_id: B256,
        cumulative_amount: u128,
    ) -> String {
        sol! {
            #[derive(Default)]
            struct Voucher {
                bytes32 channelId;
                uint128 cumulativeAmount;
            }
        }

        let domain = eip712_domain! {
            name: "Tempo Stream Channel",
            version: "1",
            chain_id: TEST_CHAIN_ID,
            verifying_contract: TEST_ESCROW.parse::<Address>().unwrap(),
        };

        let voucher = Voucher {
            channelId: channel_id,
            cumulativeAmount: cumulative_amount,
        };

        let hash = voucher.eip712_signing_hash(&domain);
        let sig = signer.sign_hash_sync(&hash).unwrap();
        format!("0x{}", hex::encode(sig.as_bytes()))
    }

    fn stream_request() -> StreamRequest {
        StreamRequest {
            amount: "1000".into(),
            unit_type: "llm_token".into(),
            currency: "0x20c0000000000000000000000000000000000000".into(),
            method_details: Some(serde_json::json!({
                "escrowContract": TEST_ESCROW,
                "chainId": TEST_CHAIN_ID
            })),
            ..Default::default()
        }
    }

    fn make_credential(raw: serde_json::Value) -> PaymentCredential {
        let echo = ChallengeEcho {
            id: "test-id".into(),
            realm: "test.com".into(),
            method: "tempo".into(),
            intent: "stream".into(),
            request: "eyJ0ZXN0IjoidmFsdWUifQ".into(),
            expires: None,
            digest: None,
        };
        PaymentCredential::with_raw_payload(echo, "did:test", raw)
    }

    fn make_method() -> StreamMethod<
        alloy::providers::fillers::FillProvider<
            alloy::providers::fillers::JoinFill<
                alloy::providers::Identity,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::NonceFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::GasFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
            alloy::providers::RootProvider<TempoNetwork>,
            TempoNetwork,
        >,
        InMemoryChannelStorage,
    > {
        let provider = alloy::providers::ProviderBuilder::new_with_network::<TempoNetwork>()
            .connect_http("https://rpc.example.com".parse().unwrap());
        let storage = InMemoryChannelStorage::new();
        StreamMethod::new(provider, storage)
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
        let method = make_method();
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
        let method = make_method();
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
        let method = make_method();
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("missing raw_payload"));
    }

    #[test]
    fn test_open_stores_channel_and_verifies_voucher() {
        let signer = test_signer();
        let channel_id = B256::repeat_byte(0xAA);
        let voucher_sig = sign_voucher(&signer, channel_id, 5000);

        let raw = serde_json::json!({
            "action": "open",
            "type": "transaction",
            "channelId": format!("{:#x}", channel_id),
            "transaction": "0xdeadbeef",
            "signature": voucher_sig,
            "authorizedSigner": format!("{:#x}", signer.address()),
            "cumulativeAmount": "5000"
        });
        let credential = make_credential(raw);
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let method = make_method();
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_ok());
        let receipt = result.unwrap();
        assert!(receipt.is_success());

        let stored = rt
            .block_on(method.storage().get_channel(channel_id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, ChannelStatus::Open);
        assert_eq!(stored.authorized_signer, signer.address());

        let session = rt
            .block_on(method.storage().get_session(channel_id))
            .unwrap()
            .unwrap();
        assert_eq!(session.last_cumulative, 5000);
    }

    #[test]
    fn test_voucher_verifies_signature_and_enforces_monotonicity() {
        let signer = test_signer();
        let channel_id = B256::repeat_byte(0xBB);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let method = make_method();

        // Open channel first
        let open_sig = sign_voucher(&signer, channel_id, 1000);
        let open_raw = serde_json::json!({
            "action": "open",
            "type": "transaction",
            "channelId": format!("{:#x}", channel_id),
            "transaction": "0xdeadbeef",
            "signature": open_sig,
            "authorizedSigner": format!("{:#x}", signer.address()),
            "cumulativeAmount": "1000"
        });
        let result = rt.block_on(method.verify(&make_credential(open_raw), &stream_request()));
        assert!(result.is_ok());

        // Submit voucher with higher amount — should succeed
        let sig2 = sign_voucher(&signer, channel_id, 3000);
        let voucher_raw = serde_json::json!({
            "action": "voucher",
            "channelId": format!("{:#x}", channel_id),
            "cumulativeAmount": "3000",
            "signature": sig2
        });
        let result = rt.block_on(method.verify(&make_credential(voucher_raw), &stream_request()));
        assert!(result.is_ok());

        // Submit voucher with same amount — should fail (monotonicity)
        let sig3 = sign_voucher(&signer, channel_id, 3000);
        let voucher_raw2 = serde_json::json!({
            "action": "voucher",
            "channelId": format!("{:#x}", channel_id),
            "cumulativeAmount": "3000",
            "signature": sig3
        });
        let result = rt.block_on(method.verify(&make_credential(voucher_raw2), &stream_request()));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("monotonicity"));

        // Submit voucher with lower amount — should fail
        let sig4 = sign_voucher(&signer, channel_id, 2000);
        let voucher_raw3 = serde_json::json!({
            "action": "voucher",
            "channelId": format!("{:#x}", channel_id),
            "cumulativeAmount": "2000",
            "signature": sig4
        });
        let result = rt.block_on(method.verify(&make_credential(voucher_raw3), &stream_request()));
        assert!(result.is_err());
    }

    #[test]
    fn test_voucher_rejects_bad_signature() {
        let signer = test_signer();
        let channel_id = B256::repeat_byte(0xCC);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let method = make_method();

        // Open channel
        let open_sig = sign_voucher(&signer, channel_id, 1000);
        let open_raw = serde_json::json!({
            "action": "open",
            "type": "transaction",
            "channelId": format!("{:#x}", channel_id),
            "transaction": "0xdeadbeef",
            "signature": open_sig,
            "authorizedSigner": format!("{:#x}", signer.address()),
            "cumulativeAmount": "1000"
        });
        rt.block_on(method.verify(&make_credential(open_raw), &stream_request()))
            .unwrap();

        // Submit voucher with wrong signature (sign for different amount)
        let bad_sig = sign_voucher(&signer, channel_id, 9999);
        let voucher_raw = serde_json::json!({
            "action": "voucher",
            "channelId": format!("{:#x}", channel_id),
            "cumulativeAmount": "2000",
            "signature": bad_sig
        });
        let result = rt.block_on(method.verify(&make_credential(voucher_raw), &stream_request()));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("signature"));
    }

    #[test]
    fn test_close_marks_channel_closed() {
        let signer = test_signer();
        let channel_id = B256::repeat_byte(0xDD);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let method = make_method();

        // Open
        let open_sig = sign_voucher(&signer, channel_id, 1000);
        let open_raw = serde_json::json!({
            "action": "open",
            "type": "transaction",
            "channelId": format!("{:#x}", channel_id),
            "transaction": "0xdeadbeef",
            "signature": open_sig,
            "authorizedSigner": format!("{:#x}", signer.address()),
            "cumulativeAmount": "1000"
        });
        rt.block_on(method.verify(&make_credential(open_raw), &stream_request()))
            .unwrap();

        // Close
        let close_sig = sign_voucher(&signer, channel_id, 5000);
        let close_raw = serde_json::json!({
            "action": "close",
            "channelId": format!("{:#x}", channel_id),
            "cumulativeAmount": "5000",
            "signature": close_sig
        });
        let result = rt.block_on(method.verify(&make_credential(close_raw), &stream_request()));
        assert!(result.is_ok());

        // Verify channel is closed
        let stored = rt
            .block_on(method.storage().get_channel(channel_id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, ChannelStatus::Closed);

        // Further vouchers should fail
        let sig = sign_voucher(&signer, channel_id, 6000);
        let voucher_raw = serde_json::json!({
            "action": "voucher",
            "channelId": format!("{:#x}", channel_id),
            "cumulativeAmount": "6000",
            "signature": sig
        });
        let result = rt.block_on(method.verify(&make_credential(voucher_raw), &stream_request()));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("closed"));
    }

    #[test]
    fn test_top_up_increases_deposit() {
        let signer = test_signer();
        let channel_id = B256::repeat_byte(0xEE);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let method = make_method();

        // Open
        let open_sig = sign_voucher(&signer, channel_id, 0);
        let open_raw = serde_json::json!({
            "action": "open",
            "type": "transaction",
            "channelId": format!("{:#x}", channel_id),
            "transaction": "0xdeadbeef",
            "signature": open_sig,
            "authorizedSigner": format!("{:#x}", signer.address()),
            "cumulativeAmount": "0"
        });
        rt.block_on(method.verify(&make_credential(open_raw), &stream_request()))
            .unwrap();

        // TopUp
        let topup_raw = serde_json::json!({
            "action": "topUp",
            "type": "transaction",
            "channelId": format!("{:#x}", channel_id),
            "transaction": "0xfeed",
            "additionalDeposit": "50000"
        });
        let result = rt.block_on(method.verify(&make_credential(topup_raw), &stream_request()));
        assert!(result.is_ok());

        let stored = rt
            .block_on(method.storage().get_channel(channel_id))
            .unwrap()
            .unwrap();
        assert_eq!(stored.deposit, Some(50000));
    }

    #[test]
    fn test_voucher_with_envelope_signature() {
        let signer = test_signer();
        let channel_id = B256::repeat_byte(0xFF);
        let wallet_addr = Address::repeat_byte(0x99);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let method = make_method();

        // Open
        let open_sig = sign_voucher(&signer, channel_id, 1000);
        let open_raw = serde_json::json!({
            "action": "open",
            "type": "transaction",
            "channelId": format!("{:#x}", channel_id),
            "transaction": "0xdeadbeef",
            "signature": open_sig,
            "authorizedSigner": format!("{:#x}", signer.address()),
            "cumulativeAmount": "1000"
        });
        rt.block_on(method.verify(&make_credential(open_raw), &stream_request()))
            .unwrap();

        // Voucher with envelope signature
        let sig = sign_voucher(&signer, channel_id, 3000);
        let voucher_raw = serde_json::json!({
            "action": "voucher",
            "channelId": format!("{:#x}", channel_id),
            "cumulativeAmount": "3000",
            "signature": {
                "userAddress": format!("{:#x}", wallet_addr),
                "signature": sig
            }
        });
        let result = rt.block_on(method.verify(&make_credential(voucher_raw), &stream_request()));
        assert!(result.is_ok());

        // Verify payer_address was stored
        let session = rt
            .block_on(method.storage().get_session(channel_id))
            .unwrap()
            .unwrap();
        assert_eq!(session.payer_address, Some(wallet_addr));
    }

    #[test]
    fn test_open_missing_authorized_signer() {
        let signer = test_signer();
        let channel_id = B256::repeat_byte(0x11);
        let sig = sign_voucher(&signer, channel_id, 1000);

        let raw = serde_json::json!({
            "action": "open",
            "type": "transaction",
            "channelId": format!("{:#x}", channel_id),
            "transaction": "0xdeadbeef",
            "signature": sig,
            "cumulativeAmount": "1000"
        });
        let credential = make_credential(raw);
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let method = make_method();
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("authorizedSigner"));
    }

    #[test]
    fn test_voucher_for_nonexistent_channel() {
        let signer = test_signer();
        let channel_id = B256::repeat_byte(0x22);
        let sig = sign_voucher(&signer, channel_id, 1000);

        let raw = serde_json::json!({
            "action": "voucher",
            "channelId": format!("{:#x}", channel_id),
            "cumulativeAmount": "1000",
            "signature": sig
        });
        let credential = make_credential(raw);
        let request = stream_request();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let method = make_method();
        let result = rt.block_on(method.verify(&credential, &request));
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("not found"));
    }
}
