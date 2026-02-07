//! Server-side stream payment verification.
//!
//! Provides [`StreamServer`] for verifying stream payment credentials,
//! managing session accounting, and charging against session balances.
//!
//! # Verification Flow
//!
//! 1. Client sends a `StreamCredentialPayload` (voucher, open, topUp, or close action)
//! 2. Server verifies the payload and updates channel/session state
//! 3. Server returns a `StreamReceipt` on success
//!
//! # Charging
//!
//! After a session is established (via voucher/open), the server can charge
//! against the session balance using [`StreamServer::charge`]. Each charge
//! deducts from the session's available balance (accepted_cumulative - spent).
//!
//! # Example
//!
//! ```ignore
//! use mpay::protocol::methods::tempo::stream::server::{StreamServer, StreamConfig};
//! use mpay::protocol::methods::tempo::stream::storage::MemoryStorage;
//!
//! let storage = MemoryStorage::new();
//! let server = StreamServer::new(storage, StreamConfig {
//!     chain_id: 42431,
//!     escrow_contract: "0x...".parse().unwrap(),
//!     min_delta: 0,
//! });
//!
//! // Verify a voucher credential
//! let receipt = server.verify(&payload, "challenge-id").await?;
//!
//! // Charge against the session
//! let receipt = server.charge(channel_id, 100_000).await?;
//! ```

use std::sync::Arc;
use std::time::SystemTime;

use alloy::primitives::{Address, FixedBytes};

use super::errors::StreamError;
use super::receipt::{create_stream_receipt, CreateStreamReceiptParams};
use super::storage::{ChannelStorage, SessionState};
use super::types::{StreamCredentialPayload, StreamReceipt};
use super::voucher;

/// Configuration for the stream server.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Chain ID for EIP-712 domain (e.g., 42431 for Moderato).
    pub chain_id: u64,
    /// Address of the on-chain escrow contract.
    pub escrow_contract: Address,
    /// Minimum voucher delta the server will accept (0 = no minimum).
    pub min_delta: u128,
}

/// Server-side stream payment verifier.
///
/// Handles voucher verification, session accounting, and charging.
/// Generic over [`ChannelStorage`] for pluggable persistence backends.
///
/// For on-chain operations (open, topUp, close with settlement),
/// a provider will be needed — these operations will be supported
/// in a future update.
pub struct StreamServer<S> {
    storage: Arc<S>,
    config: StreamConfig,
}

impl<S: ChannelStorage> StreamServer<S> {
    /// Create a new stream server.
    pub fn new(storage: S, config: StreamConfig) -> Self {
        Self {
            storage: Arc::new(storage),
            config,
        }
    }

    /// Get a reference to the storage backend.
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Get a reference to the server configuration.
    pub fn config(&self) -> &StreamConfig {
        &self.config
    }

    /// Verify a stream credential and return a receipt.
    ///
    /// Dispatches to the appropriate handler based on the credential's `action` field.
    pub async fn verify(
        &self,
        payload: &StreamCredentialPayload,
        challenge_id: &str,
    ) -> Result<StreamReceipt, StreamError> {
        match payload {
            StreamCredentialPayload::Voucher {
                channel_id,
                cumulative_amount,
                signature,
            } => {
                self.handle_voucher(channel_id, cumulative_amount, signature, challenge_id)
                    .await
            }
            StreamCredentialPayload::Open { .. } => Err(StreamError::BadRequest {
                reason: "open action requires on-chain provider (not yet supported)".into(),
            }),
            StreamCredentialPayload::TopUp { .. } => Err(StreamError::BadRequest {
                reason: "topUp action requires on-chain provider (not yet supported)".into(),
            }),
            StreamCredentialPayload::Close { .. } => Err(StreamError::BadRequest {
                reason: "close action requires on-chain provider (not yet supported)".into(),
            }),
        }
    }

    /// Handle a voucher submission.
    ///
    /// Verifies the voucher signature, checks monotonicity and deposit limits,
    /// and atomically updates channel and session state.
    async fn handle_voucher(
        &self,
        channel_id: &str,
        cumulative_amount: &str,
        signature: &str,
        challenge_id: &str,
    ) -> Result<StreamReceipt, StreamError> {
        let signed = voucher::parse_voucher_from_payload(channel_id, cumulative_amount, signature)
            .map_err(|e| StreamError::BadRequest {
                reason: e.to_string(),
            })?;

        // Verify signature before entering the atomic update. This is pure
        // crypto (no state dependency) so it's safe to do outside the callback.
        let recovered = voucher::verify_voucher(
            &signed,
            self.config.chain_id,
            self.config.escrow_contract,
        )
        .map_err(|e| StreamError::InvalidSignature {
            reason: format!("Voucher signature verification failed: {e}"),
        })?;

        if recovered == Address::ZERO {
            return Err(StreamError::InvalidSignature {
                reason: "Recovered zero address from voucher signature".into(),
            });
        }

        let session = self
            .verify_and_accept_voucher(&signed, recovered, challenge_id)
            .await?;

        Ok(create_stream_receipt(CreateStreamReceiptParams {
            challenge_id: challenge_id.to_string(),
            channel_id: signed.channel_id,
            accepted_cumulative: session.accepted_cumulative,
            spent: session.spent,
            units: Some(session.units),
            tx_hash: None,
        }))
    }

    /// Atomically verify and accept a voucher.
    ///
    /// All state-dependent validation (monotonicity, deposit limits, session
    /// conflict, signer check) happens inside the `update_channel` callback
    /// to prevent TOCTOU races. The session is updated in a second atomic
    /// step afterward.
    ///
    /// Returns the updated session state on success.
    async fn verify_and_accept_voucher(
        &self,
        signed: &super::types::SignedVoucher,
        recovered_signer: Address,
        challenge_id: &str,
    ) -> Result<SessionState, StreamError> {
        let signed_clone = signed.clone();
        let challenge_id_owned = challenge_id.to_string();
        let min_delta = self.config.min_delta;

        // Channel error slot: the closure writes any validation error here.
        let channel_error: std::sync::Arc<std::sync::Mutex<Option<StreamError>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let error_slot = channel_error.clone();

        self.storage
            .update_channel(
                signed.channel_id,
                Box::new(move |current| {
                    let Some(mut ch) = current else {
                        *error_slot.lock().unwrap() = Some(StreamError::ChannelNotFound {
                            reason: format!("Channel {} not found", signed_clone.channel_id),
                        });
                        return None;
                    };

                    if ch.finalized {
                        *error_slot.lock().unwrap() = Some(StreamError::ChannelClosed {
                            reason: format!("Channel {} is finalized", signed_clone.channel_id),
                        });
                        return Some(ch);
                    }

                    if let Some(ref active) = ch.active_session_id {
                        if *active != challenge_id_owned {
                            *error_slot.lock().unwrap() = Some(StreamError::ChannelConflict {
                                reason: format!(
                                    "Channel {} has active session {}, cannot use {}",
                                    signed_clone.channel_id, active, challenge_id_owned
                                ),
                            });
                            return Some(ch);
                        }
                    }

                    if ch.authorized_signer == Address::ZERO {
                        *error_slot.lock().unwrap() = Some(StreamError::InvalidSignature {
                            reason: "Channel has zero address as authorized signer".into(),
                        });
                        return Some(ch);
                    }

                    if recovered_signer != ch.authorized_signer {
                        *error_slot.lock().unwrap() = Some(StreamError::InvalidSignature {
                            reason: format!(
                                "Voucher signed by {}, expected {}",
                                recovered_signer, ch.authorized_signer
                            ),
                        });
                        return Some(ch);
                    }

                    if signed_clone.cumulative_amount < ch.highest_voucher_amount {
                        *error_slot.lock().unwrap() = Some(StreamError::DeltaTooSmall {
                            reason: format!(
                                "Cumulative amount {} is less than current highest {}",
                                signed_clone.cumulative_amount, ch.highest_voucher_amount
                            ),
                        });
                        return Some(ch);
                    }

                    if signed_clone.cumulative_amount > ch.deposit {
                        *error_slot.lock().unwrap() = Some(StreamError::AmountExceedsDeposit {
                            reason: format!(
                                "Cumulative amount {} exceeds deposit {}",
                                signed_clone.cumulative_amount, ch.deposit
                            ),
                        });
                        return Some(ch);
                    }

                    if min_delta > 0 {
                        let delta =
                            signed_clone.cumulative_amount - ch.highest_voucher_amount;
                        if delta > 0 && delta < min_delta {
                            *error_slot.lock().unwrap() = Some(StreamError::DeltaTooSmall {
                                reason: format!(
                                    "Voucher delta {} is below minimum {}",
                                    delta, min_delta
                                ),
                            });
                            return Some(ch);
                        }
                    }

                    if signed_clone.cumulative_amount > ch.highest_voucher_amount {
                        ch.highest_voucher_amount = signed_clone.cumulative_amount;
                        ch.highest_voucher = Some(signed_clone);
                    }
                    ch.active_session_id = Some(challenge_id_owned);
                    Some(ch)
                }),
            )
            .await;

        if let Some(err) = channel_error.lock().unwrap().take() {
            return Err(err);
        }

        let channel_id = signed.channel_id;
        let new_cumulative = signed.cumulative_amount;
        let challenge_for_session = challenge_id.to_string();

        let session = self
            .storage
            .update_session(
                challenge_id,
                Box::new(move |current| {
                    let mut session = current.unwrap_or_else(|| SessionState {
                        challenge_id: challenge_for_session,
                        channel_id,
                        accepted_cumulative: 0,
                        spent: 0,
                        units: 0,
                        created_at: SystemTime::now(),
                    });
                    session.accepted_cumulative = new_cumulative;
                    Some(session)
                }),
            )
            .await
            .expect("update_session callback always returns Some");

        Ok(session)
    }

    /// Charge against a session's balance.
    ///
    /// Deducts `cost` from the session's available balance
    /// (accepted_cumulative - spent). Returns a receipt on success.
    ///
    /// # Errors
    ///
    /// - [`StreamError::ChannelNotFound`] if the channel or session doesn't exist
    /// - [`StreamError::InsufficientBalance`] if the session balance is too low
    pub async fn charge(
        &self,
        channel_id: FixedBytes<32>,
        cost: u128,
    ) -> Result<StreamReceipt, StreamError> {
        let channel = self
            .storage
            .get_channel(channel_id)
            .await
            .ok_or_else(|| StreamError::ChannelNotFound {
                reason: format!("Channel {} not found", channel_id),
            })?;

        let challenge_id =
            channel
                .active_session_id
                .ok_or_else(|| StreamError::ChannelNotFound {
                    reason: "No active session on channel".into(),
                })?;

        let charge_error: std::sync::Arc<std::sync::Mutex<Option<StreamError>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let error_slot = charge_error.clone();

        let updated = self
            .storage
            .update_session(
                &challenge_id,
                Box::new(move |current| {
                    let Some(mut s) = current else {
                        *error_slot.lock().unwrap() = Some(StreamError::ChannelNotFound {
                            reason: "Session not found".into(),
                        });
                        return None;
                    };
                    let balance = s.accepted_cumulative.saturating_sub(s.spent);
                    if balance < cost {
                        *error_slot.lock().unwrap() = Some(StreamError::InsufficientBalance {
                            reason: format!("Balance {} is less than cost {}", balance, cost),
                        });
                        return Some(s);
                    }
                    s.spent += cost;
                    s.units += 1;
                    Some(s)
                }),
            )
            .await;

        if let Some(err) = charge_error.lock().unwrap().take() {
            return Err(err);
        }

        let updated = updated.expect("update_session callback always returns Some on success");

        Ok(create_stream_receipt(CreateStreamReceiptParams {
            challenge_id,
            channel_id,
            accepted_cumulative: updated.accepted_cumulative,
            spent: updated.spent,
            units: Some(updated.units),
            tx_hash: None,
        }))
    }

    /// Get the remaining balance for a channel's active session.
    ///
    /// Returns `(balance, session)` where balance = accepted_cumulative - spent.
    pub async fn balance(
        &self,
        channel_id: FixedBytes<32>,
    ) -> Result<(u128, SessionState), StreamError> {
        let channel = self
            .storage
            .get_channel(channel_id)
            .await
            .ok_or_else(|| StreamError::ChannelNotFound {
                reason: format!("Channel {} not found", channel_id),
            })?;

        let challenge_id =
            channel
                .active_session_id
                .ok_or_else(|| StreamError::ChannelNotFound {
                    reason: "No active session on channel".into(),
                })?;

        let session = self
            .storage
            .get_session(&challenge_id)
            .await
            .ok_or_else(|| StreamError::ChannelNotFound {
                reason: format!("Session {} not found", challenge_id),
            })?;

        let balance = session.accepted_cumulative.saturating_sub(session.spent);
        Ok((balance, session))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::storage::{ChannelState, MemoryStorage};
    use super::super::types::{SignedVoucher, Voucher as VoucherType};
    use super::super::voucher::sign_voucher;
    use alloy::primitives::hex;
    use alloy_signer_local::PrivateKeySigner;

    fn test_escrow_address() -> Address {
        "0x1234567890abcdef1234567890abcdef12345678"
            .parse()
            .unwrap()
    }

    fn test_channel_id() -> FixedBytes<32> {
        FixedBytes::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 1,
        ])
    }

    fn test_config() -> StreamConfig {
        StreamConfig {
            chain_id: 42431,
            escrow_contract: test_escrow_address(),
            min_delta: 0,
        }
    }

    async fn setup_channel(storage: &MemoryStorage, signer_address: Address) {
        let id = test_channel_id();
        storage
            .update_channel(
                id,
                Box::new(move |_| {
                    Some(ChannelState {
                        channel_id: id,
                        payer: Address::ZERO,
                        payee: Address::ZERO,
                        token: Address::ZERO,
                        authorized_signer: signer_address,
                        deposit: 10_000_000,
                        settled_on_chain: 0,
                        highest_voucher_amount: 0,
                        highest_voucher: None,
                        active_session_id: None,
                        finalized: false,
                        created_at: SystemTime::now(),
                    })
                }),
            )
            .await;
    }

    fn make_voucher_payload(
        signed: &SignedVoucher,
    ) -> StreamCredentialPayload {
        StreamCredentialPayload::Voucher {
            channel_id: signed.channel_id.to_string(),
            cumulative_amount: signed.cumulative_amount.to_string(),
            signature: format!("0x{}", hex::encode(signed.signature.as_ref())),
        }
    }

    // ==================== Voucher Verification Tests ====================

    #[tokio::test]
    async fn test_handle_voucher_success() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());

        let voucher = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 5_000_000,
        };
        let signed = sign_voucher(&signer, &voucher, 42431, test_escrow_address())
            .await
            .unwrap();

        let payload = make_voucher_payload(&signed);
        let receipt = server.verify(&payload, "challenge-1").await.unwrap();

        assert_eq!(receipt.method, "tempo");
        assert_eq!(receipt.intent, "stream");
        assert_eq!(receipt.status, "success");
        assert_eq!(receipt.accepted_cumulative, "5000000");
        assert_eq!(receipt.spent, "0");
        assert_eq!(receipt.units, Some(0));
        assert_eq!(receipt.challenge_id, "challenge-1");
    }

    #[tokio::test]
    async fn test_handle_voucher_incremental() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        // First voucher: 3M
        let v1 = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 3_000_000,
        };
        let s1 = sign_voucher(&signer, &v1, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        let r1 = server
            .verify(&make_voucher_payload(&s1), "challenge-1")
            .await
            .unwrap();
        assert_eq!(r1.accepted_cumulative, "3000000");

        // Second voucher: 7M (higher cumulative)
        let v2 = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 7_000_000,
        };
        let s2 = sign_voucher(&signer, &v2, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        let r2 = server
            .verify(&make_voucher_payload(&s2), "challenge-1")
            .await
            .unwrap();
        assert_eq!(r2.accepted_cumulative, "7000000");
    }

    #[tokio::test]
    async fn test_voucher_monotonic_rejection() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        // First voucher: 5M
        let v1 = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 5_000_000,
        };
        let s1 = sign_voucher(&signer, &v1, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        server
            .verify(&make_voucher_payload(&s1), "challenge-1")
            .await
            .unwrap();

        // Second voucher: 3M (lower — should fail)
        let v2 = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 3_000_000,
        };
        let s2 = sign_voucher(&signer, &v2, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        let result = server
            .verify(&make_voucher_payload(&s2), "challenge-1")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StreamError::DeltaTooSmall { .. }));
    }

    #[tokio::test]
    async fn test_voucher_exceeds_deposit() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        // Voucher for more than deposit (10M)
        let voucher = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 20_000_000,
        };
        let signed = sign_voucher(&signer, &voucher, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        let result = server
            .verify(&make_voucher_payload(&signed), "challenge-1")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StreamError::AmountExceedsDeposit { .. }));
    }

    #[tokio::test]
    async fn test_voucher_wrong_signer() {
        let signer = PrivateKeySigner::random();
        let wrong_signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        // Sign with wrong signer
        let voucher = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 5_000_000,
        };
        let signed = sign_voucher(&wrong_signer, &voucher, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        let result = server
            .verify(&make_voucher_payload(&signed), "challenge-1")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StreamError::InvalidSignature { .. }));
    }

    #[tokio::test]
    async fn test_voucher_channel_not_found() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        // Don't set up any channel

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        let voucher = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 5_000_000,
        };
        let signed = sign_voucher(&signer, &voucher, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        let result = server
            .verify(&make_voucher_payload(&signed), "challenge-1")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StreamError::ChannelNotFound { .. }));
        assert_eq!(err.status(), 410);
    }

    #[tokio::test]
    async fn test_voucher_channel_finalized() {
        let signer = PrivateKeySigner::random();
        let signer_address = signer.address();
        let storage = MemoryStorage::new();
        let id = test_channel_id();

        // Create a finalized channel
        storage
            .update_channel(
                id,
                Box::new(move |_| {
                    Some(ChannelState {
                        channel_id: id,
                        payer: Address::ZERO,
                        payee: Address::ZERO,
                        token: Address::ZERO,
                        authorized_signer: signer_address,
                        deposit: 10_000_000,
                        settled_on_chain: 0,
                        highest_voucher_amount: 0,
                        highest_voucher: None,
                        active_session_id: None,
                        finalized: true,
                        created_at: SystemTime::now(),
                    })
                }),
            )
            .await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        let voucher = VoucherType {
            channel_id: id,
            cumulative_amount: 5_000_000,
        };
        let signed = sign_voucher(&signer, &voucher, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        let result = server
            .verify(&make_voucher_payload(&signed), "challenge-1")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StreamError::ChannelClosed { .. }));
        assert_eq!(err.status(), 410);
    }

    #[tokio::test]
    async fn test_session_conflict() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        // First voucher with challenge-1
        let v1 = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 3_000_000,
        };
        let s1 = sign_voucher(&signer, &v1, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        server
            .verify(&make_voucher_payload(&s1), "challenge-1")
            .await
            .unwrap();

        // Second voucher with different challenge — should conflict
        let v2 = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 5_000_000,
        };
        let s2 = sign_voucher(&signer, &v2, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        let result = server
            .verify(&make_voucher_payload(&s2), "challenge-2")
            .await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StreamError::ChannelConflict { .. }));
        assert_eq!(err.status(), 409);
    }

    // ==================== Charge Tests ====================

    #[tokio::test]
    async fn test_charge_success() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        // Submit a voucher for 5M
        let voucher = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 5_000_000,
        };
        let signed = sign_voucher(&signer, &voucher, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        server
            .verify(&make_voucher_payload(&signed), "challenge-1")
            .await
            .unwrap();

        // Charge 1M
        let receipt = server.charge(test_channel_id(), 1_000_000).await.unwrap();
        assert_eq!(receipt.spent, "1000000");
        assert_eq!(receipt.units, Some(1));
        assert_eq!(receipt.accepted_cumulative, "5000000");

        // Charge another 2M
        let receipt = server.charge(test_channel_id(), 2_000_000).await.unwrap();
        assert_eq!(receipt.spent, "3000000");
        assert_eq!(receipt.units, Some(2));
    }

    #[tokio::test]
    async fn test_charge_insufficient_balance() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        // Submit a voucher for 5M
        let voucher = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 5_000_000,
        };
        let signed = sign_voucher(&signer, &voucher, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        server
            .verify(&make_voucher_payload(&signed), "challenge-1")
            .await
            .unwrap();

        // Try to charge more than balance
        let result = server.charge(test_channel_id(), 6_000_000).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, StreamError::InsufficientBalance { .. }));
        assert_eq!(err.status(), 402);
    }

    #[tokio::test]
    async fn test_charge_no_active_session() {
        let storage = MemoryStorage::new();
        let id = test_channel_id();

        // Create channel with no active session
        storage
            .update_channel(
                id,
                Box::new(move |_| {
                    Some(ChannelState {
                        channel_id: id,
                        payer: Address::ZERO,
                        payee: Address::ZERO,
                        token: Address::ZERO,
                        authorized_signer: Address::ZERO,
                        deposit: 10_000_000,
                        settled_on_chain: 0,
                        highest_voucher_amount: 0,
                        highest_voucher: None,
                        active_session_id: None,
                        finalized: false,
                        created_at: SystemTime::now(),
                    })
                }),
            )
            .await;

        let server = StreamServer::new(storage, test_config());
        let result = server.charge(id, 1_000_000).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StreamError::ChannelNotFound { .. }
        ));
    }

    // ==================== Balance Tests ====================

    #[tokio::test]
    async fn test_balance() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        // Submit voucher for 5M
        let voucher = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 5_000_000,
        };
        let signed = sign_voucher(&signer, &voucher, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        server
            .verify(&make_voucher_payload(&signed), "challenge-1")
            .await
            .unwrap();

        let (balance, session) = server.balance(test_channel_id()).await.unwrap();
        assert_eq!(balance, 5_000_000);
        assert_eq!(session.accepted_cumulative, 5_000_000);
        assert_eq!(session.spent, 0);

        // Charge 2M
        server.charge(test_channel_id(), 2_000_000).await.unwrap();

        let (balance, session) = server.balance(test_channel_id()).await.unwrap();
        assert_eq!(balance, 3_000_000);
        assert_eq!(session.spent, 2_000_000);
    }

    // ==================== Min Delta Tests ====================

    #[tokio::test]
    async fn test_min_delta_enforcement() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let config = StreamConfig {
            chain_id: 42431,
            escrow_contract: test_escrow_address(),
            min_delta: 1_000_000, // Minimum 1M delta
        };
        let server = StreamServer::new(storage, config);

        // First voucher: 5M (delta = 5M, OK)
        let v1 = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 5_000_000,
        };
        let s1 = sign_voucher(&signer, &v1, 42431, test_escrow_address())
            .await
            .unwrap();
        server
            .verify(&make_voucher_payload(&s1), "challenge-1")
            .await
            .unwrap();

        // Second voucher: 5.5M (delta = 500K, below min_delta)
        let v2 = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 5_500_000,
        };
        let s2 = sign_voucher(&signer, &v2, 42431, test_escrow_address())
            .await
            .unwrap();
        let result = server
            .verify(&make_voucher_payload(&s2), "challenge-1")
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StreamError::DeltaTooSmall { .. }
        ));
    }

    // ==================== Lifecycle Tests ====================

    #[tokio::test]
    async fn test_voucher_charge_lifecycle() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        // Submit initial voucher: 3M
        let v1 = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 3_000_000,
        };
        let s1 = sign_voucher(&signer, &v1, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        server
            .verify(&make_voucher_payload(&s1), "challenge-1")
            .await
            .unwrap();

        // Charge 1M
        let r = server.charge(test_channel_id(), 1_000_000).await.unwrap();
        assert_eq!(r.units, Some(1));
        assert_eq!(r.spent, "1000000");

        // Charge 1M again
        let r = server.charge(test_channel_id(), 1_000_000).await.unwrap();
        assert_eq!(r.units, Some(2));
        assert_eq!(r.spent, "2000000");

        // Balance should be 1M
        let (balance, _) = server.balance(test_channel_id()).await.unwrap();
        assert_eq!(balance, 1_000_000);

        // Submit higher voucher: 8M
        let v2 = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 8_000_000,
        };
        let s2 = sign_voucher(&signer, &v2, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        server
            .verify(&make_voucher_payload(&s2), "challenge-1")
            .await
            .unwrap();

        // Balance should be 8M - 2M = 6M
        let (balance, _) = server.balance(test_channel_id()).await.unwrap();
        assert_eq!(balance, 6_000_000);

        // Charge 3M
        let r = server.charge(test_channel_id(), 3_000_000).await.unwrap();
        assert_eq!(r.units, Some(3));
        assert_eq!(r.spent, "5000000");

        // Try to charge more than remaining (3M > 3M balance)
        let result = server.charge(test_channel_id(), 4_000_000).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StreamError::InsufficientBalance { .. }
        ));
    }

    // ==================== Error Status Code Tests ====================

    #[tokio::test]
    async fn test_error_status_codes() {
        let signer = PrivateKeySigner::random();
        let storage = MemoryStorage::new();
        setup_channel(&storage, signer.address()).await;

        let server = StreamServer::new(storage, test_config());
        let cfg = test_config();

        // Channel not found → 410
        let voucher = VoucherType {
            channel_id: FixedBytes::from([0u8; 32]),
            cumulative_amount: 1_000_000,
        };
        let signed = sign_voucher(&signer, &voucher, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        let err = server
            .verify(&make_voucher_payload(&signed), "c1")
            .await
            .unwrap_err();
        assert_eq!(err.status(), 410);

        // Amount exceeds deposit → 402
        let voucher = VoucherType {
            channel_id: test_channel_id(),
            cumulative_amount: 999_000_000,
        };
        let signed = sign_voucher(&signer, &voucher, cfg.chain_id, cfg.escrow_contract)
            .await
            .unwrap();
        let err = server
            .verify(&make_voucher_payload(&signed), "c2")
            .await
            .unwrap_err();
        assert_eq!(err.status(), 402);
    }
}
