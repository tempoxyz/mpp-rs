//! Channel and session storage for stream payments.
//!
//! Provides the [`ChannelStorage`] trait for persisting channel and session state,
//! and a [`MemoryStorage`] implementation for testing and examples.

use alloy::primitives::{Address, FixedBytes};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Mutex;
use std::time::SystemTime;

use super::types::SignedVoucher;

/// Channel state tracked by the server.
///
/// Represents the server's view of a payment channel, including the highest
/// voucher received and the on-chain settlement status.
#[derive(Debug, Clone)]
pub struct ChannelState {
    /// Channel identifier (bytes32).
    pub channel_id: FixedBytes<32>,
    /// Payer address (channel opener).
    pub payer: Address,
    /// Payee address (server/recipient).
    pub payee: Address,
    /// Token address.
    pub token: Address,
    /// Authorized voucher signer.
    pub authorized_signer: Address,
    /// Current on-chain deposit.
    pub deposit: u128,
    /// Amount already settled on-chain.
    pub settled_on_chain: u128,
    /// Highest voucher cumulative amount accepted.
    pub highest_voucher_amount: u128,
    /// The actual highest voucher (for on-chain settlement).
    pub highest_voucher: Option<SignedVoucher>,
    /// Active session ID (prevents concurrent streams).
    pub active_session_id: Option<String>,
    /// Whether the channel is finalized.
    pub finalized: bool,
    /// When the channel state was created.
    pub created_at: SystemTime,
}

/// Session state for per-challenge accounting.
///
/// Tracks how much has been accepted and spent within a single stream session
/// (identified by challenge ID).
#[derive(Debug, Clone)]
pub struct SessionState {
    /// Challenge ID this session corresponds to.
    pub challenge_id: String,
    /// Channel this session is attached to.
    pub channel_id: FixedBytes<32>,
    /// Latest accepted cumulative amount (monotonically increasing).
    pub accepted_cumulative: u128,
    /// Amount spent (deducted) in this session.
    pub spent: u128,
    /// Number of charges in this session.
    pub units: u64,
    /// When the session was created.
    pub created_at: SystemTime,
}

/// Storage interface for channel state persistence.
///
/// Uses atomic update callbacks for read-modify-write safety.
/// Backends implement atomicity via their native mechanisms
/// (Rust Mutex, database transactions, etc.).
///
/// The update callbacks are intentionally synchronous — they receive the current
/// state and return the new state. Any async work (signature verification, RPC calls)
/// should be done before or after the update call, not inside the callback.
pub trait ChannelStorage: Send + Sync {
    /// Get the current state of a channel.
    fn get_channel(
        &self,
        channel_id: FixedBytes<32>,
    ) -> impl Future<Output = Option<ChannelState>> + Send;

    /// Get the current state of a session.
    fn get_session(&self, challenge_id: &str) -> impl Future<Output = Option<SessionState>> + Send;

    /// Atomic read-modify-write for channel state.
    ///
    /// The callback receives the current state (or None if not found) and returns
    /// the new state (or None to delete). The implementation must ensure atomicity.
    fn update_channel(
        &self,
        channel_id: FixedBytes<32>,
        f: Box<dyn FnOnce(Option<ChannelState>) -> Option<ChannelState> + Send>,
    ) -> impl Future<Output = Option<ChannelState>> + Send;

    /// Atomic read-modify-write for session state.
    ///
    /// The callback receives the current state (or None if not found) and returns
    /// the new state (or None to delete). The implementation must ensure atomicity.
    fn update_session(
        &self,
        challenge_id: &str,
        f: Box<dyn FnOnce(Option<SessionState>) -> Option<SessionState> + Send>,
    ) -> impl Future<Output = Option<SessionState>> + Send;
}

/// In-memory storage implementation for testing and examples.
///
/// Uses `std::sync::Mutex` for atomic updates. Suitable for single-process
/// usage (tests, examples, simple servers). For production, implement
/// `ChannelStorage` with a database backend.
pub struct MemoryStorage {
    channels: Mutex<HashMap<FixedBytes<32>, ChannelState>>,
    sessions: Mutex<HashMap<String, SessionState>>,
}

impl MemoryStorage {
    /// Create a new empty in-memory storage.
    pub fn new() -> Self {
        Self {
            channels: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelStorage for MemoryStorage {
    fn get_channel(
        &self,
        channel_id: FixedBytes<32>,
    ) -> impl Future<Output = Option<ChannelState>> + Send {
        let result = self.channels.lock().unwrap().get(&channel_id).cloned();
        async move { result }
    }

    fn get_session(&self, challenge_id: &str) -> impl Future<Output = Option<SessionState>> + Send {
        let result = self.sessions.lock().unwrap().get(challenge_id).cloned();
        async move { result }
    }

    fn update_channel(
        &self,
        channel_id: FixedBytes<32>,
        f: Box<dyn FnOnce(Option<ChannelState>) -> Option<ChannelState> + Send>,
    ) -> impl Future<Output = Option<ChannelState>> + Send {
        let result = {
            let mut channels = self.channels.lock().unwrap();
            let current = channels.get(&channel_id).cloned();
            let next = f(current);
            if let Some(ref state) = next {
                channels.insert(channel_id, state.clone());
            } else {
                channels.remove(&channel_id);
            }
            next
        };
        async move { result }
    }

    fn update_session(
        &self,
        challenge_id: &str,
        f: Box<dyn FnOnce(Option<SessionState>) -> Option<SessionState> + Send>,
    ) -> impl Future<Output = Option<SessionState>> + Send {
        let result = {
            let mut sessions = self.sessions.lock().unwrap();
            let current = sessions.get(challenge_id).cloned();
            let next = f(current);
            if let Some(ref state) = next {
                sessions.insert(challenge_id.to_string(), state.clone());
            } else {
                sessions.remove(challenge_id);
            }
            next
        };
        async move { result }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_channel_id() -> FixedBytes<32> {
        FixedBytes::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ])
    }

    #[tokio::test]
    async fn test_memory_storage_channel_crud() {
        let storage = MemoryStorage::new();
        let id = test_channel_id();

        assert!(storage.get_channel(id).await.is_none());

        let created = storage
            .update_channel(
                id,
                Box::new(|_| {
                    Some(ChannelState {
                        channel_id: test_channel_id(),
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
        assert!(created.is_some());
        assert_eq!(created.unwrap().deposit, 10_000_000);

        let ch = storage.get_channel(id).await.unwrap();
        assert_eq!(ch.deposit, 10_000_000);

        let updated = storage
            .update_channel(
                id,
                Box::new(|current| {
                    current.map(|mut ch| {
                        ch.deposit = 20_000_000;
                        ch
                    })
                }),
            )
            .await;
        assert_eq!(updated.unwrap().deposit, 20_000_000);

        let deleted = storage.update_channel(id, Box::new(|_| None)).await;
        assert!(deleted.is_none());
        assert!(storage.get_channel(id).await.is_none());
    }

    #[tokio::test]
    async fn test_memory_storage_session_crud() {
        let storage = MemoryStorage::new();
        let challenge_id = "test-challenge";

        assert!(storage.get_session(challenge_id).await.is_none());

        let created = storage
            .update_session(
                challenge_id,
                Box::new(|_| {
                    Some(SessionState {
                        challenge_id: "test-challenge".to_string(),
                        channel_id: test_channel_id(),
                        accepted_cumulative: 5_000_000,
                        spent: 0,
                        units: 0,
                        created_at: SystemTime::now(),
                    })
                }),
            )
            .await;
        assert!(created.is_some());
        assert_eq!(created.unwrap().accepted_cumulative, 5_000_000);

        let session = storage.get_session(challenge_id).await.unwrap();
        assert_eq!(session.accepted_cumulative, 5_000_000);

        let updated = storage
            .update_session(
                challenge_id,
                Box::new(|current| {
                    current.map(|mut s| {
                        s.spent = 1_000_000;
                        s.units = 1;
                        s
                    })
                }),
            )
            .await;
        assert_eq!(updated.as_ref().unwrap().spent, 1_000_000);
        assert_eq!(updated.unwrap().units, 1);

        let deleted = storage
            .update_session(challenge_id, Box::new(|_| None))
            .await;
        assert!(deleted.is_none());
        assert!(storage.get_session(challenge_id).await.is_none());
    }

    #[tokio::test]
    async fn test_update_channel_atomicity() {
        let storage = MemoryStorage::new();
        let id = test_channel_id();

        storage
            .update_channel(
                id,
                Box::new(|_| {
                    Some(ChannelState {
                        channel_id: test_channel_id(),
                        payer: Address::ZERO,
                        payee: Address::ZERO,
                        token: Address::ZERO,
                        authorized_signer: Address::ZERO,
                        deposit: 10_000_000,
                        settled_on_chain: 0,
                        highest_voucher_amount: 5_000_000,
                        highest_voucher: None,
                        active_session_id: None,
                        finalized: false,
                        created_at: SystemTime::now(),
                    })
                }),
            )
            .await;

        // Monotonic update: only increase highest_voucher_amount
        storage
            .update_channel(
                id,
                Box::new(|current| {
                    current.map(|mut ch| {
                        let new_amount = 3_000_000u128;
                        if new_amount > ch.highest_voucher_amount {
                            ch.highest_voucher_amount = new_amount;
                        }
                        ch
                    })
                }),
            )
            .await;

        // Should not have decreased
        let ch = storage.get_channel(id).await.unwrap();
        assert_eq!(ch.highest_voucher_amount, 5_000_000);
    }
}
