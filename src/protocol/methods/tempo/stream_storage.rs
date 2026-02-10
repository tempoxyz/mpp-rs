//! Channel and session storage for server-side stream payment verification.

use alloy::primitives::{Address, B256};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStatus {
    Open,
    Closed,
}

#[derive(Debug, Clone)]
pub struct ChannelState {
    pub channel_id: B256,
    pub authorized_signer: Address,
    pub status: ChannelStatus,
    pub deposit: Option<u128>,
}

#[derive(Debug, Clone)]
pub struct SessionState {
    pub channel_id: B256,
    pub last_cumulative: u128,
    pub payer_address: Option<Address>,
}

#[derive(Debug, Clone)]
pub enum StorageError {
    NotFound,
    ChannelClosed,
    Conflict(String),
    Internal(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "not found"),
            Self::ChannelClosed => write!(f, "channel is closed"),
            Self::Conflict(msg) => write!(f, "conflict: {}", msg),
            Self::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

/// Trait for channel and session storage.
///
/// Uses `impl Future` return types (consistent with the rest of mpay-rs).
pub trait ChannelStorage: Clone + Send + Sync + 'static {
    fn get_channel(
        &self,
        channel_id: B256,
    ) -> impl Future<Output = Result<Option<ChannelState>, StorageError>> + Send;

    fn put_channel(
        &self,
        channel: ChannelState,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    fn get_session(
        &self,
        channel_id: B256,
    ) -> impl Future<Output = Result<Option<SessionState>, StorageError>> + Send;

    fn put_session(
        &self,
        session: SessionState,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// In-memory channel storage for demos and testing.
#[derive(Clone, Default)]
pub struct InMemoryChannelStorage {
    channels: Arc<RwLock<HashMap<B256, ChannelState>>>,
    sessions: Arc<RwLock<HashMap<B256, SessionState>>>,
}

impl InMemoryChannelStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ChannelStorage for InMemoryChannelStorage {
    fn get_channel(
        &self,
        channel_id: B256,
    ) -> impl Future<Output = Result<Option<ChannelState>, StorageError>> + Send {
        let channels = self.channels.clone();
        async move {
            let guard = channels.read().await;
            Ok(guard.get(&channel_id).cloned())
        }
    }

    fn put_channel(
        &self,
        channel: ChannelState,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        let channels = self.channels.clone();
        async move {
            let mut guard = channels.write().await;
            guard.insert(channel.channel_id, channel);
            Ok(())
        }
    }

    fn get_session(
        &self,
        channel_id: B256,
    ) -> impl Future<Output = Result<Option<SessionState>, StorageError>> + Send {
        let sessions = self.sessions.clone();
        async move {
            let guard = sessions.read().await;
            Ok(guard.get(&channel_id).cloned())
        }
    }

    fn put_session(
        &self,
        session: SessionState,
    ) -> impl Future<Output = Result<(), StorageError>> + Send {
        let sessions = self.sessions.clone();
        async move {
            let mut guard = sessions.write().await;
            let channel_id = session.channel_id;
            if let Some(existing) = guard.get(&channel_id) {
                if session.last_cumulative <= existing.last_cumulative {
                    return Err(StorageError::Conflict(format!(
                        "cumulative amount {} does not exceed current {}",
                        session.last_cumulative, existing.last_cumulative
                    )));
                }
            }
            guard.insert(channel_id, session);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_inmemory_channel_crud() {
        let storage = InMemoryChannelStorage::new();
        let id = B256::repeat_byte(0x01);

        assert!(storage.get_channel(id).await.unwrap().is_none());

        let channel = ChannelState {
            channel_id: id,
            authorized_signer: Address::repeat_byte(0x42),
            status: ChannelStatus::Open,
            deposit: Some(1_000_000),
        };
        storage.put_channel(channel).await.unwrap();

        let loaded = storage.get_channel(id).await.unwrap().unwrap();
        assert_eq!(loaded.authorized_signer, Address::repeat_byte(0x42));
        assert_eq!(loaded.status, ChannelStatus::Open);
    }

    #[tokio::test]
    async fn test_inmemory_session_monotonicity() {
        let storage = InMemoryChannelStorage::new();
        let id = B256::repeat_byte(0x02);

        let session1 = SessionState {
            channel_id: id,
            last_cumulative: 1000,
            payer_address: None,
        };
        storage.put_session(session1).await.unwrap();

        let session2 = SessionState {
            channel_id: id,
            last_cumulative: 2000,
            payer_address: None,
        };
        storage.put_session(session2).await.unwrap();

        let session3 = SessionState {
            channel_id: id,
            last_cumulative: 2000,
            payer_address: None,
        };
        assert!(storage.put_session(session3).await.is_err());

        let session4 = SessionState {
            channel_id: id,
            last_cumulative: 1500,
            payer_address: None,
        };
        assert!(storage.put_session(session4).await.is_err());
    }

    #[tokio::test]
    async fn test_inmemory_first_session_any_amount() {
        let storage = InMemoryChannelStorage::new();
        let id = B256::repeat_byte(0x03);

        let session = SessionState {
            channel_id: id,
            last_cumulative: 0,
            payer_address: None,
        };
        storage.put_session(session).await.unwrap();
    }

    #[tokio::test]
    async fn test_channel_update_status() {
        let storage = InMemoryChannelStorage::new();
        let id = B256::repeat_byte(0x04);

        let channel = ChannelState {
            channel_id: id,
            authorized_signer: Address::repeat_byte(0x01),
            status: ChannelStatus::Open,
            deposit: Some(1_000_000),
        };
        storage.put_channel(channel).await.unwrap();

        let mut loaded = storage.get_channel(id).await.unwrap().unwrap();
        assert_eq!(loaded.status, ChannelStatus::Open);

        loaded.status = ChannelStatus::Closed;
        storage.put_channel(loaded).await.unwrap();

        let reloaded = storage.get_channel(id).await.unwrap().unwrap();
        assert_eq!(reloaded.status, ChannelStatus::Closed);
    }

    #[tokio::test]
    async fn test_channel_deposit_update() {
        let storage = InMemoryChannelStorage::new();
        let id = B256::repeat_byte(0x05);

        let channel = ChannelState {
            channel_id: id,
            authorized_signer: Address::repeat_byte(0x01),
            status: ChannelStatus::Open,
            deposit: Some(1_000_000),
        };
        storage.put_channel(channel).await.unwrap();

        let mut loaded = storage.get_channel(id).await.unwrap().unwrap();
        loaded.deposit = Some(loaded.deposit.unwrap_or(0) + 500_000);
        storage.put_channel(loaded).await.unwrap();

        let reloaded = storage.get_channel(id).await.unwrap().unwrap();
        assert_eq!(reloaded.deposit, Some(1_500_000));
    }
}
