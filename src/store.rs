//! Pluggable key-value store abstraction.
//!
//! Modeled after the TypeScript SDK's Store interface (Cloudflare KV API style).
//! Implementations handle serialization internally.

use std::future::Future;
use std::pin::Pin;

/// Async key-value store interface.
///
/// Simple `get`/`put`/`delete` API compatible with various backends:
/// - In-memory (for development/testing)
/// - File-system (for simple persistence)
/// - Redis, SQLite, etc. (for production)
pub trait Store: Send + Sync {
    /// Get a value by key. Returns None if not found.
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>;

    /// Put a value by key.
    fn put(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;

    /// Delete a value by key.
    fn delete(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>>;
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Store error: {0}")]
    Internal(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

// ==================== MemoryStore ====================

/// In-memory store backed by a HashMap. JSON-roundtrips values to match production behavior.
pub struct MemoryStore {
    data: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            data: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemoryStore {
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>
    {
        let result = self.data.lock().unwrap().get(key).cloned();
        Box::pin(async move {
            match result {
                Some(raw) => {
                    let value = serde_json::from_str(&raw)
                        .map_err(|e| StoreError::Serialization(e.to_string()))?;
                    Ok(Some(value))
                }
                None => Ok(None),
            }
        })
    }

    fn put(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let key = key.to_string();
        let serialized =
            serde_json::to_string(&value).map_err(|e| StoreError::Serialization(e.to_string()));
        Box::pin(async move {
            let serialized = serialized?;
            self.data.lock().unwrap().insert(key, serialized);
            Ok(())
        })
    }

    fn delete(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        self.data.lock().unwrap().remove(key);
        Box::pin(async { Ok(()) })
    }
}

// ==================== FileStore ====================

/// File-system backed store. Each key is stored as a JSON file.
///
/// Useful for development and simple deployments where a database is overkill.
pub struct FileStore {
    dir: std::path::PathBuf,
}

impl FileStore {
    /// Create a new FileStore that persists data in the given directory.
    ///
    /// Creates the directory if it does not exist.
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Result<Self, StoreError> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)
            .map_err(|e| StoreError::Internal(format!("Failed to create store dir: {}", e)))?;
        Ok(Self { dir })
    }

    fn key_path(&self, key: &str) -> std::path::PathBuf {
        // Sanitize key: replace path separators and special chars
        let safe_key: String = key
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{}.json", safe_key))
    }
}

impl Store for FileStore {
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>
    {
        let path = self.key_path(key);
        Box::pin(async move {
            match std::fs::read_to_string(&path) {
                Ok(raw) => {
                    let value = serde_json::from_str(&raw)
                        .map_err(|e| StoreError::Serialization(e.to_string()))?;
                    Ok(Some(value))
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(StoreError::Internal(e.to_string())),
            }
        })
    }

    fn put(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let path = self.key_path(key);
        Box::pin(async move {
            let serialized = serde_json::to_string_pretty(&value)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            std::fs::write(&path, serialized).map_err(|e| StoreError::Internal(e.to_string()))?;
            Ok(())
        })
    }

    fn delete(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        let path = self.key_path(key);
        Box::pin(async move {
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(StoreError::Internal(e.to_string())),
            }
        })
    }
}

// ==================== ChannelStoreAdapter ====================

/// Adapter that implements `ChannelStore` using a generic `Store` backend.
///
/// This allows using any persistent store (file, Redis, etc.) for channel state.
#[cfg(all(feature = "server", feature = "tempo"))]
pub struct ChannelStoreAdapter {
    store: std::sync::Arc<dyn Store>,
    prefix: String,
}

#[cfg(all(feature = "server", feature = "tempo"))]
impl ChannelStoreAdapter {
    /// Create a new adapter with the given store and key prefix.
    pub fn new(store: std::sync::Arc<dyn Store>, prefix: impl Into<String>) -> Self {
        Self {
            store,
            prefix: prefix.into(),
        }
    }

    fn channel_key(&self, channel_id: &str) -> String {
        format!("{}{}", self.prefix, channel_id)
    }
}

#[cfg(all(feature = "server", feature = "tempo"))]
impl crate::protocol::methods::tempo::session_method::ChannelStore for ChannelStoreAdapter {
    fn get_channel(
        &self,
        channel_id: &str,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Option<crate::protocol::methods::tempo::session_method::ChannelState>,
                        crate::protocol::traits::VerificationError,
                    >,
                > + Send
                + '_,
        >,
    > {
        let key = self.channel_key(channel_id);
        Box::pin(async move {
            let value = self
                .store
                .get(&key)
                .await
                .map_err(|e| crate::protocol::traits::VerificationError::new(e.to_string()))?;
            match value {
                Some(v) => {
                    let state = serde_json::from_value(v).map_err(|e| {
                        crate::protocol::traits::VerificationError::new(format!(
                            "Failed to deserialize channel state: {}",
                            e
                        ))
                    })?;
                    Ok(Some(state))
                }
                None => Ok(None),
            }
        })
    }

    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<
            dyn FnOnce(
                    Option<crate::protocol::methods::tempo::session_method::ChannelState>,
                ) -> Result<
                    Option<crate::protocol::methods::tempo::session_method::ChannelState>,
                    crate::protocol::traits::VerificationError,
                > + Send,
        >,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Option<crate::protocol::methods::tempo::session_method::ChannelState>,
                        crate::protocol::traits::VerificationError,
                    >,
                > + Send
                + '_,
        >,
    > {
        let key = self.channel_key(channel_id);
        Box::pin(async move {
            let current_value = self
                .store
                .get(&key)
                .await
                .map_err(|e| crate::protocol::traits::VerificationError::new(e.to_string()))?;
            let current_state: Option<
                crate::protocol::methods::tempo::session_method::ChannelState,
            > = match current_value {
                Some(v) => Some(serde_json::from_value(v).map_err(|e| {
                    crate::protocol::traits::VerificationError::new(format!(
                        "Failed to deserialize channel state: {}",
                        e
                    ))
                })?),
                None => None,
            };

            let result = updater(current_state)?;

            match &result {
                Some(state) => {
                    let value = serde_json::to_value(state).map_err(|e| {
                        crate::protocol::traits::VerificationError::new(format!(
                            "Failed to serialize channel state: {}",
                            e
                        ))
                    })?;
                    self.store.put(&key, value).await.map_err(|e| {
                        crate::protocol::traits::VerificationError::new(e.to_string())
                    })?;
                }
                None => {
                    self.store.delete(&key).await.map_err(|e| {
                        crate::protocol::traits::VerificationError::new(e.to_string())
                    })?;
                }
            }

            Ok(result)
        })
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_store_get_put_delete() {
        let store = MemoryStore::new();

        // Missing key returns None
        assert!(store.get("missing").await.unwrap().is_none());

        // Put and get
        let value = serde_json::json!({"name": "alice", "balance": 100});
        store.put("user:1", value.clone()).await.unwrap();
        assert_eq!(store.get("user:1").await.unwrap(), Some(value));

        // Delete
        store.delete("user:1").await.unwrap();
        assert!(store.get("user:1").await.unwrap().is_none());

        // Delete missing key is a no-op
        store.delete("nonexistent").await.unwrap();
    }

    #[tokio::test]
    async fn memory_store_overwrite() {
        let store = MemoryStore::new();
        store.put("k", serde_json::json!("first")).await.unwrap();
        store.put("k", serde_json::json!("second")).await.unwrap();
        assert_eq!(
            store.get("k").await.unwrap(),
            Some(serde_json::json!("second"))
        );
    }

    #[tokio::test]
    async fn file_store_get_put_delete() {
        let tmp = std::env::temp_dir().join(format!("mpp_file_store_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let store = FileStore::new(&tmp).unwrap();

        // Missing key returns None
        assert!(store.get("missing").await.unwrap().is_none());

        // Put and get
        let value = serde_json::json!({"name": "bob", "items": [1, 2, 3]});
        store.put("data:1", value.clone()).await.unwrap();
        assert_eq!(store.get("data:1").await.unwrap(), Some(value));

        // Delete
        store.delete("data:1").await.unwrap();
        assert!(store.get("data:1").await.unwrap().is_none());

        // Delete missing key is a no-op
        store.delete("nonexistent").await.unwrap();

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test]
    async fn file_store_overwrite() {
        let tmp = std::env::temp_dir().join(format!(
            "mpp_file_store_overwrite_test_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        let store = FileStore::new(&tmp).unwrap();

        store.put("k", serde_json::json!("first")).await.unwrap();
        store.put("k", serde_json::json!("second")).await.unwrap();
        assert_eq!(
            store.get("k").await.unwrap(),
            Some(serde_json::json!("second"))
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}

#[cfg(all(test, feature = "server", feature = "tempo"))]
mod adapter_tests {
    use super::*;
    use crate::protocol::methods::tempo::session_method::{ChannelState, ChannelStore};
    use alloy::primitives::Address;
    use std::sync::Arc;

    fn test_channel_state(channel_id: &str) -> ChannelState {
        ChannelState {
            channel_id: channel_id.to_string(),
            chain_id: 42431,
            escrow_contract: Address::ZERO,
            payer: Address::ZERO,
            payee: Address::ZERO,
            token: Address::ZERO,
            authorized_signer: Address::ZERO,
            deposit: 1000,
            settled_on_chain: 0,
            highest_voucher_amount: 0,
            highest_voucher_signature: None,
            spent: 0,
            units: 0,
            finalized: false,
            close_requested_at: 0,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn channel_store_adapter_get_and_update() {
        let store = Arc::new(MemoryStore::new());
        let adapter = ChannelStoreAdapter::new(store, "channels:");

        // Get missing channel
        assert!(adapter.get_channel("ch1").await.unwrap().is_none());

        // Update (insert) a channel
        let state = test_channel_state("ch1");
        let result = adapter
            .update_channel("ch1", Box::new(move |_current| Ok(Some(state))))
            .await
            .unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().channel_id, "ch1");

        // Get the channel back
        let fetched = adapter.get_channel("ch1").await.unwrap().unwrap();
        assert_eq!(fetched.channel_id, "ch1");
        assert_eq!(fetched.deposit, 1000);

        // Update existing channel (increment spent)
        let result = adapter
            .update_channel(
                "ch1",
                Box::new(|current| {
                    let mut s = current.unwrap();
                    s.spent = 500;
                    s.units = 10;
                    Ok(Some(s))
                }),
            )
            .await
            .unwrap();
        let updated = result.unwrap();
        assert_eq!(updated.spent, 500);
        assert_eq!(updated.units, 10);

        // Delete via update returning None
        let result = adapter
            .update_channel("ch1", Box::new(|_| Ok(None)))
            .await
            .unwrap();
        assert!(result.is_none());
        assert!(adapter.get_channel("ch1").await.unwrap().is_none());
    }
}
