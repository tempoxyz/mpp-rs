//! Pluggable key-value store abstraction.
//!
//! Modeled after the TypeScript SDK's Store interface (Cloudflare KV API style).
//! Implementations handle serialization internally.

use std::future::Future;
use std::io::Write;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};

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

    /// Atomically replace or delete a value only if it equals `expected`.
    ///
    /// `None` represents an absent key. Backends must perform comparison and
    /// mutation in one transaction across all clients/processes sharing storage.
    /// The default fails closed; get-then-put is not a valid implementation.
    fn compare_exchange(
        &self,
        _key: &str,
        _expected: Option<serde_json::Value>,
        _value: Option<serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        Box::pin(async { Err(StoreError::AtomicUnsupported) })
    }

    /// Atomically store `value` only if `key` is absent; returns `true` if inserted.
    ///
    /// A generic `get`-then-`put` is racy, so the default **fails closed** with
    /// [`StoreError::AtomicUnsupported`]. Backends used for replay protection
    /// must override this with native atomics (Redis `SET NX`, SQL
    /// `ON CONFLICT DO NOTHING`, CAS, etc.).
    fn put_if_absent(
        &self,
        _key: &str,
        _value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        Box::pin(async { Err(StoreError::AtomicUnsupported) })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Store error: {0}")]
    Internal(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("required atomic operation is not supported by this store backend")]
    AtomicUnsupported,
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

    fn compare_exchange(
        &self,
        key: &str,
        expected: Option<serde_json::Value>,
        value: Option<serde_json::Value>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            let mut data = self.data.lock().unwrap();
            let current = data
                .get(&key)
                .map(|raw| serde_json::from_str(raw))
                .transpose()
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            if current != expected {
                return Ok(false);
            }
            if let Some(value) = value {
                let raw = serde_json::to_string(&value)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                data.insert(key, raw);
            } else {
                data.remove(&key);
            }
            Ok(true)
        })
    }

    fn put_if_absent(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let key = key.to_string();
        let serialized =
            serde_json::to_string(&value).map_err(|e| StoreError::Serialization(e.to_string()));
        Box::pin(async move {
            let serialized = serialized?;
            // Check-and-insert under one mutex guard.
            let mut data = self.data.lock().unwrap();
            if data.contains_key(&key) {
                return Ok(false);
            }
            data.insert(key, serialized);
            Ok(true)
        })
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

    /// Unique sibling of `path` for staging a write before it is moved into place.
    fn tmp_path(path: &std::path::Path) -> std::path::PathBuf {
        static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

        path.with_extension(format!(
            "{}-{}.tmp",
            std::process::id(),
            TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
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
        let tmp_path = Self::tmp_path(&path);
        Box::pin(async move {
            let serialized = serde_json::to_string_pretty(&value)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            // Write the full value to a private temp file, then rename it over the key
            // path. Readers see either the old or the new value, never a truncated one,
            // and a failed write leaves the old value in place.
            let result = std::fs::write(&tmp_path, serialized)
                .and_then(|()| std::fs::rename(&tmp_path, &path));
            if result.is_err() {
                let _ = std::fs::remove_file(&tmp_path);
            }
            result.map_err(|e| StoreError::Internal(e.to_string()))
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

    fn put_if_absent(
        &self,
        key: &str,
        value: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
        let path = self.key_path(key);
        let tmp_path = Self::tmp_path(&path);
        Box::pin(async move {
            let serialized = serde_json::to_string_pretty(&value)
                .map_err(|e| StoreError::Serialization(e.to_string()))?;
            // Write the full value to a private temp file, then hard-link it into place.
            // The link fails with `AlreadyExists` if the key is taken, and the key path
            // never points at a partially written file, so a failed or interrupted write
            // cannot poison the key.
            let result = (|| {
                let mut f = std::fs::File::create(&tmp_path)?;
                f.write_all(serialized.as_bytes())?;
                f.sync_all()?;
                std::fs::hard_link(&tmp_path, &path)
            })();
            let _ = std::fs::remove_file(&tmp_path);
            match result {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(e) => Err(StoreError::Internal(e.to_string())),
            }
        })
    }
}

// ==================== ChannelStoreAdapter ====================

/// Adapter that implements `ChannelStore` using a generic `Store` backend.
///
/// Local locks reduce contention; correctness requires backend-native
/// [`Store::compare_exchange`]. Unsupported stores (including `FileStore`) fail
/// closed on updates. A conflict returns an error before authorizing delivery;
/// the caller may retry its operation against fresh state.
#[cfg(all(feature = "server", feature = "tempo"))]
pub struct ChannelStoreAdapter {
    store: std::sync::Arc<dyn Store>,
    prefix: String,
    channel_locks:
        std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
}

#[cfg(all(feature = "server", feature = "tempo"))]
impl ChannelStoreAdapter {
    /// Create a new adapter with the given store and key prefix.
    pub fn new(store: std::sync::Arc<dyn Store>, prefix: impl Into<String>) -> Self {
        Self {
            store,
            prefix: prefix.into(),
            channel_locks: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn channel_key(&self, channel_id: &str) -> String {
        let channel_id =
            crate::protocol::methods::tempo::session_method::normalize_channel_id(channel_id);
        format!("{}{}", self.prefix, channel_id)
    }

    fn channel_lock(&self, key: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        self.channel_locks
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }
}

#[cfg(all(feature = "server", feature = "tempo"))]
impl crate::protocol::methods::tempo::session_method::ChannelStore for ChannelStoreAdapter {
    fn check_writable(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<(), crate::protocol::traits::VerificationError>> + Send + '_,
        >,
    > {
        Box::pin(async move {
            let key = format!("{}:atomic-probe", self.prefix);
            self.store
                .compare_exchange(&key, None, None)
                .await
                .map_err(|e| crate::protocol::traits::VerificationError::internal(e.to_string()))?;
            Ok(())
        })
    }

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
            let value =
                self.store.get(&key).await.map_err(|e| {
                    crate::protocol::traits::VerificationError::internal(e.to_string())
                })?;
            match value {
                Some(v) => {
                    let state = serde_json::from_value(v).map_err(|e| {
                        crate::protocol::traits::VerificationError::internal(format!(
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
        let channel_lock = self.channel_lock(&key);
        Box::pin(async move {
            let _guard = channel_lock.lock().await;
            let current_value =
                self.store.get(&key).await.map_err(|e| {
                    crate::protocol::traits::VerificationError::internal(e.to_string())
                })?;
            let current_state: Option<
                crate::protocol::methods::tempo::session_method::ChannelState,
            > = match current_value.clone() {
                Some(v) => Some(serde_json::from_value(v).map_err(|e| {
                    crate::protocol::traits::VerificationError::internal(format!(
                        "Failed to deserialize channel state: {}",
                        e
                    ))
                })?),
                None => None,
            };

            let result = updater(current_state)?;

            let value = result
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|e| crate::protocol::traits::VerificationError::internal(e.to_string()))?;
            let committed = self
                .store
                .compare_exchange(&key, current_value, value)
                .await
                .map_err(|e| crate::protocol::traits::VerificationError::internal(e.to_string()))?;
            if !committed {
                return Err(crate::protocol::traits::VerificationError::internal(
                    "channel changed concurrently; retry against fresh state",
                ));
            }
            if result.is_none() {
                if let Ok(mut locks) = self.channel_locks.lock() {
                    locks.remove(&key);
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
    async fn memory_store_put_if_absent() {
        let store = MemoryStore::new();

        // First reservation succeeds.
        assert!(store
            .put_if_absent("k", serde_json::json!(true))
            .await
            .unwrap());
        assert_eq!(store.get("k").await.unwrap(), Some(serde_json::json!(true)));

        // Second reservation of the same key fails and does not overwrite.
        assert!(!store
            .put_if_absent("k", serde_json::json!("other"))
            .await
            .unwrap());
        assert_eq!(store.get("k").await.unwrap(), Some(serde_json::json!(true)));
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
    async fn default_put_if_absent_fails_closed() {
        // Inherited default must refuse rather than silently race.
        struct MinimalStore;
        impl Store for MinimalStore {
            fn get(
                &self,
                _key: &str,
            ) -> Pin<
                Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>,
            > {
                Box::pin(async { Ok(None) })
            }
            fn put(
                &self,
                _key: &str,
                _value: serde_json::Value,
            ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
                Box::pin(async { Ok(()) })
            }
            fn delete(
                &self,
                _key: &str,
            ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
                Box::pin(async { Ok(()) })
            }
        }

        let err = MinimalStore
            .put_if_absent("k", serde_json::json!(true))
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::AtomicUnsupported));
    }

    #[tokio::test]
    async fn memory_store_put_if_absent_sequential() {
        let store = MemoryStore::new();
        assert!(store
            .put_if_absent("k", serde_json::json!("first"))
            .await
            .unwrap());
        assert!(!store
            .put_if_absent("k", serde_json::json!("second"))
            .await
            .unwrap());
        assert_eq!(
            store.get("k").await.unwrap(),
            Some(serde_json::json!("first"))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn memory_store_put_if_absent_concurrent_exactly_one_wins() {
        let store = std::sync::Arc::new(MemoryStore::new());
        let start = std::sync::Arc::new(tokio::sync::Barrier::new(16));
        let mut handles = Vec::new();
        for i in 0..16 {
            let store = store.clone();
            let start = start.clone();
            handles.push(tokio::spawn(async move {
                start.wait().await;
                store
                    .put_if_absent("k", serde_json::json!(i))
                    .await
                    .unwrap()
            }));
        }
        let mut winners = 0;
        for h in handles {
            if h.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one put_if_absent must win");
        assert!(store.get("k").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn file_store_put_if_absent_sequential() {
        let tmp =
            std::env::temp_dir().join(format!("mpp_file_store_pia_seq_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let store = FileStore::new(&tmp).unwrap();
        assert!(store
            .put_if_absent("k", serde_json::json!("first"))
            .await
            .unwrap());
        assert!(!store
            .put_if_absent("k", serde_json::json!("second"))
            .await
            .unwrap());
        assert_eq!(
            store.get("k").await.unwrap(),
            Some(serde_json::json!("first"))
        );
        let files: Vec<_> = std::fs::read_dir(&tmp)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(files, ["k.json"], "temp files must not be left behind");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_store_put_if_absent_concurrent_exactly_one_wins() {
        let tmp =
            std::env::temp_dir().join(format!("mpp_file_store_pia_conc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let store = std::sync::Arc::new(FileStore::new(&tmp).unwrap());
        let start = std::sync::Arc::new(tokio::sync::Barrier::new(16));
        let mut handles = Vec::new();
        for i in 0..16 {
            let store = store.clone();
            let start = start.clone();
            handles.push(tokio::spawn(async move {
                start.wait().await;
                store
                    .put_if_absent("k", serde_json::json!(i))
                    .await
                    .unwrap()
            }));
        }
        let mut winners = 0;
        for h in handles {
            if h.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one put_if_absent must win");
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn file_store_put_is_atomic_for_concurrent_readers() {
        let tmp =
            std::env::temp_dir().join(format!("mpp_file_store_atomic_put_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let store = std::sync::Arc::new(FileStore::new(&tmp).unwrap());

        let values = [
            serde_json::json!("a".repeat(256 * 1024)),
            serde_json::json!("b".repeat(128 * 1024)),
        ];
        store.put("k", values[0].clone()).await.unwrap();

        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut readers = Vec::new();
        for _ in 0..3 {
            let store = store.clone();
            let values = values.clone();
            let done = done.clone();
            readers.push(tokio::spawn(async move {
                while !done.load(Ordering::Relaxed) {
                    match store.get("k").await {
                        Ok(Some(value)) if values.contains(&value) => {}
                        Ok(other) => panic!(
                            "read a torn value of {} bytes",
                            other.map_or(0, |v| v.to_string().len())
                        ),
                        Err(e) => panic!("read a torn value: {e}"),
                    }
                }
            }));
        }

        for i in 0..100 {
            store.put("k", values[i % 2].clone()).await.unwrap();
        }
        done.store(true, Ordering::Relaxed);
        for reader in readers {
            reader.await.unwrap();
        }

        let files: Vec<_> = std::fs::read_dir(&tmp)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(files, ["k.json"], "temp files must not be left behind");
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

#[cfg(all(test, feature = "server", feature = "tempo"))]
mod adapter_tests {
    use super::*;
    use crate::protocol::methods::tempo::session_method::deduct_from_channel;
    use crate::protocol::methods::tempo::session_method::{ChannelState, ChannelStore};
    use alloy::primitives::Address;
    use std::sync::Arc;
    use std::time::Duration;

    struct SlowMemoryStore {
        inner: MemoryStore,
        delay: Duration,
    }

    impl SlowMemoryStore {
        fn new(delay: Duration) -> Self {
            Self {
                inner: MemoryStore::new(),
                delay,
            }
        }
    }

    impl Store for SlowMemoryStore {
        fn get(
            &self,
            key: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>
        {
            let key = key.to_string();
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                self.inner.get(&key).await
            })
        }

        fn compare_exchange(
            &self,
            key: &str,
            expected: Option<serde_json::Value>,
            value: Option<serde_json::Value>,
        ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
            self.inner.compare_exchange(key, expected, value)
        }

        fn put(
            &self,
            key: &str,
            value: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
            let key = key.to_string();
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                self.inner.put(&key, value).await
            })
        }

        fn delete(
            &self,
            key: &str,
        ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
            let key = key.to_string();
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                self.inner.delete(&key).await
            })
        }
    }

    struct SynchronizedStore {
        inner: MemoryStore,
        readers: tokio::sync::Barrier,
    }

    impl Store for SynchronizedStore {
        fn get(
            &self,
            key: &str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<serde_json::Value>, StoreError>> + Send + '_>>
        {
            let key = key.to_owned();
            Box::pin(async move {
                let value = self.inner.get(&key).await?;
                self.readers.wait().await;
                Ok(value)
            })
        }
        fn put(
            &self,
            key: &str,
            value: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
            self.inner.put(key, value)
        }
        fn delete(
            &self,
            key: &str,
        ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
            self.inner.delete(key)
        }
        fn compare_exchange(
            &self,
            key: &str,
            expected: Option<serde_json::Value>,
            value: Option<serde_json::Value>,
        ) -> Pin<Box<dyn Future<Output = Result<bool, StoreError>> + Send + '_>> {
            self.inner.compare_exchange(key, expected, value)
        }
    }

    #[tokio::test]
    async fn independent_adapters_cannot_spend_the_same_balance() {
        let store = Arc::new(SynchronizedStore {
            inner: MemoryStore::new(),
            readers: tokio::sync::Barrier::new(2),
        });
        let mut state = test_channel_state("ch1");
        state.highest_voucher_amount = 10_000;
        store
            .inner
            .put("channels:ch1", serde_json::to_value(state).unwrap())
            .await
            .unwrap();
        let first = ChannelStoreAdapter::new(store.clone(), "channels:");
        let second = ChannelStoreAdapter::new(store.clone(), "channels:");
        let (a, b) = tokio::join!(
            deduct_from_channel(&first, "ch1", 7_000),
            deduct_from_channel(&second, "ch1", 7_000)
        );
        assert_ne!(a.is_ok(), b.is_ok());
        let saved: ChannelState =
            serde_json::from_value(store.inner.get("channels:ch1").await.unwrap().unwrap())
                .unwrap();
        assert_eq!(saved.spent, 7_000);
        assert_eq!(saved.units, 1);
    }

    #[tokio::test]
    async fn adapter_requires_native_compare_exchange() {
        let dir = std::env::temp_dir().join(format!("mpp_cas_unsupported_{}", std::process::id()));
        let adapter =
            ChannelStoreAdapter::new(Arc::new(FileStore::new(&dir).unwrap()), "channels:");
        assert!(adapter.check_writable().await.is_err());
        let result = adapter
            .update_channel("ch1", Box::new(|_| Ok(Some(test_channel_state("ch1")))))
            .await;
        assert!(result.unwrap_err().to_string().contains("atomic operation"));
        assert!(adapter.get_channel("ch1").await.unwrap().is_none());
    }

    fn test_channel_state(channel_id: &str) -> ChannelState {
        ChannelState {
            channel_id: channel_id.to_string(),
            chain_id: 42431,
            escrow_contract: Address::ZERO,
            payer: Address::ZERO,
            payee: Address::ZERO,
            token: Address::ZERO,
            settlement_route: None,
            authorized_signer: Address::ZERO,
            deposit: 1000,
            settled_on_chain: 0,
            highest_voucher_amount: 0,
            highest_voucher_signature: None,
            spent: 0,
            units: 0,
            finalized: false,
            closing: false,
            pending_close: None,
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

    #[tokio::test]
    async fn channel_store_adapter_reports_store_failures_as_internal() {
        let store = Arc::new(MemoryStore::new());
        store
            .put("channels:ch1", serde_json::json!("not a channel"))
            .await
            .unwrap();
        let adapter = ChannelStoreAdapter::new(store, "channels:");

        let err = adapter.get_channel("ch1").await.unwrap_err();
        assert_eq!(err.code, Some(crate::protocol::traits::ErrorCode::Internal));
        let err = adapter
            .update_channel("ch1", Box::new(Ok))
            .await
            .unwrap_err();
        assert_eq!(err.code, Some(crate::protocol::traits::ErrorCode::Internal));
    }

    #[tokio::test]
    async fn channel_store_adapter_channel_ids_are_case_insensitive() {
        let store = Arc::new(MemoryStore::new());
        let adapter = ChannelStoreAdapter::new(store.clone(), "channels:");
        let lower = format!("0x{}", "ab".repeat(32));
        let upper = format!("0x{}", "AB".repeat(32));

        let state = test_channel_state(&lower);
        adapter
            .update_channel(&upper, Box::new(move |_| Ok(Some(state))))
            .await
            .unwrap();

        // Stored under the lowercase key, reachable with either spelling.
        assert!(store
            .get(&format!("channels:{lower}"))
            .await
            .unwrap()
            .is_some());
        assert!(adapter.get_channel(&lower).await.unwrap().is_some());
        assert!(adapter.get_channel(&upper).await.unwrap().is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_store_adapter_same_channel_deduction_race() {
        let store = Arc::new(SlowMemoryStore::new(Duration::from_millis(25)));
        let adapter = Arc::new(ChannelStoreAdapter::new(store, "channels:"));

        let mut state = test_channel_state("ch1");
        state.highest_voucher_amount = 10_000;
        adapter
            .update_channel("ch1", Box::new(move |_| Ok(Some(state))))
            .await
            .unwrap();

        let start = Arc::new(tokio::sync::Barrier::new(3));

        let adapter1 = adapter.clone();
        let start1 = start.clone();
        let task1 = tokio::spawn(async move {
            start1.wait().await;
            deduct_from_channel(&*adapter1, "ch1", 7_000).await
        });

        let adapter2 = adapter.clone();
        let start2 = start.clone();
        let task2 = tokio::spawn(async move {
            start2.wait().await;
            deduct_from_channel(&*adapter2, "ch1", 7_000).await
        });

        // This is the original repro path: two concurrent deductions against the
        // same adapter-backed channel. Before the fix, both calls could report
        // success even though only one update was persisted.
        start.wait().await;

        let result1 = task1.await.unwrap();
        let result2 = task2.await.unwrap();
        let successes = [result1.is_ok(), result2.is_ok()]
            .into_iter()
            .filter(|ok| *ok)
            .count();
        assert_eq!(
            successes, 1,
            "the repro must not allow both concurrent deductions to succeed"
        );

        let error = result1.err().or_else(|| result2.err()).unwrap();
        assert!(
            error.to_string().contains("available 3000"),
            "expected insufficient balance after the first deduction, got: {error}"
        );

        let stored = adapter.get_channel("ch1").await.unwrap().unwrap();
        assert_eq!(stored.spent, 7_000);
        assert_eq!(stored.units, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn channel_store_adapter_serializes_same_channel_update_channel_calls() {
        let store = Arc::new(SlowMemoryStore::new(Duration::from_millis(25)));
        let adapter = Arc::new(ChannelStoreAdapter::new(store, "channels:"));

        let state = test_channel_state("ch1");
        adapter
            .update_channel("ch1", Box::new(move |_| Ok(Some(state))))
            .await
            .unwrap();

        let start = Arc::new(tokio::sync::Barrier::new(3));

        let adapter1 = adapter.clone();
        let start1 = start.clone();
        let task1 = tokio::spawn(async move {
            start1.wait().await;
            adapter1
                .update_channel(
                    "ch1",
                    Box::new(|current| {
                        let mut state = current.unwrap();
                        state.spent += 1;
                        state.units += 1;
                        Ok(Some(state))
                    }),
                )
                .await
        });

        let adapter2 = adapter.clone();
        let start2 = start.clone();
        let task2 = tokio::spawn(async move {
            start2.wait().await;
            adapter2
                .update_channel(
                    "ch1",
                    Box::new(|current| {
                        let mut state = current.unwrap();
                        state.spent += 1;
                        state.units += 1;
                        Ok(Some(state))
                    }),
                )
                .await
        });

        start.wait().await;

        let result1 = task1.await.unwrap().unwrap().unwrap();
        let result2 = task2.await.unwrap().unwrap().unwrap();
        let mut returned_spent = [result1.spent, result2.spent];
        returned_spent.sort_unstable();
        assert_eq!(returned_spent, [1, 2]);

        let stored = adapter.get_channel("ch1").await.unwrap().unwrap();
        assert_eq!(stored.spent, 2);
        assert_eq!(stored.units, 2);
    }

    #[tokio::test]
    async fn channel_store_adapter_evicts_lock_on_channel_delete() {
        let store = Arc::new(MemoryStore::new());
        let adapter = ChannelStoreAdapter::new(store, "channels:");

        // Create channels
        for id in ["ch1", "ch2", "ch3"] {
            let state = test_channel_state(id);
            adapter
                .update_channel(id, Box::new(move |_| Ok(Some(state))))
                .await
                .unwrap();
        }
        assert_eq!(adapter.channel_locks.lock().unwrap().len(), 3);

        // Delete ch2 via update returning None
        adapter
            .update_channel("ch2", Box::new(|_| Ok(None)))
            .await
            .unwrap();

        // Lock entry for ch2 should be evicted
        let locks = adapter.channel_locks.lock().unwrap();
        assert_eq!(locks.len(), 2);
        assert!(!locks.contains_key("channels:ch2"));
        assert!(locks.contains_key("channels:ch1"));
        assert!(locks.contains_key("channels:ch3"));
    }
}
