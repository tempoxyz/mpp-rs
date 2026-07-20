//! Persistence for reusable TIP-1034 payer channels.
//!
//! Recovery policy lives in the session manager. A [`ChannelStore`] only
//! persists the latest client view and can therefore be replaced without
//! changing snapshot or on-chain hydration behavior.

use std::{collections::HashMap, sync::Mutex};

use alloy::primitives::{Address, B256};
use serde::{Deserialize, Serialize};

use crate::protocol::methods::tempo::session::ChannelDescriptor;

/// A reusable TIP-1034 channel persisted by a payer client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredChannelEntry {
    /// TIP-1034 channel identifier.
    pub channel_id: B256,
    /// Highest cumulative voucher amount authorized by this client.
    pub cumulative_amount: u128,
    /// Latest known channel deposit.
    pub deposit: u128,
    /// Full descriptor required to derive the channel ID and sign vouchers.
    pub descriptor: ChannelDescriptor,
    /// TIP-1034 escrow/precompile address.
    pub escrow: Address,
    /// EVM chain ID.
    pub chain_id: u64,
    /// Whether the channel remains locally eligible for reuse.
    pub opened: bool,
}

impl StoredChannelEntry {
    /// Return the MPPx-compatible payment-scope key for this channel.
    pub fn key(&self) -> String {
        channel_key(
            &self.descriptor.payee,
            &self.descriptor.token,
            self.escrow,
            self.chain_id,
        )
    }
}

/// Return the MPPx-compatible payment-scope key.
pub fn channel_key(payee: &str, token: &str, escrow: Address, chain_id: u64) -> String {
    format!(
        "{}:{}:{:#x}:{}",
        payee.to_ascii_lowercase(),
        token.to_ascii_lowercase(),
        escrow,
        chain_id
    )
}

/// Store failures are deliberately separate from session recovery failures.
#[derive(Debug, thiserror::Error)]
pub enum ChannelStoreError {
    /// Filesystem or SQLite failure.
    #[error("channel store I/O failed: {0}")]
    Io(String),
    /// A persisted channel could not be decoded.
    #[error("invalid persisted channel: {0}")]
    InvalidEntry(String),
}

/// Result returned by payer channel stores.
pub type ChannelStoreResult<T> = std::result::Result<T, ChannelStoreError>;

/// Store of reusable payer session channels keyed by payment scope.
#[async_trait::async_trait]
pub trait ChannelStore: Send + Sync {
    /// Return the channel cached for `key`, when present.
    async fn get(&self, key: &str) -> ChannelStoreResult<Option<StoredChannelEntry>>;
    /// Insert or replace a channel entry.
    async fn set(&self, entry: &StoredChannelEntry) -> ChannelStoreResult<()>;
    /// Remove the channel cached for `key`.
    async fn delete(&self, key: &str) -> ChannelStoreResult<()>;
}

/// In-memory channel store used when persistence is not configured.
#[derive(Debug, Default)]
pub struct MemoryChannelStore {
    entries: Mutex<HashMap<String, StoredChannelEntry>>,
}

#[async_trait::async_trait]
impl ChannelStore for MemoryChannelStore {
    async fn get(&self, key: &str) -> ChannelStoreResult<Option<StoredChannelEntry>> {
        Ok(self.entries.lock().unwrap().get(key).cloned())
    }

    async fn set(&self, entry: &StoredChannelEntry) -> ChannelStoreResult<()> {
        let mut entries = self.entries.lock().unwrap();
        let merged = match entries.get(&entry.key()) {
            Some(current) if current.channel_id == entry.channel_id => StoredChannelEntry {
                cumulative_amount: current.cumulative_amount.max(entry.cumulative_amount),
                deposit: current.deposit.max(entry.deposit),
                ..entry.clone()
            },
            _ => entry.clone(),
        };
        entries.insert(merged.key(), merged);
        Ok(())
    }

    async fn delete(&self, key: &str) -> ChannelStoreResult<()> {
        self.entries.lock().unwrap().remove(key);
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonChannelEntry {
    channel_id: String,
    cumulative_amount: String,
    deposit: String,
    descriptor: ChannelDescriptor,
    escrow: String,
    chain_id: u64,
    opened: bool,
}

impl From<&StoredChannelEntry> for JsonChannelEntry {
    fn from(entry: &StoredChannelEntry) -> Self {
        Self {
            channel_id: format!("{:#x}", entry.channel_id),
            cumulative_amount: entry.cumulative_amount.to_string(),
            deposit: entry.deposit.to_string(),
            descriptor: entry.descriptor.clone(),
            escrow: format!("{:#x}", entry.escrow),
            chain_id: entry.chain_id,
            opened: entry.opened,
        }
    }
}

impl TryFrom<JsonChannelEntry> for StoredChannelEntry {
    type Error = ChannelStoreError;

    fn try_from(entry: JsonChannelEntry) -> Result<Self, Self::Error> {
        fn invalid(field: &str, error: impl std::fmt::Display) -> ChannelStoreError {
            ChannelStoreError::InvalidEntry(format!("invalid {field}: {error}"))
        }

        Ok(Self {
            channel_id: entry
                .channel_id
                .parse()
                .map_err(|e| invalid("channelId", e))?,
            cumulative_amount: entry
                .cumulative_amount
                .parse()
                .map_err(|e| invalid("cumulativeAmount", e))?,
            deposit: entry.deposit.parse().map_err(|e| invalid("deposit", e))?,
            descriptor: entry.descriptor,
            escrow: entry.escrow.parse().map_err(|e| invalid("escrow", e))?,
            chain_id: entry.chain_id,
            opened: entry.opened,
        })
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use rusqlite::{params, Connection, OptionalExtension};

    use super::*;

    const SCHEMA_VERSION: u32 = 2;

    /// SQLite store options compatible with MPPx's Node channel store.
    #[derive(Debug, Clone, Default)]
    pub struct SqliteChannelStoreOptions {
        /// Service namespace, normally the protected API origin.
        pub namespace: String,
        /// SQLite path. Defaults to `~/.tempo/wallet/channels.db`.
        pub path: Option<PathBuf>,
        /// Full protected URL retained for CLI management requests.
        pub request_url: Option<String>,
    }

    /// SQLite-backed MPPx-compatible payer channel store.
    pub struct SqliteChannelStore {
        connection: Mutex<Connection>,
        namespace: String,
        origin: String,
        path: PathBuf,
        request_url: String,
    }

    impl std::fmt::Debug for SqliteChannelStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqliteChannelStore")
                .field("namespace", &self.namespace)
                .field("path", &self.path)
                .field("request_url", &self.request_url)
                .finish_non_exhaustive()
        }
    }

    /// Return the database path shared by Tempo command-line applications.
    pub fn default_channel_database_path() -> ChannelStoreResult<PathBuf> {
        dirs::home_dir()
            .map(|home| home.join(".tempo").join("wallet").join("channels.db"))
            .ok_or_else(|| ChannelStoreError::Io("home directory is unavailable".into()))
    }

    impl SqliteChannelStore {
        /// Open a SQLite channel store and migrate compatible legacy schemas.
        pub fn open(options: SqliteChannelStoreOptions) -> ChannelStoreResult<Self> {
            let path = match options.path {
                Some(path) => path,
                None => default_channel_database_path()?,
            };
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(io_error)?;
            }
            let connection = Connection::open(&path).map_err(io_error)?;
            connection
                .execute_batch(
                    "PRAGMA journal_mode = WAL;
                     PRAGMA busy_timeout = 5000;",
                )
                .map_err(io_error)?;
            ensure_schema(&connection)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(io_error)?;
            }

            let request_url = options
                .request_url
                .unwrap_or_else(|| options.namespace.clone());
            let origin = reqwest::Url::parse(&request_url)
                .map(|url| url.origin().ascii_serialization())
                .unwrap_or_else(|_| options.namespace.clone());
            Ok(Self {
                connection: Mutex::new(connection),
                namespace: options.namespace,
                origin,
                path,
                request_url,
            })
        }

        /// Return the opened database path.
        pub fn path(&self) -> &Path {
            &self.path
        }

        fn scoped_key(&self, key: &str) -> String {
            format!("{}\n{}", self.namespace, key)
        }
    }

    #[async_trait::async_trait]
    impl ChannelStore for SqliteChannelStore {
        async fn get(&self, key: &str) -> ChannelStoreResult<Option<StoredChannelEntry>> {
            let connection = self.connection.lock().unwrap();
            let row = connection
                .query_row(
                    "SELECT channel_id, chain_id, escrow_contract, cumulative_amount, deposit,
                            descriptor_json, entry_json, state
                     FROM channels WHERE scope_key = ?1",
                    [self.scoped_key(key)],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, Option<String>>(6)?,
                            row.get::<_, String>(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(io_error)?;

            let Some((channel_id, chain_id, escrow, cumulative, deposit, descriptor, json, state)) =
                row
            else {
                return Ok(None);
            };
            let chain_id = u64::try_from(chain_id).map_err(|_| {
                ChannelStoreError::InvalidEntry("chainId must be non-negative".into())
            })?;
            if let Some(json) = json {
                let mut entry: JsonChannelEntry = serde_json::from_str(&json)
                    .map_err(|e| ChannelStoreError::InvalidEntry(e.to_string()))?;
                entry.opened = state == "active";
                return entry.try_into().map(Some);
            }
            let descriptor = descriptor.ok_or_else(|| {
                ChannelStoreError::InvalidEntry("v2 row is missing descriptor_json".into())
            })?;
            JsonChannelEntry {
                channel_id,
                cumulative_amount: cumulative,
                deposit,
                descriptor: serde_json::from_str(&descriptor)
                    .map_err(|e| ChannelStoreError::InvalidEntry(e.to_string()))?,
                escrow,
                chain_id,
                opened: state == "active",
            }
            .try_into()
            .map(Some)
        }

        async fn set(&self, entry: &StoredChannelEntry) -> ChannelStoreResult<()> {
            let key = entry.key();
            let scope_key = self.scoped_key(&key);
            let mut connection = self.connection.lock().unwrap();
            let transaction = connection.transaction().map_err(io_error)?;
            let current: Option<StoredChannelEntry> = transaction
                .query_row(
                    "SELECT entry_json FROM channels WHERE scope_key = ?1",
                    [&scope_key],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(io_error)?
                .flatten()
                .map(|json| {
                    serde_json::from_str::<JsonChannelEntry>(&json)
                        .map_err(|e| ChannelStoreError::InvalidEntry(e.to_string()))?
                        .try_into()
                })
                .transpose()?;
            let merged = match current {
                Some(current) if current.channel_id == entry.channel_id => StoredChannelEntry {
                    cumulative_amount: current.cumulative_amount.max(entry.cumulative_amount),
                    deposit: current.deposit.max(entry.deposit),
                    ..entry.clone()
                },
                _ => entry.clone(),
            };
            let json = serde_json::to_string(&JsonChannelEntry::from(&merged))
                .map_err(|e| ChannelStoreError::InvalidEntry(e.to_string()))?;
            let descriptor = serde_json::to_string(&merged.descriptor)
                .map_err(|e| ChannelStoreError::InvalidEntry(e.to_string()))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io_error)?
                .as_secs();
            let now = i64::try_from(now)
                .map_err(|_| ChannelStoreError::Io("system time exceeds SQLite range".into()))?;
            let chain_id = i64::try_from(merged.chain_id).map_err(|_| {
                ChannelStoreError::InvalidEntry("chainId exceeds SQLite range".into())
            })?;
            transaction
                .execute(
                    "DELETE FROM channels WHERE scope_key = ?1 AND channel_id <> ?2",
                    params![scope_key, format!("{:#x}", merged.channel_id)],
                )
                .map_err(io_error)?;
            transaction
                .execute(
                    "INSERT INTO channels (
                        channel_id, version, scope_key, origin, request_url, chain_id,
                        escrow_contract, token, payee, payer, authorized_signer, salt,
                        session_protocol, descriptor_json, entry_json, deposit,
                        cumulative_amount, accepted_cumulative, challenge_echo, state,
                        close_requested_at, grace_ready_at, created_at, last_used_at, server_spent
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                        'v2', ?13, ?14, ?15, ?16, '0', '{}', ?17, 0, 0, ?18, ?18, '0')
                     ON CONFLICT(channel_id) DO UPDATE SET
                        version=excluded.version, scope_key=excluded.scope_key,
                        origin=excluded.origin, request_url=excluded.request_url,
                        chain_id=excluded.chain_id, escrow_contract=excluded.escrow_contract,
                        token=excluded.token, payee=excluded.payee, payer=excluded.payer,
                        authorized_signer=excluded.authorized_signer, salt=excluded.salt,
                        session_protocol=excluded.session_protocol,
                        descriptor_json=excluded.descriptor_json, entry_json=excluded.entry_json,
                        deposit=excluded.deposit, cumulative_amount=excluded.cumulative_amount,
                        state=excluded.state, close_requested_at=0,
                        last_used_at=excluded.last_used_at",
                    params![
                        format!("{:#x}", merged.channel_id),
                        i64::from(SCHEMA_VERSION),
                        scope_key,
                        self.origin,
                        self.request_url,
                        chain_id,
                        format!("{:#x}", merged.escrow),
                        merged.descriptor.token,
                        merged.descriptor.payee,
                        merged.descriptor.payer,
                        merged.descriptor.authorized_signer,
                        merged.descriptor.salt,
                        descriptor,
                        json,
                        merged.deposit.to_string(),
                        merged.cumulative_amount.to_string(),
                        if merged.opened { "active" } else { "pending" },
                        now,
                    ],
                )
                .map_err(io_error)?;
            transaction.commit().map_err(io_error)
        }

        async fn delete(&self, key: &str) -> ChannelStoreResult<()> {
            self.connection
                .lock()
                .unwrap()
                .execute(
                    "DELETE FROM channels WHERE scope_key = ?1",
                    [self.scoped_key(key)],
                )
                .map_err(io_error)?;
            Ok(())
        }
    }

    fn ensure_schema(connection: &Connection) -> ChannelStoreResult<()> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS channels (
                    channel_id TEXT PRIMARY KEY,
                    version INTEGER NOT NULL DEFAULT 1,
                    scope_key TEXT,
                    origin TEXT NOT NULL,
                    request_url TEXT NOT NULL DEFAULT '',
                    chain_id INTEGER NOT NULL,
                    escrow_contract TEXT NOT NULL,
                    token TEXT NOT NULL,
                    payee TEXT NOT NULL,
                    payer TEXT NOT NULL,
                    authorized_signer TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    deposit TEXT NOT NULL,
                    cumulative_amount TEXT NOT NULL,
                    challenge_echo TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'active',
                    close_requested_at INTEGER NOT NULL DEFAULT 0,
                    grace_ready_at INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    last_used_at INTEGER NOT NULL,
                    accepted_cumulative TEXT NOT NULL DEFAULT '0',
                    server_spent TEXT NOT NULL DEFAULT '0',
                    session_protocol TEXT NOT NULL DEFAULT 'v1',
                    descriptor_json TEXT,
                    entry_json TEXT
                );",
            )
            .map_err(io_error)?;
        add_column(connection, "scope_key", "TEXT")?;
        add_column(connection, "entry_json", "TEXT")?;
        connection
            .execute_batch(
                "UPDATE channels
                 SET scope_key = origin || char(10) || lower(payee) || ':' || lower(token) || ':' ||
                     lower(escrow_contract) || ':' || chain_id
                 WHERE scope_key IS NULL AND session_protocol = 'v2' AND descriptor_json IS NOT NULL;
                 CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_scope_key
                     ON channels(scope_key) WHERE scope_key IS NOT NULL;
                 CREATE INDEX IF NOT EXISTS idx_channels_origin ON channels(origin);",
            )
            .map_err(io_error)
    }

    fn add_column(
        connection: &Connection,
        name: &'static str,
        definition: &'static str,
    ) -> ChannelStoreResult<()> {
        let mut statement = connection
            .prepare("PRAGMA table_info(channels)")
            .map_err(io_error)?;
        let exists = statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(io_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(io_error)?
            .iter()
            .any(|column| column == name);
        if !exists {
            connection
                .execute_batch(&format!(
                    "ALTER TABLE channels ADD COLUMN {name} {definition}"
                ))
                .map_err(io_error)?;
        }
        Ok(())
    }

    fn io_error(error: impl std::fmt::Display) -> ChannelStoreError {
        ChannelStoreError::Io(error.to_string())
    }

    pub use SqliteChannelStore as Store;
    pub use SqliteChannelStoreOptions as Options;
}

#[cfg(feature = "sqlite")]
pub use sqlite::Store as SqliteChannelStore;
#[cfg(feature = "sqlite")]
pub use sqlite::{default_channel_database_path, Options as SqliteChannelStoreOptions};

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> StoredChannelEntry {
        StoredChannelEntry {
            channel_id: B256::repeat_byte(0x11),
            cumulative_amount: 2_000_000,
            deposit: 10_000_000,
            descriptor: ChannelDescriptor {
                authorized_signer: "0x0000000000000000000000000000000000000001".into(),
                expiring_nonce_hash: format!("{:#x}", B256::repeat_byte(0x22)),
                operator: format!("{:#x}", Address::ZERO),
                payee: "0x0000000000000000000000000000000000000002".into(),
                payer: "0x0000000000000000000000000000000000000003".into(),
                salt: format!("{:#x}", B256::repeat_byte(0x33)),
                token: "0x0000000000000000000000000000000000000004".into(),
            },
            escrow: "0x0000000000000000000000000000000000000005"
                .parse()
                .unwrap(),
            chain_id: 4217,
            opened: true,
        }
    }

    #[tokio::test]
    async fn memory_store_is_monotonic() {
        let store = MemoryChannelStore::default();
        let current = entry();
        store.set(&current).await.unwrap();
        store
            .set(&StoredChannelEntry {
                cumulative_amount: 1_000_000,
                deposit: 5_000_000,
                ..current.clone()
            })
            .await
            .unwrap();
        assert_eq!(store.get(&current.key()).await.unwrap(), Some(current));
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_roundtrip_uses_mppx_entry_json() {
        let directory = std::env::temp_dir().join(format!("mpp-rs-store-{}", uuid::Uuid::new_v4()));
        let path = directory.join("channels.db");
        let current = entry();
        let store = SqliteChannelStore::open(SqliteChannelStoreOptions {
            namespace: "https://api.example.com".into(),
            path: Some(path.clone()),
            request_url: None,
        })
        .unwrap();
        store.set(&current).await.unwrap();
        assert_eq!(
            store.get(&current.key()).await.unwrap(),
            Some(current.clone())
        );

        let connection = rusqlite::Connection::open(path).unwrap();
        let json: String = connection
            .query_row("SELECT entry_json FROM channels", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap(),
            serde_json::to_value(JsonChannelEntry::from(&current)).unwrap()
        );
        let pending = StoredChannelEntry {
            channel_id: B256::repeat_byte(0x12),
            opened: false,
            ..current
        };
        store.set(&pending).await.unwrap();
        assert_eq!(store.get(&pending.key()).await.unwrap(), Some(pending));
        let state: String = connection
            .query_row("SELECT state FROM channels", [], |row| row.get(0))
            .unwrap();
        assert_eq!(state, "pending");
        drop(connection);
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_migrates_wallet_cli_v2_row_into_mppx_scope() {
        let directory =
            std::env::temp_dir().join(format!("mpp-rs-wallet-store-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("channels.db");
        let current = entry();
        let descriptor = serde_json::to_string(&current.descriptor).unwrap();
        {
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE channels (
                        channel_id TEXT PRIMARY KEY, version INTEGER NOT NULL DEFAULT 1,
                        origin TEXT NOT NULL, request_url TEXT NOT NULL DEFAULT '',
                        chain_id INTEGER NOT NULL, escrow_contract TEXT NOT NULL,
                        token TEXT NOT NULL, payee TEXT NOT NULL, payer TEXT NOT NULL,
                        authorized_signer TEXT NOT NULL, salt TEXT NOT NULL,
                        deposit TEXT NOT NULL, cumulative_amount TEXT NOT NULL,
                        challenge_echo TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'active',
                        close_requested_at INTEGER NOT NULL DEFAULT 0,
                        grace_ready_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL,
                        last_used_at INTEGER NOT NULL,
                        accepted_cumulative TEXT NOT NULL DEFAULT '0',
                        server_spent TEXT NOT NULL DEFAULT '0',
                        session_protocol TEXT NOT NULL DEFAULT 'v1', descriptor_json TEXT
                    );",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO channels (
                        channel_id, version, origin, request_url, chain_id, escrow_contract,
                        token, payee, payer, authorized_signer, salt, deposit,
                        cumulative_amount, challenge_echo, state, close_requested_at,
                        grace_ready_at, created_at, last_used_at, accepted_cumulative,
                        server_spent, session_protocol, descriptor_json
                     ) VALUES (?1, 1, ?2, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                        '{}', 'active', 0, 0, 1, 1, '0', '0', 'v2', ?12)",
                    rusqlite::params![
                        format!("{:#x}", current.channel_id),
                        "https://api.example.com",
                        i64::try_from(current.chain_id).unwrap(),
                        format!("{:#x}", current.escrow),
                        current.descriptor.token,
                        current.descriptor.payee,
                        current.descriptor.payer,
                        current.descriptor.authorized_signer,
                        current.descriptor.salt,
                        current.deposit.to_string(),
                        current.cumulative_amount.to_string(),
                        descriptor,
                    ],
                )
                .unwrap();
        }

        let store = SqliteChannelStore::open(SqliteChannelStoreOptions {
            namespace: "https://api.example.com".into(),
            path: Some(path),
            request_url: None,
        })
        .unwrap();
        assert_eq!(store.get(&current.key()).await.unwrap(), Some(current));
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
