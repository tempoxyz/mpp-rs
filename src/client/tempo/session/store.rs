//! Persistence for reusable TIP-1034 payer channels.
//!
//! Recovery policy lives in the session manager. A [`ChannelStore`] only
//! persists the latest client view and can therefore be replaced without
//! changing snapshot or on-chain hydration behavior.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

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
    /// Immutable machine-token settlement route, when enabled.
    pub settlement_route: Option<crate::protocol::methods::tempo::session::SettlementRoute>,
    /// TIP-1034 escrow/precompile address.
    pub escrow: Address,
    /// EVM chain ID.
    pub chain_id: u64,
    /// Whether the channel remains locally eligible for reuse.
    pub opened: bool,
    /// Challenge whose opening payment has not yet received a verified receipt.
    pub pending_open: Option<String>,
    /// HTTP origin the channel pays, bound by the session provider that
    /// persisted it. Absent on legacy entries, which stay usable and take an
    /// origin on their next reuse.
    pub origin: Option<String>,
}

impl StoredChannelEntry {
    /// Return the MPPx-compatible payment-scope key for this channel.
    pub fn key(&self) -> String {
        if let Some(route) = &self.settlement_route {
            return format!(
                "{}:{}:{}:{:#x}:{}",
                route.adapter.to_ascii_lowercase(),
                route.recipient.to_ascii_lowercase(),
                route.target_token.to_ascii_lowercase(),
                self.escrow,
                self.chain_id,
            );
        }
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

/// Keeps the origin a stored channel is bound to: a new entry may name no
/// origin or the same one, never another, as mppx's `persistChannel` does.
fn merge_origin(
    current: Option<&StoredChannelEntry>,
    entry: &StoredChannelEntry,
) -> ChannelStoreResult<Option<String>> {
    match (
        current.and_then(|current| current.origin.as_ref()),
        &entry.origin,
    ) {
        (Some(current), Some(origin)) if current != origin => Err(origin_mismatch()),
        (Some(current), _) => Ok(Some(current.clone())),
        (None, origin) => Ok(origin.clone()),
    }
}

fn origin_mismatch() -> ChannelStoreError {
    ChannelStoreError::InvalidEntry("stored channel origin mismatch".into())
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

/// Exclusive payment-scope lease held until a credential is committed or rolled back.
pub trait ChannelStoreLease: Send {}

impl ChannelStoreLease for () {}
impl ChannelStoreLease for tokio::sync::OwnedMutexGuard<()> {}

/// Store of reusable payer session channels keyed by payment scope.
#[async_trait::async_trait]
pub trait ChannelStore: Send + Sync {
    /// Serialize credential creation and delivery for one payment scope.
    ///
    /// Stores shared by multiple processes must override this with a
    /// cross-process lease. Cumulative vouchers must reach the server in the
    /// same order they are allocated.
    async fn acquire(&self, _key: &str) -> ChannelStoreResult<Box<dyn ChannelStoreLease>> {
        Ok(Box::new(()))
    }
    /// Return the channel cached for `key`, when present.
    async fn get(&self, key: &str) -> ChannelStoreResult<Option<StoredChannelEntry>>;
    /// Insert or replace a channel entry.
    async fn set(&self, entry: &StoredChannelEntry) -> ChannelStoreResult<()>;
    /// Remove the channel cached for `key`.
    async fn delete(&self, key: &str) -> ChannelStoreResult<()>;
    /// The `spent` a server receipt last reported for `channel_id`, the channel
    /// cached for `key`. `None` when the store keeps no such record, or when
    /// the channel's vouchers moved after it was recorded: a client that keeps
    /// no record, such as mppx, may have spent on the channel since. A restored
    /// channel's first receipt is then costed at its quoted price.
    async fn server_spent(
        &self,
        _key: &str,
        _channel_id: B256,
    ) -> ChannelStoreResult<Option<u128>> {
        Ok(None)
    }
    /// Record the `spent` a server receipt reported for `channel_id`, the
    /// channel cached for `key`, so a later process can cost the channel's
    /// next receipt as the change from it. Stores that keep no such record
    /// ignore it.
    async fn set_server_spent(
        &self,
        _key: &str,
        _channel_id: B256,
        _spent: u128,
    ) -> ChannelStoreResult<()> {
        Ok(())
    }
}

/// In-memory channel store used when persistence is not configured.
#[derive(Debug, Default)]
pub struct MemoryChannelStore {
    entries: Mutex<HashMap<String, StoredChannelEntry>>,
    leases: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    server_spent: Mutex<HashMap<String, (B256, u128, u128)>>,
}

#[async_trait::async_trait]
impl ChannelStore for MemoryChannelStore {
    async fn acquire(&self, key: &str) -> ChannelStoreResult<Box<dyn ChannelStoreLease>> {
        let lock = {
            let mut leases = self.leases.lock().unwrap();
            leases.entry(key.to_owned()).or_default().clone()
        };
        Ok(Box::new(lock.lock_owned().await))
    }

    async fn get(&self, key: &str) -> ChannelStoreResult<Option<StoredChannelEntry>> {
        Ok(self.entries.lock().unwrap().get(key).cloned())
    }

    async fn set(&self, entry: &StoredChannelEntry) -> ChannelStoreResult<()> {
        let mut entries = self.entries.lock().unwrap();
        let current = entries.get(&entry.key());
        let origin = merge_origin(current, entry)?;
        let mut merged = match current {
            Some(current) if current.channel_id == entry.channel_id => StoredChannelEntry {
                cumulative_amount: current.cumulative_amount.max(entry.cumulative_amount),
                deposit: current.deposit.max(entry.deposit),
                ..entry.clone()
            },
            _ => entry.clone(),
        };
        merged.origin = origin;
        entries.insert(merged.key(), merged);
        Ok(())
    }

    async fn delete(&self, key: &str) -> ChannelStoreResult<()> {
        self.entries.lock().unwrap().remove(key);
        self.server_spent.lock().unwrap().remove(key);
        Ok(())
    }

    async fn server_spent(&self, key: &str, channel_id: B256) -> ChannelStoreResult<Option<u128>> {
        let cumulative = self
            .entries
            .lock()
            .unwrap()
            .get(key)
            .filter(|entry| entry.channel_id == channel_id)
            .map(|entry| entry.cumulative_amount);
        Ok(self
            .server_spent
            .lock()
            .unwrap()
            .get(key)
            .filter(|(id, _, recorded)| *id == channel_id && Some(*recorded) == cumulative)
            .map(|(_, spent, _)| *spent))
    }

    async fn set_server_spent(
        &self,
        key: &str,
        channel_id: B256,
        spent: u128,
    ) -> ChannelStoreResult<()> {
        let cumulative = self
            .entries
            .lock()
            .unwrap()
            .get(key)
            .filter(|entry| entry.channel_id == channel_id)
            .map(|entry| entry.cumulative_amount);
        if let Some(cumulative) = cumulative {
            self.server_spent
                .lock()
                .unwrap()
                .insert(key.to_owned(), (channel_id, spent, cumulative));
        }
        Ok(())
    }
}

/// A session provider's view of its channel store, bound to the provider's
/// HTTP origin: entries it writes carry that origin, and an entry bound to
/// another origin is refused. An unbound provider adopts the origin of the
/// first bound entry it reads, so it cannot later pay another origin with it.
pub(crate) struct OriginBoundChannelStore {
    pub(crate) inner: Arc<dyn ChannelStore>,
    pub(crate) origin: Arc<Mutex<Option<String>>>,
}

#[async_trait::async_trait]
impl ChannelStore for OriginBoundChannelStore {
    async fn acquire(&self, key: &str) -> ChannelStoreResult<Box<dyn ChannelStoreLease>> {
        self.inner.acquire(key).await
    }

    async fn get(&self, key: &str) -> ChannelStoreResult<Option<StoredChannelEntry>> {
        let entry = self.inner.get(key).await?;
        if let Some(stored) = entry.as_ref().and_then(|entry| entry.origin.as_ref()) {
            let mut bound = self.origin.lock().unwrap();
            match bound.as_ref() {
                Some(bound) if bound != stored => return Err(origin_mismatch()),
                Some(_) => {}
                None => *bound = Some(stored.clone()),
            }
        }
        Ok(entry)
    }

    async fn set(&self, entry: &StoredChannelEntry) -> ChannelStoreResult<()> {
        let bound = self.origin.lock().unwrap().clone();
        let mut entry = entry.clone();
        match (&entry.origin, bound) {
            (Some(origin), Some(bound)) if *origin != bound => return Err(origin_mismatch()),
            (_, Some(bound)) => entry.origin = Some(bound),
            (_, None) => {}
        }
        self.inner.set(&entry).await
    }

    async fn delete(&self, key: &str) -> ChannelStoreResult<()> {
        self.inner.delete(key).await
    }

    async fn server_spent(&self, key: &str, channel_id: B256) -> ChannelStoreResult<Option<u128>> {
        self.inner.server_spent(key, channel_id).await
    }

    async fn set_server_spent(
        &self,
        key: &str,
        channel_id: B256,
        spent: u128,
    ) -> ChannelStoreResult<()> {
        self.inner.set_server_spent(key, channel_id, spent).await
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsonChannelEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
    channel_id: String,
    cumulative_amount: String,
    deposit: String,
    descriptor: ChannelDescriptor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    settlement_route: Option<crate::protocol::methods::tempo::session::SettlementRoute>,
    escrow: String,
    chain_id: u64,
    opened: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_open: Option<String>,
}

impl From<&StoredChannelEntry> for JsonChannelEntry {
    fn from(entry: &StoredChannelEntry) -> Self {
        Self {
            origin: entry.origin.clone(),
            channel_id: format!("{:#x}", entry.channel_id),
            cumulative_amount: entry.cumulative_amount.to_string(),
            deposit: entry.deposit.to_string(),
            descriptor: entry.descriptor.clone(),
            settlement_route: entry.settlement_route.clone(),
            escrow: format!("{:#x}", entry.escrow),
            chain_id: entry.chain_id,
            opened: entry.opened,
            pending_open: entry.pending_open.clone(),
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
            settlement_route: entry.settlement_route,
            escrow: entry.escrow.parse().map_err(|e| invalid("escrow", e))?,
            chain_id: entry.chain_id,
            opened: entry.opened,
            pending_open: entry.pending_open.clone(),
            origin: entry.origin,
        })
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use std::{
        fs::{self, File, OpenOptions},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use fs2::FileExt;
    use rusqlite::{params, Connection, OptionalExtension};
    use sha2::{Digest, Sha256};

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

    struct SqliteChannelStoreLease {
        _file: File,
    }

    impl ChannelStoreLease for SqliteChannelStoreLease {}

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
        tempo_alloy::accounts::default_accounts_store_path()
            .map(|path| path.with_file_name("channels.db"))
            .map_err(|error| ChannelStoreError::Io(error.to_string()))
    }

    impl SqliteChannelStore {
        /// Open a SQLite channel store and migrate compatible legacy schemas.
        pub fn open(options: SqliteChannelStoreOptions) -> ChannelStoreResult<Self> {
            let path = match options.path {
                Some(path) => path,
                None => default_channel_database_path()?,
            };
            if let Some(parent) = path.parent() {
                let mut builder = fs::DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                builder.create(parent).map_err(io_error)?;
            }
            let _schema_lease = lock_file(&database_lock_path(&path))?;
            // SQLite derives new sidecar modes from the database. Secure it before
            // opening SQLite, and repair sidecars left by older store versions.
            #[cfg(unix)]
            secure_database_files(&path)?;
            let connection = Connection::open(&path).map_err(io_error)?;
            connection
                .execute_batch(
                    "PRAGMA journal_mode = WAL;
                     PRAGMA busy_timeout = 5000;",
                )
                .map_err(io_error)?;
            ensure_schema(&connection)?;

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

        /// Return the signer of the most recently used active session for this service.
        ///
        /// Wallet-backed clients can use this before constructing their session
        /// provider so a cold process retains the exact access key authorized by
        /// the existing channel descriptor.
        pub fn latest_authorized_signer(&self) -> ChannelStoreResult<Option<Address>> {
            let value = self
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT authorized_signer FROM channels
                     WHERE origin = ?1 AND state = 'active' AND session_protocol = 'v2'
                         AND scope_key IS NOT NULL
                     ORDER BY last_used_at DESC LIMIT 1",
                    [&self.origin],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(io_error)?;
            value
                .map(|address| {
                    address.parse().map_err(|error| {
                        ChannelStoreError::InvalidEntry(format!(
                            "invalid authorized_signer: {error}"
                        ))
                    })
                })
                .transpose()
        }

        /// The store's namespace as an HTTP origin, which its channels are bound to.
        fn http_origin(&self) -> Option<String> {
            (self.origin.starts_with("http://") || self.origin.starts_with("https://"))
                .then(|| self.origin.clone())
        }

        fn scoped_key(&self, key: &str) -> String {
            format!("{}\n{}", self.namespace, key)
        }

        fn payment_lock_path(&self, key: &str) -> PathBuf {
            let digest = Sha256::digest(self.scoped_key(key).as_bytes());
            let name = self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("channels.db");
            self.path
                .with_file_name(format!("{name}.{}.lock", alloy::hex::encode(digest)))
        }
    }

    #[async_trait::async_trait]
    impl ChannelStore for SqliteChannelStore {
        async fn acquire(&self, key: &str) -> ChannelStoreResult<Box<dyn ChannelStoreLease>> {
            let path = self.payment_lock_path(key);
            tokio::task::spawn_blocking(move || {
                lock_file(&path).map(|file| {
                    Box::new(SqliteChannelStoreLease { _file: file }) as Box<dyn ChannelStoreLease>
                })
            })
            .await
            .map_err(io_error)?
        }

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
                entry.origin = entry.origin.or_else(|| self.http_origin());
                return entry.try_into().map(Some);
            }
            let descriptor = descriptor.ok_or_else(|| {
                ChannelStoreError::InvalidEntry("v2 row is missing descriptor_json".into())
            })?;
            JsonChannelEntry {
                origin: self.http_origin(),
                channel_id,
                cumulative_amount: cumulative,
                deposit,
                descriptor: serde_json::from_str(&descriptor)
                    .map_err(|e| ChannelStoreError::InvalidEntry(e.to_string()))?,
                settlement_route: None,
                escrow,
                chain_id,
                opened: state == "active",
                pending_open: None,
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
            let mut entry = entry.clone();
            if let Some(origin) = self.http_origin() {
                if entry.origin.as_ref().is_some_and(|entry| *entry != origin) {
                    return Err(origin_mismatch());
                }
                entry.origin = Some(origin);
            }
            let conflict: Option<(Option<String>, String)> = transaction
                .query_row(
                    "SELECT scope_key, origin FROM channels WHERE channel_id = ?1",
                    [format!("{:#x}", entry.channel_id)],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(io_error)?;
            if conflict.is_some_and(|(scope, origin)| {
                scope.is_some_and(|scope| scope != scope_key) || origin != self.origin
            }) {
                return Err(origin_mismatch());
            }
            let origin = merge_origin(current.as_ref(), &entry)?;
            let mut merged = match current {
                Some(current) if current.channel_id == entry.channel_id => StoredChannelEntry {
                    cumulative_amount: current.cumulative_amount.max(entry.cumulative_amount),
                    deposit: current.deposit.max(entry.deposit),
                    ..entry.clone()
                },
                _ => entry.clone(),
            };
            merged.origin = origin;
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
            let changed = transaction
                .execute(
                    "INSERT INTO channels (
                        channel_id, version, scope_key, origin, request_url, chain_id,
                        escrow_contract, token, payee, payer, authorized_signer, salt,
                        session_protocol, descriptor_json, entry_json, deposit,
                        cumulative_amount, accepted_cumulative, challenge_echo, state,
                        close_requested_at, grace_ready_at, created_at, last_used_at, server_spent
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                        'v2', ?13, ?14, ?15, ?16, '0', '{}', 'active', 0, 0, ?17, ?17, '0')
                     ON CONFLICT(channel_id) DO UPDATE SET
                        version=excluded.version, scope_key=excluded.scope_key,
                        origin=excluded.origin, request_url=excluded.request_url,
                        chain_id=excluded.chain_id, escrow_contract=excluded.escrow_contract,
                        token=excluded.token, payee=excluded.payee, payer=excluded.payer,
                        authorized_signer=excluded.authorized_signer, salt=excluded.salt,
                        session_protocol=excluded.session_protocol,
                        descriptor_json=excluded.descriptor_json, entry_json=excluded.entry_json,
                        deposit=excluded.deposit, cumulative_amount=excluded.cumulative_amount,
                        state='active', close_requested_at=0, last_used_at=excluded.last_used_at
                     WHERE (channels.scope_key IS NULL OR channels.scope_key = excluded.scope_key) AND channels.origin = excluded.origin",
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
                        now,
                    ],
                )
                .map_err(io_error)?;
            if changed != 1 {
                return Err(origin_mismatch());
            }
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

        /// Reads the `server_spent` column, which tempo-wallet also keeps. Its
        /// default `'0'`, written by mppx and by rows this store never
        /// recorded a receipt for, means unknown, as it does to tempo-wallet.
        /// `server_spent_cumulative` holds the vouchers' cumulative amount when
        /// this store recorded it; once the row's has moved, a client that does
        /// not keep `server_spent` may have spent on the channel. A value
        /// tempo-wallet recorded, with no cumulative beside it, is current.
        async fn server_spent(
            &self,
            key: &str,
            channel_id: B256,
        ) -> ChannelStoreResult<Option<u128>> {
            let row: Option<(String, Option<String>, String)> = self
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT server_spent, server_spent_cumulative, cumulative_amount
                     FROM channels WHERE scope_key = ?1 AND channel_id = ?2",
                    params![self.scoped_key(key), format!("{:#x}", channel_id)],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(io_error)?;
            Ok(row
                .filter(|(_, recorded, cumulative)| {
                    recorded
                        .as_ref()
                        .is_none_or(|recorded| recorded == cumulative)
                })
                .and_then(|(spent, _, _)| spent.parse::<u128>().ok())
                .filter(|spent| *spent > 0))
        }

        async fn set_server_spent(
            &self,
            key: &str,
            channel_id: B256,
            spent: u128,
        ) -> ChannelStoreResult<()> {
            self.connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE channels SET server_spent = ?3, server_spent_cumulative = cumulative_amount
                     WHERE scope_key = ?1 AND channel_id = ?2",
                    params![
                        self.scoped_key(key),
                        format!("{:#x}", channel_id),
                        spent.to_string()
                    ],
                )
                .map_err(io_error)?;
            Ok(())
        }
    }

    fn database_lock_path(path: &Path) -> PathBuf {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("channels.db");
        path.with_file_name(format!("{name}.lock"))
    }

    fn lock_file(path: &Path) -> ChannelStoreResult<File> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(io_error)?;
        file.lock_exclusive().map_err(io_error)?;
        Ok(file)
    }

    #[cfg(unix)]
    fn secure_database_files(path: &Path) -> ChannelStoreResult<()> {
        use std::os::unix::fs::OpenOptionsExt;

        // Never open/close existing database or sidecar descriptors here: on
        // Unix that releases this process's SQLite record locks on the inode.
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error(error)),
        }
        set_private_permissions_nofollow(path).map_err(io_error)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(suffix);
            match set_private_permissions_nofollow(Path::new(&sidecar)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn set_private_permissions_nofollow(path: &Path) -> std::io::Result<()> {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};

        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SQLite database and sidecars must not be symbolic links",
            ));
        }
        let path = CString::new(path.as_os_str().as_bytes())?;
        // Unlike a metadata check followed by chmod, this cannot follow a link
        // swapped in between the two operations. Do not open/close SQLite
        // data-file descriptors to chmod them.
        // SAFETY: path is a live NUL-terminated string; no pointers are retained.
        let result = unsafe {
            libc::fchmodat(
                libc::AT_FDCWD,
                path.as_ptr(),
                0o600,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            let error = std::io::Error::last_os_error();
            #[cfg(target_os = "linux")]
            if error.raw_os_error() == Some(libc::EOPNOTSUPP) {
                return set_private_permissions_linux(&path);
            }
            Err(error)
        }
    }

    #[cfg(target_os = "linux")]
    fn set_private_permissions_linux(path: &std::ffi::CStr) -> std::io::Result<()> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::PermissionsExt;

        // O_PATH pins the inode without opening it for I/O. Closing this kind
        // of descriptor does not release the process's SQLite POSIX locks.
        // SAFETY: path is a live NUL-terminated string and open retains no pointer.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: open returned a new descriptor, owned exclusively here.
        let file = unsafe { File::from_raw_fd(fd) };
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SQLite permission repair requires a regular file",
            ));
        }
        // New kernels support descriptor-based chmod even when /proc is absent.
        // SAFETY: fd is live, the empty path is NUL-terminated, and all arguments
        // match fchmodat2's ABI. Older kernels return ENOSYS or EINVAL.
        let result = unsafe {
            libc::syscall(
                linux_raw_sys::general::__NR_fchmodat2 as libc::c_long,
                file.as_raw_fd(),
                c"".as_ptr(),
                0o600,
                libc::AT_EMPTY_PATH,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL | libc::EOPNOTSUPP)
        ) {
            return Err(error);
        }
        // On older kernels, this procfs link names the pinned inode, never the
        // mutable caller-supplied path. Keep the descriptor live through chmod.
        fs::set_permissions(
            format!("/proc/self/fd/{}", file.as_raw_fd()),
            fs::Permissions::from_mode(0o600),
        )
    }

    #[cfg(all(test, unix))]
    #[test]
    fn permission_repair_does_not_follow_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        for suffix in ["", "-wal", "-shm", "-journal"] {
            let directory =
                std::env::temp_dir().join(format!("mpp-symlink-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("channels.db");
            let target = directory.join("unrelated-executable");
            fs::write(&target, b"unrelated file").unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
            symlink(&target, directory.join(format!("channels.db{suffix}"))).unwrap();
            assert!(secure_database_files(&path).is_err());
            #[cfg(target_os = "linux")]
            {
                use std::{ffi::CString, os::unix::ffi::OsStrExt};
                let link = directory.join(format!("channels.db{suffix}"));
                assert!(set_private_permissions_linux(
                    &CString::new(link.as_os_str().as_bytes()).unwrap()
                )
                .is_err());
            }
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o755
            );
            assert_eq!(fs::read(&target).unwrap(), b"unrelated file");
            fs::remove_dir_all(directory).unwrap();
        }
    }

    #[cfg(all(test, unix))]
    #[test]
    fn permission_repair_preserves_sqlite_writer_lock() {
        const CHILD_PATH: &str = "MPP_SQLITE_LOCK_CHILD_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let connection = Connection::open(path).unwrap();
            connection.busy_timeout(std::time::Duration::ZERO).unwrap();
            let error = connection.execute_batch("BEGIN IMMEDIATE").unwrap_err();
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
            return;
        }
        let directory = std::env::temp_dir().join(format!("mpp-lock-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("channels.db");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE test(value INTEGER); BEGIN IMMEDIATE; INSERT INTO test VALUES(1);").unwrap();
        secure_database_files(&path).unwrap();
        #[cfg(target_os = "linux")]
        {
            use std::{ffi::CString, os::unix::ffi::OsStrExt};
            for suffix in ["", "-wal", "-shm"] {
                let target = directory.join(format!("channels.db{suffix}"));
                set_private_permissions_linux(
                    &CString::new(target.as_os_str().as_bytes()).unwrap(),
                )
                .unwrap();
            }
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "client::tempo::session::store::sqlite::permission_repair_preserves_sqlite_writer_lock", "--nocapture"])
            .env(CHILD_PATH, &path).status().unwrap();
        assert!(status.success());
        connection.execute_batch("COMMIT").unwrap();
        drop(connection);
        fs::remove_dir_all(directory).unwrap();
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
        add_column(connection, "server_spent_cumulative", "TEXT")?;
        connection
            .execute_batch(
                "WITH ranked AS (
                     SELECT channel_id,
                            row_number() OVER (
                                PARTITION BY origin, lower(payee), lower(token),
                                             lower(escrow_contract), chain_id
                                ORDER BY scope_key IS NOT NULL DESC,
                                         state = 'active' DESC,
                                         last_used_at DESC,
                                         created_at DESC,
                                         channel_id DESC
                            ) AS scope_rank
                     FROM channels
                     WHERE origin <> '' AND session_protocol = 'v2'
                         AND descriptor_json IS NOT NULL
                 )
                 UPDATE channels
                 SET scope_key = origin || char(10) || lower(payee) || ':' || lower(token) || ':' ||
                     lower(escrow_contract) || ':' || chain_id
                 WHERE scope_key IS NULL AND origin <> '' AND session_protocol = 'v2'
                     AND descriptor_json IS NOT NULL
                     AND channel_id IN (
                         SELECT channel_id FROM ranked WHERE scope_rank = 1
                     );
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

    pub use self::SqliteChannelStoreOptions as Options;
    pub use SqliteChannelStore as Store;
}

#[cfg(feature = "sqlite")]
pub use sqlite::Store as SqliteChannelStore;
#[cfg(feature = "sqlite")]
pub use sqlite::{default_channel_database_path, Options as SqliteChannelStoreOptions};

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "sqlite")]
    #[test]
    fn default_database_path_follows_tempo_home() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        let directory =
            std::env::temp_dir().join(format!("mpp-rs-tempo-home-{}", uuid::Uuid::new_v4()));
        let previous = std::env::var_os("TEMPO_HOME");
        std::env::set_var("TEMPO_HOME", &directory);
        let actual = default_channel_database_path().unwrap();
        match previous {
            Some(value) => std::env::set_var("TEMPO_HOME", value),
            None => std::env::remove_var("TEMPO_HOME"),
        }
        assert_eq!(actual, directory.join("wallet/channels.db"));
    }

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
            settlement_route: None,
            escrow: "0x0000000000000000000000000000000000000005"
                .parse()
                .unwrap(),
            chain_id: 4217,
            opened: true,
            pending_open: None,
            origin: None,
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

    #[tokio::test]
    async fn memory_store_keeps_server_spent_per_channel() {
        let store = MemoryChannelStore::default();
        let current = entry();
        let key = current.key();
        store.set(&current).await.unwrap();
        assert_eq!(
            store.server_spent(&key, current.channel_id).await.unwrap(),
            None
        );
        store
            .set_server_spent(&key, current.channel_id, 1_500)
            .await
            .unwrap();
        assert_eq!(
            store.server_spent(&key, current.channel_id).await.unwrap(),
            Some(1_500)
        );
        assert_eq!(
            store
                .server_spent(&key, B256::repeat_byte(0x99))
                .await
                .unwrap(),
            None
        );
        store
            .set(&StoredChannelEntry {
                cumulative_amount: current.cumulative_amount + 1,
                ..current.clone()
            })
            .await
            .unwrap();
        assert_eq!(
            store.server_spent(&key, current.channel_id).await.unwrap(),
            None
        );
        store
            .set_server_spent(&key, current.channel_id, 1_600)
            .await
            .unwrap();
        store.delete(&key).await.unwrap();
        assert_eq!(
            store.server_spent(&key, current.channel_id).await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn stored_channel_origin_is_retained_and_cannot_be_rebound() {
        let store = MemoryChannelStore::default();
        let bound = StoredChannelEntry {
            origin: Some("https://api.example.test".into()),
            ..entry()
        };
        store.set(&bound).await.unwrap();
        store.set(&entry()).await.unwrap();
        assert_eq!(
            store.get(&bound.key()).await.unwrap().unwrap().origin,
            bound.origin
        );
        let error = store
            .set(&StoredChannelEntry {
                origin: Some("https://evil.example".into()),
                ..entry()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("origin mismatch"));
        assert_eq!(store.get(&bound.key()).await.unwrap(), Some(bound));
    }

    #[test]
    fn legacy_json_entry_without_origin_still_decodes() {
        let json = serde_json::to_value(JsonChannelEntry::from(&entry())).unwrap();
        assert!(json.get("origin").is_none());
        let decoded: StoredChannelEntry = serde_json::from_value::<JsonChannelEntry>(json)
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(decoded, entry());
    }

    #[cfg(all(feature = "sqlite", unix))]
    #[tokio::test]
    async fn sqlite_secures_active_and_recreated_sidecars() {
        use std::os::unix::fs::PermissionsExt;
        if std::env::var_os("MPP_SQLITE_PERMISSIONS_CHILD").is_none() {
            let status = std::process::Command::new("/bin/sh")
                .args(["-c", "umask 022; exec \"$1\" --exact client::tempo::session::store::tests::sqlite_secures_active_and_recreated_sidecars --nocapture", "sh"])
                .arg(std::env::current_exe().unwrap())
                .env("MPP_SQLITE_PERMISSIONS_CHILD", "1")
                .status().unwrap();
            assert!(status.success());
            return;
        }
        let directory =
            std::env::temp_dir().join(format!("mpp-rs-permissions-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = directory.join("channels.db");
        let options = SqliteChannelStoreOptions {
            namespace: "https://api.example.com".into(),
            path: Some(path.clone()),
            request_url: Some("https://api.example.com/private?query=sensitive".into()),
        };
        let paths = [
            path.clone(),
            directory.join("channels.db-wal"),
            directory.join("channels.db-shm"),
        ];
        let assert_private = || {
            for file in &paths {
                assert_eq!(
                    std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                    0o600,
                    "{}",
                    file.display()
                );
            }
        };
        let first = SqliteChannelStore::open(options.clone()).unwrap();
        first.set(&entry()).await.unwrap();
        assert_private();
        // Emulate an older store while its WAL remains active.
        for file in &paths {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let second = SqliteChannelStore::open(options.clone()).unwrap();
        second.set(&entry()).await.unwrap();
        assert_private();
        drop(second);
        drop(first);
        let reopened = SqliteChannelStore::open(options).unwrap();
        reopened.set(&entry()).await.unwrap();
        assert_private();
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_roundtrip_uses_mppx_entry_json() {
        let directory = std::env::temp_dir().join(format!("mpp-rs-store-{}", uuid::Uuid::new_v4()));
        let path = directory.join("channels.db");
        let mut current = entry();
        current.pending_open = Some("unconfirmed-opening".into());
        current.origin = Some("https://api.example.com".into());
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
        assert_eq!(
            store.latest_authorized_signer().unwrap(),
            Some(current.descriptor.authorized_signer.parse().unwrap())
        );

        let connection = rusqlite::Connection::open(path).unwrap();
        let json: String = connection
            .query_row("SELECT entry_json FROM channels", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap(),
            serde_json::to_value(JsonChannelEntry::from(&current)).unwrap()
        );
        drop(connection);
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_keeps_server_spent_across_writes_and_processes() {
        let directory = std::env::temp_dir().join(format!("mpp-rs-store-{}", uuid::Uuid::new_v4()));
        let path = directory.join("channels.db");
        let open = || {
            SqliteChannelStore::open(SqliteChannelStoreOptions {
                namespace: "https://api.example.com".into(),
                path: Some(path.clone()),
                request_url: None,
            })
            .unwrap()
        };
        let current = entry();
        let key = current.key();
        let store = open();
        store.set(&current).await.unwrap();
        assert_eq!(
            store.server_spent(&key, current.channel_id).await.unwrap(),
            None
        );
        store
            .set_server_spent(&key, current.channel_id, 1_500)
            .await
            .unwrap();
        store.set(&current).await.unwrap();
        assert_eq!(
            store.server_spent(&key, current.channel_id).await.unwrap(),
            Some(1_500)
        );
        assert_eq!(
            store
                .server_spent(&key, B256::repeat_byte(0x99))
                .await
                .unwrap(),
            None
        );
        drop(store);
        assert_eq!(
            open().server_spent(&key, current.channel_id).await.unwrap(),
            Some(1_500)
        );

        let connection = rusqlite::Connection::open(&path).unwrap();
        let column: String = connection
            .query_row("SELECT server_spent FROM channels", [], |row| row.get(0))
            .unwrap();
        assert_eq!(column, "1500");

        // Vouchers another client signed since make the recorded spent stale.
        connection
            .execute("UPDATE channels SET cumulative_amount = '2000001'", [])
            .unwrap();
        assert_eq!(
            open().server_spent(&key, current.channel_id).await.unwrap(),
            None
        );
        // tempo-wallet keeps server_spent current itself and records no cumulative.
        connection
            .execute(
                "UPDATE channels SET server_spent = '1700', server_spent_cumulative = NULL",
                [],
            )
            .unwrap();
        assert_eq!(
            open().server_spent(&key, current.channel_id).await.unwrap(),
            Some(1_700)
        );
        connection
            .execute("UPDATE channels SET server_spent = '0'", [])
            .unwrap();
        drop(connection);
        assert_eq!(
            open().server_spent(&key, current.channel_id).await.unwrap(),
            None
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_rejects_cross_origin_channel_id_conflicts() {
        let directory = std::env::temp_dir().join(format!("mpp-rs-store-{}", uuid::Uuid::new_v4()));
        let path = directory.join("channels.db");
        let first = SqliteChannelStore::open(SqliteChannelStoreOptions {
            namespace: "https://first.example".into(),
            path: Some(path.clone()),
            request_url: None,
        })
        .unwrap();
        let second = SqliteChannelStore::open(SqliteChannelStoreOptions {
            namespace: "https://second.example".into(),
            path: Some(path),
            request_url: None,
        })
        .unwrap();
        let original = entry();
        first.set(&original).await.unwrap();
        let before = first.get(&original.key()).await.unwrap();
        let error = second.set(&original).await.unwrap_err();
        assert!(error.to_string().contains("origin mismatch"));
        assert_eq!(first.get(&original.key()).await.unwrap(), before);
        assert!(second.get(&original.key()).await.unwrap().is_none());
        first.set(&original).await.unwrap();
        drop(first);
        drop(second);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_lease_serializes_delivery_across_store_instances() {
        let directory =
            std::env::temp_dir().join(format!("mpp-rs-store-lock-{}", uuid::Uuid::new_v4()));
        let path = directory.join("channels.db");
        let options = SqliteChannelStoreOptions {
            namespace: "https://api.example.com".into(),
            path: Some(path),
            request_url: None,
        };
        let first = SqliteChannelStore::open(options.clone()).unwrap();
        let second = SqliteChannelStore::open(options).unwrap();
        let first_lease = first.acquire("scope").await.unwrap();
        let mut waiter = tokio::spawn(async move { second.acquire("scope").await });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut waiter)
                .await
                .is_err(),
            "the second store must wait for the first delivery lease"
        );
        drop(first_lease);

        let second_lease = tokio::time::timeout(std::time::Duration::from_secs(1), async move {
            waiter.await.unwrap().unwrap()
        })
        .await
        .expect("the second lease should be released");
        drop(second_lease);
        drop(first);
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
        // A migrated row is bound to the store's namespace origin.
        let current = StoredChannelEntry {
            origin: Some("https://api.example.com".into()),
            ..current
        };
        assert_eq!(store.get(&current.key()).await.unwrap(), Some(current));
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_migrates_only_one_of_multiple_sessions_for_the_same_scope() {
        let directory =
            std::env::temp_dir().join(format!("mpp-rs-recovered-store-{}", uuid::Uuid::new_v4()));
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
            for channel_id in [B256::repeat_byte(0x11), B256::repeat_byte(0x12)] {
                connection
                    .execute(
                        "INSERT INTO channels (
                            channel_id, version, origin, request_url, chain_id, escrow_contract,
                            token, payee, payer, authorized_signer, salt, deposit,
                            cumulative_amount, challenge_echo, state, close_requested_at,
                            grace_ready_at, created_at, last_used_at, accepted_cumulative,
                            server_spent, session_protocol, descriptor_json
                         ) VALUES (?1, 1, 'https://api.example.com', 'https://api.example.com',
                            ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                            '{}', 'active', 0, 0, 1, 1, '0', '0', 'v2', ?11)",
                        rusqlite::params![
                            format!("{channel_id:#x}"),
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
        }

        let store = SqliteChannelStore::open(SqliteChannelStoreOptions {
            namespace: "https://api.example.com".into(),
            path: Some(path.clone()),
            request_url: None,
        })
        .unwrap();
        drop(store);

        let connection = rusqlite::Connection::open(&path).unwrap();
        let scoped: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM channels WHERE scope_key IS NOT NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(scoped, 1);
        let total: i64 = connection
            .query_row("SELECT COUNT(*) FROM channels", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total, 2);
        let unscoped: String = connection
            .query_row(
                "SELECT channel_id FROM channels WHERE scope_key IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(connection);
        let store = SqliteChannelStore::open(SqliteChannelStoreOptions {
            namespace: "https://api.example.com".into(),
            path: Some(path.clone()),
            request_url: None,
        })
        .unwrap();
        let mut recovered = current;
        recovered.channel_id = unscoped.parse().unwrap();
        store.set(&recovered).await.unwrap();
        assert_eq!(
            store
                .get(&recovered.key())
                .await
                .unwrap()
                .unwrap()
                .channel_id,
            recovered.channel_id
        );
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
