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
    /// HTTP origin the channel pays, set by the session provider that
    /// persisted it: the origin whose namespace keeps the channel (see
    /// [`origin_channel_key`]). Absent on legacy entries and on channels
    /// paid over a transport without an HTTP origin, which only providers
    /// without an HTTP origin use.
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
    /// Insert or replace `entry` under `key` instead of its payment-scope
    /// key [`StoredChannelEntry::key`], merging it with a stored entry for the
    /// same channel as [`set`](Self::set) does.
    ///
    /// A session provider bound to an HTTP origin keeps its channels in that
    /// origin's namespace, under [`origin_channel_key`], unless the store
    /// keeps only that origin's channels ([`origin`](Self::origin)). `get` and
    /// `delete` must then find and remove the entry under `key`.
    async fn set_at(&self, key: &str, entry: &StoredChannelEntry) -> ChannelStoreResult<()>;
    /// Return the key channel `channel_id` is stored under, or `None` only
    /// when the store keeps no entry for it under any key.
    ///
    /// Session providers use it to leave a channel in the namespace that
    /// keeps it, such as a channel another origin's provider opened that a
    /// server snapshot names, instead of copying it into their own. It is
    /// required, with no default, because `None` vouches that no other
    /// namespace owns the channel.
    async fn find_channel(&self, channel_id: B256) -> ChannelStoreResult<Option<String>>;
    /// The HTTP origin, such as `"https://api.example.com"`, that every
    /// channel this store keeps is bound to, when it keeps only one origin's
    /// channels. A session provider using the store is bound to it.
    ///
    /// Defaults to `None`: the store keeps channels for any origin, with the
    /// origin each entry names.
    fn origin(&self) -> Option<String> {
        None
    }
    /// Remove the channel cached for `key`.
    async fn delete(&self, key: &str) -> ChannelStoreResult<()>;
}

/// In-memory channel store used when persistence is not configured.
#[derive(Debug, Default)]
pub struct MemoryChannelStore {
    entries: Mutex<HashMap<String, StoredChannelEntry>>,
    leases: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
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
        self.set_at(&entry.key(), entry).await
    }

    async fn set_at(&self, key: &str, entry: &StoredChannelEntry) -> ChannelStoreResult<()> {
        let mut entries = self.entries.lock().unwrap();
        let current = entries.get(key);
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
        entries.insert(key.to_owned(), merged);
        Ok(())
    }

    async fn find_channel(&self, channel_id: B256) -> ChannelStoreResult<Option<String>> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .find(|(_, entry)| entry.channel_id == channel_id)
            .map(|(key, _)| key.clone()))
    }

    async fn delete(&self, key: &str) -> ChannelStoreResult<()> {
        self.entries.lock().unwrap().remove(key);
        Ok(())
    }
}

/// Key under which a session provider bound to the HTTP origin `origin`
/// keeps its channel for payment scope `key` in a store that keeps several
/// origins' channels: `"{key}@{origin}"`, such as
/// `"0xpayee:0xtoken:0xescrow:4217@https://api.example.com"`.
///
/// Each origin's channels live in their own namespace. The payment-scope key
/// itself is the namespace of channels without an origin: those of providers
/// with no HTTP origin (paying through a bare `pay` or a non-HTTP MCP
/// resource) and legacy entries written before origins existed. A store that
/// keeps only one origin's channels ([`ChannelStore::origin`]) keeps that
/// origin's channels under their payment-scope key.
pub fn origin_channel_key(key: &str, origin: &str) -> String {
    format!("{key}@{origin}")
}

/// A session provider's view of its channel store, confined to one
/// namespace: the provider's HTTP origin once it is bound to one, or the
/// namespace of channels without an origin while it is not.
///
/// A provider reads and writes channels only in its current namespace (see
/// [`origin_channel_key`]) and never reads, reuses, overwrites, rebinds or
/// deletes an entry in another, so providers sharing a store never touch
/// each other's channels. Reading never binds a provider.
///
/// The namespace is fixed when the provider is bound. Each channel belongs
/// to the namespace the provider first read, wrote or opened it in, and stays
/// stored there: a channel a provider used before it was bound stays in the
/// namespace without an origin, and once bound the provider refuses to
/// write, delete or sign for it, so it is never carried into the origin's
/// namespace. A provider without an origin closes it.
pub(crate) struct OriginBoundChannelStore {
    inner: Arc<dyn ChannelStore>,
    origin: Arc<Mutex<Option<String>>>,
    /// The namespace each channel this provider read, wrote or opened
    /// belongs to.
    claims: Mutex<HashMap<B256, Option<String>>>,
}

impl OriginBoundChannelStore {
    /// A view of `inner` for the provider bound through `origin`. A store
    /// that keeps only one HTTP origin's channels ([`ChannelStore::origin`])
    /// binds an unbound provider to that origin.
    pub(crate) fn new(inner: Arc<dyn ChannelStore>, origin: Arc<Mutex<Option<String>>>) -> Self {
        if let Some(store_origin) = inner.origin() {
            origin.lock().unwrap().get_or_insert(store_origin);
        }
        Self {
            inner,
            origin,
            claims: Mutex::default(),
        }
    }

    /// The origin of the underlying store, when it keeps only one HTTP
    /// origin's channels ([`ChannelStore::origin`]).
    pub(crate) fn store_origin(&self) -> Option<String> {
        self.inner.origin()
    }

    /// The provider's current namespace: its HTTP origin, if bound.
    fn namespace(&self) -> Option<String> {
        self.origin.lock().unwrap().clone()
    }

    /// Where namespace `namespace` keeps its channel for payment scope `key`.
    fn location(&self, key: &str, namespace: Option<&str>) -> String {
        match namespace {
            Some(origin) if self.inner.origin().as_deref() != Some(origin) => {
                origin_channel_key(key, origin)
            }
            _ => key.to_owned(),
        }
    }

    /// Record that `channel_id` belongs to `namespace`, refusing a channel
    /// that already belongs to another.
    fn claim_in(&self, channel_id: B256, namespace: Option<&str>) -> ChannelStoreResult<()> {
        let mut claims = self.claims.lock().unwrap();
        let claimed = claims
            .entry(channel_id)
            .or_insert_with(|| namespace.map(str::to_owned));
        if claimed.as_deref() == namespace {
            Ok(())
        } else {
            Err(origin_mismatch())
        }
    }

    /// Record that the provider opened `channel_id` in its current
    /// namespace, before the channel is stored.
    pub(crate) fn claim(&self, channel_id: B256) -> ChannelStoreResult<()> {
        self.claim_in(channel_id, self.namespace().as_deref())
    }

    /// Refuse a channel that belongs to another namespace than the
    /// provider's current one, such as a channel it used before it was bound.
    /// A channel the provider never read, wrote or opened passes.
    pub(crate) fn check(&self, channel_id: B256) -> ChannelStoreResult<()> {
        let namespace = self.namespace();
        match self.claims.lock().unwrap().get(&channel_id) {
            Some(claimed) if *claimed != namespace => Err(origin_mismatch()),
            _ => Ok(()),
        }
    }

    /// Whether channel `channel_id`, such as one a server snapshot names,
    /// is stored or held in another namespace than the provider's current
    /// one for payment scope `key`, and so must not be recovered into it.
    pub(crate) async fn elsewhere(&self, key: &str, channel_id: B256) -> ChannelStoreResult<bool> {
        if self.check(channel_id).is_err() {
            return Ok(true);
        }
        let namespace = self.namespace();
        let own = self.location(key, namespace.as_deref());
        if let Some(stored) = self.inner.find_channel(channel_id).await? {
            return Ok(stored != own);
        }
        // Without a lookup by channel ID, the namespace without an origin can
        // still be read directly.
        if own != key {
            if let Some(stored) = self.inner.get(key).await? {
                return Ok(stored.channel_id == channel_id);
            }
        }
        Ok(false)
    }

    /// Delete channel `channel_id` for payment scope `key`, once the
    /// session manager has confirmed it unfunded: only from the provider's
    /// current namespace, and only while that namespace still stores the
    /// same channel. A channel of another namespace, such as one the
    /// provider used before it was bound, is never deleted.
    pub(crate) async fn forget(&self, key: &str, channel_id: B256) -> ChannelStoreResult<()> {
        if self.check(channel_id).is_err() {
            return Ok(());
        }
        let namespace = self.namespace();
        let at = self.location(key, namespace.as_deref());
        match self.inner.get(&at).await? {
            Some(stored) if stored.channel_id == channel_id && stored.origin == namespace => {
                self.inner.delete(&at).await
            }
            _ => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl ChannelStore for OriginBoundChannelStore {
    async fn acquire(&self, key: &str) -> ChannelStoreResult<Box<dyn ChannelStoreLease>> {
        self.inner.acquire(key).await
    }

    fn origin(&self) -> Option<String> {
        self.inner.origin()
    }

    /// The channel stored for `key` in the provider's current namespace. An
    /// entry there bound to another origin, such as one an earlier release
    /// bound under the payment-scope key of a store keeping several origins'
    /// channels, is refused rather than reused or overwritten.
    async fn get(&self, key: &str) -> ChannelStoreResult<Option<StoredChannelEntry>> {
        let namespace = self.namespace();
        let at = self.location(key, namespace.as_deref());
        let Some(stored) = self.inner.get(&at).await? else {
            return Ok(None);
        };
        if stored.origin != namespace {
            return Err(origin_mismatch());
        }
        self.claim_in(stored.channel_id, namespace.as_deref())?;
        Ok(Some(stored))
    }

    /// Write `entry` to the provider's current namespace, bound to its
    /// origin. A channel of another namespace, or an entry there bound to
    /// another origin, is refused.
    async fn set(&self, entry: &StoredChannelEntry) -> ChannelStoreResult<()> {
        let namespace = self.namespace();
        if entry.origin.is_some() && entry.origin != namespace {
            return Err(origin_mismatch());
        }
        let mut entry = entry.clone();
        entry.origin = namespace.clone();
        self.check(entry.channel_id)?;
        let key = entry.key();
        let at = self.location(&key, namespace.as_deref());
        // A channel lives in exactly one namespace.
        if self
            .inner
            .find_channel(entry.channel_id)
            .await?
            .is_some_and(|stored| stored != at)
        {
            return Err(origin_mismatch());
        }
        if let Some(current) = self.inner.get(&at).await? {
            if current.origin != namespace {
                return Err(origin_mismatch());
            }
        }
        if at == key {
            self.inner.set(&entry).await?;
        } else {
            self.inner.set_at(&at, &entry).await?;
        }
        self.claim_in(entry.channel_id, namespace.as_deref())
    }

    /// Only [`set`](Self::set) chooses where a provider's channel goes.
    async fn set_at(&self, key: &str, entry: &StoredChannelEntry) -> ChannelStoreResult<()> {
        if key != entry.key() {
            return Err(ChannelStoreError::InvalidEntry(format!(
                "session providers choose the key for {key}"
            )));
        }
        self.set(entry).await
    }

    async fn find_channel(&self, channel_id: B256) -> ChannelStoreResult<Option<String>> {
        self.inner.find_channel(channel_id).await
    }

    /// Delete the provider's channel for `key` from its current namespace.
    /// An entry there bound to another origin is never deleted.
    async fn delete(&self, key: &str) -> ChannelStoreResult<()> {
        let namespace = self.namespace();
        let at = self.location(key, namespace.as_deref());
        match self.inner.get(&at).await? {
            Some(stored) if stored.origin == namespace && self.check(stored.channel_id).is_ok() => {
                self.inner.delete(&at).await
            }
            _ => Ok(()),
        }
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
                fs::create_dir_all(parent).map_err(io_error)?;
            }
            let _schema_lease = lock_file(&database_lock_path(&path))?;
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

        fn origin(&self) -> Option<String> {
            self.http_origin()
        }

        async fn set(&self, entry: &StoredChannelEntry) -> ChannelStoreResult<()> {
            self.set_at(&entry.key(), entry).await
        }

        async fn set_at(&self, key: &str, entry: &StoredChannelEntry) -> ChannelStoreResult<()> {
            let scope_key = self.scoped_key(key);
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

        async fn find_channel(&self, channel_id: B256) -> ChannelStoreResult<Option<String>> {
            let scope = self
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT scope_key FROM channels WHERE lower(channel_id) = ?1",
                    [format!("{channel_id:#x}")],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(io_error)?;
            // A row of another namespace, or one no payment scope names, keeps
            // its full scope key, which no key in this namespace equals.
            let prefix = self.scoped_key("");
            Ok(scope.map(|scope| {
                let scope = scope.unwrap_or_default();
                scope
                    .strip_prefix(&prefix)
                    .map(str::to_owned)
                    .unwrap_or(scope)
            }))
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
            .map_err(io_error)?;
        // Releases before per-origin namespaces kept a channel a provider
        // bound to an HTTP origin under its payment-scope key, even in a
        // namespace (such as `wallet`) that keeps several origins' channels.
        // Move each such row into its origin's namespace, under
        // `origin_channel_key`, so the payment-scope key stays the namespace
        // of channels without an origin. Rows without an origin, and rows of a
        // namespace that keeps only their origin's channels, stay in place.
        connection
            .execute_batch(
                "WITH bound AS (
                     SELECT channel_id,
                            CASE WHEN json_valid(entry_json)
                                THEN json_extract(entry_json, '$.origin') END AS entry_origin
                     FROM channels
                     WHERE entry_json IS NOT NULL AND scope_key IS NOT NULL
                         -- The persisted key is namespace, newline, payment-scope
                         -- key: only an '@' after the newline marks a key already
                         -- in an origin's namespace, since namespaces such as
                         -- alice@example.com may contain one.
                         AND instr(substr(scope_key, instr(scope_key, char(10)) + 1), '@') = 0
                 )
                 UPDATE channels
                 SET scope_key = scope_key || '@' || (
                     SELECT entry_origin FROM bound WHERE bound.channel_id = channels.channel_id
                 )
                 WHERE channel_id IN (
                     SELECT bound.channel_id FROM bound
                     JOIN channels AS row ON row.channel_id = bound.channel_id
                     WHERE bound.entry_origin IS NOT NULL
                         AND typeof(bound.entry_origin) = 'text'
                         AND bound.entry_origin <> row.origin
                         AND NOT EXISTS (
                             SELECT 1 FROM channels AS taken
                             WHERE taken.scope_key = row.scope_key || '@' || bound.entry_origin
                         )
                 );",
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

    const ORIGIN: &str = "https://api.example.test";
    const OTHER: &str = "https://other.example";

    fn view(inner: &Arc<dyn ChannelStore>, origin: Option<&str>) -> OriginBoundChannelStore {
        OriginBoundChannelStore::new(
            inner.clone(),
            Arc::new(Mutex::new(origin.map(str::to_owned))),
        )
    }

    fn other_channel(byte: u8) -> StoredChannelEntry {
        StoredChannelEntry {
            channel_id: B256::repeat_byte(byte),
            ..entry()
        }
    }

    #[cfg(feature = "sqlite")]
    fn sqlite_store(namespace: &str) -> (Arc<dyn ChannelStore>, std::path::PathBuf) {
        let directory = std::env::temp_dir().join(format!("mpp-rs-store-{}", uuid::Uuid::new_v4()));
        let store = SqliteChannelStore::open(SqliteChannelStoreOptions {
            namespace: namespace.into(),
            path: Some(directory.join("channels.db")),
            request_url: None,
        })
        .unwrap();
        (Arc::new(store), directory)
    }

    /// Runs `check` against a memory store and, with `sqlite`, a SQLite
    /// store whose namespace keeps several origins' channels.
    async fn on_every_store<F, Fut>(check: F)
    where
        F: Fn(Arc<dyn ChannelStore>) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        check(Arc::new(MemoryChannelStore::default())).await;
        #[cfg(feature = "sqlite")]
        {
            let (store, directory) = sqlite_store("wallet");
            check(store).await;
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[tokio::test]
    async fn bound_and_unbound_providers_keep_separate_namespaces() {
        on_every_store(|inner| async move {
            let key = entry().key();
            let mine = entry();
            let theirs = other_channel(0x77);
            let unbound = view(&inner, None);
            let bound = view(&inner, Some(ORIGIN));
            unbound.set(&mine).await.unwrap();
            bound.set(&theirs).await.unwrap();
            for _ in 0..2 {
                unbound
                    .set(&StoredChannelEntry {
                        cumulative_amount: mine.cumulative_amount + 1,
                        ..mine.clone()
                    })
                    .await
                    .unwrap();
                bound.set(&theirs).await.unwrap();
            }

            // The unbound provider's channel stays under the scope key without
            // an origin, the bound provider's under its origin's key.
            let stored = unbound.get(&key).await.unwrap().unwrap();
            assert_eq!(
                (
                    stored.channel_id,
                    stored.origin.clone(),
                    stored.cumulative_amount
                ),
                (mine.channel_id, None, mine.cumulative_amount + 1)
            );
            assert_eq!(inner.get(&key).await.unwrap(), Some(stored));
            let stored = bound.get(&key).await.unwrap().unwrap();
            assert_eq!(stored.channel_id, theirs.channel_id);
            assert_eq!(stored.origin.as_deref(), Some(ORIGIN));
            assert_eq!(
                inner.get(&origin_channel_key(&key, ORIGIN)).await.unwrap(),
                Some(stored)
            );
            // Neither deletes the other's channel, and reading never binds.
            unbound.forget(&key, theirs.channel_id).await.unwrap();
            bound.forget(&key, mine.channel_id).await.unwrap();
            assert!(inner.get(&key).await.unwrap().is_some());
            assert!(inner
                .get(&origin_channel_key(&key, ORIGIN))
                .await
                .unwrap()
                .is_some());
            assert!(unbound.namespace().is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn legacy_entry_is_left_to_unbound_providers() {
        on_every_store(|inner| async move {
            let legacy = entry();
            let key = legacy.key();
            inner.set(&legacy).await.unwrap();

            // A bound provider never reads, deletes or overwrites it.
            let bound = view(&inner, Some(ORIGIN));
            assert!(bound.get(&key).await.unwrap().is_none());
            assert!(bound.elsewhere(&key, legacy.channel_id).await.unwrap());
            let opened = other_channel(0x77);
            bound.set(&opened).await.unwrap();
            bound.forget(&key, legacy.channel_id).await.unwrap();
            bound.delete(&key).await.unwrap();
            assert!(bound.get(&key).await.unwrap().is_none());
            assert_eq!(inner.get(&key).await.unwrap(), Some(legacy.clone()));

            // A provider without an origin reuses and closes it.
            let unbound = view(&inner, None);
            assert_eq!(unbound.get(&key).await.unwrap(), Some(legacy.clone()));
            assert!(!unbound.elsewhere(&key, legacy.channel_id).await.unwrap());
            unbound.forget(&key, legacy.channel_id).await.unwrap();
            assert!(inner.get(&key).await.unwrap().is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn providers_bound_to_different_origins_are_isolated() {
        on_every_store(|inner| async move {
            let key = entry().key();
            let first = view(&inner, Some(ORIGIN));
            let second = view(&inner, Some(OTHER));
            first.set(&entry()).await.unwrap();
            second.set(&other_channel(0x77)).await.unwrap();
            assert_eq!(
                first.get(&key).await.unwrap().unwrap().channel_id,
                entry().channel_id
            );
            assert_eq!(
                second.get(&key).await.unwrap().unwrap().channel_id,
                B256::repeat_byte(0x77)
            );
            // A snapshot naming the other origin's channel is not recovered.
            assert!(second.elsewhere(&key, entry().channel_id).await.unwrap());
            assert!(!second
                .elsewhere(&key, B256::repeat_byte(0x77))
                .await
                .unwrap());
            second.forget(&key, entry().channel_id).await.unwrap();
            assert!(first.get(&key).await.unwrap().is_some());
            // Nothing reaches the namespace without an origin.
            assert!(inner.get(&key).await.unwrap().is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn binding_leaves_earlier_channels_in_the_originless_namespace() {
        on_every_store(|inner| async move {
            let key = entry().key();
            let origin = Arc::new(Mutex::new(None));
            let provider = OriginBoundChannelStore::new(inner.clone(), origin.clone());
            provider.set(&entry()).await.unwrap();
            let opened = other_channel(0x55);
            provider.claim(opened.channel_id).unwrap();

            *origin.lock().unwrap() = Some(ORIGIN.into());
            // The bound namespace starts empty; the earlier channels are
            // refused rather than carried into it, and never deleted.
            assert!(provider.get(&key).await.unwrap().is_none());
            assert!(provider.check(entry().channel_id).is_err());
            assert!(provider.check(opened.channel_id).is_err());
            assert!(provider.set(&entry()).await.is_err());
            assert!(provider.set(&opened).await.is_err());
            assert!(provider.elsewhere(&key, entry().channel_id).await.unwrap());
            provider.forget(&key, entry().channel_id).await.unwrap();
            assert!(inner
                .get(&origin_channel_key(&key, ORIGIN))
                .await
                .unwrap()
                .is_none());
            let stored = inner.get(&key).await.unwrap().unwrap();
            assert_eq!(
                (stored.channel_id, stored.origin),
                (entry().channel_id, None)
            );

            // A new channel goes to the origin's namespace, and a provider
            // without an origin still finds the earlier one to close it.
            let fresh = other_channel(0x77);
            provider.set(&fresh).await.unwrap();
            assert_eq!(
                provider.get(&key).await.unwrap().unwrap().channel_id,
                fresh.channel_id
            );
            assert_eq!(
                view(&inner, None)
                    .get(&key)
                    .await
                    .unwrap()
                    .unwrap()
                    .channel_id,
                entry().channel_id
            );
        })
        .await;
    }

    #[tokio::test]
    async fn unbound_provider_refuses_an_entry_bound_under_the_scope_key() {
        // An earlier release kept a bound provider's channel under the scope
        // key. A provider without an origin neither reuses nor overwrites it.
        let inner: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::default());
        let earlier = StoredChannelEntry {
            origin: Some(ORIGIN.into()),
            ..entry()
        };
        inner.set(&earlier).await.unwrap();
        let unbound = view(&inner, None);
        let key = earlier.key();
        assert!(unbound
            .get(&key)
            .await
            .unwrap_err()
            .to_string()
            .contains("origin mismatch"));
        assert!(unbound.set(&other_channel(0x77)).await.is_err());
        unbound.forget(&key, earlier.channel_id).await.unwrap();
        unbound.delete(&key).await.unwrap();
        assert_eq!(inner.get(&key).await.unwrap(), Some(earlier));
    }

    #[tokio::test]
    async fn unbound_provider_never_recovers_another_origins_channel() {
        let inner: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::default());
        let bound = view(&inner, Some(ORIGIN));
        bound.set(&entry()).await.unwrap();
        let unbound = view(&inner, None);
        let key = entry().key();
        assert!(unbound.get(&key).await.unwrap().is_none());
        assert!(unbound.elsewhere(&key, entry().channel_id).await.unwrap());
        assert!(!unbound
            .elsewhere(&key, B256::repeat_byte(0x77))
            .await
            .unwrap());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn origin_namespaced_sqlite_store_binds_its_providers() {
        let (store, directory) = sqlite_store("https://api.example.com");
        assert_eq!(store.origin().as_deref(), Some("https://api.example.com"));
        let first = view(&store, None);
        assert_eq!(
            first.namespace().as_deref(),
            Some("https://api.example.com")
        );
        first.set(&entry()).await.unwrap();
        // The store is the origin's namespace: its channels stay under their
        // payment-scope key, and another provider of the service reuses them.
        let key = entry().key();
        assert_eq!(
            store.get(&key).await.unwrap().unwrap().origin.as_deref(),
            Some("https://api.example.com")
        );
        let second = view(&store, None);
        assert_eq!(
            second.get(&key).await.unwrap().unwrap().channel_id,
            entry().channel_id
        );
        let replacement = other_channel(0x77);
        second.set(&replacement).await.unwrap();
        assert_eq!(
            store.get(&key).await.unwrap().unwrap().channel_id,
            replacement.channel_id
        );
        // A provider pinned to another origin sees none of them and cannot
        // write there.
        let foreign = view(&store, Some("https://evil.example"));
        assert!(foreign.get(&key).await.unwrap().is_none());
        assert!(foreign.set(&other_channel(0x78)).await.is_err());
        drop((first, second, foreign, store));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_moves_channels_bound_under_the_scope_key_into_their_namespace() {
        let directory = std::env::temp_dir().join(format!("mpp-rs-store-{}", uuid::Uuid::new_v4()));
        let path = directory.join("channels.db");
        let open = |namespace: &str| {
            SqliteChannelStore::open(SqliteChannelStoreOptions {
                namespace: namespace.into(),
                path: Some(path.clone()),
                request_url: None,
            })
            .unwrap()
        };
        // An earlier release kept a bound channel under its scope key, in a
        // namespace that keeps several origins' channels, next to a legacy
        // channel without an origin and a channel of an origin's own store.
        let bound = StoredChannelEntry {
            origin: Some(ORIGIN.into()),
            ..entry()
        };
        let legacy = StoredChannelEntry {
            descriptor: ChannelDescriptor {
                payee: "0x0000000000000000000000000000000000000009".into(),
                ..entry().descriptor
            },
            ..other_channel(0x77)
        };
        let service = StoredChannelEntry {
            origin: Some(ORIGIN.into()),
            ..other_channel(0x78)
        };
        open("wallet").set(&bound).await.unwrap();
        open("wallet").set(&legacy).await.unwrap();
        open(ORIGIN).set(&service).await.unwrap();

        let wallet: Arc<dyn ChannelStore> = Arc::new(open("wallet"));
        let key = bound.key();
        assert!(wallet.get(&key).await.unwrap().is_none());
        assert_eq!(
            wallet.get(&origin_channel_key(&key, ORIGIN)).await.unwrap(),
            Some(bound.clone())
        );
        assert_eq!(
            view(&wallet, Some(ORIGIN)).get(&key).await.unwrap(),
            Some(bound)
        );
        assert_eq!(
            view(&wallet, None).get(&legacy.key()).await.unwrap(),
            Some(legacy)
        );
        let origin_store: Arc<dyn ChannelStore> = Arc::new(open(ORIGIN));
        assert_eq!(
            view(&origin_store, None).get(&service.key()).await.unwrap(),
            Some(service)
        );
        drop((wallet, origin_store));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_moves_bound_channels_of_a_namespace_containing_an_at_sign() {
        let directory = std::env::temp_dir().join(format!("mpp-rs-store-{}", uuid::Uuid::new_v4()));
        let path = directory.join("channels.db");
        let open = || {
            SqliteChannelStore::open(SqliteChannelStoreOptions {
                namespace: "alice@example.com".into(),
                path: Some(path.clone()),
                request_url: None,
            })
            .unwrap()
        };
        let bound = StoredChannelEntry {
            origin: Some(ORIGIN.into()),
            ..entry()
        };
        open().set(&bound).await.unwrap();

        let store: Arc<dyn ChannelStore> = Arc::new(open());
        let key = bound.key();
        assert!(store.get(&key).await.unwrap().is_none());
        assert_eq!(
            view(&store, Some(ORIGIN)).get(&key).await.unwrap(),
            Some(bound)
        );
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn providers_choose_the_key_they_write_under() {
        let inner: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::default());
        let bound = view(&inner, Some(ORIGIN));
        assert!(bound.set_at("elsewhere", &entry()).await.is_err());
        assert!(bound
            .set(&StoredChannelEntry {
                origin: Some(OTHER.into()),
                ..entry()
            })
            .await
            .is_err());
        assert!(view(&inner, None)
            .set(&StoredChannelEntry {
                origin: Some(ORIGIN.into()),
                ..entry()
            })
            .await
            .is_err());
        assert!(inner.get(&entry().key()).await.unwrap().is_none());
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
