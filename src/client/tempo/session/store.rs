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
    /// persisted it. Absent on legacy entries and on channels paid over a
    /// transport without an HTTP origin; a provider bound to an HTTP origin
    /// neither reuses nor takes over such an entry.
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

fn no_free_slot(key: &str) -> ChannelStoreError {
    ChannelStoreError::InvalidEntry(format!(
        "no free channel slot for payment scope {key}: its keys hold channels other providers own"
    ))
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
    /// Session providers sharing a store use it to keep a channel under
    /// [`origin_channel_key`] when the payment-scope key holds another
    /// provider's channel, so neither overwrites the other. `get` and `delete`
    /// must then find and remove the entry under `key`, and a store that
    /// refuses a channel already kept under another key keeps it unchanged.
    async fn set_at(&self, key: &str, entry: &StoredChannelEntry) -> ChannelStoreResult<()>;
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

    async fn delete(&self, key: &str) -> ChannelStoreResult<()> {
        self.entries.lock().unwrap().remove(key);
        Ok(())
    }
}

/// Key under which a session provider keeps its channel for payment scope
/// `key` when the scope's own entry belongs to another provider sharing the
/// store: `"{key}@{origin}"` for a provider bound to an HTTP origin, such as
/// `"0xpayee:0xtoken:0xescrow:4217@https://api.example.com"`, and
/// `"{key}@none"` for a provider without one.
///
/// The entry under `key` itself is never overwritten in that case. A
/// channel stored without an origin, such as one written before origins
/// existed, therefore stays under `key`, where [`ChannelStore::get`] finds
/// it and a provider without an HTTP origin (one that pays through a bare
/// `pay` or a non-HTTP MCP resource) still reuses and closes it.
pub fn origin_channel_key(key: &str, origin: Option<&str>) -> String {
    format!("{key}@{}", origin.unwrap_or("none"))
}

/// A session provider's view of its channel store, bound to the provider's
/// HTTP origin once it has one: entries it writes carry that origin, and an
/// entry bound to another origin is refused rather than reused or rebound, as
/// mppx does.
///
/// A provider owns a stored channel bound to its own origin, or, while it has
/// none, a channel stored without an origin. It never reuses, rebinds,
/// overwrites or deletes any other entry, and reading one never binds it:
///
/// - A bound provider leaves a channel stored without an origin (a legacy
///   entry, or one an unbound provider paying the same payee keeps) in place
///   and keeps the channel it opens under [`origin_channel_key`]. When the
///   channel it writes is that same channel, such as one recovered from a
///   server snapshot, it updates the entry in place instead of copying it,
///   except under `origin_channel_key(key, None)`, where an unbound provider
///   keeps its live channel: that write is refused rather than rebinding it.
/// - An unbound provider treats a channel bound to an origin as absent and
///   keeps its own under `origin_channel_key(key, None)`, so it never signs
///   for, or names, another origin's channel.
///
/// Each channel stays under the key it was first read from or written to for
/// as long as the provider holds it, even after the provider is bound, and is
/// only deleted there, while that key still holds the same channel. A channel
/// another provider has since bound to its origin, such as an unbound
/// provider's channel under the scope key that a bound provider recovered,
/// is no longer this provider's and reads as absent.
pub(crate) struct OriginBoundChannelStore {
    inner: Arc<dyn ChannelStore>,
    origin: Arc<Mutex<Option<String>>>,
    /// The key and channel this provider holds for each payment scope.
    slots: Mutex<HashMap<String, Slot>>,
}

/// Where a provider keeps its channel for one payment scope.
#[derive(Clone)]
struct Slot {
    key: String,
    channel_id: B256,
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
            slots: Mutex::default(),
        }
    }

    fn bound(&self) -> Option<String> {
        self.origin.lock().unwrap().clone()
    }

    /// Whether a provider bound to `bound` owns `stored` without having
    /// read or written it before.
    fn owns(bound: Option<&str>, stored: &StoredChannelEntry) -> bool {
        stored.origin.as_deref() == bound
    }

    /// Whether `stored`, the channel this provider holds, may still be used
    /// by it: a channel it wrote while unbound carries no origin.
    fn holds(bound: Option<&str>, stored: &StoredChannelEntry) -> bool {
        stored.origin.is_none() || stored.origin.as_deref() == bound
    }

    fn record(&self, key: &str, slot: &str, channel_id: B256) {
        self.slots.lock().unwrap().insert(
            key.to_owned(),
            Slot {
                key: slot.to_owned(),
                channel_id,
            },
        );
    }

    /// The keys where a provider bound to `bound` may keep its channel for
    /// `key`, most preferred first.
    fn candidates(key: &str, bound: Option<&str>) -> Vec<String> {
        let mut candidates = vec![origin_channel_key(key, bound), key.to_owned()];
        if bound.is_some() {
            // Where the provider kept a channel opened before it was bound.
            candidates.push(origin_channel_key(key, None));
        }
        candidates
    }

    /// The channel this provider holds for `key`, read from the key it was
    /// recorded under. A record whose key no longer holds that channel, or
    /// holds it for another origin, is dropped: the provider no longer owns
    /// it, so it reads as absent rather than failing every later payment.
    async fn held(
        &self,
        key: &str,
        bound: Option<&str>,
    ) -> ChannelStoreResult<Option<(String, StoredChannelEntry)>> {
        let Some(slot) = self.slots.lock().unwrap().get(key).cloned() else {
            return Ok(None);
        };
        match self.inner.get(&slot.key).await? {
            Some(stored) if stored.channel_id == slot.channel_id && Self::holds(bound, &stored) => {
                Ok(Some((slot.key, stored)))
            }
            _ => {
                self.slots.lock().unwrap().remove(key);
                Ok(None)
            }
        }
    }

    /// Find the channel this provider owns for `key` and the key it is
    /// stored under, recording it. Another provider's entry reads as absent,
    /// except that a bound provider refuses a scope entry bound to another
    /// origin, as mppx does.
    async fn locate(
        &self,
        key: &str,
        bound: Option<&str>,
    ) -> ChannelStoreResult<Option<(String, StoredChannelEntry)>> {
        if let Some(held) = self.held(key, bound).await? {
            return Ok(Some(held));
        }
        let mut foreign = false;
        for candidate in Self::candidates(key, bound) {
            match self.inner.get(&candidate).await? {
                Some(stored) if Self::owns(bound, &stored) => {
                    self.record(key, &candidate, stored.channel_id);
                    return Ok(Some((candidate, stored)));
                }
                Some(stored) if candidate == key && bound.is_some() && stored.origin.is_some() => {
                    foreign = true;
                }
                _ => {}
            }
        }
        if foreign {
            return Err(origin_mismatch());
        }
        Ok(None)
    }

    /// Forget channel `channel_id` for payment scope `key`, once the session
    /// manager has confirmed it unfunded: delete it from the key this
    /// provider holds it under, or else the key where it finds that same
    /// channel. An entry for another channel, such as a legacy entry without
    /// an origin, or one another origin has taken, is never deleted.
    pub(crate) async fn forget(&self, key: &str, channel_id: B256) -> ChannelStoreResult<()> {
        let bound = self.bound();
        let held = self.slots.lock().unwrap().get(key).cloned();
        if held
            .as_ref()
            .is_some_and(|slot| slot.channel_id == channel_id)
        {
            self.slots.lock().unwrap().remove(key);
        }
        let mut candidates = Self::candidates(key, bound.as_deref());
        if let Some(slot) = held {
            candidates.insert(0, slot.key);
        }
        for candidate in candidates {
            if let Some(stored) = self.inner.get(&candidate).await? {
                if stored.channel_id == channel_id && Self::holds(bound.as_deref(), &stored) {
                    return self.inner.delete(&candidate).await;
                }
            }
        }
        Ok(())
    }

    /// Check, before a new channel for payment scope `key` is opened and
    /// signed, that this provider has a key to keep it under, so a channel it
    /// could never store is never opened.
    pub(crate) async fn ensure_room(&self, key: &str) -> ChannelStoreResult<()> {
        let bound = self.bound();
        self.slot_for(key, bound.as_deref(), None).await.map(|_| ())
    }

    /// The key this provider writes channel `channel_id` (`None` for a
    /// channel not opened yet) under: the key it holds its channel for `key`
    /// under, else the scope key or its own [`origin_channel_key`] when
    /// already storing that same channel, else the key of an entry it owns,
    /// else the scope key when free, else its own [`origin_channel_key`]
    /// when free. Never a key holding another provider's channel: a bound
    /// provider refuses to write a channel an unbound provider keeps under
    /// `origin_channel_key(key, None)` rather than rebind it there, and a
    /// provider whose keys all hold channels it neither holds nor owns, such
    /// as an unbound provider's `origin_channel_key(key, None)` holding a
    /// channel another provider has since bound to its origin, refuses the
    /// write rather than overwrite one.
    async fn slot_for(
        &self,
        key: &str,
        bound: Option<&str>,
        channel_id: Option<B256>,
    ) -> ChannelStoreResult<String> {
        if let Some((slot, _)) = self.held(key, bound).await? {
            return Ok(slot);
        }
        let mut stored = Vec::new();
        for candidate in Self::candidates(key, bound) {
            let current = self.inner.get(&candidate).await?;
            if let Some(current) = current
                .as_ref()
                .filter(|current| Some(current.channel_id) == channel_id)
            {
                // The same channel, such as a legacy entry recovered from a
                // server snapshot: update it in place rather than copy it,
                // unless an unbound provider keeps it under its own key.
                let unbound_slot = bound.is_some()
                    && candidate == origin_channel_key(key, None)
                    && !Self::owns(bound, current);
                if unbound_slot || !Self::holds(bound, current) {
                    return Err(origin_mismatch());
                }
                return Ok(candidate);
            }
            stored.push((candidate, current));
        }
        for (candidate, current) in &stored {
            match current {
                Some(current) if Self::owns(bound, current) => return Ok(candidate.clone()),
                Some(current)
                    if candidate == key && bound.is_some() && current.origin.is_some() =>
                {
                    return Err(origin_mismatch());
                }
                _ => {}
            }
        }
        let own = origin_channel_key(key, bound);
        let free = |slot: &str| {
            stored
                .iter()
                .any(|(candidate, current)| candidate == slot && current.is_none())
        };
        if free(key) {
            return Ok(key.to_owned());
        }
        if free(&own) {
            return Ok(own);
        }
        Err(no_free_slot(key))
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

    async fn get(&self, key: &str) -> ChannelStoreResult<Option<StoredChannelEntry>> {
        let bound = self.bound();
        Ok(self
            .locate(key, bound.as_deref())
            .await?
            .map(|(_, stored)| stored))
    }

    async fn set(&self, entry: &StoredChannelEntry) -> ChannelStoreResult<()> {
        let bound = self.bound();
        let mut entry = entry.clone();
        match &bound {
            Some(bound) if entry.origin.as_ref().is_some_and(|origin| origin != bound) => {
                return Err(origin_mismatch());
            }
            Some(bound) => entry.origin = Some(bound.clone()),
            // An unbound provider never writes another origin's channel.
            None if entry.origin.is_some() => return Err(origin_mismatch()),
            None => {}
        }
        let key = entry.key();
        let slot = self
            .slot_for(&key, bound.as_deref(), Some(entry.channel_id))
            .await?;
        if slot == key {
            self.inner.set(&entry).await?;
        } else {
            self.inner.set_at(&slot, &entry).await?;
        }
        self.record(&key, &slot, entry.channel_id);
        Ok(())
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

    /// Forget this provider's channel for `key`, once the session manager has
    /// confirmed it unfunded: only under the key this provider holds it, and
    /// only while that key still stores the same channel. Another provider's
    /// channel, such as a legacy entry without an origin, is never deleted.
    async fn delete(&self, key: &str) -> ChannelStoreResult<()> {
        let bound = self.bound();
        // A channel another origin has since taken is not this provider's.
        let held = self.held(key, bound.as_deref()).await.unwrap_or(None);
        self.slots.lock().unwrap().remove(key);
        match held {
            Some((slot, _)) => self.inner.delete(&slot).await,
            None => Ok(()),
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

    fn view(inner: &Arc<dyn ChannelStore>, origin: Option<&str>) -> OriginBoundChannelStore {
        OriginBoundChannelStore::new(
            inner.clone(),
            Arc::new(Mutex::new(origin.map(str::to_owned))),
        )
    }

    async fn bound_provider_keeps_legacy_channel_recoverable(inner: Arc<dyn ChannelStore>) {
        let legacy = entry();
        let key = legacy.key();
        inner.set(&legacy).await.unwrap();
        let bound = view(&inner, Some(ORIGIN));
        // Never reused: the legacy entry reads as absent.
        assert!(bound.get(&key).await.unwrap().is_none());

        // The new channel goes under the provider's own key; the legacy one
        // stays under the scope key.
        let opened = StoredChannelEntry {
            channel_id: B256::repeat_byte(0x77),
            ..entry()
        };
        bound.set(&opened).await.unwrap();
        let own = origin_channel_key(&key, Some(ORIGIN));
        assert_eq!(own, format!("{key}@{ORIGIN}"));
        let stored = inner.get(&key).await.unwrap().unwrap();
        assert_eq!(
            (stored.channel_id, stored.origin),
            (legacy.channel_id, None)
        );
        let kept = bound.get(&key).await.unwrap().unwrap();
        assert_eq!(kept.channel_id, opened.channel_id);
        assert_eq!(kept.origin.as_deref(), Some(ORIGIN));
        assert_eq!(inner.get(&own).await.unwrap(), Some(kept));

        // A provider without an origin still finds the legacy channel to
        // close it, and the bound provider deleting its own leaves it.
        let unbound = view(&inner, None);
        assert_eq!(
            unbound.get(&key).await.unwrap().unwrap().channel_id,
            legacy.channel_id
        );
        bound.delete(&key).await.unwrap();
        assert!(inner.get(&own).await.unwrap().is_none());
        assert!(bound.get(&key).await.unwrap().is_none());
        assert_eq!(
            inner.get(&key).await.unwrap().unwrap().channel_id,
            legacy.channel_id
        );
        // Nor does deleting for a provider bound to another origin remove a
        // channel bound to this one.
        let opened = StoredChannelEntry {
            origin: Some(ORIGIN.into()),
            ..opened
        };
        inner.delete(&key).await.unwrap();
        inner.set(&opened).await.unwrap();
        view(&inner, Some("https://other.example"))
            .delete(&key)
            .await
            .unwrap();
        assert_eq!(inner.get(&key).await.unwrap(), Some(opened));
    }

    #[tokio::test]
    async fn bound_provider_never_overwrites_a_legacy_channel() {
        bound_provider_keeps_legacy_channel_recoverable(Arc::new(MemoryChannelStore::default()))
            .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bound_provider_never_overwrites_a_legacy_sqlite_channel() {
        let directory = std::env::temp_dir().join(format!("mpp-rs-store-{}", uuid::Uuid::new_v4()));
        let store = SqliteChannelStore::open(SqliteChannelStoreOptions {
            namespace: "wallet".into(),
            path: Some(directory.join("channels.db")),
            request_url: None,
        })
        .unwrap();
        bound_provider_keeps_legacy_channel_recoverable(Arc::new(store)).await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn bound_and_unbound_providers_never_overwrite_each_other() {
        let first = entry();
        let second = StoredChannelEntry {
            channel_id: B256::repeat_byte(0x77),
            ..entry()
        };
        let key = first.key();
        for unbound_first in [true, false] {
            let inner: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::default());
            let bound = view(&inner, Some(ORIGIN));
            let unbound = view(&inner, None);
            let (mine, theirs) = if unbound_first {
                unbound.set(&first).await.unwrap();
                bound.set(&second).await.unwrap();
                (first.clone(), second.clone())
            } else {
                bound.set(&second).await.unwrap();
                unbound.set(&first).await.unwrap();
                (first.clone(), second.clone())
            };
            // Each provider keeps its own channel and both records survive
            // later writes.
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
            let unbound_entry = unbound.get(&key).await.unwrap().unwrap();
            assert_eq!(unbound_entry.channel_id, mine.channel_id);
            assert_eq!(unbound_entry.origin, None);
            assert_eq!(unbound_entry.cumulative_amount, mine.cumulative_amount + 1);
            let bound_entry = bound.get(&key).await.unwrap().unwrap();
            assert_eq!(bound_entry.channel_id, theirs.channel_id);
            assert_eq!(bound_entry.origin.as_deref(), Some(ORIGIN));
            // Reading and writing never binds the unbound provider.
            assert!(unbound.origin.lock().unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn unbound_provider_never_reuses_a_bound_channel() {
        let inner: Arc<dyn ChannelStore> = Arc::new(MemoryChannelStore::default());
        let bound = view(&inner, Some(ORIGIN));
        bound.set(&entry()).await.unwrap();
        let key = entry().key();
        let unbound = view(&inner, None);
        // The bound channel reads as absent, so the provider neither signs
        // for it nor names it to another origin, and is not bound by it.
        assert!(unbound.get(&key).await.unwrap().is_none());
        assert!(unbound.origin.lock().unwrap().is_none());
        // Writing that channel is refused; the provider's own channel goes
        // under its own key and leaves the bound one in place.
        let error = unbound
            .set(&StoredChannelEntry {
                origin: Some(ORIGIN.into()),
                ..entry()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("origin mismatch"));
        let opened = StoredChannelEntry {
            channel_id: B256::repeat_byte(0x77),
            ..entry()
        };
        unbound.set(&opened).await.unwrap();
        assert_eq!(
            inner.get(&origin_channel_key(&key, None)).await.unwrap(),
            Some(opened.clone())
        );
        assert_eq!(unbound.get(&key).await.unwrap(), Some(opened));
        let stored = inner.get(&key).await.unwrap().unwrap();
        assert_eq!(
            (stored.channel_id, stored.origin.as_deref()),
            (entry().channel_id, Some(ORIGIN))
        );
        assert!(unbound.origin.lock().unwrap().is_none());
    }

    fn other_channel(byte: u8) -> StoredChannelEntry {
        StoredChannelEntry {
            channel_id: B256::repeat_byte(byte),
            ..entry()
        }
    }

    /// Two providers bound to one origin forget the channel they shared; the
    /// legacy channel under the scope key survives both deletes.
    async fn forgetting_twice_keeps_the_legacy_channel(inner: Arc<dyn ChannelStore>) {
        let legacy = entry();
        let key = legacy.key();
        inner.set(&legacy).await.unwrap();
        let first = view(&inner, Some(ORIGIN));
        let second = view(&inner, Some(ORIGIN));
        let opened = other_channel(0x77);
        first.set(&opened).await.unwrap();
        assert_eq!(
            second.get(&key).await.unwrap().unwrap().channel_id,
            opened.channel_id
        );
        first.forget(&key, opened.channel_id).await.unwrap();
        second.forget(&key, opened.channel_id).await.unwrap();
        second.delete(&key).await.unwrap();
        // Forgetting the legacy channel's id from a bound provider that never
        // held it only removes it once a provider owns it: here none does.
        view(&inner, Some(ORIGIN))
            .forget(&key, other_channel(0x78).channel_id)
            .await
            .unwrap();
        let stored = inner.get(&key).await.unwrap().unwrap();
        assert_eq!(
            (stored.channel_id, stored.origin),
            (legacy.channel_id, None)
        );
        assert!(inner
            .get(&origin_channel_key(&key, Some(ORIGIN)))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn forgetting_a_shared_channel_twice_keeps_the_legacy_channel() {
        forgetting_twice_keeps_the_legacy_channel(Arc::new(MemoryChannelStore::default())).await;
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

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn forgetting_a_shared_sqlite_channel_twice_keeps_the_legacy_channel() {
        let (store, directory) = sqlite_store("wallet");
        forgetting_twice_keeps_the_legacy_channel(store).await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// A provider that kept its channel under its own key while unbound keeps
    /// it there once bound, and never writes over the bound channel under the
    /// scope key.
    async fn binding_never_moves_a_channel(inner: Arc<dyn ChannelStore>) {
        let theirs = entry();
        let key = theirs.key();
        view(&inner, Some(ORIGIN)).set(&theirs).await.unwrap();
        let provider = view(&inner, None);
        let mine = other_channel(0x77);
        provider.set(&mine).await.unwrap();
        let own = origin_channel_key(&key, None);
        assert_eq!(
            inner.get(&own).await.unwrap().unwrap().channel_id,
            mine.channel_id
        );

        provider.origin.lock().unwrap().replace(ORIGIN.into());
        for cumulative_amount in [1_000_000, 2_000_000] {
            assert_eq!(
                provider.get(&key).await.unwrap().unwrap().channel_id,
                mine.channel_id
            );
            provider
                .set(&StoredChannelEntry {
                    cumulative_amount,
                    ..mine.clone()
                })
                .await
                .unwrap();
        }
        let kept = inner.get(&own).await.unwrap().unwrap();
        assert_eq!(
            (
                kept.channel_id,
                kept.cumulative_amount,
                kept.origin.as_deref()
            ),
            (mine.channel_id, 2_000_000, Some(ORIGIN))
        );
        let stored = inner.get(&key).await.unwrap().unwrap();
        assert_eq!(stored.channel_id, theirs.channel_id);
        assert_eq!(stored.cumulative_amount, theirs.cumulative_amount);
        // A fresh provider bound to that origin still finds both.
        assert_eq!(
            view(&inner, Some(ORIGIN))
                .get(&key)
                .await
                .unwrap()
                .unwrap()
                .channel_id,
            theirs.channel_id
        );
        provider.forget(&key, mine.channel_id).await.unwrap();
        assert!(inner.get(&own).await.unwrap().is_none());
        assert_eq!(
            inner.get(&key).await.unwrap().unwrap().channel_id,
            theirs.channel_id
        );
    }

    /// An unbound provider whose own key holds a channel another provider
    /// wrote there while unbound and has since bound to its origin, while the
    /// scope key holds a bound channel too, has nowhere to keep a channel: it
    /// refuses to open or write one rather than overwrite either, and the
    /// provider holding that channel still updates it in place.
    async fn unbound_provider_never_overwrites_a_since_bound_channel(inner: Arc<dyn ChannelStore>) {
        let theirs = entry();
        let key = theirs.key();
        let own = origin_channel_key(&key, None);
        view(&inner, Some(ORIGIN)).set(&theirs).await.unwrap();
        let provider = view(&inner, None);
        let mine = other_channel(0x77);
        provider.set(&mine).await.unwrap();
        provider.origin.lock().unwrap().replace(ORIGIN.into());
        provider
            .set(&StoredChannelEntry {
                cumulative_amount: 3_000_000,
                ..mine.clone()
            })
            .await
            .unwrap();

        let unbound = view(&inner, None);
        assert!(unbound.get(&key).await.unwrap().is_none());
        let error = unbound.ensure_room(&key).await.unwrap_err();
        assert!(error.to_string().contains("no free channel slot"));
        let opened = other_channel(0x78);
        let error = unbound.set(&opened).await.unwrap_err();
        assert!(error.to_string().contains("no free channel slot"));
        // Neither channel was overwritten, and the refused one is not held.
        let kept = inner.get(&own).await.unwrap().unwrap();
        assert_eq!(
            (
                kept.channel_id,
                kept.cumulative_amount,
                kept.origin.as_deref()
            ),
            (mine.channel_id, 3_000_000, Some(ORIGIN))
        );
        let stored = inner.get(&key).await.unwrap().unwrap();
        assert_eq!(
            (stored.channel_id, stored.origin.as_deref()),
            (theirs.channel_id, Some(ORIGIN))
        );
        assert!(unbound.get(&key).await.unwrap().is_none());
        assert!(unbound.origin.lock().unwrap().is_none());

        // The provider holding the channel still updates it in place.
        provider
            .set(&StoredChannelEntry {
                cumulative_amount: 4_000_000,
                ..mine.clone()
            })
            .await
            .unwrap();
        let kept = inner.get(&own).await.unwrap().unwrap();
        assert_eq!(
            (kept.channel_id, kept.cumulative_amount),
            (mine.channel_id, 4_000_000)
        );

        // Once that channel is forgotten, the unbound provider has room again.
        provider.forget(&key, mine.channel_id).await.unwrap();
        unbound.ensure_room(&key).await.unwrap();
        unbound.set(&opened).await.unwrap();
        assert_eq!(inner.get(&own).await.unwrap(), Some(opened.clone()));
        assert_eq!(unbound.get(&key).await.unwrap(), Some(opened));
    }

    #[tokio::test]
    async fn unbound_provider_never_overwrites_a_since_bound_memory_channel() {
        unbound_provider_never_overwrites_a_since_bound_channel(Arc::new(
            MemoryChannelStore::default(),
        ))
        .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn unbound_provider_never_overwrites_a_since_bound_sqlite_channel() {
        let (store, directory) = sqlite_store("wallet");
        unbound_provider_never_overwrites_a_since_bound_channel(store).await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn binding_never_moves_a_memory_channel() {
        binding_never_moves_a_channel(Arc::new(MemoryChannelStore::default())).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn binding_never_moves_a_sqlite_channel() {
        let (store, directory) = sqlite_store("wallet");
        binding_never_moves_a_channel(store).await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn origin_namespaced_sqlite_store_binds_its_providers() {
        let (store, directory) = sqlite_store("https://api.example.com");
        assert_eq!(store.origin().as_deref(), Some("https://api.example.com"));
        let first = view(&store, None);
        assert_eq!(first.bound().as_deref(), Some("https://api.example.com"));
        first.set(&entry()).await.unwrap();
        // Another provider of the same service reuses the channel, and its
        // own channel replaces it under the same key without a mismatch.
        let second = view(&store, None);
        let key = entry().key();
        assert_eq!(
            second.get(&key).await.unwrap().unwrap().channel_id,
            entry().channel_id
        );
        let replacement = other_channel(0x77);
        second.set(&replacement).await.unwrap();
        second
            .set(&StoredChannelEntry {
                cumulative_amount: 3_000_000,
                ..replacement.clone()
            })
            .await
            .unwrap();
        let stored = store.get(&key).await.unwrap().unwrap();
        assert_eq!(
            (stored.channel_id, stored.cumulative_amount),
            (replacement.channel_id, 3_000_000)
        );
        // A provider pinned to another origin is refused, not rebound.
        let foreign = view(&store, Some("https://evil.example"));
        assert_eq!(foreign.bound().as_deref(), Some("https://evil.example"));
        assert!(foreign.get(&key).await.is_err());
        assert!(foreign.set(&other_channel(0x78)).await.is_err());
        drop((first, second, foreign, store));
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// A bound provider that writes the legacy entry's own channel, such as
    /// one recovered from a server snapshot, updates it in place.
    async fn legacy_channel_is_recovered_in_place(inner: Arc<dyn ChannelStore>) {
        let legacy = entry();
        let key = legacy.key();
        inner.set(&legacy).await.unwrap();
        let bound = view(&inner, Some(ORIGIN));
        assert!(bound.get(&key).await.unwrap().is_none());
        bound
            .set(&StoredChannelEntry {
                cumulative_amount: 3_000_000,
                ..legacy.clone()
            })
            .await
            .unwrap();
        let stored = inner.get(&key).await.unwrap().unwrap();
        assert_eq!(
            (
                stored.channel_id,
                stored.cumulative_amount,
                stored.origin.as_deref()
            ),
            (legacy.channel_id, 3_000_000, Some(ORIGIN))
        );
        assert!(inner
            .get(&origin_channel_key(&key, Some(ORIGIN)))
            .await
            .unwrap()
            .is_none());
        assert_eq!(bound.get(&key).await.unwrap(), Some(stored));
    }

    #[tokio::test]
    async fn legacy_memory_channel_is_recovered_in_place() {
        legacy_channel_is_recovered_in_place(Arc::new(MemoryChannelStore::default())).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn legacy_sqlite_channel_is_recovered_in_place() {
        let (store, directory) = sqlite_store("wallet");
        legacy_channel_is_recovered_in_place(store).await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// A bound provider recovering the channel an unbound provider keeps
    /// under `origin_channel_key(key, None)` never rebinds it there, so the
    /// unbound provider keeps paying with it.
    async fn bound_provider_never_rebinds_an_unbound_channel(inner: Arc<dyn ChannelStore>) {
        let theirs = entry();
        let key = theirs.key();
        view(&inner, Some(ORIGIN)).set(&theirs).await.unwrap();
        let unbound = view(&inner, None);
        let mine = other_channel(0x77);
        unbound.set(&mine).await.unwrap();
        let own = origin_channel_key(&key, None);
        assert_eq!(inner.get(&own).await.unwrap(), Some(mine.clone()));

        let recovering = view(&inner, Some(ORIGIN));
        let error = recovering
            .set(&StoredChannelEntry {
                cumulative_amount: 3_000_000,
                ..mine.clone()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("origin mismatch"));
        assert_eq!(inner.get(&own).await.unwrap(), Some(mine.clone()));
        assert!(inner
            .get(&origin_channel_key(&key, Some(ORIGIN)))
            .await
            .unwrap()
            .is_none());

        for cumulative_amount in [3_000_000, 4_000_000] {
            assert_eq!(
                unbound.get(&key).await.unwrap().unwrap().channel_id,
                mine.channel_id
            );
            unbound
                .set(&StoredChannelEntry {
                    cumulative_amount,
                    ..mine.clone()
                })
                .await
                .unwrap();
        }
        let kept = inner.get(&own).await.unwrap().unwrap();
        assert_eq!(
            (kept.channel_id, kept.cumulative_amount, kept.origin),
            (mine.channel_id, 4_000_000, None)
        );
        let stored = inner.get(&key).await.unwrap().unwrap();
        assert_eq!(stored.channel_id, theirs.channel_id);
    }

    #[tokio::test]
    async fn bound_provider_never_rebinds_an_unbound_memory_channel() {
        bound_provider_never_rebinds_an_unbound_channel(Arc::new(MemoryChannelStore::default()))
            .await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn bound_provider_never_rebinds_an_unbound_sqlite_channel() {
        let (store, directory) = sqlite_store("wallet");
        bound_provider_never_rebinds_an_unbound_channel(store).await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// An unbound provider whose channel under the scope key a bound provider
    /// has since recovered reads it as absent and opens its own, rather than
    /// failing every payment with an origin mismatch.
    async fn rebound_channel_reads_as_absent(inner: Arc<dyn ChannelStore>) {
        let shared = entry();
        let key = shared.key();
        let unbound = view(&inner, None);
        unbound.set(&shared).await.unwrap();
        assert_eq!(unbound.get(&key).await.unwrap(), Some(shared.clone()));

        view(&inner, Some(ORIGIN))
            .set(&StoredChannelEntry {
                cumulative_amount: 3_000_000,
                ..shared.clone()
            })
            .await
            .unwrap();
        assert_eq!(
            inner.get(&key).await.unwrap().unwrap().origin.as_deref(),
            Some(ORIGIN)
        );

        assert!(unbound.get(&key).await.unwrap().is_none());
        // Deleting reads the same: the bound channel is not this provider's.
        unbound.delete(&key).await.unwrap();
        assert_eq!(
            inner.get(&key).await.unwrap().unwrap().channel_id,
            shared.channel_id
        );
        let opened = other_channel(0x78);
        unbound.set(&opened).await.unwrap();
        assert_eq!(unbound.get(&key).await.unwrap(), Some(opened.clone()));
        assert_eq!(
            inner.get(&origin_channel_key(&key, None)).await.unwrap(),
            Some(opened)
        );
        let stored = inner.get(&key).await.unwrap().unwrap();
        assert_eq!(
            (stored.channel_id, stored.origin.as_deref()),
            (shared.channel_id, Some(ORIGIN))
        );
        assert!(unbound.origin.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn rebound_memory_channel_reads_as_absent() {
        rebound_channel_reads_as_absent(Arc::new(MemoryChannelStore::default())).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn rebound_sqlite_channel_reads_as_absent() {
        let (store, directory) = sqlite_store("wallet");
        rebound_channel_reads_as_absent(store).await;
        std::fs::remove_dir_all(directory).unwrap();
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
