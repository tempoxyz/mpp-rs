//! Channel state and its persistence.

use std::future::Future;
use std::sync::Arc;

use alloy::primitives::Address;

use crate::protocol::traits::VerificationError;

/// State for an on-chain payment channel, including per-session accounting.
///
/// Tracks the channel's identity, on-chain balance, the highest voucher
/// the server has accepted, and the current session's spend counters.
///
/// Mirrors the TypeScript `ChannelStore.State` interface.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChannelState {
    pub channel_id: String,
    pub chain_id: u64,
    pub escrow_contract: Address,
    pub payer: Address,
    pub payee: Address,
    pub token: Address,
    /// Immutable machine-token settlement route accepted at open.
    #[serde(default)]
    pub settlement_route: Option<crate::protocol::methods::tempo::session::SettlementRoute>,
    pub authorized_signer: Address,
    pub deposit: u128,
    pub settled_on_chain: u128,
    pub highest_voucher_amount: u128,
    /// Serialized signature bytes of the highest voucher (hex-encoded).
    pub highest_voucher_signature: Option<Vec<u8>>,
    pub spent: u128,
    pub units: u64,
    pub finalized: bool,
    #[serde(default)]
    pub closing: bool,
    #[serde(default)]
    pub close_requested_at: u64,
    pub created_at: String,
}

/// Trait for channel state persistence.
///
/// Implementations must provide atomic read-modify-write semantics for
/// `update_channel`. The callback receives the current state (or `None`)
/// and returns the next state (or `None` to delete).
///
/// Object-safe so it can be used as `Arc<dyn ChannelStore>`.
///
/// The session method and the SSE/WebSocket helpers lowercase channel IDs
/// before calling the store. Implementations that are also called with
/// client-supplied IDs should key by the lowercase form too.
///
/// # Note
///
/// This is a minimal trait defined inline. It should be consolidated with
/// a shared store abstraction in a future refactor.
pub trait ChannelStore: Send + Sync {
    fn get_channel(
        &self,
        channel_id: &str,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    >;

    #[allow(clippy::type_complexity)]
    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<
            dyn FnOnce(Option<ChannelState>) -> Result<Option<ChannelState>, VerificationError>
                + Send,
        >,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    >;

    /// Wait for the next update to a channel.
    /// Default implementation returns immediately (poll-based fallback).
    fn wait_for_update(
        &self,
        _channel_id: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

/// Normalize a channel ID to the lowercase form that channel state is keyed by.
///
/// Channel IDs are hex strings, so clients may send them in any case.
pub(crate) fn normalize_channel_id(channel_id: &str) -> String {
    channel_id.to_ascii_lowercase()
}

/// Atomically deduct `amount` from a channel's available balance.
///
/// Returns `Ok(state)` on success, `Err` if insufficient balance or channel not found.
pub async fn deduct_from_channel(
    store: &dyn ChannelStore,
    channel_id: &str,
    amount: u128,
) -> Result<ChannelState, VerificationError> {
    let result = store
        .update_channel(
            channel_id,
            Box::new(move |current| {
                let state = current
                    .ok_or_else(|| VerificationError::channel_not_found("channel not found"))?;
                if state.finalized {
                    return Err(VerificationError::channel_closed("channel is finalized"));
                }
                if state.closing {
                    return Err(VerificationError::channel_closed("channel is closing"));
                }
                let available = state.highest_voucher_amount.saturating_sub(state.spent);
                if available >= amount {
                    Ok(Some(ChannelState {
                        spent: state.spent + amount,
                        units: state.units + 1,
                        ..state
                    }))
                } else {
                    Err(VerificationError::insufficient_balance(format!(
                        "requested {}, available {}",
                        amount, available
                    )))
                }
            }),
        )
        .await?;

    result.ok_or_else(|| VerificationError::channel_not_found("channel not found"))
}

/// In-memory channel store for testing.
///
/// Uses a `Mutex<HashMap>` for thread-safe access.
pub struct InMemoryChannelStore {
    pub(super) channels: std::sync::Mutex<std::collections::HashMap<String, ChannelState>>,
    notifiers: std::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Notify>>>,
}

impl Default for InMemoryChannelStore {
    fn default() -> Self {
        Self {
            channels: std::sync::Mutex::new(std::collections::HashMap::new()),
            notifiers: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl InMemoryChannelStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of a channel (for test assertions).
    pub fn get_channel_sync(&self, channel_id: &str) -> Option<ChannelState> {
        self.channels
            .lock()
            .unwrap()
            .get(&normalize_channel_id(channel_id))
            .cloned()
    }
}

impl InMemoryChannelStore {
    /// Insert a channel directly (for test setup).
    pub fn insert(&self, channel_id: &str, state: ChannelState) {
        self.channels
            .lock()
            .unwrap()
            .insert(normalize_channel_id(channel_id), state);
    }
}

impl ChannelStore for InMemoryChannelStore {
    fn get_channel(
        &self,
        channel_id: &str,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    > {
        let result = self.get_channel_sync(channel_id);
        Box::pin(async move { Ok(result) })
    }

    fn update_channel(
        &self,
        channel_id: &str,
        updater: Box<
            dyn FnOnce(Option<ChannelState>) -> Result<Option<ChannelState>, VerificationError>
                + Send,
        >,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<Option<ChannelState>, VerificationError>> + Send + '_>,
    > {
        let channel_id = normalize_channel_id(channel_id);
        let mut map = self.channels.lock().unwrap();
        let current = map.get(&channel_id).cloned();
        let result = updater(current);
        match result {
            Ok(Some(state)) => {
                map.insert(channel_id.clone(), state.clone());
                // Notify waiters that the channel was updated
                if let Some(notify) = self.notifiers.lock().unwrap().get(&channel_id) {
                    notify.notify_waiters();
                }
                Box::pin(async move { Ok(Some(state)) })
            }
            Ok(None) => {
                map.remove(&channel_id);
                Box::pin(async { Ok(None) })
            }
            Err(e) => Box::pin(async { Err(e) }),
        }
    }

    fn wait_for_update(
        &self,
        channel_id: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let notify = self
            .notifiers
            .lock()
            .unwrap()
            .entry(normalize_channel_id(channel_id))
            .or_insert_with(|| Arc::new(tokio::sync::Notify::new()))
            .clone();
        Box::pin(async move {
            notify.notified().await;
        })
    }
}
