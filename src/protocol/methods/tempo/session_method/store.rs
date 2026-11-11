//! Channel state and its persistence.

use std::future::Future;
use std::sync::Arc;

use alloy::primitives::Address;

use crate::protocol::traits::VerificationError;

/// Durable evidence for reconciling a submitted close after a lost response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingClose {
    pub transaction_hash: alloy::primitives::B256,
    pub nonce: u64,
    pub cumulative_amount: u128,
    pub signature: Vec<u8>,
    /// Unix time (seconds) after which the close transaction can no longer
    /// land, for closes signed with an expiring nonce. `None` for evidence
    /// written before this field existed.
    #[serde(default)]
    pub valid_before: Option<u64>,
}

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
    /// Blocks metering while a close is in flight or its outcome is unknown.
    /// Use `SessionMethod::reconcile_pending_close` after an ambiguous error.
    /// An absent receipt is not evidence of failure. Persist this guard and
    /// `pending_close` across process restarts.
    #[serde(default)]
    pub closing: bool,
    /// Recorded before submission, even if the caller discards the error.
    #[serde(default)]
    pub pending_close: Option<PendingClose>,
    #[serde(default)]
    pub close_requested_at: u64,
    pub created_at: String,
    /// Vouchers accepted within the reorder window, when the session method
    /// accepts vouchers out of order (see
    /// [`SessionMethod::with_reorder_window`](super::SessionMethod::with_reorder_window)).
    /// `None` until the first such voucher, which reads as a window whose
    /// floor is `highest_voucher_amount`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<VoucherWindow>,
}

/// The vouchers a channel accepted within its reorder window: its replay
/// protection when vouchers may arrive out of order.
///
/// Every voucher at or below `floor` is refused as stale. Above it, a
/// voucher is accepted once: its increment `(after, cumulativeAmount]` must
/// not overlap an accepted run.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoucherWindow {
    /// Cumulative amount at or below which every voucher is refused.
    pub floor: u128,
    /// Accepted intervals, sorted and disjoint. Intervals that touch are merged.
    pub runs: Vec<VoucherRun>,
}

/// An interval of accepted voucher increments, `(from, to]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoucherRun {
    /// Exclusive lower bound.
    pub from: u128,
    /// Inclusive upper bound.
    pub to: u128,
    /// When the latest voucher in the run was accepted, in Unix milliseconds.
    pub at: u64,
}

impl VoucherWindow {
    /// Moves runs accepted at or before `cutoff` (Unix milliseconds) below
    /// the floor, and drops runs the floor covers.
    pub(super) fn prune(&mut self, cutoff: u64) {
        let floor = self
            .runs
            .iter()
            .filter(|run| run.at <= cutoff)
            .map(|run| run.to)
            .fold(self.floor, u128::max);
        self.floor = floor;
        self.runs.retain(|run| run.at > cutoff && run.to > floor);
    }

    /// Whether `(from, to]` overlaps an accepted run.
    pub(super) fn overlaps(&self, from: u128, to: u128) -> bool {
        self.runs.iter().any(|run| from < run.to && run.from < to)
    }

    /// Records `(from, to]`, which overlaps no run, accepted at `at`, and
    /// merges it with the runs it touches. Past [`MAX_VOUCHER_RUNS`] runs,
    /// the lowest ones move below the floor: that refuses more vouchers as
    /// stale, never accepts a replay.
    pub(super) fn insert(&mut self, from: u128, to: u128, at: u64) {
        let index = self.runs.partition_point(|run| run.to <= from);
        self.runs.insert(index, VoucherRun { from, to, at });
        let mut merged: Vec<VoucherRun> = Vec::with_capacity(self.runs.len());
        for run in self.runs.drain(..) {
            match merged.last_mut() {
                Some(last) if last.to == run.from => {
                    last.to = run.to;
                    last.at = last.at.max(run.at);
                }
                _ => merged.push(run),
            }
        }
        self.runs = merged;
        let excess = self.runs.len().saturating_sub(MAX_VOUCHER_RUNS);
        if excess > 0 {
            self.floor = self.floor.max(self.runs[excess - 1].to);
            self.runs.drain(..excess);
        }
    }
}

/// Most disjoint runs a [`VoucherWindow`] keeps, which bounds the stored
/// channel state. Runs are holes left by vouchers in flight or lost.
pub const MAX_VOUCHER_RUNS: usize = 256;

/// Trait for channel state persistence.
///
/// Implementations must provide atomic read-modify-write semantics for
/// `update_channel`. The callback receives the current state (or `None`)
/// and returns the next state (or `None` to delete). If the callback returns
/// an error, the stored state must remain unchanged.
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
    /// Validate required write capabilities before funding a new channel.
    fn check_writable(
        &self,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), VerificationError>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }

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
                state.deduct(amount).map(Some)
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
