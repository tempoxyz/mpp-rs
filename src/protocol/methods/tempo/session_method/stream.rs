//! Live escrow checks for metered streams.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use super::chain::get_on_chain_channel;
use super::{normalize_channel_id, SessionMethod};
use crate::protocol::traits::VerificationError;

/// How long a successful escrow read covers later stream charges.
const STREAM_CHECK_TTL: Duration = Duration::from_secs(5);

/// A check a metered stream runs before it charges for and delivers each
/// value. It receives the lowercase channel ID; an error stops the stream.
///
/// [`SessionMethod::stream_check`] checks the channel's live escrow.
pub type StreamCheck = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<(), VerificationError>> + Send>>
        + Send
        + Sync,
>;

impl<P> SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Check that a streaming channel's escrow can still fund delivery.
    ///
    /// Fails when the channel is closing or finalized in the store or on
    /// chain, when its on-chain deposit was withdrawn, or when the escrow
    /// cannot be read. Successful reads are reused for up to five seconds.
    pub async fn verify_stream(&self, channel_id: &str) -> Result<(), VerificationError> {
        let channel_id = normalize_channel_id(channel_id);
        let closed = || VerificationError::channel_closed("stream channel is closed");
        let channel = self
            .store
            .get_channel(&channel_id)
            .await?
            .ok_or_else(closed)?;
        if channel.finalized || channel.closing || channel.close_requested_at != 0 {
            return Err(closed());
        }

        let now = Instant::now();
        let last_verified = self.stream_checks().get(&channel_id).copied();
        if last_verified.is_some_and(|at| now.duration_since(at) < STREAM_CHECK_TTL) {
            return Ok(());
        }

        // Only successful reads are cached: a failed check must read again.
        self.stream_checks().remove(&channel_id);
        let id = Self::parse_channel_id(&channel_id)?;
        // Transport errors can include private RPC URLs or credentials.
        let on_chain = get_on_chain_channel(&*self.provider, channel.escrow_contract, id)
            .await
            .map_err(|_| VerificationError::network_error("Unable to verify stream escrow"))?;
        if on_chain.deposit == 0 {
            return Err(VerificationError::channel_not_found(
                "channel not funded on-chain",
            ));
        }
        if on_chain.finalized || on_chain.close_requested_at != 0 {
            return Err(VerificationError::channel_closed(
                "channel has a pending close request",
            ));
        }
        // Record the on-chain settlement. Settling a voucher this store
        // accepted does not deliver its unspent credit, so only amounts above
        // the highest accepted voucher (settled by another instance) count as
        // spent before the stream charges again.
        self.store
            .update_channel(
                &channel_id,
                Box::new(move |current| {
                    Ok(current.map(|state| {
                        let spent = if on_chain.settled > state.highest_voucher_amount {
                            std::cmp::max(on_chain.settled, state.spent)
                        } else {
                            state.spent
                        };
                        let mut state = state.refresh_on_chain(&on_chain);
                        state.spent = spent;
                        state
                    }))
                }),
            )
            .await?
            .ok_or_else(closed)?;

        let mut checks = self.stream_checks();
        // Expired entries are never reused, so drop them to keep the map
        // bounded by the channels streamed in the last few seconds.
        checks.retain(|_, at| now.duration_since(*at) < STREAM_CHECK_TTL);
        checks.insert(channel_id, now);
        Ok(())
    }

    /// [`verify_stream`](Self::verify_stream) as a hook for
    /// [`ServeOptions::before_charge`](crate::server::sse::ServeOptions::before_charge).
    pub fn stream_check(&self) -> StreamCheck {
        let method = self.clone();
        Arc::new(move |channel_id| {
            let method = method.clone();
            Box::pin(async move { method.verify_stream(&channel_id).await })
        })
    }

    pub(super) fn stream_checks(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, Instant>> {
        self.stream_checks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
