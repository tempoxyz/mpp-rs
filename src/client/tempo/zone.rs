//! Paying Tempo charges from a Zone balance, as mppx's `tempo.charge`
//! client `zone` option.
//!
//! The client withdraws the charge amount from the Zone to the recipient with
//! a challenge-bound memo, waits for the Zone's portal to settle the
//! withdrawal on Tempo, and answers with a `zone` Credential naming the
//! settlement transaction and the withdrawal's sender tag.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::Filter;
use alloy::sol_types::{SolCall, SolEvent};
use tempo_alloy::contracts::precompiles::ITIP20;
use tempo_alloy::primitives::transaction::Call;
use tempo_alloy::TempoNetwork;
use tokio::sync::OnceCell;

use crate::error::{MppError, ResultExt};
use crate::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::methods::tempo::charge::TempoChargeExt;
use crate::protocol::methods::tempo::zone::{self, IZoneOutbox, IZonePortal};

use super::charge::{SignOptions, TempoCharge};
use super::signing::{TempoPrimitiveSigner, TempoSigningMode};

/// Number of Tempo blocks searched back for a settled Zone withdrawal.
const LOOKBACK_BLOCKS: u64 = 7_200;

/// Time between polls for a settled Zone withdrawal.
const POLLING_INTERVAL: Duration = Duration::from_millis(500);

/// The least time a settlement wait gives its RPC calls, so a zero or short
/// timeout still completes the first search.
const FIRST_SCAN_TIMEOUT: Duration = Duration::from_secs(10);

/// Time the client allows for sending a Zone withdrawal before it waits for
/// settlement.
const SUBMISSION_MARGIN: Duration = Duration::from_secs(15);

/// How long to look for a withdrawal's receipt on the Zone after its send
/// response fails.
const RECEIPT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(15);

/// The error code `eth_sendRawTransactionSync` answers with when the node
/// admitted the transaction but no receipt arrived in time (EIP-7966).
const SYNC_SEND_TIMEOUT_CODE: i64 = 4;

/// Whether a send error's `message` names a rejection a node makes before it
/// admits a transaction, so the transaction can never run.
///
/// Errors about a transaction that may already be pending (nonce too low,
/// already known, replacement or underpriced) never count.
fn rejected_before_admission(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    const MAYBE_PENDING: [&str; 5] = [
        "nonce too low",
        "already known",
        "known transaction",
        "replacement",
        "underpriced",
    ];
    const REJECTED: [&str; 7] = [
        "insufficient funds",
        "insufficient balance",
        "intrinsic gas too low",
        "exceeds block gas limit",
        "invalid signature",
        "less than block base fee",
        "fee cap less than base fee",
    ];
    !MAYBE_PENDING.iter().any(|text| message.contains(text))
        && REJECTED.iter().any(|text| message.contains(text))
}

/// A Zone to pay Tempo charges from, set with
/// [`TempoProvider::with_zone`](super::TempoProvider::with_zone).
///
/// The provider's signer withdraws from its balance in the Zone. Zone RPCs
/// authorize each request with an `X-Authorization-Token` header: set it on
/// the client passed to [`with_http_client`](Self::with_http_client).
#[derive(Clone)]
pub struct TempoZone {
    rpc_url: reqwest::Url,
    rpc_provider: alloy::providers::RootProvider<TempoNetwork>,
    chain_id: u64,
    zone_id: Option<u32>,
    parent_chain_id: Option<u64>,
    settlement_timeout: Duration,
    /// The token the withdrawal pays its Zone gas in; the charge currency
    /// when unset.
    fee_token: Option<Address>,
    /// How long to look for a withdrawal's receipt after its send fails.
    receipt_recovery_timeout: Duration,
    /// Withdrawals by Zone, paying account, signing key and Challenge, so a
    /// retry resumes waiting instead of paying again. Shared by clones, so
    /// providers with different signers never share a withdrawal.
    pending: Arc<Mutex<HashMap<String, Arc<PendingWithdrawal>>>>,
    /// Per-account locks held from the protocol nonce lookup until the
    /// withdrawal's outcome is known, so concurrent payments of different
    /// Challenges never sign with the same nonce. Shared by clones.
    nonce_locks: Arc<Mutex<HashMap<Address, Arc<tokio::sync::Mutex<()>>>>>,
}

impl std::fmt::Debug for TempoZone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempoZone")
            .field("chain_id", &self.chain_id)
            .field("zone_id", &self.zone_id)
            .field("parent_chain_id", &self.parent_chain_id)
            .field("settlement_timeout", &self.settlement_timeout)
            .finish_non_exhaustive()
    }
}

/// The client's caps on what one charge may cost, checked against the amount
/// plus the Zone withdrawal fee before anything is signed or sent.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ZoneCaps {
    /// The provider's `max_amount`, in base units of the charge currency.
    pub(crate) max_amount: Option<U256>,
    /// The provider's `max_atomic_amount`.
    pub(crate) max_atomic_amount: Option<U256>,
}

/// A Zone withdrawal that was sent, or is being sent, and has not yet produced
/// a Credential. Every payment of its Challenge, and of a later Challenge for
/// the same terms, shares it.
struct PendingWithdrawal {
    /// The Challenge the withdrawal pays, bound to it by its memo.
    challenge: PaymentChallenge,
    /// The HTTP origin that issued the Challenge, when known.
    origin: Option<String>,
    /// What another Challenge must ask for to be paid by this withdrawal:
    /// `None` when the Challenge's metadata can't be read, so it never
    /// matches another.
    terms: Option<String>,
    request: OnceCell<Result<B256, WithdrawalFailure>>,
    /// The sender tag of a withdrawal whose Credential was returned after its
    /// challenge expired, as mppx's `redeemedLate`. Only a retry of that
    /// challenge may get the Credential again; until its redemption window
    /// ends, a challenge with the same terms fails closed, since the server
    /// may have redeemed or refused it.
    redeemed_late: Mutex<Option<String>>,
    /// Payments waiting on this withdrawal for a Credential right now.
    waiters: std::sync::atomic::AtomicUsize,
    /// The first Tempo block the first wait for its settlement searched: a
    /// resumed wait searches from there again, so a settlement older than
    /// the lookback window is still found.
    settlement_cursor: Mutex<Option<u64>>,
}

/// Why a Zone withdrawal request failed, shared by every payment of its
/// Challenge.
#[derive(Clone, Debug)]
enum WithdrawalFailure {
    /// Nothing was withdrawn: the Challenge may be paid again.
    Retryable(String),
    /// The transaction may have been sent: reconcile its hash.
    OutcomeUnknown(String),
    /// Every payment waiting on the withdrawal was dropped before its
    /// transaction was sent, so nothing was signed or sent. Never stored: the
    /// next payment requests the withdrawal again.
    Abandoned,
}

impl WithdrawalFailure {
    fn to_error(&self) -> MppError {
        match self {
            Self::Retryable(message) => MppError::Http(message.clone()),
            Self::OutcomeUnknown(transaction_hash) => MppError::PaymentOutcomeUnknown {
                transaction_hash: transaction_hash.clone(),
            },
            Self::Abandoned => abandoned_error(),
        }
    }
}

impl TempoZone {
    /// A Zone reached at `rpc_url` whose chain ID is `chain_id`.
    ///
    /// The Zone ID and the Tempo chain the Zone settles on are derived from the
    /// chain ID when it follows a known Zone scheme; otherwise set them with
    /// [`with_zone_id`](Self::with_zone_id) and
    /// [`with_parent_chain_id`](Self::with_parent_chain_id).
    pub fn new(rpc_url: impl AsRef<str>, chain_id: u64) -> Result<Self, MppError> {
        let rpc_url: reqwest::Url = rpc_url
            .as_ref()
            .parse()
            .mpp_config("invalid Zone RPC URL")?;
        Ok(Self {
            rpc_provider: super::rpc_provider(rpc_url.clone(), None),
            rpc_url,
            chain_id,
            zone_id: zone::id_from_chain_id(chain_id),
            parent_chain_id: zone::parent_chain_id_from_chain_id(chain_id),
            settlement_timeout: zone::DEFAULT_SETTLEMENT_TIMEOUT,
            fee_token: None,
            receipt_recovery_timeout: RECEIPT_RECOVERY_TIMEOUT,
            pending: Arc::default(),
            nonce_locks: Arc::default(),
        })
    }

    /// Set the Zone ID, as mppx's `zone.zoneId`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid Zone ID, and one that differs from the Zone the
    /// chain ID names, which would fail only after an irreversible withdrawal.
    pub fn with_zone_id(mut self, zone_id: u32) -> Result<Self, MppError> {
        if !zone::is_id(u64::from(zone_id)) {
            return Err(MppError::InvalidConfig(format!(
                "invalid Zone ID {zone_id}"
            )));
        }
        if zone::parent_chain_id_from_chain_id(self.chain_id).is_some() {
            if let Some(derived) = zone::id_from_chain_id(self.chain_id) {
                if derived != zone_id {
                    return Err(MppError::InvalidConfig(format!(
                        "zone_id {zone_id} does not match Zone {derived} of the Zone chain {}",
                        self.chain_id
                    )));
                }
            }
        }
        self.zone_id = Some(zone_id);
        Ok(self)
    }

    /// Set the Tempo chain the Zone settles on, as the Zone chain's
    /// `sourceId` in mppx. Derived from the chain ID by default.
    ///
    /// When the chain ID follows a known Zone scheme, it names the Tempo
    /// chain the Zone settles on, and a different `chain_id` is rejected by
    /// [`TempoProvider::with_zone`](super::TempoProvider::with_zone) and
    /// before any withdrawal: the withdrawal would settle on the Zone's real
    /// parent while the client waited on another chain.
    pub fn with_parent_chain_id(mut self, chain_id: u64) -> Self {
        self.parent_chain_id = Some(chain_id);
        self
    }

    /// Checks that the configured parent chain agrees with the one the Zone
    /// chain ID names, when it follows a known Zone scheme.
    pub(crate) fn check_parent_chain_id(&self) -> Result<(), MppError> {
        match zone::parent_chain_id_from_chain_id(self.chain_id) {
            Some(derived) if self.parent_chain_id != Some(derived) => {
                Err(MppError::InvalidConfig(format!(
                    "parent_chain_id {} does not match Tempo chain {derived} of the Zone chain {}",
                    self.parent_chain_id
                        .map_or_else(|| "unset".to_owned(), |id| id.to_string()),
                    self.chain_id
                )))
            }
            _ => Ok(()),
        }
    }

    /// How long to wait for a withdrawal to settle on Tempo (default: 60
    /// seconds), as mppx's `zone.settlementTimeoutMs`.
    pub fn with_settlement_timeout(mut self, timeout: Duration) -> Self {
        self.settlement_timeout = timeout;
        self
    }

    /// Pay the withdrawal's Zone gas in `fee_token` instead of the charge
    /// currency.
    ///
    /// The payer's Zone balance must hold it. The provider's
    /// [`with_fee_token`](super::TempoProvider::with_fee_token) names a token
    /// on Tempo and does not apply here: by default a withdrawal pays its gas
    /// in the currency it withdraws, which a payer of the charge holds.
    pub fn with_fee_token(mut self, fee_token: Address) -> Self {
        self.fee_token = Some(fee_token);
        self
    }

    /// Send every Zone RPC request through `client`, such as one whose default
    /// headers carry the Zone's `X-Authorization-Token`.
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.rpc_provider = super::rpc_provider(self.rpc_url.clone(), Some(&client));
        self
    }

    /// The Zone ID, when known.
    pub fn zone_id(&self) -> Option<u32> {
        self.zone_id
    }

    /// The Zone's chain ID.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Whether to pay `challenge` (on Tempo chain `chain_id`) from this Zone: a
    /// non-zero charge on the chain the Zone settles on, in a mode that allows
    /// `push`, without splits, that accepts this Zone, and that leaves time to
    /// settle before it expires.
    pub(crate) fn pays(
        &self,
        challenge: &PaymentChallenge,
        request: &ChargeRequest,
        chain_id: u64,
        signer: &TempoPrimitiveSigner,
        signing_mode: &TempoSigningMode,
    ) -> Result<bool, MppError> {
        let Some(zone_id) = self.zone_id else {
            return Ok(false);
        };
        // A withdrawal settles on the Zone's real parent: never start one for
        // a Challenge on a contradicting parent chain.
        self.check_parent_chain_id()?;
        // The Zone must settle on the chain the client signs on and on the one
        // the Challenge names, when it names one.
        let challenge_chain_id = {
            use crate::protocol::methods::tempo::charge::TempoChargeExt;
            request.chain_id()
        };
        if request.amount_u256()?.is_zero()
            || self.parent_chain_id != Some(chain_id)
            || challenge_chain_id.is_some_and(|id| self.parent_chain_id != Some(id))
        {
            return Ok(false);
        }
        let details = request.tempo_method_details()?;
        let supports_push = request
            .method_details
            .as_ref()
            .and_then(|details| details.get("supportedModes"))
            .filter(|modes| !modes.is_null())
            .is_none_or(|modes| {
                modes
                    .as_array()
                    .is_some_and(|modes| modes.iter().any(|mode| mode.as_str() == Some("push")))
            });
        if !supports_push
            || !zone::is_accepted(details.zones.as_ref(), zone_id)
            || details.splits.is_some()
        {
            return Ok(false);
        }
        // A withdrawal can't be undone, so one still outstanding for these
        // terms is resumed, even under a new challenge, and a new one starts
        // only when it can settle before the challenge expires; an expired
        // challenge would invite another payment.
        if self
            .find_pending(challenge, signer, signing_mode)?
            .is_some()
        {
            return Ok(true);
        }
        // With nothing outstanding, an expired challenge can't be paid: its
        // server refuses any Credential for it, so a payment on Tempo would
        // be lost.
        ensure_unexpired(challenge)?;
        Ok(settles_before_expiry(challenge, self.settlement_timeout))
    }

    /// The Zone, the paying account and its signing key, so a clone used by
    /// another signer never answers with this signer's withdrawal.
    fn signer_scope(
        &self,
        signer: &TempoPrimitiveSigner,
        signing_mode: &TempoSigningMode,
    ) -> String {
        let key = alloy::signers::Signer::address(signer);
        let from = signing_mode.from_address(key);
        format!("{}:{:?}:{from:#x}:{key:#x}", self.chain_id, self.zone_id)
    }

    /// The key of a withdrawal paying `challenge` from this Zone with
    /// `signer`.
    fn pending_key(
        &self,
        challenge: &PaymentChallenge,
        signer: &TempoPrimitiveSigner,
        signing_mode: &TempoSigningMode,
    ) -> String {
        // The whole challenge, so one from another realm or request with the
        // same ID never matches.
        let challenge =
            serde_json::to_string(challenge).unwrap_or_else(|_| format!("{challenge:?}"));
        format!("{}:{challenge}", self.signer_scope(signer, signing_mode))
    }

    /// Keys what `challenge` asks a withdrawal to pay, as mppx's
    /// `zoneTermsKey`: its realm, method, intent, request, digest and route
    /// metadata, everything a server compares when it accepts another
    /// challenge's Credential, but not its ID, expiry or issuance nonce.
    /// `None` when its metadata can't be read.
    fn terms_key(
        &self,
        challenge: &PaymentChallenge,
        signer: &TempoPrimitiveSigner,
        signing_mode: &TempoSigningMode,
    ) -> Option<String> {
        let zone_id = self.zone_id?;
        let request = challenge.request.decode_value().ok()?;
        let mut terms = serde_json::Map::new();
        terms.insert("zoneId".into(), zone_id.into());
        terms.insert("realm".into(), challenge.realm.clone().into());
        terms.insert("method".into(), challenge.method.as_str().into());
        terms.insert("intent".into(), challenge.intent.as_str().into());
        terms.insert("request".into(), request);
        if let Some(digest) = &challenge.digest {
            terms.insert("digest".into(), digest.clone().into());
        }
        if let Some(opaque) = &challenge.opaque {
            let serde_json::Value::Object(mut meta) = opaque.decode_value().ok()? else {
                return None;
            };
            // Issuance nonces differ between challenges for the same route.
            for nonce in ["_mppx_nonce", "_mpp_nonce", "_mppx_identity"] {
                meta.remove(nonce);
            }
            if !meta.is_empty() {
                terms.insert("meta".into(), meta.into());
            }
        }
        let terms = serde_json_canonicalizer::to_string(&serde_json::Value::Object(terms)).ok()?;
        Some(format!(
            "{}:{terms}",
            self.signer_scope(signer, signing_mode)
        ))
    }

    /// The outstanding withdrawal that pays `challenge`, with its key: its
    /// own, or, for a new challenge with the same terms, one an earlier
    /// challenge started and no payment is still waiting on. A withdrawal
    /// stays outstanding until it produces a Credential, even after its
    /// challenge expires: it may have settled, so paying its terms again could
    /// pay twice. It stops paying other challenges once its own can no longer
    /// be redeemed, as mppx's `findZoneWithdrawal`.
    ///
    /// # Errors
    ///
    /// [`MppError::ZoneSettlementPending`], naming the challenge the
    /// withdrawal paid and its sender tag, when a withdrawal with the same
    /// terms returned its Credential after its challenge expired and may still
    /// be redeemed.
    fn find_pending(
        &self,
        challenge: &PaymentChallenge,
        signer: &TempoPrimitiveSigner,
        signing_mode: &TempoSigningMode,
    ) -> Result<Option<(String, Arc<PendingWithdrawal>)>, MppError> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.find_pending_in(&mut pending, challenge, signer, signing_mode)
    }

    /// [`find_pending`](Self::find_pending) over the locked map, so a
    /// payment can look up and insert its withdrawal under one lock.
    fn find_pending_in(
        &self,
        pending: &mut HashMap<String, Arc<PendingWithdrawal>>,
        challenge: &PaymentChallenge,
        signer: &TempoPrimitiveSigner,
        signing_mode: &TempoSigningMode,
    ) -> Result<Option<(String, Arc<PendingWithdrawal>)>, MppError> {
        let key = self.pending_key(challenge, signer, signing_mode);
        if let Some(own) = pending.get(&key) {
            return Ok(Some((key, own.clone())));
        }
        let Some(terms) = self.terms_key(challenge, signer, signing_mode) else {
            return Ok(None);
        };
        // No server accepts their Credentials any more, so they can't pay
        // this challenge.
        pending.retain(|_, entry| {
            entry.terms.as_deref() != Some(terms.as_str()) || is_redeemable(&entry.challenge)
        });
        for (key, entry) in pending.iter() {
            if entry.terms.as_deref() != Some(terms.as_str()) {
                continue;
            }
            // Its Credential was sent after its challenge expired, and its
            // server may still accept or refuse it. Sending it again for this
            // challenge could redeem it twice, and a new payment could pay
            // twice if it was refused, so fail closed until its redemption
            // window ends. The error names the challenge the withdrawal paid,
            // whose retry gets its Credential.
            let redeemed_late = entry
                .redeemed_late
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if let Some(sender_tag) = redeemed_late {
                return Err(MppError::ZoneSettlementPending {
                    challenge: Box::new(entry.challenge.clone()),
                    challenge_id: entry.challenge.id.clone(),
                    sender_tag,
                    zone_id: self.zone_id.unwrap_or_default(),
                });
            }
            // A payment still waiting on it is another payment in flight, not
            // one this challenge retries: sharing its Credential would leave
            // one of the two unpaid.
            if entry.waiters.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                continue;
            }
            return Ok(Some((key.clone(), entry.clone())));
        }
        Ok(None)
    }

    fn forget(&self, key: &str, withdrawal: &Arc<PendingWithdrawal>) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if pending
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, withdrawal))
        {
            pending.remove(key);
        }
    }

    /// Forgets `withdrawal`, abandoned before its transaction was sent, unless
    /// a payment joined it since: one checked under the same lock that
    /// payments join under, so a joining payment never shares an entry another
    /// payment can't find.
    fn forget_abandoned(&self, key: &str, withdrawal: &Arc<PendingWithdrawal>) {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if withdrawal.waiters.load(std::sync::atomic::Ordering::SeqCst) == 0
            && !withdrawal.request.initialized()
            && pending
                .get(key)
                .is_some_and(|current| Arc::ptr_eq(current, withdrawal))
        {
            pending.remove(key);
        }
    }

    /// Pay `challenge`, issued by `origin` when the caller verified it, from
    /// the Zone and wait for its settlement on Tempo through `tempo`.
    ///
    /// A withdrawal already outstanding for `challenge`, or for an earlier
    /// challenge with the same terms, is resumed instead of paying again, and
    /// the Credential answers the challenge that withdrawal pays.
    ///
    /// # Errors
    ///
    /// [`MppError::ZoneSettlementPending`] when the withdrawal did not settle
    /// in time, or when it pays an earlier challenge that only its own origin
    /// may be sent a Credential for: paying the challenge it carries again
    /// resumes the wait.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn pay(
        &self,
        challenge: &PaymentChallenge,
        origin: Option<&str>,
        client_id: Option<&str>,
        caps: ZoneCaps,
        signer: &TempoPrimitiveSigner,
        signing_mode: &TempoSigningMode,
        tempo: &impl Provider<TempoNetwork>,
    ) -> Result<PaymentCredential, MppError> {
        let zone_id = self.zone_id.ok_or_else(|| {
            MppError::InvalidConfig("Zone ID is unknown: use TempoZone::with_zone_id".into())
        })?;
        self.check_parent_chain_id()?;
        // Read what the withdrawal needs before storing it, so a challenge it
        // can't pay leaves nothing behind.
        challenge
            .request
            .decode::<ChargeRequest>()?
            .recipient_address()?;

        // A withdrawal can't be undone, so a retry after a failed wait, or
        // under a new challenge for the same terms, resumes it instead of
        // paying again. Concurrent payments share the request, which is stored
        // before it is sent.
        let own_key = self.pending_key(challenge, signer, signing_mode);
        let (key, withdrawal, waiting) = {
            // One lock covers the lookup and the insertion, so two payments
            // for the same terms never both find nothing and both withdraw.
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match self.find_pending_in(&mut pending, challenge, signer, signing_mode)? {
                Some((key, entry)) => {
                    let waiting = Waiting::new(&entry);
                    (key, entry, waiting)
                }
                None => {
                    // With nothing outstanding, an expired challenge can't be
                    // paid: its server refuses any Credential for it.
                    ensure_unexpired(challenge)?;
                    let entry = pending
                        .entry(own_key.clone())
                        .or_insert_with(|| {
                            Arc::new(PendingWithdrawal {
                                challenge: challenge.clone(),
                                origin: origin.map(str::to_owned),
                                terms: self.terms_key(challenge, signer, signing_mode),
                                request: OnceCell::new(),
                                redeemed_late: Mutex::default(),
                                waiters: Default::default(),
                                settlement_cursor: Mutex::default(),
                            })
                        })
                        .clone();
                    // Counted while the map is locked, so a concurrent payment
                    // for the same terms never shares it.
                    let waiting = Waiting::new(&entry);
                    (own_key.clone(), entry, waiting)
                }
            }
        };
        // The withdrawal pays its own challenge, which may be an earlier one.
        let paid = &withdrawal.challenge;
        let pending_error = |sender_tag: String| MppError::ZoneSettlementPending {
            challenge: Box::new(paid.clone()),
            challenge_id: paid.id.clone(),
            sender_tag,
            zone_id,
        };
        let checked = (|| {
            // A withdrawal started for an earlier challenge pays only that
            // challenge, so its Credential goes only back to the origin that
            // issued it; under any other origin, or one the caller did not
            // verify, fail closed.
            let foreign = key != own_key;
            let other_origin = if foreign {
                origin.is_none() || origin != withdrawal.origin.as_deref()
            } else {
                origin.is_some()
                    && withdrawal.origin.is_some()
                    && origin != withdrawal.origin.as_deref()
            };
            if other_origin {
                return Err(pending_error(String::new()));
            }
            // Past its redemption window, the server refuses the challenge's
            // Credential, but the withdrawal may still have paid it: fail
            // closed rather than withdraw again.
            if !is_redeemable(paid) {
                return Err(pending_error(String::new()));
            }
            let request: ChargeRequest = paid.request.decode()?;
            request.recipient_address()
        })();
        let recipient = match checked {
            Ok(recipient) => recipient,
            Err(error) => {
                // Nothing was requested: a withdrawal this payment stored, and
                // no other payment waits on, is forgotten.
                drop(waiting);
                self.forget_abandoned(&key, &withdrawal);
                return Err(error);
            }
        };
        // The request runs in its own task, so a caller that is cancelled or
        // times out after the transaction is sent still leaves its outcome in
        // the shared cell for the retry to reconcile, instead of sending
        // another withdrawal. Until it is sent, the request stops once no
        // payment waits on it, and leaves the cell empty for the next one.
        let task = {
            let zone = self.clone();
            let key = key.clone();
            let withdrawal = withdrawal.clone();
            let challenge = paid.clone();
            let client_id = client_id.map(str::to_owned);
            let signer = signer.clone();
            let signing_mode = signing_mode.clone();
            tokio::spawn(async move {
                let abandoned =
                    || withdrawal.waiters.load(std::sync::atomic::Ordering::SeqCst) == 0;
                let mut own_error = None;
                let outcome = withdrawal
                    .request
                    .get_or_try_init(|| async {
                        // A payment dropped while another held the request
                        // starts nothing.
                        if abandoned() {
                            return Err(());
                        }
                        match zone
                            .request_withdrawal(
                                &challenge,
                                client_id.as_deref(),
                                caps,
                                &signer,
                                &signing_mode,
                                &abandoned,
                            )
                            .await
                        {
                            Ok(sender_tag) => Ok(Ok(sender_tag)),
                            Err((WithdrawalFailure::Abandoned, error)) => {
                                own_error = Some(error);
                                Err(())
                            }
                            Err((failure, error)) => {
                                own_error = Some(error);
                                Ok(Err(failure))
                            }
                        }
                    })
                    .await
                    .cloned();
                let outcome = outcome.unwrap_or_else(|()| {
                    zone.forget_abandoned(&key, &withdrawal);
                    Err(WithdrawalFailure::Abandoned)
                });
                (outcome, own_error)
            })
        };
        let (outcome, own_error) = match task.await {
            Ok(result) => result,
            Err(e) => {
                // A request that never started sent nothing.
                drop(waiting);
                self.forget_abandoned(&key, &withdrawal);
                return Err(MppError::Http(format!(
                    "Zone withdrawal request failed: {e}"
                )));
            }
        };
        let sender_tag = match outcome {
            Ok(sender_tag) => sender_tag,
            Err(failure) => {
                // Only a failure before the transaction was sent is safe to
                // retry. After that, the withdrawal may have gone through, so
                // retries of this challenge keep failing.
                if matches!(
                    failure,
                    WithdrawalFailure::Retryable(_) | WithdrawalFailure::Abandoned
                ) {
                    self.forget(&key, &withdrawal);
                }
                return Err(own_error.unwrap_or_else(|| failure.to_error()));
            }
        };

        let timeout = settlement_timeout(paid, self.settlement_timeout);
        let expired = is_expired(paid);
        // Even the first search ends at the challenge's expiry. After it, the
        // wait looks once: only a settlement from before then can still be
        // redeemed.
        let limit = if expired {
            FIRST_SCAN_TIMEOUT
        } else {
            settlement_timeout(paid, timeout.max(FIRST_SCAN_TIMEOUT))
        };
        let settlement = wait_for_settlement_from(
            tempo,
            zone::portal_address(zone_id),
            sender_tag,
            Some(recipient),
            timeout,
            limit,
            &withdrawal.settlement_cursor,
        )
        .await
        .map_err(|_| pending_error(format!("{sender_tag:#x}")))?;
        // The Credential pays once: a later challenge with the same terms is a
        // new payment. One made after its challenge expired is accepted only by
        // a server that grants a grace period, so the withdrawal stays for a
        // retry of its own challenge, which would otherwise pay again on Tempo,
        // and blocks other challenges for its terms until its window ends. A
        // bounced payout paid nothing and may be paid again.
        if settlement.bounced || !expired {
            self.forget(&key, &withdrawal);
        } else {
            *withdrawal
                .redeemed_late
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(format!("{sender_tag:#x}"));
        }
        // A bounced payout returned the amount to the payer's Zone balance and
        // paid nothing, so the server would reject its Credential: fail
        // without one, and let a retry withdraw again. The withdrawal's fees
        // are spent, so it gets its own error, which callers such as MCP do
        // not answer by paying another offer.
        if settlement.bounced {
            return Err(MppError::ZoneWithdrawalBounced {
                challenge_id: paid.id.clone(),
                sender_tag: format!("{sender_tag:#x}"),
                zone_id,
            });
        }
        let hash = settlement.hash;

        Ok(PaymentCredential::new(
            paid.to_echo(),
            PaymentPayload::zone(format!("{hash:#x}"), format!("{sender_tag:#x}"), zone_id),
        ))
    }

    /// Requests a Zone withdrawal of the challenge amount to its recipient,
    /// bound to the challenge by its memo, and returns its sender tag.
    // The error pairs the cached failure with the caller's own error; it is
    // returned once per withdrawal, so boxing it buys nothing.
    #[allow(clippy::result_large_err)]
    async fn request_withdrawal(
        &self,
        challenge: &PaymentChallenge,
        client_id: Option<&str>,
        caps: ZoneCaps,
        signer: &TempoPrimitiveSigner,
        signing_mode: &TempoSigningMode,
        abandoned: &(dyn Fn() -> bool + Sync),
    ) -> Result<B256, (WithdrawalFailure, MppError)> {
        let abandon = || (WithdrawalFailure::Abandoned, abandoned_error());
        let retryable = |error: MppError| (WithdrawalFailure::Retryable(error.to_string()), error);
        let request: ChargeRequest = challenge.request.decode().map_err(retryable)?;
        let amount = request.amount_u256().map_err(retryable)?;
        let currency = request.currency_address().map_err(retryable)?;
        let recipient = request.recipient_address().map_err(retryable)?;
        let amount_u128 = u128::try_from(amount).map_err(|_| {
            retryable(MppError::InvalidAmount(
                "Zone withdrawal amount exceeds uint128".into(),
            ))
        })?;
        let from = signing_mode.from_address(alloy::signers::Signer::address(signer));
        let memo = crate::tempo::attribution::encode(&challenge.id, &challenge.realm, client_id);

        // The outbox pulls the amount plus its withdrawal fee.
        let fee = self.withdrawal_fee().await.map_err(retryable)?;
        // The fee is part of what the charge costs the payer, so it counts
        // against the client's caps; offer selection compared the bare
        // amount. Nothing is signed or sent past a cap.
        let total = amount.saturating_add(U256::from(fee));
        for (cap, name) in [
            (caps.max_atomic_amount, "max_atomic_amount"),
            (caps.max_amount, "max_amount"),
        ] {
            if cap.is_some_and(|cap| total > cap) {
                return Err(retryable(MppError::InvalidChallenge {
                    id: Some(challenge.id.clone()),
                    reason: Some(format!(
                        "Tempo charge amount plus Zone withdrawal fee exceeds {name}."
                    )),
                }));
            }
        }
        let calls = vec![
            Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: ITIP20::approveCall {
                    spender: zone::ZONE_OUTBOX,
                    amount: amount.saturating_add(U256::from(fee)),
                }
                .abi_encode()
                .into(),
            },
            Call {
                to: TxKind::Call(zone::ZONE_OUTBOX),
                value: U256::ZERO,
                input: IZoneOutbox::requestWithdrawalCall {
                    token: currency,
                    to: recipient,
                    amount: amount_u128,
                    memo: memo.into(),
                    gasLimit: 0,
                    // A bounced payout refunds the payer, not the payee's Zone address.
                    zoneFallbackRecipient: from,
                    data: Bytes::new(),
                    revealTo: Bytes::new(),
                }
                .abi_encode()
                .into(),
            },
        ];
        // Hold the account's nonce lock until the outcome is known, so another
        // payment from this account reads the nonce after this one is spent.
        let nonce_lock = self.nonce_lock(from);
        let _nonce_guard = nonce_lock.lock().await;
        // Waiting for the lock may have outlasted every payment of this
        // withdrawal: sign nothing for them.
        if abandoned() {
            return Err(abandon());
        }
        let expiring = || {
            retryable(MppError::Http(
                "Zone withdrawal can no longer settle before the challenge expires.".into(),
            ))
        };
        // Another withdrawal may have held the lock past the time this one
        // needs to settle: send nothing once the challenge would expire first.
        if !settles_before_expiry(challenge, self.settlement_timeout) {
            return Err(expiring());
        }
        // Prepare and sign first: a failure there sent nothing, so the
        // challenge may be retried. The protocol nonce is the Zone's.
        let nonce = self
            .rpc_provider
            .get_transaction_count(from)
            .pending()
            .await
            .map_err(|e| retryable(MppError::Http(format!("failed to fetch Zone nonce: {e}"))))?;
        let signed = TempoCharge::from_challenge(challenge)
            .map_err(retryable)?
            .into_zone_withdrawal(self.chain_id, calls)
            .sign_with_primitive_provider_options(
                signer,
                &self.rpc_provider,
                SignOptions {
                    signing_mode: Some(signing_mode.clone()),
                    nonce: Some(nonce),
                    nonce_key: Some(U256::ZERO),
                    // The Zone's configured gas token; the charge currency
                    // otherwise.
                    fee_token: self.fee_token,
                    ..Default::default()
                },
            )
            .await
            .map_err(retryable)?;
        let tx_bytes = signed.tx_bytes().to_vec();
        // The signed transaction fixes its hash, so a lost send response can
        // still be recovered from the Zone.
        let hash = alloy::primitives::keccak256(&tx_bytes);
        let unknown = || {
            (
                WithdrawalFailure::OutcomeUnknown(format!("{hash:#x}")),
                MppError::PaymentOutcomeUnknown {
                    transaction_hash: format!("{hash:#x}"),
                },
            )
        };
        // Preparing the transaction awaited Zone RPCs: check again that it can
        // still settle before the challenge expires, since the send can't be
        // undone.
        if !settles_before_expiry(challenge, self.settlement_timeout) {
            return Err(expiring());
        }
        // The last point a dropped payment can stop the withdrawal: once the
        // send starts, its outcome is kept for a retry to reconcile.
        if abandoned() {
            return Err(abandon());
        }
        let receipt: serde_json::Value = match self
            .rpc_provider
            .raw_request(
                "eth_sendRawTransactionSync".into(),
                [alloy::hex::encode_prefixed(&tx_bytes)],
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => {
                if self.refused(&error, hash).await {
                    return Err(retryable(MppError::Http(format!(
                        "failed to send Zone withdrawal: {error}"
                    ))));
                }
                self.recover_receipt(hash).await.ok_or_else(unknown)?
            }
        };
        // Only a receipt of the transaction signed here says what happened to
        // it: one for another hash proves nothing, so the outcome stays
        // unknown under the local hash.
        let receipt_hash = receipt
            .get("transactionHash")
            .and_then(serde_json::Value::as_str)
            .and_then(|hash| hash.parse::<B256>().ok());
        if receipt_hash != Some(hash) {
            return Err(unknown());
        }
        match receipt.get("status").and_then(serde_json::Value::as_str) {
            Some("0x1") => {}
            // A reverted withdrawal moved nothing, so the challenge may be retried.
            Some("0x0") => {
                return Err(retryable(MppError::Http(format!(
                    "Zone withdrawal transaction {hash:#x} reverted."
                ))));
            }
            _ => return Err(unknown()),
        }
        // The withdrawal succeeded but its event can't be found, or doesn't
        // describe the withdrawal signed here: its outcome is unknown, so no
        // flow pays the challenge another way.
        let requested = withdrawal_requested(&receipt)
            .filter(|event| {
                event.sender == from
                    && event.token == currency
                    && event.to == recipient
                    && event.amount == amount_u128
                    && event.memo == B256::from(memo)
            })
            .ok_or_else(unknown)?;
        Ok(zone::sender_tag(
            requested.sender,
            hash,
            requested.fallbackNonce,
        ))
    }

    /// Whether the Zone refused the withdrawal `hash` whose send failed with
    /// `error`, so it never ran.
    ///
    /// Invalid parameters prove it. Otherwise only an error that names a
    /// rejection made before the node admits a transaction does (such as fees
    /// its balance can't pay), and only once the node also doesn't know the
    /// transaction. Any other error, or an empty lookup alone, proves nothing:
    /// a load-balanced or still-indexing node may not report a transaction it
    /// accepted yet, and paying the challenge again would pay twice.
    async fn refused(&self, error: &alloy::transports::TransportError, hash: B256) -> bool {
        let Some(response) = error.as_error_resp() else {
            return false;
        };
        if response.code == -32602 {
            return true;
        }
        if response.code == SYNC_SEND_TIMEOUT_CODE || !rejected_before_admission(&response.message)
        {
            return false;
        }
        matches!(
            self.rpc_provider
                .raw_request::<_, Option<serde_json::Value>>(
                    "eth_getTransactionByHash".into(),
                    [hash],
                )
                .await,
            Ok(None)
        )
    }

    /// The lock serializing `from`'s Zone withdrawals.
    fn nonce_lock(&self, from: Address) -> Arc<tokio::sync::Mutex<()>> {
        self.nonce_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(from)
            .or_default()
            .clone()
    }

    /// The Zone outbox's fee for a withdrawal without a callback.
    async fn withdrawal_fee(&self) -> Result<u128, MppError> {
        let data = alloy::hex::encode_prefixed(
            IZoneOutbox::calculateWithdrawalFeeCall { gasLimit: 0 }.abi_encode(),
        );
        let result: Bytes = self
            .rpc_provider
            .raw_request(
                "eth_call".into(),
                (
                    serde_json::json!({ "to": zone::ZONE_OUTBOX, "data": data }),
                    "latest",
                ),
            )
            .await
            .map_err(|e| MppError::Http(format!("failed to read the Zone withdrawal fee: {e}")))?;
        IZoneOutbox::calculateWithdrawalFeeCall::abi_decode_returns(&result)
            .map_err(|e| MppError::Http(format!("invalid Zone withdrawal fee: {e}")))
    }

    /// Looks for the receipt of a withdrawal whose send response failed.
    async fn recover_receipt(&self, hash: B256) -> Option<serde_json::Value> {
        let deadline = tokio::time::Instant::now().checked_add(self.receipt_recovery_timeout);
        loop {
            let receipt: Result<Option<serde_json::Value>, _> = self
                .rpc_provider
                .raw_request("eth_getTransactionReceipt".into(), [hash])
                .await;
            if let Ok(Some(receipt)) = receipt {
                return Some(receipt);
            }
            if deadline
                .is_some_and(|deadline| tokio::time::Instant::now() + POLLING_INTERVAL > deadline)
            {
                return None;
            }
            tokio::time::sleep(POLLING_INTERVAL).await;
        }
    }
}

/// The outbox's `WithdrawalRequested` event in a receipt's logs.
fn withdrawal_requested(receipt: &serde_json::Value) -> Option<IZoneOutbox::WithdrawalRequested> {
    receipt
        .get("logs")?
        .as_array()?
        .iter()
        .filter_map(|log| serde_json::from_value::<alloy::rpc::types::Log>(log.clone()).ok())
        .filter(|log| log.address() == zone::ZONE_OUTBOX)
        .find_map(|log| IZoneOutbox::WithdrawalRequested::decode_log_data(log.data()).ok())
}

/// Whether a Zone withdrawal can be sent and waited on for up to `timeout`
/// before the challenge expires.
fn settles_before_expiry(challenge: &PaymentChallenge, timeout: Duration) -> bool {
    if challenge.expires.is_none() {
        return true;
    }
    // An unparsable expiry is not one the withdrawal can beat.
    // A timeout too long to add the margin to never beats an expiry.
    challenge.expires_at().is_some_and(|expires_at| {
        timeout
            .checked_add(SUBMISSION_MARGIN)
            .is_some_and(|needed| expires_at - time::OffsetDateTime::now_utc() > needed)
    })
}

/// Refuse an expired `challenge` before paying it, as mppx's
/// `Expires.assert`.
fn ensure_unexpired(challenge: &PaymentChallenge) -> Result<(), MppError> {
    if is_expired(challenge) {
        return Err(MppError::payment_expired(
            challenge.expires.clone().unwrap_or_default(),
        ));
    }
    Ok(())
}

/// Counts a payment waiting on a withdrawal for as long as it lives, so the
/// count drops when the payment is cancelled too.
struct Waiting(Arc<PendingWithdrawal>);

impl Waiting {
    fn new(withdrawal: &Arc<PendingWithdrawal>) -> Self {
        withdrawal
            .waiters
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self(withdrawal.clone())
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.0
            .waiters
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The error of a payment dropped before its Zone withdrawal was sent.
fn abandoned_error() -> MppError {
    MppError::Http("Zone payment was cancelled before its withdrawal was sent.".into())
}

/// Whether `challenge` has expired.
fn is_expired(challenge: &PaymentChallenge) -> bool {
    challenge
        .expires_at()
        .is_some_and(|expires_at| time::OffsetDateTime::now_utc() >= expires_at)
}

/// Whether a Credential for `challenge` may still be redeemed: until
/// [`zone::MAX_ZONE_CREDENTIAL_GRACE`], the longest grace a server gives, after
/// it expires.
fn is_redeemable(challenge: &PaymentChallenge) -> bool {
    // An expiry too far in the future to add the grace to is redeemable.
    challenge.expires_at().is_none_or(|expires_at| {
        expires_at
            .checked_add(
                time::Duration::try_from(zone::MAX_ZONE_CREDENTIAL_GRACE)
                    .unwrap_or(time::Duration::MAX),
            )
            .is_none_or(|end| time::OffsetDateTime::now_utc() < end)
    })
}

/// How long to wait for settlement: `timeout`, cut short at the challenge's
/// expiry.
fn settlement_timeout(challenge: &PaymentChallenge, timeout: Duration) -> Duration {
    let Some(expires_at) = challenge.expires_at() else {
        return timeout;
    };
    let remaining = expires_at - time::OffsetDateTime::now_utc();
    timeout.min(Duration::try_from(remaining).unwrap_or(Duration::ZERO))
}

/// Waits until `portal` emits `WithdrawalProcessed` for `sender_tag` (and `to`,
/// when given) on Tempo and returns the transaction hash that settled it.
///
/// Searches the last 7,200 blocks once, then polls new blocks every 500 ms
/// until `timeout`, as mppx's `Zone.waitForSettlement`.
pub async fn wait_for_settlement(
    provider: &impl Provider<TempoNetwork>,
    portal: Address,
    sender_tag: B256,
    to: Option<Address>,
    timeout: Duration,
) -> Result<B256, MppError> {
    let limit = timeout.max(FIRST_SCAN_TIMEOUT);
    let settlement = wait_for_settlement_from(
        provider,
        portal,
        sender_tag,
        to,
        timeout,
        limit,
        &Mutex::new(None),
    )
    .await?;
    Ok(settlement.hash)
}

/// A `WithdrawalProcessed` event found on Tempo.
struct Settlement {
    /// The transaction that emitted it.
    hash: B256,
    /// Whether it reports the payout bounced (`callbackSuccess` false).
    bounced: bool,
}

/// [`wait_for_settlement`], searching from `cursor`'s block when set instead
/// of the lookback window, and leaving in it the first block it searched.
/// Polling stops at `timeout`; `limit` also bounds the RPC calls, so a stalled
/// RPC can't hold the payment past it, nor a slow reply settle after it.
async fn wait_for_settlement_from(
    provider: &impl Provider<TempoNetwork>,
    portal: Address,
    sender_tag: B256,
    to: Option<Address>,
    timeout: Duration,
    limit: Duration,
    cursor: &Mutex<Option<u64>>,
) -> Result<Settlement, MppError> {
    // A timeout past what an Instant can hold waits without a deadline.
    let deadline = tokio::time::Instant::now().checked_add(timeout);
    let timed_out = || {
        MppError::Http(format!(
            "Zone withdrawal {sender_tag:#x} did not settle on Tempo within {}ms.",
            timeout.as_millis()
        ))
    };
    let search = async {
        // A failed Tempo RPC call is retried at the next poll rather than ending
        // the wait: the withdrawal is already sent, so giving up early would
        // report a settlement as pending that the next poll could find.
        let mut latest: Option<u64> = None;
        let mut from_block: Option<u64> = None;
        loop {
            if let Ok(block) = provider.get_block_number().await {
                latest = Some(latest.map_or(block, |latest| latest.max(block)));
            }
            if let Some(latest) = latest {
                // Scan the lookback window once, then only blocks added since the
                // previous poll. A resumed wait searches again from where the first
                // one started, which also covers blocks a lagging log index missed.
                let from = *from_block.get_or_insert_with(|| {
                    *cursor
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get_or_insert_with(|| latest.saturating_sub(LOOKBACK_BLOCKS))
                });
                if from <= latest {
                    let mut filter = Filter::new()
                        .address(portal)
                        .event_signature(IZonePortal::WithdrawalProcessed::SIGNATURE_HASH)
                        .topic2(sender_tag)
                        .from_block(from)
                        .to_block(latest);
                    if let Some(to) = to {
                        filter = filter.topic1(to.into_word());
                    }
                    if let Ok(logs) = provider.get_logs(&filter).await {
                        if let Some((log, hash)) = logs
                            .iter()
                            .find_map(|log| Some((log, log.transaction_hash?)))
                        {
                            // Only an event that reports a bounce counts as one: the
                            // server verifies the Credential's settlement either way.
                            let bounced =
                                IZonePortal::WithdrawalProcessed::decode_log_data(log.data())
                                    .is_ok_and(|event| !event.callbackSuccess);
                            return Ok(Settlement { hash, bounced });
                        }
                        from_block = Some(latest + 1);
                    }
                }
            }
            if deadline
                .is_some_and(|deadline| tokio::time::Instant::now() + POLLING_INTERVAL > deadline)
            {
                return Err(timed_out());
            }
            tokio::time::sleep(POLLING_INTERVAL).await;
        }
    };
    match tokio::time::Instant::now().checked_add(limit) {
        Some(limit) => tokio::time::timeout_at(limit, search)
            .await
            .unwrap_or_else(|_| Err(timed_out())),
        None => search.await,
    }
}

#[cfg(test)]
mod tests;
