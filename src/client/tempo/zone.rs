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
    /// Withdrawals by Challenge, so a retry resumes waiting instead of paying
    /// again. Shared by clones.
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

/// A withdrawal request shared by every payment of one Challenge.
#[derive(Default)]
struct PendingWithdrawal {
    request: OnceCell<Result<B256, WithdrawalFailure>>,
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
}

impl WithdrawalFailure {
    fn to_error(&self) -> MppError {
        match self {
            Self::Retryable(message) => MppError::Http(message.clone()),
            Self::OutcomeUnknown(transaction_hash) => MppError::PaymentOutcomeUnknown {
                transaction_hash: transaction_hash.clone(),
            },
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
    pub fn with_parent_chain_id(mut self, chain_id: u64) -> Self {
        self.parent_chain_id = Some(chain_id);
        self
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
    ) -> Result<bool, MppError> {
        let Some(zone_id) = self.zone_id else {
            return Ok(false);
        };
        if request.amount_u256()?.is_zero() || self.parent_chain_id != Some(chain_id) {
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
        // A withdrawal can't be undone, so start one only when it can settle
        // before the challenge expires; an expired challenge would invite
        // another payment.
        Ok(self.pending_withdrawal(challenge).is_some()
            || settles_before_expiry(challenge, self.settlement_timeout))
    }

    fn pending_key(challenge: &PaymentChallenge) -> String {
        // The whole challenge, so one from another realm or request with the
        // same ID never matches.
        serde_json::to_string(challenge).unwrap_or_else(|_| format!("{challenge:?}"))
    }

    fn pending_withdrawal(&self, challenge: &PaymentChallenge) -> Option<Arc<PendingWithdrawal>> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&Self::pending_key(challenge))
            .cloned()
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

    /// Pay `challenge` from the Zone and wait for its settlement on Tempo
    /// through `tempo`.
    ///
    /// # Errors
    ///
    /// [`MppError::ZoneSettlementPending`] when the withdrawal did not settle
    /// in time: paying the challenge it carries again resumes the wait.
    pub(crate) async fn pay(
        &self,
        challenge: &PaymentChallenge,
        client_id: Option<&str>,
        signer: &TempoPrimitiveSigner,
        signing_mode: &TempoSigningMode,
        tempo: &impl Provider<TempoNetwork>,
    ) -> Result<PaymentCredential, MppError> {
        let zone_id = self.zone_id.ok_or_else(|| {
            MppError::InvalidConfig("Zone ID is unknown: use TempoZone::with_zone_id".into())
        })?;
        let request: ChargeRequest = challenge.request.decode()?;
        let recipient = request.recipient_address()?;

        // A withdrawal can't be undone, so a retry after a failed wait resumes
        // it instead of paying again. Concurrent payments of one challenge
        // share the request, which is stored before it is sent.
        let key = Self::pending_key(challenge);
        let withdrawal = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(key.clone())
            .or_default()
            .clone();
        // The request runs in its own task, so a caller that is cancelled or
        // times out after the transaction is sent still leaves its outcome in
        // the shared cell for the retry to reconcile, instead of sending
        // another withdrawal.
        let task = {
            let zone = self.clone();
            let withdrawal = withdrawal.clone();
            let challenge = challenge.clone();
            let client_id = client_id.map(str::to_owned);
            let signer = signer.clone();
            let signing_mode = signing_mode.clone();
            tokio::spawn(async move {
                let mut own_error = None;
                let outcome = withdrawal
                    .request
                    .get_or_init(|| async {
                        match zone
                            .request_withdrawal(
                                &challenge,
                                client_id.as_deref(),
                                &signer,
                                &signing_mode,
                            )
                            .await
                        {
                            Ok(sender_tag) => Ok(sender_tag),
                            Err((failure, error)) => {
                                own_error = Some(error);
                                Err(failure)
                            }
                        }
                    })
                    .await
                    .clone();
                (outcome, own_error)
            })
        };
        let (outcome, own_error) = task
            .await
            .map_err(|e| MppError::Http(format!("Zone withdrawal request failed: {e}")))?;
        let sender_tag = match outcome {
            Ok(sender_tag) => sender_tag,
            Err(failure) => {
                // Only a failure before the transaction was sent is safe to
                // retry. After that, the withdrawal may have gone through, so
                // retries of this challenge keep failing.
                if matches!(failure, WithdrawalFailure::Retryable(_)) {
                    self.forget(&key, &withdrawal);
                }
                return Err(own_error.unwrap_or_else(|| failure.to_error()));
            }
        };

        let timeout = settlement_timeout(challenge, self.settlement_timeout);
        let settlement = wait_for_settlement_from(
            tempo,
            zone::portal_address(zone_id),
            sender_tag,
            Some(recipient),
            timeout,
            &withdrawal.settlement_cursor,
        )
        .await
        .map_err(|_| MppError::ZoneSettlementPending {
            challenge: Box::new(challenge.clone()),
            challenge_id: challenge.id.clone(),
            sender_tag: format!("{sender_tag:#x}"),
            zone_id,
        })?;
        self.forget(&key, &withdrawal);
        // A bounced payout returned the amount to the payer's Zone balance and
        // paid nothing, so the server would reject its Credential: fail
        // without one, and let a retry withdraw again.
        if settlement.bounced {
            return Err(MppError::Http(format!(
                "Zone withdrawal {sender_tag:#x} bounced on Tempo in {:#x}: its amount was returned to the payer's Zone balance.",
                settlement.hash
            )));
        }
        let hash = settlement.hash;

        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::zone(format!("{hash:#x}"), format!("{sender_tag:#x}"), zone_id),
        ))
    }

    /// Requests a Zone withdrawal of the challenge amount to its recipient,
    /// bound to the challenge by its memo, and returns its sender tag.
    async fn request_withdrawal(
        &self,
        challenge: &PaymentChallenge,
        client_id: Option<&str>,
        signer: &TempoPrimitiveSigner,
        signing_mode: &TempoSigningMode,
    ) -> Result<B256, (WithdrawalFailure, MppError)> {
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
        // Another withdrawal may have held the lock past the time this one
        // needs to settle: send nothing once the challenge would expire first.
        if !settles_before_expiry(challenge, self.settlement_timeout) {
            return Err(retryable(MppError::Http(
                "Zone withdrawal can no longer settle before the challenge expires.".into(),
            )));
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
        let transaction_hash = receipt
            .get("transactionHash")
            .and_then(serde_json::Value::as_str)
            .and_then(|hash| hash.parse::<B256>().ok())
            .unwrap_or(hash);
        // The withdrawal succeeded but can't be found: its outcome is unknown,
        // so no flow pays the challenge another way.
        let requested = withdrawal_requested(&receipt).ok_or_else(unknown)?;
        Ok(zone::sender_tag(
            requested.sender,
            transaction_hash,
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
        let deadline = tokio::time::Instant::now() + self.receipt_recovery_timeout;
        loop {
            let receipt: Result<Option<serde_json::Value>, _> = self
                .rpc_provider
                .raw_request("eth_getTransactionReceipt".into(), [hash])
                .await;
            if let Ok(Some(receipt)) = receipt {
                return Some(receipt);
            }
            if tokio::time::Instant::now() + POLLING_INTERVAL > deadline {
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
    challenge.expires_at().is_some_and(|expires_at| {
        expires_at - time::OffsetDateTime::now_utc() > timeout + SUBMISSION_MARGIN
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
    let settlement =
        wait_for_settlement_from(provider, portal, sender_tag, to, timeout, &Mutex::new(None))
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
async fn wait_for_settlement_from(
    provider: &impl Provider<TempoNetwork>,
    portal: Address,
    sender_tag: B256,
    to: Option<Address>,
    timeout: Duration,
    cursor: &Mutex<Option<u64>>,
) -> Result<Settlement, MppError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let block_number = || async {
        provider
            .get_block_number()
            .await
            .map_err(|e| MppError::Http(format!("failed to fetch the Tempo block number: {e}")))
    };
    let mut latest = block_number().await?;
    // Scan the lookback window once, then only blocks added since the previous
    // poll. A resumed wait searches again from where the first one started,
    // which also covers blocks a lagging log index missed.
    let mut from_block = *cursor
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get_or_insert_with(|| latest.saturating_sub(LOOKBACK_BLOCKS));
    loop {
        if from_block <= latest {
            let mut filter = Filter::new()
                .address(portal)
                .event_signature(IZonePortal::WithdrawalProcessed::SIGNATURE_HASH)
                .topic2(sender_tag)
                .from_block(from_block)
                .to_block(latest);
            if let Some(to) = to {
                filter = filter.topic1(to.into_word());
            }
            let logs = provider
                .get_logs(&filter)
                .await
                .map_err(|e| MppError::Http(format!("failed to fetch Zone settlements: {e}")))?;
            if let Some((log, hash)) = logs
                .iter()
                .find_map(|log| Some((log, log.transaction_hash?)))
            {
                // Only an event that reports a bounce counts as one: the
                // server verifies the Credential's settlement either way.
                let bounced = IZonePortal::WithdrawalProcessed::decode_log_data(log.data())
                    .is_ok_and(|event| !event.callbackSuccess);
                return Ok(Settlement { hash, bounced });
            }
            from_block = latest + 1;
        }
        if tokio::time::Instant::now() + POLLING_INTERVAL > deadline {
            return Err(MppError::Http(format!(
                "Zone withdrawal {sender_tag:#x} did not settle on Tempo within {}ms.",
                timeout.as_millis()
            )));
        }
        tokio::time::sleep(POLLING_INTERVAL).await;
        latest = block_number().await?;
    }
}

#[cfg(test)]
mod tests;
