//! Tempo charge method for server-side payment verification.
//!
//! This module provides [`ChargeMethod`] which implements the [`ChargeMethod`]
//! trait for **Tempo blockchain** payments using alloy's typed Provider.
//!
//! # Tempo-Specific
//!
//! This verifier is designed specifically for the Tempo network (chain ID 42431).
//! It uses Tempo-specific constants and expects a `TempoNetwork` provider.
//! For other chains (Base, Ethereum mainnet, etc.), use separate method modules.
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use mpp::server::{tempo_provider, TempoChargeMethod};
//! use mpp::protocol::traits::ChargeMethod as ChargeMethodTrait;
//! use mpp::store::MemoryStore;
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
//! // The store makes credentials single-use; `TempoChargeMethod::new` has none.
//! let method = TempoChargeMethod::new(provider).with_store(Arc::new(MemoryStore::new()));
//!
//! // In your server handler:
//! let receipt = method.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use alloy::consensus::transaction::SignerRecoverable;
use alloy::eips::Decodable2718;
use alloy::network::ReceiptResponse;
use alloy::primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::simulate::{SimBlock, SimCallResult, SimulatePayload};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use std::future::Future;
use std::sync::Arc;
use tempo_alloy::contracts::precompiles::{
    IAccountKeychain, IStablecoinDEX, ACCOUNT_KEYCHAIN_ADDRESS, ITIP20, STABLECOIN_DEX_ADDRESS,
};
use tempo_alloy::primitives::transaction::{PrimitiveSignature, TempoSignature};
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_alloy::TempoNetwork;
use tokio::sync::OnceCell;

use crate::protocol::core::{ChallengeEcho, PaymentCredential, PaymentPayload, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{
    ChargeMethod as ChargeMethodTrait, ChargeValidation, VerificationError,
};
use crate::store::Store;
use crate::tempo::attribution;

use super::transfers::{get_request_transfers, Transfer};
use super::{
    network::TempoNetwork as KnownTempoNetwork, proof, relay::Relay, RelayConfig, TempoChargeExt,
    CHAIN_ID, INTENT_CHARGE, METHOD_NAME, PATH_USD,
};

const MAX_FEE_PAYER_GAS_LIMIT: u64 = 2_000_000;
const MAX_FEE_PER_GAS_DEFAULT: u128 = 100_000_000_000;
const MAX_PRIORITY_FEE_PER_GAS_DEFAULT: u128 = 10_000_000_000;
const MAX_VALIDITY_WINDOW_SECS_DEFAULT: u64 = 15 * 60;
const MAX_TOTAL_FEE_DEFAULT: u128 = 50_000_000_000_000_000; // lower than max_gas * max_fee_per_gas

/// TIP-20 Transfer event topic: keccak256("Transfer(address,address,uint256)")
/// TIP-20 is Tempo's token standard (compatible with ERC-20 Transfer events).
const TRANSFER_EVENT_TOPIC: B256 =
    alloy::primitives::b256!("ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");

/// TIP-20 TransferWithMemo event topic: keccak256("TransferWithMemo(address,address,uint256,bytes32)")
const TRANSFER_WITH_MEMO_EVENT_TOPIC: B256 =
    alloy::primitives::b256!("57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0");

/// TIP-20 transfer function selector: bytes4(keccak256("transfer(address,uint256)"))
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// TIP-20 transferWithMemo function selector: bytes4(keccak256("transferWithMemo(address,uint256,bytes32)"))
const TRANSFER_WITH_MEMO_SELECTOR: [u8; 4] = [0x95, 0x77, 0x7d, 0x59];

fn no_matching_payment_call_error() -> VerificationError {
    VerificationError::new("Invalid transaction: no matching payment call found".to_string())
}

fn disallowed_fee_payer_call_pattern_error() -> VerificationError {
    VerificationError::new("Fee-sponsored transaction contains disallowed call pattern".to_string())
}

fn call_selector(data: &Bytes) -> Option<[u8; 4]> {
    if data.len() < 4 {
        None
    } else {
        data[..4].try_into().ok()
    }
}

fn decode_approve(call: &tempo_alloy::primitives::transaction::Call) -> Option<(Address, U256)> {
    if call_selector(&call.input) != Some(ITIP20::approveCall::SELECTOR) || call.input.len() != 68 {
        return None;
    }

    Some((
        Address::from_slice(&call.input[16..36]),
        U256::from_be_slice(&call.input[36..68]),
    ))
}

fn decode_swap(
    call: &tempo_alloy::primitives::transaction::Call,
) -> Option<IStablecoinDEX::swapExactAmountOutCall> {
    if call_selector(&call.input) != Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR) {
        return None;
    }

    IStablecoinDEX::swapExactAmountOutCall::abi_decode_raw(&call.input[4..]).ok()
}

fn transfer_call_offset(
    calls: &[tempo_alloy::primitives::transaction::Call],
) -> Result<usize, VerificationError> {
    let first_selector = calls.first().and_then(|call| call_selector(&call.input));

    if first_selector == Some(ITIP20::approveCall::SELECTOR) {
        let second_selector = calls.get(1).and_then(|call| call_selector(&call.input));
        if second_selector != Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR) {
            return Err(no_matching_payment_call_error());
        }
        Ok(2)
    } else if first_selector == Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR) {
        Err(no_matching_payment_call_error())
    } else {
        Ok(0)
    }
}

fn get_transfer_calls(
    calls: &[tempo_alloy::primitives::transaction::Call],
) -> Result<&[tempo_alloy::primitives::transaction::Call], VerificationError> {
    let offset = transfer_call_offset(calls)?;
    let transfer_calls = &calls[offset..];

    if transfer_calls.is_empty()
        || transfer_calls.iter().any(|call| {
            !matches!(
                call_selector(&call.input),
                Some(TRANSFER_SELECTOR) | Some(TRANSFER_WITH_MEMO_SELECTOR)
            )
        })
    {
        return Err(no_matching_payment_call_error());
    }

    Ok(transfer_calls)
}

fn validate_fee_payer_calls(
    calls: &[tempo_alloy::primitives::transaction::Call],
    currency: Address,
    expected: &[Transfer],
) -> Result<(), VerificationError> {
    if calls.is_empty() {
        return Err(disallowed_fee_payer_call_pattern_error());
    }

    let has_swap_prefix = calls.first().and_then(|call| call_selector(&call.input))
        == Some(ITIP20::approveCall::SELECTOR);

    if has_swap_prefix {
        if calls.get(1).and_then(|call| call_selector(&call.input))
            != Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR)
        {
            return Err(disallowed_fee_payer_call_pattern_error());
        }
    } else if calls.first().and_then(|call| call_selector(&call.input))
        == Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR)
    {
        return Err(disallowed_fee_payer_call_pattern_error());
    }

    let transfer_calls = &calls[if has_swap_prefix { 2 } else { 0 }..];
    if transfer_calls.is_empty()
        || transfer_calls.len() > 11
        || transfer_calls.iter().any(|call| {
            !matches!(
                call_selector(&call.input),
                Some(TRANSFER_SELECTOR) | Some(TRANSFER_WITH_MEMO_SELECTOR)
            )
        })
    {
        return Err(disallowed_fee_payer_call_pattern_error());
    }

    if has_swap_prefix {
        let approve_target = match &calls[0].to {
            TxKind::Call(address) => *address,
            _ => return Err(disallowed_fee_payer_call_pattern_error()),
        };
        let swap = decode_swap(&calls[1]).ok_or_else(disallowed_fee_payer_call_pattern_error)?;
        if approve_target != swap.tokenIn {
            return Err(VerificationError::new(
                "Fee-sponsored transaction approve target is not the swap input token".to_string(),
            ));
        }

        let (approve_spender, approve_amount) =
            decode_approve(&calls[0]).ok_or_else(disallowed_fee_payer_call_pattern_error)?;
        if approve_spender != STABLECOIN_DEX_ADDRESS {
            return Err(VerificationError::new(
                "Fee-sponsored transaction approve spender is not the DEX".to_string(),
            ));
        }
        if approve_amount != U256::from(swap.maxAmountIn) {
            return Err(VerificationError::new(
                "Fee-sponsored transaction approve amount does not match the swap max input"
                    .to_string(),
            ));
        }

        match &calls[1].to {
            TxKind::Call(address) if *address == STABLECOIN_DEX_ADDRESS => {}
            _ => {
                return Err(VerificationError::new(
                    "Fee-sponsored transaction swap target is not the DEX".to_string(),
                ));
            }
        }

        if swap.tokenOut != currency {
            return Err(VerificationError::new(
                "Fee-sponsored transaction swap output token is not the payment currency"
                    .to_string(),
            ));
        }
        let payment_amount = expected.iter().fold(U256::ZERO, |sum, transfer| {
            sum.saturating_add(transfer.amount)
        });
        if U256::from(swap.amountOut) != payment_amount {
            return Err(VerificationError::new(
                "Fee-sponsored transaction swap output does not match the payment amount"
                    .to_string(),
            ));
        }
    }

    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchedTransferLog {
    Transfer,
    Memo([u8; 32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedTransferLog {
    Transfer {
        address: Address,
        amount: U256,
        from: Address,
        to: Address,
    },
    Memo {
        address: Address,
        amount: U256,
        from: Address,
        memo: [u8; 32],
        to: Address,
    },
}

struct ReceiptSenderPolicy<'a> {
    expected_sender: Address,
    source: Option<&'a str>,
    validate_sender: Option<&'a ValidateSenderCallback>,
    transaction_sender: Address,
    settlement_senders: &'a [Address],
}

impl ParsedTransferLog {
    fn address(&self) -> Address {
        match self {
            Self::Transfer { address, .. } | Self::Memo { address, .. } => *address,
        }
    }

    fn amount(&self) -> U256 {
        match self {
            Self::Transfer { amount, .. } | Self::Memo { amount, .. } => *amount,
        }
    }

    fn from(&self) -> Address {
        match self {
            Self::Transfer { from, .. } | Self::Memo { from, .. } => *from,
        }
    }

    fn matched(&self) -> MatchedTransferLog {
        match self {
            Self::Transfer { .. } => MatchedTransferLog::Transfer,
            Self::Memo { memo, .. } => MatchedTransferLog::Memo(*memo),
        }
    }

    fn memo(&self) -> Option<[u8; 32]> {
        match self {
            Self::Transfer { .. } => None,
            Self::Memo { memo, .. } => Some(*memo),
        }
    }

    fn to(&self) -> Address {
        match self {
            Self::Transfer { to, .. } | Self::Memo { to, .. } => *to,
        }
    }

    /// Whether `self` and `other` are the `Transfer` and `TransferWithMemo`
    /// events of the same transfer.
    fn is_twin_of(&self, other: &Self) -> bool {
        self.memo().is_some() != other.memo().is_some()
            && self.address() == other.address()
            && self.from() == other.from()
            && self.to() == other.to()
            && self.amount() == other.amount()
    }
}

fn parse_receipt_transfer_log(log: &serde_json::Value) -> Option<ParsedTransferLog> {
    let address = log
        .get("address")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Address>().ok())?;

    let topics: Vec<&str> = log
        .get("topics")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())?;
    if topics.len() < 3 {
        return None;
    }

    let topic0 = topics[0].parse::<B256>().ok()?;
    let from = topics[1]
        .parse::<B256>()
        .ok()
        .map(|b| Address::from_slice(&b[12..]))?;
    let to = topics[2]
        .parse::<B256>()
        .ok()
        .map(|b| Address::from_slice(&b[12..]))?;

    let data = log.get("data").and_then(|v| v.as_str()).unwrap_or("0x");
    if topic0 == TRANSFER_EVENT_TOPIC {
        if data.len() < 66 {
            return None;
        }

        let amount = U256::from_str_radix(&data[2..66], 16).ok()?;
        return Some(ParsedTransferLog::Transfer {
            address,
            amount,
            from,
            to,
        });
    }

    if topic0 == TRANSFER_WITH_MEMO_EVENT_TOPIC {
        if topics.len() < 4 || data.len() < 66 {
            return None;
        }

        let amount = U256::from_str_radix(&data[2..66], 16).ok()?;
        let memo = topics[3].parse::<B256>().ok().map(|bytes| bytes.0)?;
        return Some(ParsedTransferLog::Memo {
            address,
            amount,
            from,
            memo,
            to,
        });
    }

    None
}

/// Parse receipt logs into transfer effects, one per token transfer.
///
/// TIP-20 `transferWithMemo` emits `Transfer` immediately followed by
/// `TransferWithMemo` for the same transfer. Such adjacent pairs are merged
/// into one memo effect so a single transfer cannot satisfy two expected
/// transfers.
fn receipt_transfer_effects(logs: &[serde_json::Value]) -> Vec<ParsedTransferLog> {
    let mut parsed = logs.iter().map(parse_receipt_transfer_log).peekable();
    let mut effects = Vec::new();

    while let Some(log) = parsed.next() {
        let Some(log) = log else {
            continue;
        };
        let twin = parsed
            .peek()
            .and_then(|next| next.filter(|next| log.is_twin_of(next)));
        if let Some(twin) = twin {
            parsed.next();
            effects.push(if log.memo().is_some() { log } else { twin });
        } else {
            effects.push(log);
        }
    }

    effects
}

/// Parse a hash credential `source`: `Ok(None)` if absent, `Ok(Some(address))`
/// for a `did:pkh:eip155` DID matching `expected_chain_id`, else `Err`.
fn parse_hash_credential_source(
    source: Option<&str>,
    expected_chain_id: u64,
) -> Result<Option<Address>, VerificationError> {
    let Some(source) = source else {
        return Ok(None);
    };

    let invalid = || VerificationError::new("Hash credential source is invalid.");

    let parsed = proof::parse_proof_source(source).map_err(|_| invalid())?;
    if parsed.chain_id != expected_chain_id {
        return Err(invalid());
    }

    Ok(Some(parsed.address))
}

/// Check a transaction credential `source` against the recovered transaction
/// sender: `Ok` if absent or a `did:pkh:eip155` DID for `expected_chain_id`
/// naming `sender`, else `Err`.
fn ensure_transaction_credential_source(
    source: Option<&str>,
    sender: Address,
    expected_chain_id: u64,
) -> Result<(), VerificationError> {
    let Some(source) = source else {
        return Ok(());
    };

    let invalid = || VerificationError::new("Transaction credential source is invalid.");

    let parsed = proof::parse_proof_source(source).map_err(|_| invalid())?;
    if parsed.chain_id != expected_chain_id {
        return Err(invalid());
    }
    if parsed.address != sender {
        return Err(VerificationError::new(
            "Transaction credential source does not match the transaction sender.",
        ));
    }

    Ok(())
}

#[cfg(test)]
fn match_receipt_transfer_logs(
    logs: &[serde_json::Value],
    expected_sender: Address,
    currency: Address,
    expected: &[Transfer],
    source: Option<&str>,
    validate_sender: Option<&ValidateSenderCallback>,
) -> Result<Vec<MatchedTransferLog>, VerificationError> {
    match_receipt_transfer_logs_with_settlement(
        logs,
        currency,
        expected,
        ReceiptSenderPolicy {
            expected_sender,
            source,
            validate_sender,
            transaction_sender: expected_sender,
            settlement_senders: &[],
        },
    )
}

fn match_receipt_transfer_logs_with_settlement(
    logs: &[serde_json::Value],
    currency: Address,
    expected: &[Transfer],
    sender_policy: ReceiptSenderPolicy<'_>,
) -> Result<Vec<MatchedTransferLog>, VerificationError> {
    let mut sorted_expected: Vec<(usize, &Transfer)> = expected.iter().enumerate().collect();
    sorted_expected.sort_by_key(|(_, t)| if t.memo.is_some() { 0 } else { 1 });

    let parsed_logs = receipt_transfer_effects(logs);
    let mut used_logs: Vec<bool> = vec![false; parsed_logs.len()];
    let mut matched_logs = Vec::with_capacity(expected.len());

    for (_, transfer) in &sorted_expected {
        if transfer.amount.is_zero() {
            return Err(VerificationError::new(
                "Invalid amount: expected_amount must be greater than zero".to_string(),
            ));
        }
        if transfer.recipient.is_zero() {
            return Err(VerificationError::new(
                "Invalid recipient: expected_recipient cannot be the zero address".to_string(),
            ));
        }

        let find_match = |prefer_memo: bool| {
            for (log_idx, parsed) in parsed_logs.iter().enumerate() {
                if used_logs[log_idx] {
                    continue;
                }

                if parsed.address() != currency
                    || parsed.to() != transfer.recipient
                    || parsed.amount() != transfer.amount
                {
                    continue;
                }

                if let Some(exp_memo) = transfer.memo {
                    if parsed.memo() != Some(exp_memo) {
                        continue;
                    }
                } else if prefer_memo != parsed.memo().is_some() {
                    continue;
                }

                // On a sender mismatch, validate_sender may authorize the log.
                let sender = parsed.from();
                if sender != sender_policy.expected_sender {
                    let authorized = (sender_policy.transaction_sender
                        == sender_policy.expected_sender
                        && sender_policy.settlement_senders.contains(&sender))
                        || sender_policy.validate_sender.is_some_and(|cb| {
                            cb(SenderValidation {
                                expected_sender: sender_policy.expected_sender,
                                sender,
                                source: sender_policy.source,
                            })
                        });
                    if !authorized {
                        continue;
                    }
                }

                return Some((log_idx, parsed.matched()));
            }

            None
        };

        let matched = if transfer.memo.is_some() {
            find_match(true)
        } else {
            find_match(true).or_else(|| find_match(false))
        };

        let Some((log_idx, matched_log)) = matched else {
            return Err(VerificationError::new(format!(
                "No matching transfer event found for {} to {}{}",
                transfer.amount,
                transfer.recipient,
                if transfer.memo.is_some() {
                    " with memo"
                } else {
                    ""
                }
            )));
        };

        used_logs[log_idx] = true;
        matched_logs.push(matched_log);
    }

    Ok(matched_logs)
}

fn assert_challenge_bound_memo(
    matched_logs: &[MatchedTransferLog],
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    let memos = matched_logs.iter().filter_map(|log| match log {
        MatchedTransferLog::Transfer => None,
        MatchedTransferLog::Memo(memo) => Some(memo),
    });
    assert_challenge_bound_memos(memos, challenge_id, realm)
}

/// Require a challenge-bound attribution memo among the memos of the matched
/// transfers, and reject MPP attribution for any other challenge or server.
///
/// Otherwise one transaction could carry attribution for several challenges
/// and be accepted for each of them. Non-MPP memos are ignored.
fn assert_challenge_bound_memos<'a>(
    memos: impl IntoIterator<Item = &'a [u8; 32]>,
    challenge_id: &str,
    realm: &str,
) -> Result<(), VerificationError> {
    let mut bound = false;
    for memo in memos {
        if !attribution::is_mpp_memo(memo) {
            continue;
        }
        if !is_challenge_bound_memo(memo, challenge_id, realm) {
            return Err(challenge_bound_memo_error());
        }
        bound = true;
    }

    if bound {
        Ok(())
    } else {
        Err(challenge_bound_memo_error())
    }
}

fn is_challenge_bound_memo(memo: &[u8; 32], challenge_id: &str, realm: &str) -> bool {
    attribution::verify_server(memo, realm)
        && attribution::verify_challenge_binding(memo, challenge_id)
}

fn challenge_bound_memo_error() -> VerificationError {
    VerificationError::new("Payment verification failed: memo is not bound to this challenge.")
}

#[derive(Debug, Clone, Copy, Default)]
struct TransactionValidationOptions<'a> {
    require_exact_calls: bool,
    machine_token_enabled: bool,
    challenge_binding: Option<(&'a str, &'a str)>,
}

/// Arguments passed to a [`ValidateSenderCallback`] on a sender mismatch.
#[derive(Debug, Clone, Copy)]
pub struct SenderValidation<'a> {
    /// The expected sender (source address, or receipt sender if no source).
    pub expected_sender: Address,
    /// The actual `from` address on the transfer log.
    pub sender: Address,
    /// The raw credential source DID, if provided.
    pub source: Option<&'a str>,
}

/// Authorizes a transfer whose sender differs from the expected sender;
/// return `true` to accept.
pub type ValidateSenderCallback =
    dyn for<'a> Fn(SenderValidation<'a>) -> bool + Send + Sync + 'static;

fn request_settlement_senders(charge: &ChargeRequest, chain_id: u64) -> Vec<Address> {
    if charge.machine_token_enabled() {
        super::machine_token::settlement_sender(chain_id)
            .into_iter()
            .collect()
    } else {
        Vec::new()
    }
}

/// Reject a credential whose submission mode the challenge does not allow.
///
/// `type="hash"` is `push` mode and `type="transaction"` is `pull` mode.
/// `methodDetails.supportedModes`, when present, lists the allowed modes.
/// Proof credentials are exempt: zero-amount charges have no submission mode.
fn ensure_submission_mode_allowed(
    charge: &ChargeRequest,
    payload: &PaymentPayload,
) -> Result<(), VerificationError> {
    let (mode, kind) = if payload.is_hash() {
        ("push", "Hash")
    } else if payload.is_transaction() {
        ("pull", "Transaction")
    } else {
        return Ok(());
    };

    let supported_modes = charge
        .method_details
        .as_ref()
        .and_then(|details| details.get("supportedModes"))
        .filter(|modes| !modes.is_null());
    if let Some(supported_modes) = supported_modes {
        let supported = supported_modes
            .as_array()
            .is_some_and(|modes| modes.iter().any(|m| m.as_str() == Some(mode)));
        if !supported {
            return Err(VerificationError::new(format!(
                "{kind} credentials are not supported for this challenge."
            )));
        }
    }

    Ok(())
}

/// Tempo charge method for one-time payment verification.
///
/// This is a **Tempo-specific** payment verifier. It expects:
/// - `method="tempo"` in the credential
/// - Chain ID 42431 (Tempo Moderato) by default
/// - A provider configured for `TempoNetwork`
///
/// For other chains (Base, Ethereum), use or create separate method modules.
///
/// # Verification Flow
///
/// 1. Parse the credential payload (hash or signed transaction)
/// 2. For transaction credentials: validate call data before broadcasting
/// 3. Fetch the transaction receipt from Tempo RPC
/// 4. Verify transfer amount, recipient, and currency match
///
/// # Credential Types
///
/// - `hash`: Client already broadcast the transaction, provides tx hash
/// - `transaction`: Client provides signed transaction for server to broadcast
///
/// # Example
///
/// ```ignore
/// use std::sync::Arc;
/// use mpp::server::{tempo_provider, TempoChargeMethod};
/// use mpp::protocol::traits::ChargeMethod as ChargeMethodTrait;
/// use mpp::store::MemoryStore;
///
/// let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
/// // The store makes credentials single-use; `TempoChargeMethod::new` has none.
/// let method = TempoChargeMethod::new(provider).with_store(Arc::new(MemoryStore::new()));
///
/// // Verify a payment
/// let receipt = method.verify(&credential, &request).await?;
/// if receipt.is_success() {
///     println!("Payment verified: {}", receipt.reference);
/// }
/// ```
#[derive(Clone)]
pub struct ChargeMethod<P> {
    provider: Arc<P>,
    fee_payer_signer: Option<Arc<super::DynSigner>>,
    store: Option<Arc<dyn Store>>,
    cached_chain_id: Arc<OnceCell<u64>>,
    fee_payer_policy_override: Option<FeePayerPolicyOverride>,
    validate_sender: Option<Arc<ValidateSenderCallback>>,
    fee_payer_allowed_fee_tokens: Option<Vec<Address>>,
    relay: Option<Relay>,
    fee_payer_fee_token: Option<Address>,
    fee_payer_allow_key_authorization: bool,
}

#[derive(Debug, Clone)]
pub struct FeePayerPolicy {
    pub max_gas: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub max_total_fee: u128,
    pub max_validity_window_seconds: u64,
}

#[derive(Debug, Clone, Default)]
pub struct FeePayerPolicyOverride {
    pub max_gas: Option<u64>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub max_total_fee: Option<u128>,
    pub max_validity_window_seconds: Option<u64>,
}

impl Default for FeePayerPolicy {
    fn default() -> FeePayerPolicy {
        Self::get_by_chain_id(CHAIN_ID)
    }
}

impl FeePayerPolicy {
    /// Merge overrides onto the per-chain default.
    pub fn resolve(chain_id: u64, overrides: Option<&FeePayerPolicyOverride>) -> Self {
        let mut policy = Self::get_by_chain_id(chain_id);
        if let Some(o) = overrides {
            policy.max_gas = o.max_gas.unwrap_or(policy.max_gas);
            policy.max_fee_per_gas = o.max_fee_per_gas.unwrap_or(policy.max_fee_per_gas);
            policy.max_priority_fee_per_gas = o
                .max_priority_fee_per_gas
                .unwrap_or(policy.max_priority_fee_per_gas);
            policy.max_total_fee = o.max_total_fee.unwrap_or(policy.max_total_fee);
            policy.max_validity_window_seconds = o
                .max_validity_window_seconds
                .unwrap_or(policy.max_validity_window_seconds);
        }
        policy
    }

    /// Return the default sponsor fee-token allowlist for a transaction chain.
    ///
    /// pathUSD, then the chain's default currency when known (mainnet:
    /// pathUSD and USDC.e; Moderato and unknown chains: pathUSD), matching
    /// mppx. The allowlist is independent of the charge currency, so charges
    /// in other tokens (for example OUSD) are sponsored with one of these.
    pub fn default_allowed_fee_tokens(chain_id: u64) -> Vec<Address> {
        default_fee_payer_allowed_fee_tokens(chain_id)
    }

    /// Check whether the default sponsor allowlist accepts `fee_token`.
    pub fn default_allows_fee_token(chain_id: u64, fee_token: Address) -> bool {
        fee_token_allowed(&Self::default_allowed_fee_tokens(chain_id), fee_token)
    }

    fn get_by_chain_id(chain_id: u64) -> Self {
        let network = KnownTempoNetwork::from_chain_id(chain_id);
        let mut policy = Self {
            max_gas: MAX_FEE_PAYER_GAS_LIMIT,
            max_fee_per_gas: MAX_FEE_PER_GAS_DEFAULT,
            max_priority_fee_per_gas: MAX_PRIORITY_FEE_PER_GAS_DEFAULT,
            max_total_fee: MAX_TOTAL_FEE_DEFAULT,
            max_validity_window_seconds: MAX_VALIDITY_WINDOW_SECS_DEFAULT,
        };
        if network == Some(KnownTempoNetwork::Moderato) {
            // Moderato regularly needs a higher priority fee than mainnet.
            policy.max_priority_fee_per_gas = 50_000_000_000;
        }
        policy
    }
}

fn default_fee_payer_allowed_fee_tokens(chain_id: u64) -> Vec<Address> {
    let mut tokens = vec![PATH_USD
        .parse::<Address>()
        .expect("pathUSD is a valid address")];
    if let Some(network) = KnownTempoNetwork::from_chain_id(chain_id) {
        let token = network
            .default_currency()
            .parse()
            .expect("default Tempo fee token is a valid address");
        if !tokens.contains(&token) {
            tokens.push(token);
        }
    }
    tokens
}

fn fee_token_allowed(allowed_fee_tokens: &[Address], fee_token: Address) -> bool {
    allowed_fee_tokens.contains(&fee_token)
}

/// `tempo_simulateV1` response; we only read the per-call status.
#[derive(Debug, Clone, serde::Deserialize)]
struct TempoSimulateResponse {
    #[serde(default)]
    blocks: Vec<TempoSimulateBlock>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct TempoSimulateBlock {
    #[serde(default)]
    calls: Vec<SimCallResult>,
}

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Create a new Tempo charge method with the given alloy Provider.
    ///
    /// The provider must be configured for `TempoNetwork`. Use
    /// [`tempo_provider`](crate::server::tempo_provider) to create one.
    ///
    /// No replay store is configured. Until [`with_store`](Self::with_store) is
    /// called, a hash or proof credential is accepted again for as long as its
    /// challenge is valid. [`Mpp::create`](crate::server::Mpp::create) configures
    /// an in-memory store by default.
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
            fee_payer_signer: None,
            store: None,
            cached_chain_id: Arc::new(OnceCell::new()),
            fee_payer_policy_override: None,
            validate_sender: None,
            fee_payer_allowed_fee_tokens: None,
            relay: None,
            fee_payer_fee_token: None,
            fee_payer_allow_key_authorization: true,
        }
    }

    /// Delegate credential validation and finalization to a Tempo API relay.
    ///
    /// The relay broadcasts pull credentials and finalizes already-broadcast
    /// push credentials without submitting them again.
    pub fn with_relay(mut self, config: RelayConfig) -> crate::error::Result<Self> {
        self.relay = Some(Relay::new(config)?);
        Ok(self)
    }

    /// Set a callback invoked when a hash-credential transfer's sender differs
    /// from the expected sender; returning `true` accepts the transfer.
    pub fn with_validate_sender<F>(mut self, validate_sender: F) -> Self
    where
        F: for<'a> Fn(SenderValidation<'a>) -> bool + Send + Sync + 'static,
    {
        self.validate_sender = Some(Arc::new(validate_sender));
        self
    }

    /// Override the fee-sponsor policy applied to fee-payer envelopes.
    ///
    /// Each unset field falls back to the per-chain default. Use to raise or
    /// lower `max_gas`, `max_fee_per_gas`, `max_priority_fee_per_gas`,
    /// `max_total_fee`, or `max_validity_window_seconds` per server.
    pub fn with_fee_payer_policy_override(mut self, overrides: FeePayerPolicyOverride) -> Self {
        self.fee_payer_policy_override = Some(overrides);
        self
    }

    /// Replace the default sponsor fee-token allowlist.
    ///
    /// By default, fee-payer co-signing accepts pathUSD and the known default
    /// currency for the transaction chain ID (see
    /// [`FeePayerPolicy::default_allowed_fee_tokens`]). Use this to restrict
    /// or widen the accepted fee tokens for a server.
    pub fn with_fee_payer_allowed_fee_tokens(mut self, allowed_fee_tokens: Vec<Address>) -> Self {
        self.fee_payer_allowed_fee_tokens = Some(allowed_fee_tokens);
        self
    }

    #[cfg(test)]
    pub(crate) fn fee_payer_allowed_fee_tokens(&self) -> Option<&[Address]> {
        self.fee_payer_allowed_fee_tokens.as_deref()
    }

    /// Set the token the local fee payer uses to pay gas.
    ///
    /// When unset, the fee payer uses the first token in the fee-token
    /// allowlist it holds a nonzero balance of, falling back to the first
    /// allowed token. An explicit token must also be in the allowlist.
    pub fn with_fee_payer_fee_token(mut self, fee_token: Address) -> Self {
        self.fee_payer_fee_token = Some(fee_token);
        self
    }

    /// Set whether a sponsored transaction may install an access key.
    ///
    /// Allowed by default, matching mppx. A key authorization adds intrinsic
    /// gas the fee payer pays for; pass `false` to reject sponsored
    /// transactions that carry one.
    pub fn with_fee_payer_allow_key_authorization(mut self, allow: bool) -> Self {
        self.fee_payer_allow_key_authorization = allow;
        self
    }

    /// Configure a store for replay deduplication.
    ///
    /// When set, each verified transaction hash is recorded and subsequent
    /// attempts to replay the same hash are rejected. Zero-amount proof
    /// challenges are likewise made single-use per challenge id.
    ///
    /// The store must support atomic [`Store::put_if_absent`], else verification
    /// fails closed with `StoreError::AtomicUnsupported`.
    pub fn with_store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Configure a fee payer signer for sponsoring transaction fees.
    ///
    /// When set, requests with `feePayer: true` will be accepted and
    /// broadcast. Without a fee payer signer, such requests are rejected.
    pub fn with_fee_payer<S>(mut self, signer: S) -> Self
    where
        S: alloy::signers::Signer + Send + Sync + 'static,
    {
        self.fee_payer_signer = Some(Arc::new(signer));
        self
    }

    pub(crate) fn with_fee_payer_arc(mut self, signer: Arc<super::DynSigner>) -> Self {
        self.fee_payer_signer = Some(signer);
        self
    }

    /// Get a reference to the underlying provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Compute the expected transfers from a charge request (primary + splits).
    fn expected_transfers(charge: &ChargeRequest) -> Result<Vec<Transfer>, VerificationError> {
        get_request_transfers(charge)
            .map_err(|e| VerificationError::new(format!("Invalid charge request: {e}")))
    }

    async fn verify_hash(
        &self,
        tx_hash: &str,
        charge: &ChargeRequest,
        source: Option<&str>,
        expected_chain_id: u64,
        challenge: &ChallengeEcho,
        reserve: bool,
    ) -> Result<Receipt, VerificationError> {
        // Validate the source before reserving the hash.
        let source_address = parse_hash_credential_source(source, expected_chain_id)?;

        let hash = tx_hash
            .parse::<B256>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction hash: {}", e)))?;

        let replay_key = format!("mpp:charge:{:#x}", hash);

        let receipt = self
            .provider
            .get_transaction_receipt(hash)
            .await
            .map_err(|e| {
                VerificationError::network_error(format!("Failed to fetch receipt: {}", e))
            })?
            .ok_or_else(|| {
                VerificationError::pending(format!(
                    "Transaction {} not found or not yet mined",
                    tx_hash
                ))
            })?;

        if !receipt.status() {
            return Err(VerificationError::transaction_failed(format!(
                "Transaction {} reverted",
                tx_hash
            )));
        }

        let currency = charge.currency_address().map_err(|e| {
            VerificationError::new(format!("Invalid currency address in request: {}", e))
        })?;
        let expected = Self::expected_transfers(charge)?;

        // Use the source address if present, otherwise the receipt sender.
        let expected_sender = source_address.unwrap_or_else(|| receipt.from());

        // Tempo uses TIP-20 tokens exclusively (no native token transfers)
        let matched_logs = self.verify_tip20_transfers(
            &receipt,
            currency,
            &expected,
            ReceiptSenderPolicy {
                expected_sender,
                source,
                validate_sender: self.validate_sender.as_deref(),
                transaction_sender: receipt.from(),
                settlement_senders: &request_settlement_senders(charge, expected_chain_id),
            },
        )?;

        assert_challenge_bound_memo(&matched_logs, &challenge.id, &challenge.realm)?;

        if let Some(store) = &self.store {
            if reserve {
                let claimed = store
                    .put_if_absent(&replay_key, serde_json::Value::Bool(true))
                    .await
                    .map_err(|e| {
                        VerificationError::internal(format!("Failed to record tx hash: {e}"))
                    })?;
                if !claimed {
                    return Err(VerificationError::new(
                        "Transaction hash has already been used.",
                    ));
                }
            } else if store
                .get(&replay_key)
                .await
                .map_err(|e| VerificationError::internal(format!("Failed to check tx hash: {e}")))?
                .is_some()
            {
                return Err(VerificationError::new(
                    "Transaction hash has already been used.",
                ));
            }
        }

        Ok(Receipt::success(METHOD_NAME, format!("{hash:#x}")))
    }

    /// Verify that all expected transfers are present in the receipt logs.
    ///
    /// Uses order-insensitive matching: sorts expected transfers by memo-specificity
    /// (transfers with memos matched first) and uses a `used` set to prevent
    /// double-matching.
    fn verify_tip20_transfers(
        &self,
        receipt: &<TempoNetwork as alloy::network::Network>::ReceiptResponse,
        currency: Address,
        expected: &[Transfer],
        sender_policy: ReceiptSenderPolicy<'_>,
    ) -> Result<Vec<MatchedTransferLog>, VerificationError> {
        let receipt_json = serde_json::to_value(receipt).map_err(|e| {
            VerificationError::internal(format!("Failed to serialize receipt: {}", e))
        })?;

        let logs = receipt_json
            .get("logs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| VerificationError::new("Receipt has no logs".to_string()))?;

        match_receipt_transfer_logs_with_settlement(logs, currency, expected, sender_policy)
    }

    /// Validate that a transaction contains all expected payment calls (supports splits).
    ///
    /// Uses order-insensitive matching with memo-specificity sorting.
    #[cfg(test)]
    fn validate_transaction_transfers(
        &self,
        tx_bytes: &[u8],
        currency: Address,
        expected: &[Transfer],
        expected_chain_id: u64,
        require_exact_calls: bool,
    ) -> Result<(), VerificationError> {
        self.validate_transaction_transfers_with_machine_token(
            tx_bytes,
            currency,
            expected,
            expected_chain_id,
            TransactionValidationOptions {
                require_exact_calls,
                ..Default::default()
            },
        )
        .map(|_| ())
    }

    fn validate_transaction_transfers_with_machine_token(
        &self,
        tx_bytes: &[u8],
        currency: Address,
        expected: &[Transfer],
        expected_chain_id: u64,
        options: TransactionValidationOptions<'_>,
    ) -> Result<Option<Address>, VerificationError> {
        let TransactionValidationOptions {
            require_exact_calls,
            machine_token_enabled,
            challenge_binding,
        } = options;

        if currency.is_zero() {
            return Err(VerificationError::new(
                "Invalid currency: currency cannot be the zero address".to_string(),
            ));
        }

        // Skip type byte (0x76) for Tempo transactions
        let tx_data = if !tx_bytes.is_empty()
            && tx_bytes[0] == tempo_alloy::primitives::transaction::TEMPO_TX_TYPE_ID
        {
            &tx_bytes[1..]
        } else {
            tx_bytes
        };

        let signed = tempo_alloy::primitives::AASigned::rlp_decode(&mut &tx_data[..])
            .map_err(|e| VerificationError::new(format!("Failed to decode transaction: {}", e)))?;
        let tx = signed.tx();

        if tx.chain_id != expected_chain_id {
            return Err(VerificationError::new(format!(
                "Transaction chain_id mismatch: expected {}, got {}",
                expected_chain_id, tx.chain_id
            )));
        }

        let policy =
            FeePayerPolicy::resolve(expected_chain_id, self.fee_payer_policy_override.as_ref());

        if require_exact_calls && tx.gas_limit > policy.max_gas {
            return Err(VerificationError::new(format!(
                "Fee-sponsored transaction gas limit {} exceeds maximum {}",
                tx.gas_limit, policy.max_gas
            )));
        }

        let machine_token_route = machine_token_enabled
            .then(|| {
                super::machine_token::match_route(&tx.calls, expected_chain_id, currency, expected)
            })
            .flatten();

        if let Some(route) = machine_token_route {
            if let Some((challenge_id, realm)) = challenge_binding {
                let memo = route.transfer.memo.ok_or_else(challenge_bound_memo_error)?;
                if !is_challenge_bound_memo(&memo, challenge_id, realm) {
                    return Err(challenge_bound_memo_error());
                }
            }
            return Ok(Some(route.settlement_sender));
        }

        let transfer_calls = get_transfer_calls(&tx.calls)?;

        if require_exact_calls {
            validate_fee_payer_calls(&tx.calls, currency, expected)?;
        }

        // Sort expected transfers: memo-bearing first for greedy-safe matching
        let mut sorted_expected: Vec<(usize, &Transfer)> = expected.iter().enumerate().collect();
        sorted_expected.sort_by_key(|(_, t)| if t.memo.is_some() { 0 } else { 1 });

        let mut used_calls: Vec<bool> = vec![false; transfer_calls.len()];
        let mut matched_memos: Vec<[u8; 32]> = Vec::new();

        if require_exact_calls && transfer_calls.len() != expected.len() {
            return Err(VerificationError::new(format!(
                "Invalid transaction: no matching payment call found (expected {} transfer calls, got {})",
                expected.len(),
                transfer_calls.len()
            )));
        }

        for (_, transfer) in &sorted_expected {
            if transfer.amount.is_zero() {
                return Err(VerificationError::new(
                    "Invalid amount: expected_amount must be greater than zero".to_string(),
                ));
            }
            if transfer.recipient.is_zero() {
                return Err(VerificationError::new(
                    "Invalid recipient: expected_recipient cannot be the zero address".to_string(),
                ));
            }

            let mut found = false;

            for (call_idx, call) in transfer_calls.iter().enumerate() {
                if used_calls[call_idx] {
                    continue;
                }

                let call_to = match &call.to {
                    TxKind::Call(addr) => addr,
                    TxKind::Create => continue,
                };
                if call_to != &currency {
                    continue;
                }

                let data = &call.input;
                if data.len() < 4 {
                    continue;
                }

                let selector: [u8; 4] = data[..4].try_into().unwrap_or([0; 4]);

                if let Some(exp_memo) = &transfer.memo {
                    if selector == TRANSFER_WITH_MEMO_SELECTOR && data.len() == 100 {
                        let to = Address::from_slice(&data[16..36]);
                        let amount = U256::from_be_slice(&data[36..68]);
                        let memo_bytes = B256::from_slice(&data[68..100]);

                        if to == transfer.recipient
                            && amount == transfer.amount
                            && memo_bytes == B256::from(*exp_memo)
                        {
                            used_calls[call_idx] = true;
                            matched_memos.push(*exp_memo);
                            found = true;
                            break;
                        }
                    }
                } else {
                    // No memo — accept transfer or transferWithMemo
                    if selector == TRANSFER_SELECTOR && data.len() == 68 {
                        let to = Address::from_slice(&data[16..36]);
                        let amount = U256::from_be_slice(&data[36..68]);

                        if to == transfer.recipient && amount == transfer.amount {
                            used_calls[call_idx] = true;
                            found = true;
                            break;
                        }
                    }
                    if !found && selector == TRANSFER_WITH_MEMO_SELECTOR && data.len() == 100 {
                        let to = Address::from_slice(&data[16..36]);
                        let amount = U256::from_be_slice(&data[36..68]);
                        let memo = B256::from_slice(&data[68..100]);

                        if to == transfer.recipient && amount == transfer.amount {
                            used_calls[call_idx] = true;
                            matched_memos.push(memo.0);
                            found = true;
                            break;
                        }
                    }
                }
            }

            if !found {
                return Err(VerificationError::new(format!(
                    "Invalid transaction: no matching transfer call found for {} to {}{}",
                    transfer.amount,
                    transfer.recipient,
                    if transfer.memo.is_some() {
                        " with memo"
                    } else {
                        ""
                    }
                )));
            }
        }

        if require_exact_calls && !used_calls.iter().all(|used| *used) {
            return Err(VerificationError::new(
                "Fee-sponsored transaction contains unexpected calls".to_string(),
            ));
        }

        if let Some((challenge_id, realm)) = challenge_binding {
            assert_challenge_bound_memos(&matched_memos, challenge_id, realm)?;
        }

        Ok(None)
    }

    async fn validate_proof_credential(
        &self,
        credential: &PaymentCredential,
        signature: &str,
        expected_chain_id: u64,
    ) -> Result<Address, VerificationError> {
        let source = credential
            .source
            .as_deref()
            .ok_or_else(|| VerificationError::new("Proof credential must include a source."))?;
        let parsed_source = proof::parse_proof_source(source)
            .map_err(|_| VerificationError::new("Proof credential source is invalid."))?;

        if parsed_source.chain_id != expected_chain_id {
            return Err(VerificationError::new(
                "Proof credential source is invalid.",
            ));
        }

        if !proof::verify_proof(
            parsed_source.address,
            expected_chain_id,
            &credential.challenge.id,
            &credential.challenge.realm,
            signature,
            parsed_source.address,
        ) {
            let recovered = proof::recover_proof_signer(
                parsed_source.address,
                expected_chain_id,
                &credential.challenge.id,
                &credential.challenge.realm,
                signature,
            )
            .map_err(|_| VerificationError::new("Proof signature does not match source."))?;

            let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, &*self.provider);
            let key_info = keychain
                .getKey(parsed_source.address, recovered)
                .call()
                .await
                .map_err(|_| VerificationError::new("Proof signature does not match source."))?;
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if key_info.expiry == 0 || key_info.isRevoked || key_info.expiry <= now_secs {
                return Err(VerificationError::new(
                    "Proof signature does not match source.",
                ));
            }
        }

        Ok(parsed_source.address)
    }

    async fn reserve_proof_credential(
        &self,
        credential: &PaymentCredential,
    ) -> Result<(), VerificationError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let reserved = store
            .put_if_absent(
                &Self::proof_replay_key(credential),
                serde_json::Value::Bool(true),
            )
            .await
            .map_err(|e| VerificationError::internal(format!("Failed to record proof: {e}")))?;
        if !reserved {
            return Err(VerificationError::new(
                "Proof credential has already been used.",
            ));
        }
        Ok(())
    }

    /// Replay key for a proof credential: a challenge id is single-use, no
    /// matter which account or signature proves it.
    fn proof_replay_key(credential: &PaymentCredential) -> String {
        format!("mpp:charge:proof:{}", credential.challenge.id)
    }

    fn validate_transaction_credential(
        &self,
        signed_tx: &str,
        charge: &ChargeRequest,
        expected_chain_id: u64,
        challenge_id: &str,
        realm: &str,
    ) -> Result<Address, VerificationError> {
        use alloy::eips::Encodable2718;

        let tx_bytes = signed_tx
            .parse::<Bytes>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction bytes: {e}")))?;
        let currency = charge.currency_address().map_err(|e| {
            VerificationError::new(format!("Invalid currency address in request: {e}"))
        })?;
        let expected = Self::expected_transfers(charge)?;

        if charge.fee_payer() {
            if self.fee_payer_signer.is_none() {
                return Err(VerificationError::new(
                    "feePayer requested but fee sponsorship is not configured on this server",
                ));
            }
            // The sponsor fee token is chosen at co-sign time and is independent
            // of the charge currency; only a configured fee token is known here.
            let (signed, sender) =
                self.validate_fee_payer_transaction(&tx_bytes, self.fee_payer_fee_token)?;
            self.validate_transaction_transfers_with_machine_token(
                &signed.encoded_2718(),
                currency,
                &expected,
                expected_chain_id,
                TransactionValidationOptions {
                    require_exact_calls: true,
                    machine_token_enabled: charge.machine_token_enabled(),
                    challenge_binding: Some((challenge_id, realm)),
                },
            )?;
            return Ok(sender);
        }

        self.validate_transaction_transfers_with_machine_token(
            &tx_bytes,
            currency,
            &expected,
            expected_chain_id,
            TransactionValidationOptions {
                machine_token_enabled: charge.machine_token_enabled(),
                challenge_binding: Some((challenge_id, realm)),
                ..Default::default()
            },
        )?;
        let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut &tx_bytes[..])
            .map_err(|e| VerificationError::new(format!("Failed to decode transaction: {e}")))?;
        signed
            .recover_signer()
            .map_err(|e| VerificationError::new(format!("Failed to recover sender: {e}")))
    }

    async fn validate_local(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> Result<ChargeValidation, VerificationError> {
        if credential.challenge.method.as_str() != METHOD_NAME {
            return Err(VerificationError::credential_mismatch(format!(
                "Method mismatch: expected {METHOD_NAME}, got {}",
                credential.challenge.method
            )));
        }
        if credential.challenge.intent.as_str() != INTENT_CHARGE {
            return Err(VerificationError::credential_mismatch(format!(
                "Intent mismatch: expected {INTENT_CHARGE}, got {}",
                credential.challenge.intent
            )));
        }

        let expected_chain_id = request.chain_id().unwrap_or(CHAIN_ID);
        let actual_chain_id = *self
            .cached_chain_id
            .get_or_try_init(|| async {
                self.provider.get_chain_id().await.map_err(|e| {
                    VerificationError::network_error(format!("Failed to fetch chain ID: {e}"))
                })
            })
            .await?;
        if actual_chain_id != expected_chain_id {
            return Err(VerificationError::chain_id_mismatch(format!(
                "Chain ID mismatch: expected {expected_chain_id}, got {actual_chain_id}"
            )));
        }

        let payload = credential.charge_payload().map_err(|e| {
            VerificationError::with_code(
                format!("Expected charge payload: {e}"),
                crate::protocol::traits::ErrorCode::InvalidCredential,
            )
        })?;
        let is_zero_amount = request
            .amount_u256()
            .map_err(|e| VerificationError::new(format!("Invalid amount in request: {e}")))?
            .is_zero();
        if is_zero_amount && !payload.is_proof() {
            return Err(VerificationError::new(
                "Zero-amount challenges require a proof credential.",
            ));
        }
        ensure_submission_mode_allowed(request, &payload)?;

        let mut transaction_sender = None;
        let details = if payload.is_hash() {
            self.verify_hash(
                payload.tx_hash().unwrap(),
                request,
                credential.source.as_deref(),
                expected_chain_id,
                &credential.challenge,
                false,
            )
            .await?;
            serde_json::json!({ "mode": "push" })
        } else if payload.is_proof() {
            if !is_zero_amount {
                return Err(VerificationError::new(
                    "Proof credentials are only valid for zero-amount challenges.",
                ));
            }
            let sender = self
                .validate_proof_credential(
                    credential,
                    payload.proof_signature().unwrap(),
                    expected_chain_id,
                )
                .await?;
            if let Some(store) = &self.store {
                if store
                    .get(&Self::proof_replay_key(credential))
                    .await
                    .map_err(|e| {
                        VerificationError::internal(format!("Failed to check proof: {e}"))
                    })?
                    .is_some()
                {
                    return Err(VerificationError::new(
                        "Proof credential has already been used.",
                    ));
                }
            }
            serde_json::json!({ "mode": "proof", "sender": format!("{sender:#x}") })
        } else {
            let serialized_transaction = payload.signed_tx().unwrap();
            let sender = self.validate_transaction_credential(
                serialized_transaction,
                request,
                expected_chain_id,
                &credential.challenge.id,
                &credential.challenge.realm,
            )?;
            ensure_transaction_credential_source(
                credential.source.as_deref(),
                sender,
                expected_chain_id,
            )?;
            transaction_sender = Some(sender);
            serde_json::json!({
                "mode": "pull",
                "sender": format!("{sender:#x}"),
                "serializedTransaction": serialized_transaction,
            })
        };

        let mut validation = ChargeValidation::new(credential, request, details);
        // Without a claimed source, the transaction sender is the payer.
        if validation.source.is_none() {
            validation.source =
                transaction_sender.map(|sender| proof::proof_source(sender, expected_chain_id));
        }
        Ok(validation)
    }

    async fn broadcast_transaction(
        &self,
        signed_tx: &str,
        charge: &ChargeRequest,
        source: Option<&str>,
        expected_chain_id: u64,
        challenge_id: &str,
        realm: &str,
    ) -> Result<B256, VerificationError> {
        let tx_bytes = signed_tx
            .parse::<Bytes>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction bytes: {}", e)))?;

        let currency = charge.currency_address().map_err(|e| {
            VerificationError::new(format!("Invalid currency address in request: {}", e))
        })?;
        let expected = Self::expected_transfers(charge)?;

        // Reject an invalid client envelope before adding the server's sponsor
        // signature, and a source that is not the sender before broadcasting.
        // The final signed transaction is validated again below.
        if charge.fee_payer() || source.is_some() {
            let sender = self.validate_transaction_credential(
                signed_tx,
                charge,
                expected_chain_id,
                challenge_id,
                realm,
            )?;
            ensure_transaction_credential_source(source, sender, expected_chain_id)?;
        }

        // Fee payer co-signing replaces the placeholder fee_payer_signature
        // with a real co-signature and sets the fee_token.
        let final_tx_bytes = if charge.fee_payer() {
            let fee_payer_signer = self.fee_payer_signer.as_ref().ok_or_else(|| {
                VerificationError::new(
                    "feePayer requested but fee sponsorship is not configured on this server"
                        .to_string(),
                )
            })?;

            let fee_token = self
                .resolve_fee_payer_fee_token(expected_chain_id, fee_payer_signer.address())
                .await?;
            self.cosign_fee_payer_transaction(&tx_bytes, fee_payer_signer.as_ref(), fee_token)
                .await?
        } else {
            tx_bytes.to_vec()
        };

        let settlement_sender = self.validate_transaction_transfers_with_machine_token(
            &final_tx_bytes,
            currency,
            &expected,
            expected_chain_id,
            TransactionValidationOptions {
                require_exact_calls: charge.fee_payer(),
                machine_token_enabled: charge.machine_token_enabled(),
                challenge_binding: Some((challenge_id, realm)),
            },
        )?;

        // The sponsor pays the gas here, so simulate first and bail if the tx
        // would revert. Static validation above only checks call shape, not
        // execution. Fails closed: no simulation, no broadcast.
        if charge.fee_payer() {
            self.simulate_before_broadcast(&final_tx_bytes).await?;
        }

        // Pre-broadcast dedup of the final tx bytes. Separate namespace from
        // the post-broadcast hash dedup in verify_hash.
        if let Some(store) = &self.store {
            let tx_hash_pre = keccak256(&final_tx_bytes);
            let dedup_key = format!("mpp:charge:submission:{:#x}", tx_hash_pre);
            // Atomically reserve before broadcasting.
            let claimed = store
                .put_if_absent(&dedup_key, serde_json::Value::Bool(true))
                .await
                .map_err(|e| VerificationError::internal(format!("Failed to record tx: {e}")))?;
            if !claimed {
                return Err(VerificationError::new(
                    "Transaction has already been submitted.",
                ));
            }
        }

        // Use eth_sendRawTransactionSync (EIP-7966) for single-call broadcast +
        // receipt. The Tempo node holds the connection open until the transaction
        // is mined/pre-confirmed and returns the full receipt, avoiding the
        // client-side polling loop of send_raw_transaction + get_receipt.
        let raw_hex = alloy::hex::encode_prefixed(&final_tx_bytes);
        let receipt: <TempoNetwork as alloy::network::Network>::ReceiptResponse = self
            .provider
            .raw_request("eth_sendRawTransactionSync".into(), [raw_hex])
            .await
            .map_err(|e| VerificationError::network_error(format!("Failed to broadcast: {}", e)))?;

        if !receipt.status() {
            return Err(VerificationError::transaction_failed(format!(
                "Transaction {} reverted",
                receipt.transaction_hash()
            )));
        }

        // Verify the receipt contains the expected TIP-20 transfer(s).
        let settlement_senders = settlement_sender.into_iter().collect::<Vec<_>>();
        let matched_logs = self.verify_tip20_transfers(
            &receipt,
            currency,
            &expected,
            ReceiptSenderPolicy {
                expected_sender: receipt.from(),
                source: None,
                validate_sender: None,
                transaction_sender: receipt.from(),
                settlement_senders: &settlement_senders,
            },
        )?;
        assert_challenge_bound_memo(&matched_logs, challenge_id, realm)?;

        // Record the on-chain tx hash for hash-based replay protection. Use the
        // atomic claim so a concurrent hash credential for the same tx cannot
        // also succeed.
        if let Some(store) = &self.store {
            let replay_key = format!("mpp:charge:{:#x}", receipt.transaction_hash());
            let claimed = store
                .put_if_absent(&replay_key, serde_json::Value::Bool(true))
                .await
                .map_err(|e| {
                    VerificationError::internal(format!("Failed to record tx hash: {e}"))
                })?;
            if !claimed {
                return Err(VerificationError::new(
                    "Transaction hash has already been used.",
                ));
            }
        }

        Ok(receipt.transaction_hash())
    }

    /// Decode a co-signed `0x76` tx and build the equivalent
    /// `tempo_simulateV1` request.
    fn build_simulate_payload(
        final_tx_bytes: &[u8],
    ) -> Result<SimulatePayload<TempoTransactionRequest>, VerificationError> {
        let signed = tempo_alloy::primitives::AASigned::decode_2718(&mut &final_tx_bytes[..])
            .map_err(|e| {
                VerificationError::new(format!("Failed to decode co-signed tx for simulation: {e}"))
            })?;
        let sender = signed.recover_signer().map_err(|e| {
            VerificationError::new(format!("Failed to recover sender for simulation: {e}"))
        })?;

        // Extract auth metadata before `into()` discards the signature: the
        // node sizes signature gas from `keyType`/`keyData` (primitive
        // p256/webauthn included) and selects the keychain key via `keyId`.
        let (key_id, key_type, key_data) = {
            let (key_id, primitive_sig) =
                if let TempoSignature::Keychain(keychain_sig) = signed.signature() {
                    let key_id = keychain_sig.key_id(&signed.signature_hash()).map_err(|e| {
                        VerificationError::new(format!(
                            "Failed to recover keychain access key for simulation: {e}"
                        ))
                    })?;
                    (Some(key_id), Some(&keychain_sig.signature))
                } else if let TempoSignature::Primitive(primitive_sig) = signed.signature() {
                    (None, Some(primitive_sig))
                } else {
                    (None, None)
                };
            let (key_type, key_data) = if let Some(primitive_sig) = primitive_sig {
                let key_data = match primitive_sig {
                    PrimitiveSignature::WebAuthn(webauthn) => Some(webauthn.webauthn_data.clone()),
                    _ => None,
                };
                (Some(primitive_sig.signature_type()), key_data)
            } else {
                (None, None)
            };
            (key_id, key_type, key_data)
        };

        let mut req: TempoTransactionRequest = signed.into();
        req.inner.from = Some(sender);

        // `From<AASigned>` leaves `inner.to` unset, which the node reads as a
        // contract CREATE and rejects alongside the AA batch. The node rebuilds
        // the batch as `calls ++ [inner.to call]`, so fold the last sub-call
        // into `inner.to/value/input`: same resulting batch (order and
        // fee-payer signature preserved) with a real call target.
        let tail = req.calls.pop().ok_or_else(|| {
            VerificationError::new("Cannot simulate Tempo AA transaction with no calls")
        })?;
        req.inner.to = Some(tail.to);
        req.inner.value = Some(tail.value);
        req.inner.input = tail.input.into();

        req.key_type = key_type;
        req.key_data = key_data;
        if let Some(key_id) = key_id {
            req.key_id = Some(key_id);
        }

        Ok(SimulatePayload {
            block_state_calls: vec![SimBlock {
                block_overrides: None,
                state_overrides: None,
                calls: vec![req],
            }],
            // We only care about execution outcome, not mempool admission.
            validation: false,
            trace_transfers: false,
            return_full_transactions: false,
        })
    }

    /// Simulate a co-signed `0x76` tx and error if it would revert. Fails
    /// closed: an RPC error is treated as a failed check, not a pass. Nodes
    /// without `tempo_simulateV1` (JSON-RPC -32601) are asked to `eth_call`
    /// the transaction's calls instead.
    async fn simulate_before_broadcast(
        &self,
        final_tx_bytes: &[u8],
    ) -> Result<(), VerificationError> {
        // Standard JSON-RPC "method not found" code.
        const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;

        let payload = Self::build_simulate_payload(final_tx_bytes)?;

        // tempo_simulateV1(payload, block?) — omit block to use the latest state.
        let response: TempoSimulateResponse = match self
            .provider
            .raw_request("tempo_simulateV1".into(), (&payload,))
            .await
        {
            Ok(response) => response,
            Err(e) => {
                if e.as_error_resp()
                    .is_some_and(|err| err.code == JSONRPC_METHOD_NOT_FOUND)
                {
                    return self.simulate_with_eth_call(payload).await;
                }
                return Err(VerificationError::network_error(format!(
                    "Pre-broadcast simulation failed: {e}"
                )));
            }
        };

        let call: &SimCallResult = response
            .blocks
            .first()
            .and_then(|block| block.calls.first())
            .ok_or_else(|| {
                VerificationError::internal("Pre-broadcast simulation returned no call results")
            })?;

        if !call.status {
            let detail = match &call.error {
                Some(err) => format!("{} (code {})", err.message, err.code),
                None if !call.return_data.is_empty() => {
                    format!(
                        "revert data {}",
                        alloy::hex::encode_prefixed(&call.return_data)
                    )
                }
                None => "no revert reason returned".to_string(),
            };
            return Err(VerificationError::transaction_failed(format!(
                "Sponsored transaction would revert in pre-broadcast simulation: {detail}"
            )));
        }

        Ok(())
    }

    /// Reduce a simulation request to its sender and calls. Without fee
    /// fields or signatures the node only checks call execution, so the
    /// sender does not need to hold a fee token (mppx simulates the same way).
    fn sender_call_request(request: TempoTransactionRequest) -> TempoTransactionRequest {
        TempoTransactionRequest {
            inner: TransactionRequest {
                from: request.inner.from,
                to: request.inner.to,
                value: request.inner.value,
                input: request.inner.input,
                ..Default::default()
            },
            calls: request.calls,
            ..Default::default()
        }
    }

    /// `eth_call` fallback for [`Self::simulate_before_broadcast`].
    async fn simulate_with_eth_call(
        &self,
        payload: SimulatePayload<TempoTransactionRequest>,
    ) -> Result<(), VerificationError> {
        // JSON-RPC error code nodes return for a reverted call.
        const JSONRPC_EXECUTION_REVERTED: i64 = 3;

        let requests = payload
            .block_state_calls
            .into_iter()
            .flat_map(|block| block.calls);
        for request in requests {
            if let Err(e) = self.provider.call(Self::sender_call_request(request)).await {
                return Err(match e.as_error_resp() {
                    Some(err) if err.code == JSONRPC_EXECUTION_REVERTED => {
                        VerificationError::transaction_failed(format!(
                            "Sponsored transaction would revert in pre-broadcast simulation: {} (code {})",
                            err.message, err.code
                        ))
                    }
                    _ => VerificationError::network_error(format!(
                        "Pre-broadcast simulation failed: {e}"
                    )),
                });
            }
        }

        Ok(())
    }

    fn validate_fee_payer_transaction(
        &self,
        tx_bytes: &[u8],
        fee_token: Option<Address>,
    ) -> Result<(tempo_alloy::primitives::AASigned, Address), VerificationError> {
        use super::fee_payer_envelope::{FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID};
        use tempo_alloy::primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;

        if tx_bytes.is_empty() {
            return Err(VerificationError::new("Empty transaction bytes"));
        }

        let type_byte = tx_bytes[0];
        if type_byte != TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID {
            return Err(VerificationError::new(format!(
                "Expected fee payer envelope (0x78), got 0x{type_byte:02x}"
            )));
        }

        let env = FeePayerEnvelope78::decode_envelope(tx_bytes)
            .map_err(|e| VerificationError::new(format!("Failed to decode 0x78 envelope: {e}")))?;

        let signed = env.to_recoverable_signed();
        let sender = signed
            .recover_signer()
            .map_err(|e| VerificationError::new(format!("Failed to recover sender: {e}")))?;
        if sender != env.sender {
            return Err(VerificationError::new(format!(
                "Sender mismatch in 0x78 envelope: envelope={:#x} recovered={:#x}",
                env.sender, sender
            )));
        }

        let tx = signed.tx();

        // Validate fee-payer invariants
        if tx.fee_payer_signature.is_none() {
            return Err(VerificationError::new(
                "Transaction must include fee_payer_signature placeholder",
            ));
        }

        if tx.fee_token.is_some() {
            return Err(VerificationError::new(
                "Fee payer transaction must not include fee_token (server sets it)",
            ));
        }

        // Stripped by `to_recoverable_signed`; guard against regression.
        debug_assert!(tx.access_list.is_empty());

        // Both add intrinsic gas the sponsor pays for without being part of
        // the charge. mppx rejects the former and makes the latter opt-out.
        if !tx.tempo_authorization_list.is_empty() {
            return Err(VerificationError::new(
                "Fee payer transaction must not include an authorization list",
            ));
        }

        if tx.key_authorization.is_some() && !self.fee_payer_allow_key_authorization {
            return Err(VerificationError::new(
                "Fee payer transaction must not include a key authorization",
            ));
        }

        if tx.nonce_key != TEMPO_EXPIRING_NONCE_KEY {
            return Err(VerificationError::new(
                "Fee payer envelope must use expiring nonce key (U256::MAX)",
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| VerificationError::internal(format!("System clock error: {e}")))?
            .as_secs();

        let valid_before = match tx.valid_before {
            None => {
                return Err(VerificationError::new(
                    "Fee payer envelope must include valid_before",
                ));
            }
            Some(vb) => {
                if vb.get() <= now {
                    return Err(VerificationError::new(format!(
                        "Fee payer envelope expired: valid_before ({vb}) is not in the future (now={now})"
                    )));
                }
                vb.get()
            }
        };

        let policy = FeePayerPolicy::resolve(tx.chain_id, self.fee_payer_policy_override.as_ref());

        if let Some(fee_token) = fee_token {
            if !fee_token_allowed(&self.allowed_fee_tokens(tx.chain_id), fee_token) {
                return Err(VerificationError::new(format!(
                    "Fee token {:#x} is not allowed by fee payer policy",
                    fee_token
                )));
            }
        }

        if tx.max_fee_per_gas > policy.max_fee_per_gas {
            return Err(VerificationError::new(format!(
                "max_fee_per_gas {} exceeds policy maximum {}",
                tx.max_fee_per_gas, policy.max_fee_per_gas
            )));
        }

        let total_fee = (tx.gas_limit as u128).saturating_mul(tx.max_fee_per_gas);
        if total_fee > policy.max_total_fee {
            return Err(VerificationError::new(format!(
                "Total fee {} (gas_limit * max_fee_per_gas) exceeds policy maximum {}",
                total_fee, policy.max_total_fee
            )));
        }

        // Priority fee above the per-gas ceiling is a client bug — EIP-1559 would
        // silently clip it to `max_fee_per_gas - base_fee`, so reject early for a
        // clearer error.
        if tx.max_priority_fee_per_gas > tx.max_fee_per_gas {
            return Err(VerificationError::new(format!(
                "max_priority_fee_per_gas {} exceeds max_fee_per_gas {}",
                tx.max_priority_fee_per_gas, tx.max_fee_per_gas
            )));
        }

        if tx.max_priority_fee_per_gas > policy.max_priority_fee_per_gas {
            return Err(VerificationError::new(format!(
                "max_priority_fee_per_gas {} exceeds policy maximum {}",
                tx.max_priority_fee_per_gas, policy.max_priority_fee_per_gas
            )));
        }

        if valid_before.saturating_sub(now) > policy.max_validity_window_seconds {
            return Err(VerificationError::new(format!(
                "valid_before window {}s exceeds policy maximum {}s",
                valid_before.saturating_sub(now),
                policy.max_validity_window_seconds
            )));
        }

        Ok((signed, sender))
    }

    /// Co-sign a fee payer transaction.
    ///
    /// Accepts a `0x78` fee payer envelope, recovers the sender via
    /// ecrecover, validates fee-payer invariants, then co-signs and
    /// returns a complete `0x76` transaction ready for broadcast.
    async fn cosign_fee_payer_transaction(
        &self,
        tx_bytes: &[u8],
        fee_payer_signer: &super::DynSigner,
        fee_token: Address,
    ) -> Result<Vec<u8>, VerificationError> {
        use alloy::eips::Encodable2718;

        let (signed, sender) = self.validate_fee_payer_transaction(tx_bytes, Some(fee_token))?;

        // Rebuild the transaction with fee_token set and real fee_payer_signature
        let (tx, client_signature, _hash) = signed.into_parts();
        let mut tx = tx;
        tx.fee_token = Some(fee_token);
        tx.fee_payer_signature = None; // Clear placeholder before computing hash

        // Compute the fee payer signature hash and co-sign
        let fp_hash = tx.fee_payer_signature_hash(sender);
        let fp_sig = fee_payer_signer.sign_hash(&fp_hash).await.map_err(|e| {
            VerificationError::internal(format!("Failed to co-sign transaction: {e}"))
        })?;

        tx.fee_payer_signature = Some(fp_sig);

        let signed_tx = tx.into_signed(client_signature);
        Ok(signed_tx.encoded_2718())
    }

    /// Sponsor fee-token allowlist: the configured list, else the chain default.
    fn allowed_fee_tokens(&self, chain_id: u64) -> Vec<Address> {
        self.fee_payer_allowed_fee_tokens
            .clone()
            .unwrap_or_else(|| FeePayerPolicy::default_allowed_fee_tokens(chain_id))
    }

    /// Choose the token a local fee payer uses to pay gas, matching mppx.
    ///
    /// Returns the configured fee token when set. Otherwise returns the first
    /// allowlisted token the fee payer holds a nonzero balance of (in
    /// allowlist order), falling back to the first allowlisted token. Balance
    /// lookups that fail count as zero. The result is still checked against
    /// the allowlist when co-signing.
    async fn resolve_fee_payer_fee_token(
        &self,
        chain_id: u64,
        fee_payer: Address,
    ) -> Result<Address, VerificationError> {
        if let Some(fee_token) = self.fee_payer_fee_token {
            return Ok(fee_token);
        }
        let allowed_fee_tokens = self.allowed_fee_tokens(chain_id);
        let Some(&first) = allowed_fee_tokens.first() else {
            return Err(VerificationError::new(
                "Fee payer policy does not allow any fee tokens",
            ));
        };
        for &token in &allowed_fee_tokens {
            let balance = ITIP20::new(token, &*self.provider)
                .balanceOf(fee_payer)
                .call()
                .await
                .unwrap_or_default();
            if !balance.is_zero() {
                return Ok(token);
            }
        }
        Ok(first)
    }
}

#[allow(clippy::manual_async_fn)]
impl<P> crate::protocol::traits::SessionMethod for ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn verify_session(
        &self,
        _credential: &PaymentCredential,
        _request: &crate::protocol::intents::SessionRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        async {
            Err(VerificationError::new(
                "Session verification not yet implemented — requires on-chain channel state lookup",
            ))
        }
    }
}

impl<P> ChargeMethodTrait for ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn supports_validation(&self) -> bool {
        true
    }

    fn validate(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<ChargeValidation, VerificationError>> + Send {
        let relay = self.relay.clone();
        let this = self.clone();
        let credential = credential.clone();
        let request = request.clone();
        async move {
            match relay {
                Some(relay) => relay.validate(&credential, &request).await,
                None => this.validate_local(&credential, &request).await,
            }
        }
    }

    fn broadcast(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let this = self.clone();
        let credential = credential.clone();
        let request = request.clone();
        async move {
            if let Some(relay) = &this.relay {
                relay.broadcast(&credential, METHOD_NAME).await
            } else {
                ChargeMethodTrait::verify(&this, &credential, &request).await
            }
        }
    }

    fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
        let credential = credential.clone();
        let request = request.clone();
        let provider = Arc::clone(&self.provider);
        let fee_payer_signer = self.fee_payer_signer.clone();
        let store = self.store.clone();
        let cached_chain_id = Arc::clone(&self.cached_chain_id);
        let fee_payer_policy_override = self.fee_payer_policy_override.clone();
        let validate_sender = self.validate_sender.clone();
        let fee_payer_allowed_fee_tokens = self.fee_payer_allowed_fee_tokens.clone();
        let relay = self.relay.clone();
        let fee_payer_fee_token = self.fee_payer_fee_token;
        let fee_payer_allow_key_authorization = self.fee_payer_allow_key_authorization;

        async move {
            if let Some(relay) = relay {
                relay.validate(&credential, &request).await?;
                return relay.broadcast(&credential, METHOD_NAME).await;
            }

            let this = ChargeMethod {
                provider,
                fee_payer_signer,
                store,
                cached_chain_id,
                fee_payer_policy_override,
                validate_sender,
                fee_payer_allowed_fee_tokens,
                relay: None,
                fee_payer_fee_token,
                fee_payer_allow_key_authorization,
            };

            if credential.challenge.method.as_str() != METHOD_NAME {
                return Err(VerificationError::credential_mismatch(format!(
                    "Method mismatch: expected {}, got {}",
                    METHOD_NAME, credential.challenge.method
                )));
            }
            if credential.challenge.intent.as_str() != INTENT_CHARGE {
                return Err(VerificationError::credential_mismatch(format!(
                    "Intent mismatch: expected {}, got {}",
                    INTENT_CHARGE, credential.challenge.intent
                )));
            }

            let expected_chain_id = request.chain_id().unwrap_or(CHAIN_ID);
            let actual_chain_id = *this
                .cached_chain_id
                .get_or_try_init(|| async {
                    this.provider.get_chain_id().await.map_err(|e| {
                        VerificationError::network_error(format!("Failed to fetch chain ID: {}", e))
                    })
                })
                .await?;

            if actual_chain_id != expected_chain_id {
                return Err(VerificationError::chain_id_mismatch(format!(
                    "Chain ID mismatch: expected {}, got {}",
                    expected_chain_id, actual_chain_id
                )));
            }

            let charge_payload = credential.charge_payload().map_err(|e| {
                VerificationError::with_code(
                    format!("Expected charge payload: {}", e),
                    crate::protocol::traits::ErrorCode::InvalidCredential,
                )
            })?;

            let is_zero_amount = request
                .amount_u256()
                .map_err(|e| VerificationError::new(format!("Invalid amount in request: {}", e)))?
                .is_zero();

            if is_zero_amount && !charge_payload.is_proof() {
                return Err(VerificationError::new(
                    "Zero-amount challenges require a proof credential.",
                ));
            }
            ensure_submission_mode_allowed(&request, &charge_payload)?;

            if charge_payload.is_hash() {
                // Client already broadcast the transaction, verify by hash
                this.verify_hash(
                    charge_payload.tx_hash().unwrap(),
                    &request,
                    credential.source.as_deref(),
                    expected_chain_id,
                    &credential.challenge,
                    true,
                )
                .await
            } else if charge_payload.is_proof() {
                if !is_zero_amount {
                    return Err(VerificationError::new(
                        "Proof credentials are only valid for zero-amount challenges.",
                    ));
                }

                let sig_hex = charge_payload.proof_signature().unwrap();
                this.validate_proof_credential(&credential, sig_hex, expected_chain_id)
                    .await?;
                this.reserve_proof_credential(&credential).await?;

                Ok(Receipt::success(METHOD_NAME, &credential.challenge.id))
            } else {
                // Client sent signed transaction, validate and broadcast it.
                // broadcast_transaction already does pre-broadcast dedup and
                // validates the receipt, so we do NOT call verify_hash here
                // (which would self-reject since the tx hash is already marked).
                let tx_hash = this
                    .broadcast_transaction(
                        charge_payload.signed_tx().unwrap(),
                        &request,
                        credential.source.as_deref(),
                        expected_chain_id,
                        &credential.challenge.id,
                        &credential.challenge.realm,
                    )
                    .await?;
                Ok(Receipt::success(METHOD_NAME, format!("{:#x}", tx_hash)))
            }
        }
    }
}

#[cfg(test)]
mod tests;
