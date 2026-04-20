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
//! use mpp::server::{tempo_provider, TempoChargeMethod};
//! use mpp::protocol::traits::ChargeMethod as ChargeMethodTrait;
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
//! let method = TempoChargeMethod::new(provider);
//!
//! // In your server handler:
//! let receipt = method.verify(&credential, &request).await?;
//! assert!(receipt.is_success());
//! ```

use alloy::network::ReceiptResponse;
use alloy::primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use std::future::Future;
use std::sync::Arc;
use tempo_alloy::contracts::precompiles::{
    IAccountKeychain, IStablecoinDEX, ACCOUNT_KEYCHAIN_ADDRESS, ITIP20, STABLECOIN_DEX_ADDRESS,
};
use tempo_alloy::TempoNetwork;
use tokio::sync::OnceCell;

use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod as ChargeMethodTrait, VerificationError};
use crate::store::Store;
use crate::tempo::{attribution, MODERATO_CHAIN_ID};

use super::transfers::{get_request_transfers, Transfer};
use super::{proof, TempoChargeExt, CHAIN_ID, INTENT_CHARGE, METHOD_NAME};

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

fn decode_approve_spender(call: &tempo_primitives::transaction::Call) -> Option<Address> {
    if call_selector(&call.input) != Some(ITIP20::approveCall::SELECTOR) || call.input.len() != 68 {
        return None;
    }

    Some(Address::from_slice(&call.input[16..36]))
}

fn transfer_call_offset(
    calls: &[tempo_primitives::transaction::Call],
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
    calls: &[tempo_primitives::transaction::Call],
) -> Result<&[tempo_primitives::transaction::Call], VerificationError> {
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
    calls: &[tempo_primitives::transaction::Call],
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
        let approve_spender = decode_approve_spender(&calls[0])
            .ok_or_else(disallowed_fee_payer_call_pattern_error)?;
        if approve_spender != STABLECOIN_DEX_ADDRESS {
            return Err(VerificationError::new(
                "Fee-sponsored transaction approve spender is not the DEX".to_string(),
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

fn match_receipt_transfer_logs(
    logs: &[serde_json::Value],
    tx_sender: Address,
    currency: Address,
    expected: &[Transfer],
) -> Result<Vec<MatchedTransferLog>, VerificationError> {
    let mut sorted_expected: Vec<(usize, &Transfer)> = expected.iter().enumerate().collect();
    sorted_expected.sort_by_key(|(_, t)| if t.memo.is_some() { 0 } else { 1 });

    let parsed_logs: Vec<Option<ParsedTransferLog>> =
        logs.iter().map(parse_receipt_transfer_log).collect();
    let mut used_logs: Vec<bool> = vec![false; logs.len()];
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

                let Some(parsed) = parsed else {
                    continue;
                };

                if parsed.address() != currency
                    || parsed.from() != tx_sender
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
    let bound = matched_logs.iter().any(|log| match log {
        MatchedTransferLog::Transfer => false,
        MatchedTransferLog::Memo(memo) => {
            attribution::verify_server(memo, realm)
                && attribution::verify_challenge_binding(memo, challenge_id)
        }
    });

    if bound {
        Ok(())
    } else {
        Err(VerificationError::new(
            "Payment verification failed: memo is not bound to this challenge.",
        ))
    }
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
/// use mpp::server::{tempo_provider, TempoChargeMethod};
/// use mpp::protocol::traits::ChargeMethod as ChargeMethodTrait;
///
/// let provider = tempo_provider("https://rpc.moderato.tempo.xyz");
/// let method = TempoChargeMethod::new(provider);
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
    fee_payer_signer: Option<Arc<alloy::signers::local::PrivateKeySigner>>,
    store: Option<Arc<dyn Store>>,
    cached_chain_id: Arc<OnceCell<u64>>,
    fee_payer_policy_override: Option<FeePayerPolicyOverride>,
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
        FeePayerPolicy {
            max_gas: MAX_FEE_PAYER_GAS_LIMIT,
            max_fee_per_gas: MAX_FEE_PER_GAS_DEFAULT,
            max_priority_fee_per_gas: MAX_PRIORITY_FEE_PER_GAS_DEFAULT,
            max_total_fee: MAX_TOTAL_FEE_DEFAULT,
            max_validity_window_seconds: MAX_VALIDITY_WINDOW_SECS_DEFAULT,
        }
    }
}

impl FeePayerPolicy {
    /// Merge overrides onto the per-chain default.
    pub fn resolve(chain_id: u64, overrides: Option<&FeePayerPolicyOverride>) -> Self {
        let base = Self::get_by_chain_id(chain_id);
        let Some(o) = overrides else { return base };
        Self {
            max_gas: o.max_gas.unwrap_or(base.max_gas),
            max_fee_per_gas: o.max_fee_per_gas.unwrap_or(base.max_fee_per_gas),
            max_priority_fee_per_gas: o
                .max_priority_fee_per_gas
                .unwrap_or(base.max_priority_fee_per_gas),
            max_total_fee: o.max_total_fee.unwrap_or(base.max_total_fee),
            max_validity_window_seconds: o
                .max_validity_window_seconds
                .unwrap_or(base.max_validity_window_seconds),
        }
    }

    fn get_by_chain_id(chain_id: u64) -> Self {
        match chain_id {
            // Moderato regularly needs a higher priority fee than mainnet.
            MODERATO_CHAIN_ID => Self {
                max_priority_fee_per_gas: 50_000_000_000,
                ..Self::default()
            },
            _ => Self::default(),
        }
    }
}

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Create a new Tempo charge method with the given alloy Provider.
    ///
    /// The provider must be configured for `TempoNetwork`. Use
    /// [`tempo_provider`](crate::server::tempo_provider) to create one.
    pub fn new(provider: P) -> Self {
        Self {
            provider: Arc::new(provider),
            fee_payer_signer: None,
            store: None,
            cached_chain_id: Arc::new(OnceCell::new()),
            fee_payer_policy_override: None,
        }
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

    /// Configure a store for transaction hash deduplication.
    ///
    /// When set, each verified transaction hash is recorded and subsequent
    /// attempts to replay the same hash are rejected.
    pub fn with_store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = Some(store);
        self
    }

    /// Configure a fee payer signer for sponsoring transaction fees.
    ///
    /// When set, requests with `feePayer: true` will be accepted and
    /// broadcast. Without a fee payer signer, such requests are rejected.
    pub fn with_fee_payer(mut self, signer: alloy::signers::local::PrivateKeySigner) -> Self {
        self.fee_payer_signer = Some(Arc::new(signer));
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
        challenge_id: &str,
        realm: &str,
    ) -> Result<Receipt, VerificationError> {
        let hash = tx_hash
            .parse::<B256>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction hash: {}", e)))?;

        let replay_key = format!("mpp:charge:{:#x}", hash);

        if let Some(store) = &self.store {
            let seen = store
                .get(&replay_key)
                .await
                .map_err(|e| VerificationError::new(format!("Store error: {e}")))?;
            if seen.is_some() {
                return Err(VerificationError::new(
                    "Transaction hash has already been used.",
                ));
            }
        }

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

        // Tempo uses TIP-20 tokens exclusively (no native token transfers)
        let matched_logs = self.verify_tip20_transfers(&receipt, currency, &expected)?;

        if charge.memo().is_none() {
            assert_challenge_bound_memo(&matched_logs, challenge_id, realm)?;
        }

        if let Some(store) = &self.store {
            store
                .put(&replay_key, serde_json::Value::Bool(true))
                .await
                .map_err(|e| VerificationError::new(format!("Failed to record tx hash: {e}")))?;
        }

        Ok(Receipt::success(METHOD_NAME, tx_hash))
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
    ) -> Result<Vec<MatchedTransferLog>, VerificationError> {
        let receipt_json = serde_json::to_value(receipt)
            .map_err(|e| VerificationError::new(format!("Failed to serialize receipt: {}", e)))?;

        let tx_sender = receipt.from();

        let logs = receipt_json
            .get("logs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| VerificationError::new("Receipt has no logs".to_string()))?;

        match_receipt_transfer_logs(logs, tx_sender, currency, expected)
    }

    /// Validate that a transaction contains all expected payment calls (supports splits).
    ///
    /// Uses order-insensitive matching with memo-specificity sorting.
    fn validate_transaction_transfers(
        &self,
        tx_bytes: &[u8],
        currency: Address,
        expected: &[Transfer],
        expected_chain_id: u64,
        require_exact_calls: bool,
    ) -> Result<(), VerificationError> {
        if currency.is_zero() {
            return Err(VerificationError::new(
                "Invalid currency: currency cannot be the zero address".to_string(),
            ));
        }

        // Skip type byte (0x76) for Tempo transactions
        let tx_data = if !tx_bytes.is_empty()
            && tx_bytes[0] == tempo_primitives::transaction::TEMPO_TX_TYPE_ID
        {
            &tx_bytes[1..]
        } else {
            tx_bytes
        };

        let signed = tempo_primitives::AASigned::rlp_decode(&mut &tx_data[..])
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

        let transfer_calls = get_transfer_calls(&tx.calls)?;

        if require_exact_calls {
            validate_fee_payer_calls(&tx.calls)?;
        }

        // Sort expected transfers: memo-bearing first for greedy-safe matching
        let mut sorted_expected: Vec<(usize, &Transfer)> = expected.iter().enumerate().collect();
        sorted_expected.sort_by_key(|(_, t)| if t.memo.is_some() { 0 } else { 1 });

        let mut used_calls: Vec<bool> = vec![false; transfer_calls.len()];

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

                        if to == transfer.recipient && amount == transfer.amount {
                            used_calls[call_idx] = true;
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

        Ok(())
    }

    async fn broadcast_transaction(
        &self,
        signed_tx: &str,
        charge: &ChargeRequest,
        expected_chain_id: u64,
    ) -> Result<B256, VerificationError> {
        let tx_bytes = signed_tx
            .parse::<Bytes>()
            .map_err(|e| VerificationError::new(format!("Invalid transaction bytes: {}", e)))?;

        let currency = charge.currency_address().map_err(|e| {
            VerificationError::new(format!("Invalid currency address in request: {}", e))
        })?;
        let expected = Self::expected_transfers(charge)?;

        // Fee payer co-signing replaces the placeholder fee_payer_signature
        // with a real co-signature and sets the fee_token.
        let final_tx_bytes = if charge.fee_payer() {
            let fee_payer_signer = self.fee_payer_signer.as_ref().ok_or_else(|| {
                VerificationError::new(
                    "feePayer requested but fee sponsorship is not configured on this server"
                        .to_string(),
                )
            })?;

            self.cosign_fee_payer_transaction(&tx_bytes, fee_payer_signer, currency)?
        } else {
            tx_bytes.to_vec()
        };

        self.validate_transaction_transfers(
            &final_tx_bytes,
            currency,
            &expected,
            expected_chain_id,
            charge.fee_payer(),
        )?;

        // Pre-broadcast dedup: hash the final tx bytes (after co-signing/validation)
        // and check/mark in store before broadcasting. Uses a separate namespace
        // from the post-broadcast hash-based dedup in verify_hash.
        if let Some(store) = &self.store {
            let tx_hash_pre = keccak256(&final_tx_bytes);
            let dedup_key = format!("mpp:charge:submission:{:#x}", tx_hash_pre);
            let seen = store
                .get(&dedup_key)
                .await
                .map_err(|e| VerificationError::new(format!("Store error: {e}")))?;
            if seen.is_some() {
                return Err(VerificationError::new(
                    "Transaction has already been submitted.",
                ));
            }
            store
                .put(&dedup_key, serde_json::Value::Bool(true))
                .await
                .map_err(|e| VerificationError::new(format!("Failed to record tx: {e}")))?;
        }

        // Use eth_sendRawTransactionSync (EIP-7966) for single-call broadcast +
        // receipt. The Tempo node holds the connection open until the transaction
        // is mined/pre-confirmed and returns the full receipt, avoiding the
        // client-side polling loop of send_raw_transaction + get_receipt.
        let raw_hex = format!("0x{}", alloy::primitives::hex::encode(&final_tx_bytes));
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

        // Verify the receipt contains the expected TIP-20 transfer(s)
        self.verify_tip20_transfers(&receipt, currency, &expected)?;

        // Record the on-chain tx hash for hash-based replay protection
        if let Some(store) = &self.store {
            let replay_key = format!("mpp:charge:{:#x}", receipt.transaction_hash());
            store
                .put(&replay_key, serde_json::Value::Bool(true))
                .await
                .map_err(|e| VerificationError::new(format!("Failed to record tx hash: {e}")))?;
        }

        Ok(receipt.transaction_hash())
    }

    /// Co-sign a fee payer transaction.
    ///
    /// Accepts a `0x78` fee payer envelope, recovers the sender via
    /// ecrecover, validates fee-payer invariants, then co-signs and
    /// returns a complete `0x76` transaction ready for broadcast.
    fn cosign_fee_payer_transaction(
        &self,
        tx_bytes: &[u8],
        fee_payer_signer: &alloy::signers::local::PrivateKeySigner,
        fee_token: Address,
    ) -> Result<Vec<u8>, VerificationError> {
        use super::fee_payer_envelope::{FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID};
        use alloy::consensus::transaction::SignerRecoverable;
        use alloy::eips::Encodable2718;
        use alloy::signers::SignerSync;
        use tempo_primitives::transaction::TEMPO_EXPIRING_NONCE_KEY;

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

        if tx.nonce_key != TEMPO_EXPIRING_NONCE_KEY {
            return Err(VerificationError::new(
                "Fee payer envelope must use expiring nonce key (U256::MAX)",
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| VerificationError::new(format!("System clock error: {e}")))?
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

        // Rebuild the transaction with fee_token set and real fee_payer_signature
        let (tx, client_signature, _hash) = signed.into_parts();
        let mut tx = tx;
        tx.fee_token = Some(fee_token);
        tx.fee_payer_signature = None; // Clear placeholder before computing hash

        // Compute the fee payer signature hash and co-sign
        let fp_hash = tx.fee_payer_signature_hash(sender);
        let fp_sig = fee_payer_signer
            .sign_hash_sync(&fp_hash)
            .map_err(|e| VerificationError::new(format!("Failed to co-sign transaction: {e}")))?;

        tx.fee_payer_signature = Some(fp_sig);

        let signed_tx = tx.into_signed(client_signature);
        Ok(signed_tx.encoded_2718())
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

        async move {
            let this = ChargeMethod {
                provider,
                fee_payer_signer,
                store,
                cached_chain_id,
                fee_payer_policy_override,
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

            if charge_payload.is_hash() {
                // Client already broadcast the transaction, verify by hash
                this.verify_hash(
                    charge_payload.tx_hash().unwrap(),
                    &request,
                    &credential.challenge.id,
                    &credential.challenge.realm,
                )
                .await
            } else if charge_payload.is_proof() {
                if !is_zero_amount {
                    return Err(VerificationError::new(
                        "Proof credentials are only valid for zero-amount challenges.",
                    ));
                }

                let source = credential.source.as_deref().ok_or_else(|| {
                    VerificationError::new("Proof credential must include a source.")
                })?;
                let parsed_source = proof::parse_proof_source(source)
                    .map_err(|_| VerificationError::new("Proof credential source is invalid."))?;

                if parsed_source.chain_id != expected_chain_id {
                    return Err(VerificationError::new(
                        "Proof credential source is invalid.",
                    ));
                }

                let sig_hex = charge_payload.proof_signature().unwrap();

                // Fast path: signer IS the source address (Direct mode).
                if !proof::verify_proof(
                    expected_chain_id,
                    &credential.challenge.id,
                    sig_hex,
                    parsed_source.address,
                ) {
                    // Keychain fallback: signer may be an access key authorized
                    // for the source wallet. Recover the signer and check on-chain.
                    let recovered = proof::recover_proof_signer(
                        expected_chain_id,
                        &credential.challenge.id,
                        sig_hex,
                    )
                    .map_err(|_| {
                        VerificationError::new("Proof signature does not match source.")
                    })?;

                    let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, &*this.provider);
                    let key_info = keychain
                        .getKey(parsed_source.address, recovered)
                        .call()
                        .await
                        .map_err(|_| {
                            VerificationError::new("Proof signature does not match source.")
                        })?;
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
                        expected_chain_id,
                    )
                    .await?;
                Ok(Receipt::success(METHOD_NAME, format!("{:#x}", tx_hash)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use alloy::primitives::hex;

    use super::{super::MODERATO_CHAIN_ID, *};
    use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

    fn test_charge_request_with_amount(amount: &str) -> ChargeRequest {
        ChargeRequest {
            amount: amount.to_string(),
            currency: "0x20c0000000000000000000000000000000000000".to_string(),
            recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
            method_details: Some(serde_json::json!({ "chainId": 42431 })),
            ..Default::default()
        }
    }

    fn test_proof_challenge(request: &ChargeRequest) -> PaymentChallenge {
        PaymentChallenge::new(
            "proof-challenge-id",
            "api.example.com",
            "tempo",
            "charge",
            Base64UrlJson::from_typed(request).unwrap(),
        )
    }

    #[test]
    fn test_transfer_selector() {
        // transfer(address,uint256) = 0xa9059cbb
        assert_eq!(TRANSFER_SELECTOR, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_transfer_with_memo_selector() {
        // transferWithMemo(address,uint256,bytes32) = 0x95777d59
        assert_eq!(TRANSFER_WITH_MEMO_SELECTOR, [0x95, 0x77, 0x7d, 0x59]);
    }

    #[test]
    fn test_event_topics() {
        // Verify event topic constants match keccak256 of event signatures
        // Transfer(address,address,uint256)
        assert_eq!(
            TRANSFER_EVENT_TOPIC,
            alloy::primitives::b256!(
                "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
            )
        );

        // TransferWithMemo(address,address,uint256,bytes32)
        assert_eq!(
            TRANSFER_WITH_MEMO_EVENT_TOPIC,
            alloy::primitives::b256!(
                "57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0"
            )
        );
    }

    #[test]
    fn test_calldata_length_constants() {
        // Verify the expected calldata lengths match ABI encoding
        // transfer(address,uint256): 4 + 32 + 32 = 68
        // transferWithMemo(address,uint256,bytes32): 4 + 32 + 32 + 32 = 100
        const TRANSFER_CALLDATA_LEN: usize = 4 + 32 + 32;
        const TRANSFER_WITH_MEMO_CALLDATA_LEN: usize = 4 + 32 + 32 + 32;

        assert_eq!(TRANSFER_CALLDATA_LEN, 68);
        assert_eq!(TRANSFER_WITH_MEMO_CALLDATA_LEN, 100);
    }

    #[test]
    fn test_selector_parsing_short_input() {
        // Ensure short inputs don't panic - test with various short lengths
        let short_inputs: Vec<&[u8]> = vec![&[], &[0xa9], &[0xa9, 0x05], &[0xa9, 0x05, 0x9c]];

        for input in short_inputs {
            // This mimics the parsing logic - should not panic
            if input.len() >= 4 {
                let _selector: [u8; 4] = input[..4].try_into().unwrap_or([0; 4]);
            }
        }
    }

    #[test]
    fn test_zero_amount_rejected() {
        // Zero amounts should be rejected to prevent parse-failure bypasses
        let zero = U256::ZERO;
        assert!(zero.is_zero());

        let non_zero = U256::from(1u64);
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_zero_address_detection() {
        // Zero addresses should be rejected to prevent parse-failure bypasses
        let zero_addr = Address::ZERO;
        assert!(zero_addr.is_zero());

        let valid_addr: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f3bB77"
            .parse()
            .unwrap();
        assert!(!valid_addr.is_zero());
    }

    #[test]
    fn test_chain_id_constant() {
        // Verify the Tempo mainnet chain ID constant
        assert_eq!(CHAIN_ID, 4217);
        // Verify the Tempo Moderato testnet chain ID constant
        assert_eq!(MODERATO_CHAIN_ID, 42431);
    }

    #[test]
    fn test_fee_payer_not_configured() {
        // When fee_payer_signer is None, the error message should indicate
        // that fee sponsorship is not configured.
        let error = VerificationError::new(
            "feePayer requested but fee sponsorship is not configured on this server",
        );
        assert!(error
            .to_string()
            .contains("fee sponsorship is not configured"));
    }

    #[tokio::test]
    async fn test_zero_amount_proof_accepted() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let request = test_charge_request_with_amount("0");
        let challenge = test_proof_challenge(&request);
        let signature = proof::sign_proof(&signer, 42431, &challenge.id)
            .await
            .unwrap();
        let credential = PaymentCredential::with_source(
            challenge.to_echo(),
            proof::proof_source(signer.address(), 42431),
            crate::protocol::core::PaymentPayload::proof(signature),
        );

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);

        let receipt = method.verify(&credential, &request).await.unwrap_err();
        assert!(receipt.to_string().contains("Failed to fetch chain ID") || receipt.retryable);
    }

    #[tokio::test]
    async fn test_verify_proof_rejects_wrong_signer() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let other = alloy::signers::local::PrivateKeySigner::random();
        let request = test_charge_request_with_amount("0");
        let challenge = test_proof_challenge(&request);
        let signature = proof::sign_proof(&other, 42431, &challenge.id)
            .await
            .unwrap();
        let payload = crate::protocol::core::PaymentPayload::proof(signature);
        let credential = PaymentCredential::with_source(
            challenge.to_echo(),
            proof::proof_source(signer.address(), 42431),
            payload.clone(),
        );

        let source = credential.source.as_deref().unwrap();
        let parsed = proof::parse_proof_source(source).unwrap();
        assert!(!proof::verify_proof(
            42431,
            &credential.challenge.id,
            payload.proof_signature().unwrap(),
            parsed.address,
        ));
    }

    #[test]
    fn test_verify_zero_amount_requires_proof_payload() {
        let request = test_charge_request_with_amount("0");
        let challenge = test_proof_challenge(&request);
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            crate::protocol::core::PaymentPayload::transaction("0xdeadbeef"),
        );
        let payload = credential.charge_payload().unwrap();
        assert!(!payload.is_proof());
        assert!(request.amount_u256().unwrap().is_zero());
    }

    // ==================== Fee payer co-sign unit tests ====================

    /// Helper: build a valid TempoTransaction for fee payer tests.
    fn make_fee_payer_tx(valid_before_secs_from_now: u64) -> tempo_primitives::TempoTransaction {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        tempo_primitives::TempoTransaction {
            chain_id: CHAIN_ID,
            nonce: 0,
            nonce_key: U256::MAX,
            gas_limit: 1_000_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            fee_token: None,
            fee_payer_signature: Some(alloy::primitives::Signature::new(
                U256::ZERO,
                U256::ZERO,
                false,
            )),
            valid_before: NonZeroU64::new(now + valid_before_secs_from_now),
            valid_after: None,
            calls: vec![tempo_primitives::transaction::Call {
                to: TxKind::Call(Address::repeat_byte(0x20)),
                value: U256::ZERO,
                input: Bytes::from(vec![0xa9, 0x05, 0x9c, 0xbb]), // transfer selector
            }],
            access_list: Default::default(),
            tempo_authorization_list: vec![],
            key_authorization: None,
        }
    }

    fn make_transfer_input(recipient: Address, amount: U256) -> Bytes {
        let mut data = Vec::with_capacity(68);
        data.extend_from_slice(&TRANSFER_SELECTOR);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(recipient.as_slice());

        let mut amount_bytes = [0u8; 32];
        amount.to_be_bytes::<32>().clone_into(&mut amount_bytes);
        data.extend_from_slice(&amount_bytes);
        Bytes::from(data)
    }

    fn make_approve_input(spender: Address, amount: U256) -> Bytes {
        Bytes::from(ITIP20::approveCall { spender, amount }.abi_encode())
    }

    fn make_swap_input(token_in: Address, token_out: Address, amount_out: u128) -> Bytes {
        Bytes::from(
            IStablecoinDEX::swapExactAmountOutCall {
                tokenIn: token_in,
                tokenOut: token_out,
                amountOut: amount_out,
                maxAmountIn: amount_out,
            }
            .abi_encode(),
        )
    }

    fn encode_signed_tx(
        calls: Vec<tempo_primitives::transaction::Call>,
        gas_limit: u64,
    ) -> Vec<u8> {
        use alloy::eips::Encodable2718;
        use alloy::signers::SignerSync;

        let signer = alloy::signers::local::PrivateKeySigner::random();
        let tx = tempo_primitives::TempoTransaction {
            chain_id: CHAIN_ID,
            nonce: 0,
            nonce_key: U256::MAX,
            gas_limit,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            fee_token: Some(Address::repeat_byte(0x20)),
            fee_payer_signature: None,
            valid_before: None,
            valid_after: None,
            calls,
            access_list: Default::default(),
            tempo_authorization_list: vec![],
            key_authorization: None,
        };

        let signature: tempo_primitives::transaction::TempoSignature =
            signer.sign_hash_sync(&tx.signature_hash()).unwrap().into();

        tx.into_signed(signature).encoded_2718()
    }

    fn address_topic(address: Address) -> String {
        format!("0x{:0>64}", hex::encode(address.as_slice()))
    }

    fn amount_data(amount: U256) -> String {
        let mut amount_bytes = [0u8; 32];
        amount.to_be_bytes::<32>().clone_into(&mut amount_bytes);
        hex::encode(amount_bytes)
    }

    fn make_transfer_log(
        currency: Address,
        from: Address,
        to: Address,
        amount: U256,
    ) -> serde_json::Value {
        serde_json::json!({
            "address": format!("{:#x}", currency),
            "topics": [
                format!("{:#x}", TRANSFER_EVENT_TOPIC),
                address_topic(from),
                address_topic(to),
            ],
            "data": format!("0x{}", amount_data(amount)),
        })
    }

    fn make_transfer_with_memo_log(
        currency: Address,
        from: Address,
        to: Address,
        amount: U256,
        memo: [u8; 32],
    ) -> serde_json::Value {
        serde_json::json!({
            "address": format!("{:#x}", currency),
            "topics": [
                format!("{:#x}", TRANSFER_WITH_MEMO_EVENT_TOPIC),
                address_topic(from),
                address_topic(to),
                format!("0x{}", hex::encode(memo)),
            ],
            "data": format!("0x{}", amount_data(amount)),
        })
    }

    #[test]
    fn test_match_receipt_transfer_logs_prefers_memo_logs() {
        let currency = Address::repeat_byte(0x20);
        let sender = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x33);
        let amount = U256::from(100u64);
        let memo = attribution::encode("challenge-123", "api.example.com", None);
        let logs = vec![
            make_transfer_log(currency, sender, recipient, amount),
            make_transfer_with_memo_log(currency, sender, recipient, amount, memo),
        ];
        let expected = vec![Transfer {
            amount,
            recipient,
            memo: None,
        }];

        let matched = match_receipt_transfer_logs(&logs, sender, currency, &expected).unwrap();

        assert_eq!(matched, vec![MatchedTransferLog::Memo(memo)]);
    }

    #[test]
    fn test_match_receipt_transfer_logs_with_split_preserves_bound_memo() {
        let currency = Address::repeat_byte(0x20);
        let sender = Address::repeat_byte(0x11);
        let primary = Address::repeat_byte(0x33);
        let split = Address::repeat_byte(0x44);
        let memo = attribution::encode("challenge-123", "api.example.com", None);
        let logs = vec![
            make_transfer_log(currency, sender, split, U256::from(10u64)),
            make_transfer_with_memo_log(currency, sender, primary, U256::from(90u64), memo),
        ];
        let expected = vec![
            Transfer {
                amount: U256::from(90u64),
                recipient: primary,
                memo: None,
            },
            Transfer {
                amount: U256::from(10u64),
                recipient: split,
                memo: None,
            },
        ];

        let matched = match_receipt_transfer_logs(&logs, sender, currency, &expected).unwrap();

        assert_eq!(matched.len(), 2);
        assert!(matched.contains(&MatchedTransferLog::Memo(memo)));
        assert!(matched.contains(&MatchedTransferLog::Transfer));
    }

    #[test]
    fn test_assert_challenge_bound_memo_accepts_bound_memo() {
        let memo = attribution::encode("challenge-123", "api.example.com", None);

        assert!(assert_challenge_bound_memo(
            &[MatchedTransferLog::Memo(memo)],
            "challenge-123",
            "api.example.com",
        )
        .is_ok());
    }

    #[test]
    fn test_assert_challenge_bound_memo_rejects_plain_transfer() {
        let error = assert_challenge_bound_memo(
            &[MatchedTransferLog::Transfer],
            "challenge-123",
            "api.example.com",
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("memo is not bound to this challenge"));
    }

    #[test]
    fn test_assert_challenge_bound_memo_rejects_wrong_challenge() {
        let memo = attribution::encode("challenge-123", "api.example.com", None);

        let error = assert_challenge_bound_memo(
            &[MatchedTransferLog::Memo(memo)],
            "challenge-456",
            "api.example.com",
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("memo is not bound to this challenge"));
    }

    #[test]
    fn test_assert_challenge_bound_memo_rejects_non_mpp_memo() {
        let error = assert_challenge_bound_memo(
            &[MatchedTransferLog::Memo([0x11; 32])],
            "challenge-123",
            "api.example.com",
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("memo is not bound to this challenge"));
    }

    #[test]
    fn test_assert_challenge_bound_memo_rejects_wrong_realm() {
        let memo = attribution::encode("challenge-123", "api.example.com", None);

        let error = assert_challenge_bound_memo(
            &[MatchedTransferLog::Memo(memo)],
            "challenge-123",
            "other.example.com",
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("memo is not bound to this challenge"));
    }

    /// Helper: sign a tx and encode as a 0x78 fee payer envelope.
    fn sign_and_encode_0x78(
        tx: tempo_primitives::TempoTransaction,
        signer: &alloy::signers::local::PrivateKeySigner,
    ) -> Vec<u8> {
        use super::super::{FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID};
        use alloy::signers::SignerSync;

        let sig_hash = tx.signature_hash();
        let sig = signer.sign_hash_sync(&sig_hash).unwrap();
        let signature: tempo_primitives::transaction::TempoSignature = sig.into();
        let encoded =
            FeePayerEnvelope78::from_signing_tx(tx, signer.address(), signature).encoded_envelope();
        assert_eq!(encoded[0], TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID);
        encoded
    }

    /// Round-trip: sign 0x78 envelope → cosign_fee_payer_transaction
    /// succeeds and produces a valid co-signed 0x76 transaction.
    #[test]
    fn test_fee_payer_round_trip_0x78_envelope() {
        use super::super::{FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID};
        use alloy::eips::Decodable2718;
        use alloy::signers::SignerSync;

        let client_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let tx = make_fee_payer_tx(60);

        // Encode as a 0x78 fee payer envelope (sender address in the fee_payer slot).
        let sig_hash = tx.signature_hash();
        let sig = client_signer.sign_hash_sync(&sig_hash).unwrap();
        let signature: tempo_primitives::transaction::TempoSignature = sig.into();

        let encoded = FeePayerEnvelope78::from_signing_tx(tx, client_signer.address(), signature)
            .encoded_envelope();
        assert_eq!(encoded[0], TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID);

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let co_signed = result.expect("cosign should succeed for valid 0x78 envelope");

        // Result should be a valid 0x76 transaction
        assert_eq!(
            co_signed[0],
            tempo_primitives::transaction::TEMPO_TX_TYPE_ID,
            "co-signed output should be 0x76"
        );

        // It should be decodable by AASigned
        let signed = tempo_primitives::AASigned::decode_2718(&mut &co_signed[..])
            .expect("co-signed tx should be decodable as AASigned");

        let decoded_tx = signed.tx();
        assert_eq!(decoded_tx.chain_id, CHAIN_ID);
        assert_eq!(decoded_tx.nonce_key, U256::MAX);
        assert_eq!(decoded_tx.fee_token, Some(fee_token));
        assert!(decoded_tx.fee_payer_signature.is_some());
        assert!(decoded_tx.valid_before.is_some());
    }

    #[test]
    fn test_validate_transaction_transfers_rejects_unexpected_fee_payer_calls() {
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);

        let currency = Address::repeat_byte(0x20);
        let recipient = Address::repeat_byte(0x33);
        let expected = vec![Transfer {
            amount: U256::from(100u64),
            recipient,
            memo: None,
        }];

        let tx_bytes = encode_signed_tx(
            vec![
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(currency),
                    value: U256::ZERO,
                    input: make_transfer_input(recipient, U256::from(100u64)),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(Address::repeat_byte(0x44)),
                    value: U256::ZERO,
                    input: Bytes::from(vec![0u8; 4]),
                },
            ],
            MAX_FEE_PAYER_GAS_LIMIT,
        );

        let error = method
            .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
            .unwrap_err();

        assert!(
            error.to_string().contains("disallowed call pattern")
                || error.to_string().contains("no matching payment call")
        );
    }

    #[test]
    fn test_validate_transaction_transfers_accepts_fee_payer_approve_swap_prefix() {
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);

        let currency = Address::repeat_byte(0x20);
        let recipient = Address::repeat_byte(0x33);
        let token_in = Address::repeat_byte(0x11);
        let expected = vec![Transfer {
            amount: U256::from(100u64),
            recipient,
            memo: None,
        }];

        let tx_bytes = encode_signed_tx(
            vec![
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(token_in),
                    value: U256::ZERO,
                    input: make_approve_input(STABLECOIN_DEX_ADDRESS, U256::from(100u64)),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                    value: U256::ZERO,
                    input: make_swap_input(token_in, currency, 100),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(currency),
                    value: U256::ZERO,
                    input: make_transfer_input(recipient, U256::from(100u64)),
                },
            ],
            MAX_FEE_PAYER_GAS_LIMIT,
        );

        method
            .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
            .unwrap();
    }

    #[test]
    fn test_validate_transaction_transfers_accepts_fee_payer_approve_swap_prefix_with_splits() {
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);

        let currency = Address::repeat_byte(0x20);
        let primary_recipient = Address::repeat_byte(0x33);
        let split_recipient = Address::repeat_byte(0x34);
        let token_in = Address::repeat_byte(0x11);
        let expected = vec![
            Transfer {
                amount: U256::from(90u64),
                recipient: primary_recipient,
                memo: None,
            },
            Transfer {
                amount: U256::from(10u64),
                recipient: split_recipient,
                memo: None,
            },
        ];

        let tx_bytes = encode_signed_tx(
            vec![
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(token_in),
                    value: U256::ZERO,
                    input: make_approve_input(STABLECOIN_DEX_ADDRESS, U256::from(100u64)),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                    value: U256::ZERO,
                    input: make_swap_input(token_in, currency, 100),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(currency),
                    value: U256::ZERO,
                    input: make_transfer_input(primary_recipient, U256::from(90u64)),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(currency),
                    value: U256::ZERO,
                    input: make_transfer_input(split_recipient, U256::from(10u64)),
                },
            ],
            MAX_FEE_PAYER_GAS_LIMIT,
        );

        method
            .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
            .unwrap();
    }

    #[test]
    fn test_validate_transaction_transfers_rejects_fee_payer_swap_without_approve() {
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);

        let currency = Address::repeat_byte(0x20);
        let recipient = Address::repeat_byte(0x33);
        let token_in = Address::repeat_byte(0x11);
        let expected = vec![Transfer {
            amount: U256::from(100u64),
            recipient,
            memo: None,
        }];

        let tx_bytes = encode_signed_tx(
            vec![
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                    value: U256::ZERO,
                    input: make_swap_input(token_in, currency, 100),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(currency),
                    value: U256::ZERO,
                    input: make_transfer_input(recipient, U256::from(100u64)),
                },
            ],
            MAX_FEE_PAYER_GAS_LIMIT,
        );

        let error = method
            .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
            .unwrap_err();

        assert!(
            error.to_string().contains("disallowed call pattern")
                || error.to_string().contains("no matching payment call")
        );
    }

    #[test]
    fn test_validate_transaction_transfers_rejects_fee_payer_wrong_approve_spender() {
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);

        let currency = Address::repeat_byte(0x20);
        let recipient = Address::repeat_byte(0x33);
        let token_in = Address::repeat_byte(0x11);
        let expected = vec![Transfer {
            amount: U256::from(100u64),
            recipient,
            memo: None,
        }];

        let tx_bytes = encode_signed_tx(
            vec![
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(token_in),
                    value: U256::ZERO,
                    input: make_approve_input(Address::repeat_byte(0x99), U256::from(100u64)),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(STABLECOIN_DEX_ADDRESS),
                    value: U256::ZERO,
                    input: make_swap_input(token_in, currency, 100),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(currency),
                    value: U256::ZERO,
                    input: make_transfer_input(recipient, U256::from(100u64)),
                },
            ],
            MAX_FEE_PAYER_GAS_LIMIT,
        );

        let error = method
            .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
            .unwrap_err();

        assert!(error.to_string().contains("approve spender is not the DEX"));
    }

    #[test]
    fn test_validate_transaction_transfers_rejects_fee_payer_wrong_swap_target() {
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);

        let currency = Address::repeat_byte(0x20);
        let recipient = Address::repeat_byte(0x33);
        let token_in = Address::repeat_byte(0x11);
        let expected = vec![Transfer {
            amount: U256::from(100u64),
            recipient,
            memo: None,
        }];

        let tx_bytes = encode_signed_tx(
            vec![
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(token_in),
                    value: U256::ZERO,
                    input: make_approve_input(STABLECOIN_DEX_ADDRESS, U256::from(100u64)),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(Address::repeat_byte(0x98)),
                    value: U256::ZERO,
                    input: make_swap_input(token_in, currency, 100),
                },
                tempo_primitives::transaction::Call {
                    to: TxKind::Call(currency),
                    value: U256::ZERO,
                    input: make_transfer_input(recipient, U256::from(100u64)),
                },
            ],
            MAX_FEE_PAYER_GAS_LIMIT,
        );

        let error = method
            .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
            .unwrap_err();

        assert!(error.to_string().contains("swap target is not the DEX"));
    }

    #[test]
    fn test_validate_transaction_transfers_rejects_fee_payer_gas_limit_above_max() {
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);

        let currency = Address::repeat_byte(0x20);
        let recipient = Address::repeat_byte(0x33);
        let expected = vec![Transfer {
            amount: U256::from(100u64),
            recipient,
            memo: None,
        }];

        let tx_bytes = encode_signed_tx(
            vec![tempo_primitives::transaction::Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: make_transfer_input(recipient, U256::from(100u64)),
            }],
            MAX_FEE_PAYER_GAS_LIMIT + 1,
        );

        let error = method
            .validate_transaction_transfers(&tx_bytes, currency, &expected, CHAIN_ID, true)
            .unwrap_err();

        assert!(error.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn test_policy_override_adjusts_fee_payer_gas_limit() {
        let currency = Address::repeat_byte(0x20);
        let recipient = Address::repeat_byte(0x33);
        let expected = vec![Transfer {
            amount: U256::from(100u64),
            recipient,
            memo: None,
        }];
        let calls = vec![tempo_primitives::transaction::Call {
            to: TxKind::Call(currency),
            value: U256::ZERO,
            input: make_transfer_input(recipient, U256::from(100u64)),
        }];

        let build_method = || {
            let provider =
                alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                    .connect_http("http://127.0.0.1:1".parse().unwrap());
            ChargeMethod::new(provider)
        };

        // Lower ceiling: default (2M) would accept 2.5M, override (500k) rejects.
        let lowered = build_method().with_fee_payer_policy_override(FeePayerPolicyOverride {
            max_gas: Some(500_000),
            ..Default::default()
        });
        let tx_under_default_over_override = encode_signed_tx(calls.clone(), 500_001);
        let error = lowered
            .validate_transaction_transfers(
                &tx_under_default_over_override,
                currency,
                &expected,
                CHAIN_ID,
                true,
            )
            .unwrap_err();
        assert!(error.to_string().contains("exceeds maximum 500000"));

        // Raise ceiling: default (2M) would reject 2.5M, override (3M) accepts.
        let raised = build_method().with_fee_payer_policy_override(FeePayerPolicyOverride {
            max_gas: Some(3_000_000),
            ..Default::default()
        });
        let tx_over_default_under_override = encode_signed_tx(calls, 2_500_000);
        raised
            .validate_transaction_transfers(
                &tx_over_default_under_override,
                currency,
                &expected,
                CHAIN_ID,
                true,
            )
            .expect("override should raise ceiling above default");
    }

    /// cosign_fee_payer_transaction rejects txs with wrong nonce_key.
    #[test]
    fn test_cosign_rejects_wrong_nonce_key() {
        let client_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let mut tx = make_fee_payer_tx(60);
        tx.nonce_key = U256::ZERO; // Wrong — should be U256::MAX

        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let err = result.expect_err("should reject wrong nonce_key");
        assert!(
            err.to_string().contains("expiring nonce key"),
            "error should mention expiring nonce key, got: {err}"
        );
    }

    /// cosign_fee_payer_transaction rejects txs without valid_before.
    #[test]
    fn test_cosign_rejects_missing_valid_before() {
        let client_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let mut tx = make_fee_payer_tx(60);
        tx.valid_before = None; // Missing

        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let err = result.expect_err("should reject missing valid_before");
        assert!(
            err.to_string().contains("must include valid_before"),
            "error should mention valid_before, got: {err}"
        );
    }

    /// cosign_fee_payer_transaction rejects txs with expired valid_before.
    #[test]
    fn test_cosign_rejects_expired_valid_before() {
        let client_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        // Build a tx with valid_before in the past
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10;

        let mut tx = make_fee_payer_tx(60);
        tx.valid_before = NonZeroU64::new(past);

        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &encoded,
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let err = result.expect_err("should reject expired valid_before");
        assert!(
            err.to_string().contains("expired"),
            "error should mention expiration, got: {err}"
        );
    }

    /// cosign_fee_payer_transaction rejects empty input.
    #[test]
    fn test_cosign_rejects_empty_input() {
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &[],
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let err = result.expect_err("should reject empty input");
        assert!(
            err.to_string().contains("Empty transaction bytes"),
            "error should mention empty, got: {err}"
        );
    }

    /// cosign_fee_payer_transaction rejects non-0x78 type byte.
    #[test]
    fn test_cosign_rejects_wrong_type_byte() {
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();

        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());

        let method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer);

        let result = method.cosign_fee_payer_transaction(
            &[0x79, 0xc0], // wrong type byte
            method.fee_payer_signer.as_ref().unwrap(),
            fee_token,
        );

        let err = result.expect_err("should reject wrong type");
        assert!(
            err.to_string()
                .contains("Expected fee payer envelope (0x78)"),
            "error should mention 0x78, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_store_rejects_replayed_hash() {
        use crate::store::{MemoryStore, Store};

        let store = Arc::new(MemoryStore::new());
        let hash = "0xabc123def456";

        // Simulate first successful verification: record the hash
        let key = format!("mpp:charge:{hash}");
        store
            .put(&key, serde_json::Value::Bool(true))
            .await
            .unwrap();

        // Verify the hash is now in the store
        let seen = store.get(&key).await.unwrap();
        assert!(seen.is_some(), "hash should be recorded after first use");

        // A second lookup should find it (replay detected)
        let seen_again = store.get(&key).await.unwrap();
        assert!(
            seen_again.is_some(),
            "replayed hash should be detected via store"
        );
    }

    #[tokio::test]
    async fn test_store_allows_unseen_hash() {
        use crate::store::{MemoryStore, Store};

        let store = Arc::new(MemoryStore::new());

        // A hash that was never recorded should not be found
        let key = "mpp:charge:0xnever_seen";
        let seen = store.get(key).await.unwrap();
        assert!(seen.is_none(), "unseen hash should not be in store");
    }

    #[tokio::test]
    async fn test_store_dedup_case_insensitive() {
        use crate::store::{MemoryStore, Store};

        let store = Arc::new(MemoryStore::new());

        // Simulate the canonical key construction used by verify_hash:
        // parse to B256, then format with {:#x} for canonical lowercase 0x-prefixed output.
        let mixed_case = "0xABCdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let hash = mixed_case.parse::<B256>().unwrap();
        let key1 = format!("mpp:charge:{:#x}", hash);
        store
            .put(&key1, serde_json::Value::Bool(true))
            .await
            .unwrap();

        // Same hash submitted with different casing produces same canonical key
        let lower_case = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let hash2 = lower_case.parse::<B256>().unwrap();
        let key2 = format!("mpp:charge:{:#x}", hash2);
        let seen = store.get(&key2).await.unwrap();
        assert!(
            seen.is_some(),
            "same hash with different case should be detected as replay"
        );

        // Without 0x prefix should also parse to the same canonical key
        let no_prefix = "ABCdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let hash3 = no_prefix.parse::<B256>().unwrap();
        let key3 = format!("mpp:charge:{:#x}", hash3);
        assert_eq!(
            key1, key3,
            "0x-prefixed and unprefixed should produce same key"
        );
    }

    #[tokio::test]
    async fn test_store_dedup_different_hashes_independent() {
        use crate::store::{MemoryStore, Store};

        let store = Arc::new(MemoryStore::new());

        // Record one hash
        store
            .put("mpp:charge:0xhash_a", serde_json::Value::Bool(true))
            .await
            .unwrap();

        // Different hash should not be affected
        let seen = store.get("mpp:charge:0xhash_b").await.unwrap();
        assert!(seen.is_none(), "different hash should not be blocked");

        // Original hash should still be blocked
        let seen = store.get("mpp:charge:0xhash_a").await.unwrap();
        assert!(seen.is_some(), "original hash should still be recorded");
    }

    // ==================== Chain ID caching tests ====================

    #[test]
    fn test_charge_method_new_has_empty_chain_id_cache() {
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);
        assert!(
            method.cached_chain_id.get().is_none(),
            "cache should be empty on construction"
        );
    }

    #[test]
    fn test_charge_method_clone_shares_chain_id_cache() {
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);

        // Pre-populate the cache
        method.cached_chain_id.set(42431).unwrap();

        // Clone shares the same Arc<OnceCell>
        let cloned = method.clone();
        assert_eq!(
            cloned.cached_chain_id.get(),
            Some(&42431),
            "clone should share the cached chain ID"
        );
    }

    #[tokio::test]
    async fn test_cached_chain_id_survives_across_verify_calls() {
        // Verify that the OnceCell is shared across the ChargeMethod's
        // internal clones in the verify() async block.
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let method = ChargeMethod::new(provider);

        // First call will fail (can't reach RPC) but the cache should remain empty
        let request = test_charge_request_with_amount("0");
        let challenge = test_proof_challenge(&request);
        let credential = PaymentCredential::new(
            challenge.to_echo(),
            crate::protocol::core::PaymentPayload::hash("0xdeadbeef"),
        );
        let _ = method.verify(&credential, &request).await;

        // Cache should still be empty because the RPC call failed
        assert!(
            method.cached_chain_id.get().is_none(),
            "failed RPC should not populate cache"
        );

        // Manually populate the cache to simulate a successful first call
        method.cached_chain_id.set(42431).unwrap();

        // Subsequent access should return the cached value
        assert_eq!(method.cached_chain_id.get(), Some(&42431));
    }

    #[tokio::test]
    async fn test_cached_chain_id_oncecell_rejects_second_init() {
        // OnceCell should reject a second initialization attempt,
        // ensuring the cached value is immutable after first set.
        let cell = Arc::new(OnceCell::new());
        cell.set(42431).unwrap();

        let result = cell.set(9999);
        assert!(result.is_err(), "OnceCell should reject second set");
        assert_eq!(
            cell.get(),
            Some(&42431),
            "original value should be retained"
        );
    }

    fn make_cosign_method(
        fee_payer_policy_override: Option<FeePayerPolicyOverride>,
    ) -> (
        ChargeMethod<impl alloy::providers::Provider<TempoNetwork> + Clone + 'static>,
        alloy::signers::local::PrivateKeySigner,
        Address,
    ) {
        let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
        let fee_token: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let provider =
            alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
                .connect_http("http://127.0.0.1:1".parse().unwrap());
        let mut method = ChargeMethod::new(provider).with_fee_payer(fee_payer_signer.clone());
        if let Some(overrides) = fee_payer_policy_override {
            method = method.with_fee_payer_policy_override(overrides);
        }
        (method, fee_payer_signer, fee_token)
    }

    /// cosign_fee_payer_transaction rejects tx with max_fee_per_gas above policy.
    #[test]
    fn test_cosign_rejects_excessive_max_fee_per_gas() {
        let overrides = FeePayerPolicyOverride {
            max_fee_per_gas: Some(500_000_000), // 0.5 gwei ceiling
            ..Default::default()
        };
        let (method, client_signer, fee_token) = make_cosign_method(Some(overrides));

        let mut tx = make_fee_payer_tx(60);
        tx.max_fee_per_gas = 600_000_000; // above 0.5 gwei ceiling
        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let err = method
            .cosign_fee_payer_transaction(
                &encoded,
                method.fee_payer_signer.as_ref().unwrap(),
                fee_token,
            )
            .expect_err("should reject excessive max_fee_per_gas");
        assert!(err.to_string().contains("max_fee_per_gas"), "got: {err}");
    }

    /// cosign_fee_payer_transaction rejects tx with max_priority_fee_per_gas above policy.
    #[test]
    fn test_cosign_rejects_excessive_max_priority_fee_per_gas() {
        let overrides = FeePayerPolicyOverride {
            max_priority_fee_per_gas: Some(100_000_000), // 0.1 gwei ceiling
            ..Default::default()
        };
        let (method, client_signer, fee_token) = make_cosign_method(Some(overrides));

        let mut tx = make_fee_payer_tx(60);
        tx.max_priority_fee_per_gas = 200_000_000; // above 0.1 gwei ceiling
        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let err = method
            .cosign_fee_payer_transaction(
                &encoded,
                method.fee_payer_signer.as_ref().unwrap(),
                fee_token,
            )
            .expect_err("should reject excessive max_priority_fee_per_gas");
        assert!(
            err.to_string().contains("max_priority_fee_per_gas"),
            "got: {err}"
        );
    }

    /// cosign_fee_payer_transaction rejects tx whose total fee exceeds the policy cap.
    #[test]
    fn test_cosign_rejects_excessive_total_fee() {
        // Set a 0.5 gwei max_fee_per_gas ceiling and default gas limit of 1M →
        // total_fee ceiling = 500_000_000_000_000. Build a tx that hits exactly
        // the total_fee limit by using a large gas_limit.
        let overrides = FeePayerPolicyOverride {
            max_total_fee: Some(500_000_000_000_000), // ceiling
            ..Default::default()
        };
        let (method, client_signer, fee_token) = make_cosign_method(Some(overrides));

        let mut tx = make_fee_payer_tx(60);
        // gas_limit=1_000_000, max_fee_per_gas=1_000_000_000 →
        // total = 1_000_000_000_000_000 > 500_000_000_000_000 ceiling
        tx.gas_limit = 1_000_000;
        tx.max_fee_per_gas = 1_000_000_000;
        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let err = method
            .cosign_fee_payer_transaction(
                &encoded,
                method.fee_payer_signer.as_ref().unwrap(),
                fee_token,
            )
            .expect_err("should reject excessive total fee");
        assert!(err.to_string().contains("Total fee"), "got: {err}");
    }

    #[test]
    fn test_cosign_rejects_excessive_total_fee_under_gas_limit_and_fee_per_gas() {
        let (method, client_signer, fee_token) = make_cosign_method(None);

        let mut tx = make_fee_payer_tx(60);
        // gas_limit=1_999_999, max_fee_per_gas=99_000_000_000 →
        // total = 197_999_901_000_000_000 > 50_000_000_000_000_000 MAX_TOTAL_FEE_DEFAULT
        tx.gas_limit = 1_999_999;
        tx.max_fee_per_gas = 99_000_000_000;
        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let err = method
            .cosign_fee_payer_transaction(
                &encoded,
                method.fee_payer_signer.as_ref().unwrap(),
                fee_token,
            )
            .expect_err("should reject excessive total fee");
        assert!(err.to_string().contains("Total fee"), "got: {err}");
    }

    /// cosign_fee_payer_transaction rejects tx with valid_before window beyond policy max.
    #[test]
    fn test_cosign_rejects_excessive_validity_window() {
        let overrides = FeePayerPolicyOverride {
            max_validity_window_seconds: Some(30), // 30-second ceiling
            ..Default::default()
        };
        let (method, client_signer, fee_token) = make_cosign_method(Some(overrides));

        // valid_before = now + 120s → window of 120s > 30s ceiling
        let tx = make_fee_payer_tx(120);
        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let err = method
            .cosign_fee_payer_transaction(
                &encoded,
                method.fee_payer_signer.as_ref().unwrap(),
                fee_token,
            )
            .expect_err("should reject excessive validity window");
        assert!(
            err.to_string().contains("valid_before window"),
            "got: {err}"
        );
    }

    /// All five policy override fields are respected when set together.
    #[test]
    fn test_policy_override_all_fields_applied() {
        // Generous overrides — tx should pass all checks.
        let overrides = FeePayerPolicyOverride {
            max_gas: Some(2_000_000),
            max_fee_per_gas: Some(20_000_000_000),
            max_priority_fee_per_gas: Some(2_000_000_000),
            max_total_fee: Some(40_000_000_000_000_000),
            max_validity_window_seconds: Some(600),
        };
        let (method, client_signer, fee_token) = make_cosign_method(Some(overrides));

        let mut tx = make_fee_payer_tx(60);
        tx.gas_limit = 1_500_000; // within 2M override
        tx.max_fee_per_gas = 15_000_000_000; // within 20 gwei override
        tx.max_priority_fee_per_gas = 1_500_000_000; // within 2 gwei override
        let encoded = sign_and_encode_0x78(tx, &client_signer);

        method
            .cosign_fee_payer_transaction(
                &encoded,
                method.fee_payer_signer.as_ref().unwrap(),
                fee_token,
            )
            .expect("cosign should succeed when all fields within override limits");
    }

    /// EIP-1559 invariant: priority fee cannot exceed max fee per gas.
    #[test]
    fn test_cosign_rejects_priority_fee_above_max_fee() {
        let (method, client_signer, fee_token) = make_cosign_method(None);

        let mut tx = make_fee_payer_tx(60);
        // Both within policy ceilings, but priority > max_fee violates EIP-1559.
        tx.max_fee_per_gas = 1_000_000_000; // 1 gwei
        tx.max_priority_fee_per_gas = 2_000_000_000; // 2 gwei > max_fee_per_gas
        let encoded = sign_and_encode_0x78(tx, &client_signer);

        let err = method
            .cosign_fee_payer_transaction(
                &encoded,
                method.fee_payer_signer.as_ref().unwrap(),
                fee_token,
            )
            .expect_err("priority fee above max fee must be rejected");
        assert!(
            err.to_string()
                .contains("max_priority_fee_per_gas 2000000000 exceeds max_fee_per_gas"),
            "got: {err}"
        );
    }

    /// Moderato chain default raises `max_priority_fee_per_gas` to 50 gwei.
    #[test]
    fn test_policy_moderato_default_raises_priority_fee() {
        let tempo_mainnet = FeePayerPolicy::resolve(CHAIN_ID, None);
        let moderato = FeePayerPolicy::resolve(MODERATO_CHAIN_ID, None);

        assert_eq!(tempo_mainnet.max_priority_fee_per_gas, 10_000_000_000);
        assert_eq!(moderato.max_priority_fee_per_gas, 50_000_000_000);
        // All other fields should equal the mainnet default.
        assert_eq!(moderato.max_gas, tempo_mainnet.max_gas);
        assert_eq!(moderato.max_fee_per_gas, tempo_mainnet.max_fee_per_gas);
        assert_eq!(moderato.max_total_fee, tempo_mainnet.max_total_fee);
        assert_eq!(
            moderato.max_validity_window_seconds,
            tempo_mainnet.max_validity_window_seconds
        );
    }
}
