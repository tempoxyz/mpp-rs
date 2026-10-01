//! Fee sponsorship: policy, fee-payer envelope validation, co-signing and
//! fee-token selection.

use alloy::consensus::transaction::SignerRecoverable;
use alloy::primitives::Address;
use alloy::providers::Provider;
use tempo_alloy::contracts::precompiles::ITIP20;
use tempo_alloy::TempoNetwork;

use crate::protocol::traits::VerificationError;

use super::super::{network::TempoNetwork as KnownTempoNetwork, CHAIN_ID, PATH_USD};
use super::ChargeMethod;

pub(super) const MAX_FEE_PAYER_GAS_LIMIT: u64 = 2_000_000;
const MAX_FEE_PER_GAS_DEFAULT: u128 = 100_000_000_000;
const MAX_PRIORITY_FEE_PER_GAS_DEFAULT: u128 = 10_000_000_000;
const MAX_VALIDITY_WINDOW_SECS_DEFAULT: u64 = 15 * 60;
const MAX_TOTAL_FEE_DEFAULT: u128 = 50_000_000_000_000_000; // lower than max_gas * max_fee_per_gas

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

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    pub(super) fn validate_fee_payer_transaction(
        &self,
        tx_bytes: &[u8],
        fee_token: Option<Address>,
    ) -> Result<(tempo_alloy::primitives::AASigned, Address), VerificationError> {
        use super::super::fee_payer_envelope::{
            FeePayerEnvelope78, TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID,
        };
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
    pub(super) async fn cosign_fee_payer_transaction(
        &self,
        tx_bytes: &[u8],
        fee_payer_signer: &super::super::DynSigner,
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
    pub(super) fn allowed_fee_tokens(&self, chain_id: u64) -> Vec<Address> {
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
    pub(super) async fn resolve_fee_payer_fee_token(
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
