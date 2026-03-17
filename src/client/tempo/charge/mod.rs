//! Tempo charge builder — a Stripe-like API for building and signing Tempo payments.
//!
//! Separates "what to pay" (parsed from the challenge) from "how to resolve
//! gas/nonce/signer" so that simple users get a 3-line path and power users
//! can inject their own nonce, gas config, and signing mode.
//!
//! # Simple path (3 lines)
//!
//! ```ignore
//! let charge = TempoCharge::from_challenge(&challenge)?;
//! let signed = charge.sign(&signer).await?;
//! let credential = signed.into_credential();
//! ```
//!
//! # Power user path
//!
//! ```ignore
//! let charge = TempoCharge::from_challenge(&challenge)?;
//! let signed = charge.sign_with_options(&signer, SignOptions {
//!     nonce: Some(42),
//!     gas_limit: Some(500_000),
//!     max_fee_per_gas: Some(2_000_000_000),
//!     max_priority_fee_per_gas: Some(100_000_000),
//!     signing_mode: TempoSigningMode::Keychain { wallet, key_authorization: None },
//!     rpc_url: Some("https://rpc.tempo.xyz".to_string()),
//!     ..Default::default()
//! }).await?;
//! let credential = signed.into_credential();
//! ```

pub mod tx_builder;

use alloy::primitives::{Address, TxKind, U256};
use tempo_primitives::transaction::{Call, SignedKeyAuthorization};

use self::tx_builder::{build_charge_credential, build_tempo_tx, estimate_gas, TempoTxOptions};
use crate::client::tempo::abi::encode_transfer;
use crate::client::tempo::signing::{
    sign_and_encode_async, sign_and_encode_fee_payer_envelope_async, TempoSigningMode,
};
use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::methods::tempo::charge::{parse_memo_bytes, TempoChargeExt};
use crate::protocol::methods::tempo::network::TempoNetwork;
use crate::protocol::methods::tempo::CHAIN_ID;

/// Nonce key for expiring nonce transactions (fee payer mode).
const EXPIRING_NONCE_KEY: U256 = U256::MAX;

/// Validity window (in seconds) for fee payer transactions.
const FEE_PAYER_VALID_BEFORE_SECS: u64 = 25;

/// A parsed, validated Tempo charge ready to be signed.
///
/// Created from a [`PaymentChallenge`] via [`TempoCharge::from_challenge`].
/// Contains all "what to pay" fields extracted from the challenge. The "how to sign"
/// details (nonce, gas, signer) are provided later via [`sign`](TempoCharge::sign) or
/// [`sign_with_options`](TempoCharge::sign_with_options).
#[derive(Debug, Clone)]
pub struct TempoCharge {
    challenge: PaymentChallenge,
    recipient: Address,
    currency: Address,
    amount: U256,
    memo: Option<[u8; 32]>,
    chain_id: u64,
    fee_payer: bool,
    calls: Option<Vec<Call>>,
}

impl TempoCharge {
    /// Parse and validate a [`PaymentChallenge`] into a [`TempoCharge`].
    ///
    /// Validates that the challenge is a Tempo charge, decodes the
    /// [`ChargeRequest`], and extracts all payment fields.
    pub fn from_challenge(challenge: &PaymentChallenge) -> Result<Self, MppError> {
        challenge.validate_for_charge("tempo")?;

        let charge_req: ChargeRequest = challenge.request.decode()?;

        let recipient = charge_req.recipient_address()?;
        let currency = charge_req.currency_address()?;
        let amount = charge_req.amount_u256()?;
        let memo = parse_memo_bytes(charge_req.memo());
        let chain_id = charge_req.chain_id().unwrap_or(CHAIN_ID);
        let fee_payer = charge_req.fee_payer();

        Ok(Self {
            challenge: challenge.clone(),
            recipient,
            currency,
            amount,
            memo,
            chain_id,
            fee_payer,
            calls: None,
        })
    }

    /// Get the chain ID extracted from the challenge.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Get the currency address.
    pub fn currency(&self) -> Address {
        self.currency
    }

    /// Get the recipient address.
    pub fn recipient(&self) -> Address {
        self.recipient
    }

    /// Get the amount.
    pub fn amount(&self) -> U256 {
        self.amount
    }

    /// Get the memo bytes, if present.
    pub fn memo(&self) -> Option<[u8; 32]> {
        self.memo
    }

    /// Set the memo bytes (e.g. an auto-generated attribution memo).
    pub fn with_memo(mut self, memo: [u8; 32]) -> Self {
        self.memo = Some(memo);
        self
    }

    /// Whether fee sponsorship is requested.
    pub fn fee_payer(&self) -> bool {
        self.fee_payer
    }

    /// Prepend a call to the transaction's call list.
    ///
    /// Used by autoswap to insert a DEX swap call before the transfer call.
    /// The swap and transfer then execute atomically in a single AA transaction.
    pub fn with_prepended_call(mut self, call: Call) -> Self {
        let calls = self.calls.get_or_insert_with(|| {
            let transfer_data =
                crate::client::tempo::abi::encode_transfer(self.recipient, self.amount, self.memo);
            vec![Call {
                to: TxKind::Call(self.currency),
                value: U256::ZERO,
                input: transfer_data,
            }]
        });
        calls.insert(0, call);
        self
    }

    /// Sign the charge with default options.
    ///
    /// This is the simple path — resolves the RPC provider from chain_id,
    /// fetches the pending nonce, reads the current base fee, estimates gas,
    /// builds and signs the transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if the chain_id is not a known Tempo network, or if
    /// RPC calls (nonce, gas estimation) fail.
    pub async fn sign(
        self,
        signer: &(impl alloy::signers::Signer + Clone),
    ) -> Result<SignedTempoCharge, MppError> {
        self.sign_with_options(signer, SignOptions::default()).await
    }

    /// Sign the charge with explicit options for gas, nonce, signing mode, etc.
    ///
    /// Power users use this to inject their own nonce resolution, gas bumping,
    /// keychain signing mode, and key authorization provisioning.
    pub async fn sign_with_options(
        self,
        signer: &(impl alloy::signers::Signer + Clone),
        options: SignOptions,
    ) -> Result<SignedTempoCharge, MppError> {
        let signing_mode = options.signing_mode.unwrap_or_default();
        let from = signing_mode.from_address(signer.address());

        // Resolve RPC provider + build calls
        let rpc_url = match options.rpc_url {
            Some(url) => url
                .parse()
                .map_err(|e| MppError::InvalidConfig(format!("invalid RPC URL: {}", e)))?,
            None => {
                let network = TempoNetwork::from_chain_id(self.chain_id).ok_or_else(|| {
                    MppError::InvalidConfig(format!(
                        "unknown chain ID {}: provide rpc_url in SignOptions",
                        self.chain_id
                    ))
                })?;
                network
                    .default_rpc_url()
                    .parse()
                    .map_err(|e| MppError::InvalidConfig(format!("invalid RPC URL: {}", e)))?
            }
        };
        let provider =
            alloy::providers::RootProvider::<tempo_alloy::TempoNetwork>::new_http(rpc_url);

        let calls = self.calls.unwrap_or_else(|| {
            let transfer_data = encode_transfer(self.recipient, self.amount, self.memo);
            vec![Call {
                to: TxKind::Call(self.currency),
                value: U256::ZERO,
                input: transfer_data,
            }]
        });

        let fee_token = options.fee_token.unwrap_or(self.currency);

        // All charge payments use expiring nonces (nonceKey=MAX, nonce=0,
        // validBefore=now+25s) so we never need a nonce fetch.
        // Tempo uses a fixed 20 gwei base fee, so gas fees are static.
        let max_fee_per_gas = options
            .max_fee_per_gas
            .unwrap_or(crate::client::tempo::MAX_FEE_PER_GAS);
        let max_priority_fee_per_gas = options
            .max_priority_fee_per_gas
            .unwrap_or(crate::client::tempo::MAX_PRIORITY_FEE_PER_GAS);

        let nonce = options.nonce.unwrap_or(0);
        let nonce_key = options.nonce_key.unwrap_or(EXPIRING_NONCE_KEY);
        let valid_before = options.valid_before.or_else(|| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            Some(now + FEE_PAYER_VALID_BEFORE_SECS)
        });

        let gas_limit = if let Some(gas) = options.gas_limit {
            gas
        } else if self.fee_payer {
            // In fee-payer mode the client may not hold native gas, so
            // eth_estimateGas would revert. Use a safe default; the server
            // co-signs and pays for gas.
            1_000_000
        } else {
            let key_auth = options
                .key_authorization
                .as_deref()
                .or_else(|| signing_mode.key_authorization());
            estimate_gas(
                &provider,
                from,
                self.chain_id,
                nonce,
                fee_token,
                &calls,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                key_auth,
                nonce_key,
                valid_before,
            )
            .await?
        };

        // Build the key_authorization for the transaction
        let tx_key_authorization = options
            .key_authorization
            .as_deref()
            .or_else(|| signing_mode.key_authorization())
            .cloned();

        let tx = build_tempo_tx(TempoTxOptions {
            calls,
            chain_id: self.chain_id,
            fee_token,
            nonce,
            nonce_key,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            fee_payer: self.fee_payer,
            valid_before,
            key_authorization: tx_key_authorization,
        });

        // If fee sponsorship is requested, send the `0x78` fee payer envelope
        // so MPPx servers can co-sign and broadcast (standard `0x76`).
        let tx_bytes = if self.fee_payer {
            sign_and_encode_fee_payer_envelope_async(tx, signer, &signing_mode).await?
        } else {
            sign_and_encode_async(tx, signer, &signing_mode).await?
        };

        Ok(SignedTempoCharge {
            challenge: self.challenge,
            tx_bytes,
            chain_id: self.chain_id,
            from,
        })
    }
}

/// Options for controlling the signing pipeline.
///
/// Power users set these to override the defaults (nonce resolution,
/// gas estimation, signing mode, etc.). All fields are optional —
/// unset fields are resolved automatically.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// Override the RPC URL (otherwise resolved from chain_id).
    pub rpc_url: Option<String>,
    /// Override the transaction nonce (otherwise fetched as pending via `eth_getTransactionCount`).
    pub nonce: Option<u64>,
    /// Override the nonce key (default: `U256::ZERO`).
    pub nonce_key: Option<U256>,
    /// Override the gas limit (otherwise estimated via `eth_estimateGas`).
    pub gas_limit: Option<u64>,
    /// Override max fee per gas in wei (otherwise derived from the latest block's base fee).
    pub max_fee_per_gas: Option<u128>,
    /// Override max priority fee per gas in wei (default: 1 gwei floor).
    pub max_priority_fee_per_gas: Option<u128>,
    /// Override the fee token address (default: the charge currency).
    pub fee_token: Option<Address>,
    /// Override the signing mode (default: [`TempoSigningMode::Direct`]).
    pub signing_mode: Option<TempoSigningMode>,
    /// Provide a key authorization to include in the transaction.
    pub key_authorization: Option<Box<SignedKeyAuthorization>>,
    /// Optional validity window upper bound (unix timestamp) for fee payer mode.
    pub valid_before: Option<u64>,
}

/// A signed Tempo charge, ready to be converted into a [`PaymentCredential`].
#[derive(Debug)]
pub struct SignedTempoCharge {
    challenge: PaymentChallenge,
    tx_bytes: Vec<u8>,
    chain_id: u64,
    from: Address,
}

impl SignedTempoCharge {
    /// Convert the signed charge into a [`PaymentCredential`].
    pub fn into_credential(self) -> PaymentCredential {
        build_charge_credential(&self.challenge, &self.tx_bytes, self.chain_id, self.from)
    }

    /// Get the raw signed transaction bytes.
    pub fn tx_bytes(&self) -> &[u8] {
        &self.tx_bytes
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Get the `from` address used for signing.
    pub fn from_address(&self) -> Address {
        self.from
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::Base64UrlJson;

    fn test_challenge() -> PaymentChallenge {
        let request_json = serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": {
                "chainId": 42431
            }
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        PaymentChallenge::new("test-id", "api.example.com", "tempo", "charge", request)
    }

    #[test]
    fn test_from_challenge_parses_fields() {
        let challenge = test_challenge();
        let charge = TempoCharge::from_challenge(&challenge).unwrap();

        assert_eq!(charge.chain_id(), 42431);
        assert_eq!(
            charge.currency(),
            "0x20c0000000000000000000000000000000000000"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            charge.recipient(),
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(charge.amount(), U256::from(1_000_000u64));
        assert!(!charge.fee_payer());
    }

    #[test]
    fn test_from_challenge_wrong_method() {
        let request = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "stripe", "charge", request);
        assert!(TempoCharge::from_challenge(&challenge).is_err());
    }

    #[test]
    fn test_from_challenge_wrong_intent() {
        let request = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let challenge = PaymentChallenge::new("id", "api", "tempo", "session", request);
        assert!(TempoCharge::from_challenge(&challenge).is_err());
    }

    #[test]
    fn test_from_challenge_with_fee_payer() {
        let request_json = serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": {
                "chainId": 42431,
                "feePayer": true
            }
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let challenge =
            PaymentChallenge::new("test-id", "api.example.com", "tempo", "charge", request);
        let charge = TempoCharge::from_challenge(&challenge).unwrap();

        assert!(charge.fee_payer());
    }

    #[test]
    fn test_from_challenge_default_chain_id() {
        let request_json = serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let challenge =
            PaymentChallenge::new("test-id", "api.example.com", "tempo", "charge", request);
        let charge = TempoCharge::from_challenge(&challenge).unwrap();

        assert_eq!(charge.chain_id(), CHAIN_ID);
    }

    #[test]
    fn test_from_challenge_with_memo() {
        let request_json = serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": {
                "chainId": 42431,
                "memo": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            }
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let challenge =
            PaymentChallenge::new("test-id", "api.example.com", "tempo", "charge", request);
        let charge = TempoCharge::from_challenge(&challenge).unwrap();

        assert!(charge.memo.is_some());
    }

    #[test]
    fn test_sign_options_default() {
        let opts = SignOptions::default();
        assert!(opts.rpc_url.is_none());
        assert!(opts.nonce.is_none());
        assert!(opts.gas_limit.is_none());
        assert!(opts.max_fee_per_gas.is_none());
        assert!(opts.max_priority_fee_per_gas.is_none());
        assert!(opts.fee_token.is_none());
        assert!(opts.signing_mode.is_none());
        assert!(opts.key_authorization.is_none());
        assert!(opts.valid_before.is_none());
        assert!(opts.nonce_key.is_none());
    }

    #[test]
    fn test_signed_charge_into_credential() {
        let challenge = test_challenge();
        let from: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
            .parse()
            .unwrap();
        let signed = SignedTempoCharge {
            challenge,
            tx_bytes: vec![0x76, 0xab, 0xcd],
            chain_id: 42431,
            from,
        };

        let credential = signed.into_credential();
        let tx_hex = credential
            .payload
            .get("signature")
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(tx_hex, "0x76abcd");

        let did = credential.source.as_ref().unwrap();
        assert!(did.starts_with("did:pkh:eip155:42431:"));
    }

    #[test]
    fn test_signed_charge_accessors() {
        let challenge = test_challenge();
        let from = Address::repeat_byte(0x11);
        let signed = SignedTempoCharge {
            challenge,
            tx_bytes: vec![0x76],
            chain_id: 4217,
            from,
        };

        assert_eq!(signed.tx_bytes(), &[0x76]);
        assert_eq!(signed.chain_id(), 4217);
        assert_eq!(signed.from_address(), from);
    }
}
