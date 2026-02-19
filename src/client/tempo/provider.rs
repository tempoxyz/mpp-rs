//! Tempo charge payment provider.

use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};

use super::signing::TempoSigningMode;
use crate::client::PaymentProvider;

/// Nonce key for expiring nonce transactions (fee payer mode).
const EXPIRING_NONCE_KEY: alloy::primitives::U256 = alloy::primitives::U256::MAX;

/// Validity window (in seconds) for fee payer transactions.
const FEE_PAYER_VALID_BEFORE_SECS: u64 = 25;

/// Tempo payment provider using EVM signing.
///
/// Signs TIP-20 token transfer transactions for charge requests. The signed
/// transaction is returned in the credential for the server to broadcast,
/// enabling fee sponsorship.
///
/// This provider:
/// 1. Parses the charge request from the challenge
/// 2. Builds and signs a TIP-20 transfer transaction
/// 3. Returns a credential with the signed transaction (server broadcasts)
///
/// # Examples
///
/// ```ignore
/// use mpp::client::TempoProvider;
/// use mpp::PrivateKeySigner;
///
/// let signer = PrivateKeySigner::from_bytes(&key)?;
/// let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
///
/// // Use with Fetch trait
/// let resp = client
///     .get("https://api.example.com/paid")
///     .send_with_payment(&provider)
///     .await?;
/// ```
#[derive(Clone)]
pub struct TempoProvider {
    signer: alloy_signer_local::PrivateKeySigner,
    rpc_url: reqwest::Url,
    client_id: Option<String>,
    signing_mode: TempoSigningMode,
}

impl TempoProvider {
    /// Create a new Tempo provider with the given signer and RPC URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC URL is invalid.
    pub fn new(
        signer: alloy_signer_local::PrivateKeySigner,
        rpc_url: impl AsRef<str>,
    ) -> Result<Self, MppError> {
        let url = rpc_url
            .as_ref()
            .parse()
            .map_err(|e| MppError::InvalidConfig(format!("invalid RPC URL: {}", e)))?;
        Ok(Self {
            signer,
            rpc_url: url,
            client_id: None,
            signing_mode: TempoSigningMode::Direct,
        })
    }

    /// Set an optional client identifier for attribution memos.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Set the signing mode (direct or keychain).
    ///
    /// Default is [`TempoSigningMode::Direct`].
    pub fn with_signing_mode(mut self, mode: TempoSigningMode) -> Self {
        self.signing_mode = mode;
        self
    }

    /// Get the signing mode.
    pub fn signing_mode(&self) -> &TempoSigningMode {
        &self.signing_mode
    }

    /// Get a reference to the signer.
    pub fn signer(&self) -> &alloy_signer_local::PrivateKeySigner {
        &self.signer
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &reqwest::Url {
        &self.rpc_url
    }
}

impl PaymentProvider for TempoProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == "tempo" && intent == "charge"
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        use crate::protocol::intents::ChargeRequest;
        use crate::protocol::methods::tempo::{TempoChargeExt, CHAIN_ID};
        use alloy::primitives::{Bytes, TxKind, B256, U256};
        use alloy::providers::{Provider, ProviderBuilder};
        use alloy::sol_types::SolCall;
        use tempo_alloy::contracts::precompiles::tip20::ITIP20;
        use tempo_alloy::TempoNetwork;
        use tempo_primitives::transaction::Call;

        use super::signing;
        use super::tx_builder;

        let charge: ChargeRequest = challenge.request.decode()?;
        let expected_chain_id = charge.chain_id().unwrap_or(CHAIN_ID);
        let from = self.signing_mode.from_address(self.signer.address());
        let fee_payer = charge.fee_payer();

        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(self.rpc_url.clone());

        let actual_chain_id: u64 = provider
            .get_chain_id()
            .await
            .map_err(|e| MppError::Http(format!("failed to get chain ID: {}", e)))?;

        if actual_chain_id != expected_chain_id {
            return Err(MppError::ChainIdMismatch {
                expected: expected_chain_id,
                got: actual_chain_id,
            });
        }

        let recipient = charge.recipient_address()?;
        let amount = charge.amount_u256()?;
        let currency = charge.currency_address()?;

        let memo: B256 = charge
            .memo()
            .and_then(|m| m.parse().ok())
            .unwrap_or_else(|| {
                crate::tempo::attribution::encode(&challenge.realm, self.client_id.as_deref())
                    .into()
            });

        let transfer_data =
            ITIP20::transferWithMemoCall::new((recipient, amount, memo)).abi_encode();

        // Fee payer mode: use expiring nonces to avoid nonce collisions
        // when the server broadcasts on the client's behalf.
        let (nonce_key, nonce, valid_before) = if fee_payer {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| MppError::Http(format!("system clock error: {}", e)))?
                .as_secs();
            (
                EXPIRING_NONCE_KEY,
                0u64,
                Some(now + FEE_PAYER_VALID_BEFORE_SECS),
            )
        } else {
            let n = provider
                .get_transaction_count(from)
                .await
                .map_err(|e| MppError::Http(format!("failed to get nonce: {}", e)))?;
            (U256::ZERO, n, None)
        };

        let gas_price = provider
            .get_gas_price()
            .await
            .map_err(|e| MppError::Http(format!("failed to get gas price: {}", e)))?;

        let calls = vec![Call {
            to: TxKind::Call(currency),
            value: alloy::primitives::U256::ZERO,
            input: Bytes::from(transfer_data),
        }];

        let tx = tx_builder::build_tempo_tx(tx_builder::TempoTxOptions {
            calls,
            chain_id: expected_chain_id,
            fee_token: currency,
            nonce,
            nonce_key,
            gas_limit: 1_000_000,
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: gas_price,
            fee_payer,
            valid_before,
            key_authorization: self.signing_mode.key_authorization().cloned(),
        });

        let tx_bytes = signing::sign_and_encode_async(tx, &self.signer, &self.signing_mode).await?;

        Ok(tx_builder::build_charge_credential(
            challenge,
            &tx_bytes,
            expected_chain_id,
            from,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tempo_provider_new() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer.clone(), "https://rpc.example.com").unwrap();

        assert_eq!(provider.rpc_url().as_str(), "https://rpc.example.com/");
        assert_eq!(provider.signer().address(), signer.address());
    }

    #[test]
    fn test_tempo_provider_invalid_url() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let result = TempoProvider::new(signer, "not a url");
        assert!(result.is_err());
    }

    #[test]
    fn test_tempo_provider_with_client_id() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_client_id("my-app");

        assert_eq!(provider.client_id.as_deref(), Some("my-app"));
    }

    #[test]
    fn test_tempo_provider_default_signing_mode() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com").unwrap();

        assert!(matches!(provider.signing_mode(), TempoSigningMode::Direct));
    }

    #[test]
    fn test_tempo_provider_with_signing_mode() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let wallet: alloy::primitives::Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_signing_mode(TempoSigningMode::Keychain {
                wallet,
                key_authorization: None,
            });

        assert!(matches!(
            provider.signing_mode(),
            TempoSigningMode::Keychain { .. }
        ));
    }

    #[test]
    fn test_tempo_provider_supports() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com").unwrap();

        assert!(provider.supports("tempo", "charge"));
        assert!(!provider.supports("tempo", "session"));
        assert!(!provider.supports("stripe", "charge"));
    }

    #[test]
    fn test_auto_generated_memo_is_mpp_memo() {
        let memo = crate::tempo::attribution::encode("api.example.com", Some("my-app"));
        assert!(crate::tempo::attribution::is_mpp_memo(&memo));
    }

    // --- Re-export verification ---

    #[test]
    fn test_reexports_accessible_from_client_tempo() {
        // Verify that all public types are accessible via the expected paths
        let _: fn() -> TempoSigningMode = || TempoSigningMode::Direct;

        // TempoProvider is accessible (we already use it in tests above)
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let _provider = TempoProvider::new(signer, "https://rpc.example.com").unwrap();

        // ChannelEntry from channel_ops
        let _entry = crate::client::tempo::ChannelEntry {
            channel_id: alloy::primitives::B256::ZERO,
            salt: alloy::primitives::B256::ZERO,
            cumulative_amount: 0,
            escrow_contract: alloy::primitives::Address::ZERO,
            chain_id: 42431,
            opened: false,
        };
    }

    #[test]
    fn test_reexports_accessible_from_client_level() {
        // Verify re-exports at crate::client:: level
        let _: fn() -> crate::client::TempoSigningMode = || crate::client::TempoSigningMode::Direct;

        let signer = alloy_signer_local::PrivateKeySigner::random();
        let _provider =
            crate::client::TempoProvider::new(signer, "https://rpc.example.com").unwrap();

        let _entry = crate::client::ChannelEntry {
            channel_id: alloy::primitives::B256::ZERO,
            salt: alloy::primitives::B256::ZERO,
            cumulative_amount: 0,
            escrow_contract: alloy::primitives::Address::ZERO,
            chain_id: 42431,
            opened: false,
        };
    }

    #[test]
    fn test_tempo_provider_supports_only_tempo_charge() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com").unwrap();

        assert!(provider.supports("tempo", "charge"));
        assert!(!provider.supports("tempo", "session"));
        assert!(!provider.supports("tempo", "open"));
        assert!(!provider.supports("stripe", "charge"));
        assert!(!provider.supports("", ""));
        assert!(!provider.supports("TEMPO", "charge"));
    }

    #[test]
    fn test_user_memo_takes_precedence() {
        let user_memo = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let hex_str = user_memo.strip_prefix("0x").unwrap();
        let bytes = hex::decode(hex_str).unwrap();
        let memo_bytes: [u8; 32] = bytes.try_into().unwrap();

        assert!(!crate::tempo::attribution::is_mpp_memo(&memo_bytes));
    }
}
