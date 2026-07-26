//! Tempo Charge provider backed by the Tempo Accounts store.

use std::path::Path;

use tempo_alloy::accounts::TempoAccountsWallet;

use super::{autoswap::AutoswapConfig, charge::SignOptions};
use crate::{
    client::PaymentProvider,
    error::{MppError, ResultExt},
    protocol::core::{PaymentChallenge, PaymentCredential},
};

/// A Tempo Charge provider that selects access keys lazily from Tempo
/// Accounts.
///
/// The wallet owns account, key, signature-type, scope, and pending
/// authorization selection. Callers do not configure a signing mode.
#[derive(Clone)]
pub struct TempoAccountsProvider {
    wallet: TempoAccountsWallet,
    rpc_url: reqwest::Url,
    rpc_provider: alloy::providers::RootProvider<tempo_alloy::TempoNetwork>,
    client_id: Option<String>,
    autoswap: Option<AutoswapConfig>,
    expected_chain_id: Option<u64>,
}

impl TempoAccountsProvider {
    /// Create a Charge provider from a Tempo Accounts wallet.
    pub fn new(wallet: TempoAccountsWallet, rpc_url: impl AsRef<str>) -> Result<Self, MppError> {
        let rpc_url: reqwest::Url = rpc_url.as_ref().parse().mpp_config("invalid RPC URL")?;
        let rpc_provider = super::rpc_provider(rpc_url.clone());
        Ok(Self {
            wallet,
            rpc_url,
            rpc_provider,
            client_id: None,
            autoswap: None,
            expected_chain_id: None,
        })
    }

    /// Open a specific Tempo Accounts store.
    pub fn from_store(path: impl AsRef<Path>, rpc_url: impl AsRef<str>) -> Result<Self, MppError> {
        let wallet = TempoAccountsWallet::from_store(path.as_ref())
            .mpp_config("failed to open Tempo Accounts store")?;
        Self::new(wallet, rpc_url)
    }

    /// Open the default Tempo Accounts store.
    pub fn from_default_store(rpc_url: impl AsRef<str>) -> Result<Self, MppError> {
        let wallet = TempoAccountsWallet::from_default_store()
            .mpp_config("failed to open Tempo Accounts store")?;
        Self::new(wallet, rpc_url)
    }

    /// Set an optional client identifier for attribution memos.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Enable an atomic stablecoin swap before payment.
    pub fn with_autoswap(mut self, config: AutoswapConfig) -> Self {
        self.autoswap = Some(config);
        self
    }

    /// Get the autoswap configuration, if set.
    pub fn autoswap(&self) -> Option<&AutoswapConfig> {
        self.autoswap.as_ref()
    }

    fn fee_token(&self) -> Option<alloy::primitives::Address> {
        self.autoswap.as_ref().map(|config| config.token_in)
    }

    /// Pin the chain ID this provider will pay on.
    pub fn with_expected_chain_id(mut self, chain_id: u64) -> Self {
        self.expected_chain_id = Some(chain_id);
        self
    }

    /// Get the pinned expected chain ID, if set.
    pub fn expected_chain_id(&self) -> Option<u64> {
        self.expected_chain_id
    }

    /// Get the lazy Accounts wallet.
    pub const fn wallet(&self) -> &TempoAccountsWallet {
        &self.wallet
    }

    /// Get the RPC URL.
    pub const fn rpc_url(&self) -> &reqwest::Url {
        &self.rpc_url
    }
}

impl PaymentProvider for TempoAccountsProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == crate::protocol::methods::tempo::METHOD_NAME
            && intent == crate::protocol::methods::tempo::INTENT_CHARGE
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        let from = self
            .wallet
            .active_account()
            .mpp_config("failed to read the active Tempo account")?;
        let charge = super::provider::prepare_charge(
            challenge,
            self.expected_chain_id,
            self.client_id.as_deref(),
            self.autoswap.as_ref(),
            &self.rpc_provider,
            from,
        )
        .await?;

        charge
            .sign_with_accounts_provider_options(
                &self.wallet,
                &self.rpc_provider,
                from,
                SignOptions {
                    fee_token: self.fee_token(),
                    ..Default::default()
                },
            )
            .await
            .map(|signed| signed.into_credential())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use alloy::{
        eips::eip2718::Decodable2718, primitives::Address, signers::local::PrivateKeySigner,
    };
    use tempo_primitives::{
        transaction::{KeychainVersion, TempoSignature},
        AASigned,
    };

    use super::*;
    use crate::protocol::core::Base64UrlJson;

    fn provider() -> (TempoAccountsProvider, std::path::PathBuf, Address) {
        let private_key = "0x1234567890123456789012345678901234567890123456789012345678901234";
        let signer = private_key.parse::<PrivateKeySigner>().unwrap();
        let account = Address::repeat_byte(0x11);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mpp-tempo-accounts-{}-{unique}.json",
            std::process::id()
        ));
        let store = serde_json::json!({
            "tempo-cli.store": {
                "state": {
                    "activeAccount": 0,
                    "chainId": 4217,
                    "accounts": [{"address": account}],
                    "accessKeys": [{
                        "access": account,
                        "address": signer.address(),
                        "chainId": 4217,
                        "keyType": "secp256k1",
                        "privateKey": private_key,
                    }],
                },
            },
        });
        std::fs::write(&path, serde_json::to_vec(&store).unwrap()).unwrap();
        let provider = TempoAccountsProvider::from_store(&path, "https://rpc.example.com").unwrap();
        (provider, path, account)
    }

    fn challenge(amount: &str, fee_payer: bool) -> PaymentChallenge {
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": amount,
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": {"chainId": 4217, "feePayer": fee_payer},
        }))
        .unwrap();
        PaymentChallenge::new(
            "challenge-123",
            "api.example.com",
            "tempo",
            "charge",
            request,
        )
    }

    fn assert_accounts_signature(signed: &AASigned, account: Address, key: Address) {
        let TempoSignature::Keychain(signature) = signed.signature() else {
            panic!("expected an Accounts keychain signature")
        };
        assert_eq!(signature.user_address, account);
        assert_eq!(signature.version, KeychainVersion::V2);
        assert_eq!(
            signature.key_id(&signed.tx().signature_hash()).unwrap(),
            key
        );
    }

    #[tokio::test]
    async fn zero_charge_uses_the_accounts_key_without_a_signing_mode() {
        let (provider, path, account) = provider();
        let credential = provider.pay(&challenge("0", false)).await.unwrap();

        assert!(credential.charge_payload().unwrap().is_proof());
        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(4217, &account.to_string()))
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn accounts_key_signs_a_standard_alloy_tempo_envelope() {
        let (provider, path, account) = provider();
        let key = provider.wallet().active_access_key().unwrap().address();
        let charge =
            super::super::charge::TempoCharge::from_challenge(&challenge("100", false)).unwrap();
        let signed = charge
            .sign_with_accounts_provider_options(
                provider.wallet(),
                &provider.rpc_provider,
                account,
                SignOptions {
                    gas_limit: Some(200_000),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let mut encoded = signed.tx_bytes();
        let decoded = AASigned::decode_2718(&mut encoded).unwrap();
        assert_eq!(decoded.tx().chain_id, 4217);
        assert_eq!(decoded.tx().gas_limit, 200_000);
        assert_eq!(
            decoded.tx().fee_token,
            Some(
                "0x20c0000000000000000000000000000000000000"
                    .parse()
                    .unwrap()
            )
        );
        assert!(decoded.tx().fee_payer_signature.is_none());
        assert_accounts_signature(&decoded, account, key);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn accounts_key_signs_a_sponsored_charge_without_a_signing_mode() {
        let (provider, path, account) = provider();
        let key = provider.wallet().active_access_key().unwrap().address();
        let credential = provider.pay(&challenge("100", true)).await.unwrap();

        let payload = credential.charge_payload().unwrap();
        assert!(payload.is_transaction());
        let encoded =
            alloy::hex::decode(payload.signed_tx().unwrap().trim_start_matches("0x")).unwrap();
        let envelope =
            crate::protocol::methods::tempo::FeePayerEnvelope78::decode_envelope(&encoded).unwrap();
        assert_eq!(envelope.chain_id, 4217);
        assert_eq!(envelope.sender, account);
        assert_eq!(envelope.nonce_key, alloy::primitives::U256::MAX);
        assert!(envelope.valid_before.is_some());
        assert!(envelope.fee_token.is_none());
        assert_accounts_signature(&envelope.to_recoverable_signed(), account, key);
        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(4217, &account.to_string()))
        );
        std::fs::remove_file(path).unwrap();
    }
}
