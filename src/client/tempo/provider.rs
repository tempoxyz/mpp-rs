//! Tempo charge payment provider.

use crate::error::{MppError, ResultExt};
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use crate::protocol::methods::tempo::proof::sign_proof;

use super::autoswap::AutoswapConfig;
use super::charge::SignOptions;
use super::signing::TempoSigningMode;
use crate::client::PaymentProvider;

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
    signer: alloy::signers::local::PrivateKeySigner,
    rpc_url: reqwest::Url,
    client_id: Option<String>,
    signing_mode: TempoSigningMode,
    autoswap: Option<AutoswapConfig>,
}

impl TempoProvider {
    /// Create a new Tempo provider with the given signer and RPC URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC URL is invalid.
    pub fn new(
        signer: alloy::signers::local::PrivateKeySigner,
        rpc_url: impl AsRef<str>,
    ) -> Result<Self, MppError> {
        let url = rpc_url.as_ref().parse().mpp_config("invalid RPC URL")?;
        Ok(Self {
            signer,
            rpc_url: url,
            client_id: None,
            signing_mode: TempoSigningMode::Direct,
            autoswap: None,
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

    /// Enable autoswap: if the client doesn't hold enough of the challenge
    /// currency, automatically swap from `config.token_in` via the Tempo
    /// Stablecoin DEX before paying.
    ///
    /// The swap and payment execute atomically in a single AA transaction.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use mpp::client::tempo::autoswap::AutoswapConfig;
    ///
    /// let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?
    ///     .with_autoswap(AutoswapConfig::new(usdc_address, 100)); // 1% slippage
    /// ```
    pub fn with_autoswap(mut self, config: AutoswapConfig) -> Self {
        self.autoswap = Some(config);
        self
    }

    /// Get the autoswap configuration, if set.
    pub fn autoswap(&self) -> Option<&AutoswapConfig> {
        self.autoswap.as_ref()
    }

    /// Get the signing mode.
    pub fn signing_mode(&self) -> &TempoSigningMode {
        &self.signing_mode
    }

    /// Get a reference to the signer.
    pub fn signer(&self) -> &alloy::signers::local::PrivateKeySigner {
        &self.signer
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &reqwest::Url {
        &self.rpc_url
    }
}

impl PaymentProvider for TempoProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == crate::protocol::methods::tempo::METHOD_NAME
            && intent == crate::protocol::methods::tempo::INTENT_CHARGE
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        let mut charge = super::charge::TempoCharge::from_challenge(challenge)?;

        if charge.amount().is_zero() {
            let signature = sign_proof(&self.signer, charge.chain_id(), &challenge.id).await?;
            let source =
                PaymentCredential::evm_did(charge.chain_id(), &self.signer.address().to_string());

            return Ok(PaymentCredential::with_source(
                challenge.to_echo(),
                source,
                crate::protocol::core::PaymentPayload::proof(signature),
            ));
        }

        // Auto-generate an attribution memo when the server doesn't provide one,
        // so MPP transactions are identifiable on-chain via `TransferWithMemo` events.
        if charge.memo().is_none() {
            let memo = crate::tempo::attribution::encode(
                &challenge.id,
                &challenge.realm,
                self.client_id.as_deref(),
            );
            charge = charge.with_memo(memo);
        }

        // If autoswap is enabled, check balance and prepend a swap call if needed.
        if let Some(autoswap_config) = &self.autoswap {
            let from = self.signing_mode.from_address(self.signer.address());
            let rpc_url: reqwest::Url = self.rpc_url.clone();
            let provider =
                alloy::providers::RootProvider::<tempo_alloy::TempoNetwork>::new_http(rpc_url);

            if let Some(swap_call) = super::autoswap::resolve_autoswap(
                &provider,
                from,
                charge.currency(),
                charge.amount(),
                autoswap_config,
            )
            .await?
            {
                charge = charge.with_prepended_call(swap_call)?;
            }
        }

        let options = SignOptions {
            rpc_url: Some(self.rpc_url.to_string()),
            signing_mode: Some(self.signing_mode.clone()),
            ..Default::default()
        };
        let signed = charge.sign_with_options(&self.signer, options).await?;
        Ok(signed.into_credential())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tempo_provider_new() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer.clone(), "https://rpc.example.com").unwrap();

        assert_eq!(provider.rpc_url().as_str(), "https://rpc.example.com/");
        assert_eq!(provider.signer().address(), signer.address());
    }

    #[test]
    fn test_tempo_provider_invalid_url() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let result = TempoProvider::new(signer, "not a url");
        assert!(result.is_err());
    }

    #[test]
    fn test_tempo_provider_with_client_id() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_client_id("my-app");

        assert_eq!(provider.client_id.as_deref(), Some("my-app"));
    }

    #[test]
    fn test_tempo_provider_default_signing_mode() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com").unwrap();

        assert!(matches!(provider.signing_mode(), TempoSigningMode::Direct));
    }

    #[test]
    fn test_tempo_provider_with_signing_mode() {
        use crate::client::tempo::signing::KeychainVersion;
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let wallet: alloy::primitives::Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_signing_mode(TempoSigningMode::Keychain {
                wallet,
                key_authorization: None,
                version: KeychainVersion::V1,
            });

        assert!(matches!(
            provider.signing_mode(),
            TempoSigningMode::Keychain { .. }
        ));
    }

    #[test]
    fn test_tempo_provider_supports() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com").unwrap();

        assert!(provider.supports("tempo", "charge"));
        assert!(!provider.supports("tempo", "session"));
        assert!(!provider.supports("stripe", "charge"));
    }

    #[test]
    fn test_auto_generated_memo_is_mpp_memo() {
        let memo =
            crate::tempo::attribution::encode("challenge-123", "api.example.com", Some("my-app"));
        assert!(crate::tempo::attribution::is_mpp_memo(&memo));
    }

    #[tokio::test]
    async fn test_zero_amount_challenge_returns_proof_credential() {
        use crate::protocol::core::Base64UrlJson;

        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer.clone(), "https://rpc.example.com").unwrap();
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "0",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": { "chainId": 42431 }
        }))
        .unwrap();
        let challenge = PaymentChallenge::new(
            "challenge-123",
            "api.example.com",
            "tempo",
            "charge",
            request,
        );

        let credential = provider.pay(&challenge).await.unwrap();
        let payload = credential.charge_payload().unwrap();

        assert!(payload.is_proof());
        assert!(payload.proof_signature().is_some());
        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(
                42431,
                &signer.address().to_string()
            ))
        );
    }

    #[test]
    fn test_tempo_provider_supports_only_tempo_charge() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
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
