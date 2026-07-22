//! Tempo charge payment provider.

use crate::error::{MppError, ResultExt};
use crate::protocol::core::{PaymentChallenge, PaymentCredential};

use super::autoswap::AutoswapConfig;
use super::charge::SignOptions;
use super::signing::{TempoPrimitiveSigner, TempoSigningMode};
use crate::client::PaymentProvider;

/// Tempo payment provider using native primitive signing.
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
    signer: TempoPrimitiveSigner,
    rpc_url: reqwest::Url,
    client_id: Option<String>,
    signing_mode: TempoSigningMode,
    autoswap: Option<AutoswapConfig>,
    expected_chain_id: Option<u64>,
}

impl TempoProvider {
    /// Create a new Tempo provider with the given signer and RPC URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC URL is invalid.
    pub fn new(
        signer: impl Into<TempoPrimitiveSigner>,
        rpc_url: impl AsRef<str>,
    ) -> Result<Self, MppError> {
        let url = rpc_url.as_ref().parse().mpp_config("invalid RPC URL")?;
        Ok(Self {
            signer: signer.into(),
            rpc_url: url,
            client_id: None,
            signing_mode: TempoSigningMode::Direct,
            autoswap: None,
            expected_chain_id: None,
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

    /// Pin the chain ID this provider will pay on. When set, [`pay`] rejects any
    /// challenge whose `methodDetails.chainId` differs, before signing.
    ///
    /// [`pay`]: TempoProvider::pay
    pub fn with_expected_chain_id(mut self, chain_id: u64) -> Self {
        self.expected_chain_id = Some(chain_id);
        self
    }

    /// Get the pinned expected chain ID, if set.
    pub fn expected_chain_id(&self) -> Option<u64> {
        self.expected_chain_id
    }

    /// Get the signing mode.
    pub fn signing_mode(&self) -> &TempoSigningMode {
        &self.signing_mode
    }

    /// Get a reference to the signer.
    pub fn signer(&self) -> &TempoPrimitiveSigner {
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

        // Chain pinning: resolve the chain to sign on before signing.
        // - challenge `chainId` present: must match the pin (if any), else reject;
        // - challenge `chainId` absent: use the pin, signing on it.
        if let Some(expected) = self.expected_chain_id {
            use crate::protocol::methods::tempo::charge::TempoChargeExt;
            let challenge_chain_id = challenge
                .request
                .decode::<crate::protocol::intents::ChargeRequest>()?
                .chain_id();
            match challenge_chain_id {
                Some(got) if got != expected => {
                    return Err(MppError::ChainIdMismatch { expected, got });
                }
                None => charge = charge.with_chain_id(expected),
                _ => {}
            }
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
            let from = self
                .signing_mode
                .from_address(alloy::signers::Signer::address(&self.signer));
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
        let signed = charge
            .sign_with_primitive_options(&self.signer, options)
            .await?;
        Ok(signed.into_credential())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::Signer;

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

    /// Regression: in Keychain mode, the proof source DID must use the wallet
    /// address (matching mppx and the paid charge path), not the access key.
    /// Server-side verify_proof handles keychain keys via on-chain lookup.
    #[tokio::test]
    async fn test_keychain_proof_source_uses_wallet_address() {
        use crate::client::tempo::signing::KeychainVersion;
        use crate::protocol::core::Base64UrlJson;

        let access_key = alloy::signers::local::PrivateKeySigner::random();
        let wallet_address: alloy::primitives::Address =
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                .parse()
                .unwrap();

        let provider = TempoProvider::new(access_key.clone(), "https://rpc.example.com")
            .unwrap()
            .with_signing_mode(TempoSigningMode::Keychain {
                wallet: wallet_address,
                key_authorization: None,
                version: KeychainVersion::V2,
            });

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

        // Source DID must use the wallet address, NOT the access key address.
        let expected_did = PaymentCredential::evm_did(42431, &wallet_address.to_string());
        assert_eq!(credential.source, Some(expected_did));

        // Sanity: wallet and access key are different addresses.
        assert_ne!(wallet_address, access_key.address());
    }

    #[tokio::test]
    async fn test_p256_access_key_signs_wallet_bound_charge_proof() {
        use crate::client::tempo::signing::{
            KeychainVersion, TempoP256Signer, TempoPrimitiveSigner,
        };
        use crate::protocol::core::Base64UrlJson;

        let access_key = TempoP256Signer::from_slice(&[7_u8; 32]).unwrap();
        let wallet_address: alloy::primitives::Address =
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                .parse()
                .unwrap();
        let provider = TempoProvider::new(access_key, "https://rpc.example.com")
            .unwrap()
            .with_signing_mode(TempoSigningMode::Keychain {
                wallet: wallet_address,
                key_authorization: None,
                version: KeychainVersion::V2,
            });
        assert!(matches!(provider.signer(), TempoPrimitiveSigner::P256(_)));

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

        assert!(credential.charge_payload().unwrap().is_proof());
        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(
                42431,
                &wallet_address.to_string()
            ))
        );
    }

    #[tokio::test]
    async fn test_p256_access_key_signs_sponsored_charge_transaction() {
        use crate::client::tempo::signing::{KeychainVersion, TempoP256Signer};
        use crate::protocol::core::Base64UrlJson;

        let access_key = TempoP256Signer::from_slice(&[9_u8; 32]).unwrap();
        let wallet_address: alloy::primitives::Address =
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                .parse()
                .unwrap();
        let provider = TempoProvider::new(access_key, "https://rpc.example.com")
            .unwrap()
            .with_signing_mode(TempoSigningMode::Keychain {
                wallet: wallet_address,
                key_authorization: None,
                version: KeychainVersion::V2,
            });
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "100",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": { "chainId": 42431, "feePayer": true }
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

        assert!(payload.is_transaction());
        let transaction = payload.signed_tx().expect("missing signed transaction");
        assert!(
            transaction.starts_with("0x78"),
            "charges use sponsorship envelopes"
        );
        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(
                42431,
                &wallet_address.to_string()
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

    /// Charge challenge with optional `chainId`. Zero amount keeps `pay()` on
    /// the no-RPC proof path so the chain-pin gate runs without a live node.
    fn chain_pin_challenge(chain_id: Option<u64>) -> PaymentChallenge {
        use crate::protocol::core::Base64UrlJson;

        let mut details = serde_json::Map::new();
        if let Some(id) = chain_id {
            details.insert("chainId".to_string(), serde_json::json!(id));
        }
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "0",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": serde_json::Value::Object(details),
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

    #[test]
    fn test_default_provider_has_no_chain_pin() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com").unwrap();
        assert_eq!(provider.expected_chain_id(), None);
    }

    #[test]
    fn test_with_expected_chain_id_sets_pin() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_expected_chain_id(42431);
        assert_eq!(provider.expected_chain_id(), Some(42431));
    }

    /// A challenge whose `chainId` differs from the pin is rejected.
    #[tokio::test]
    async fn test_conflicting_chain_id_is_rejected() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_expected_chain_id(42431);

        let challenge = chain_pin_challenge(Some(1));
        let err = provider.pay(&challenge).await.unwrap_err();

        match err {
            MppError::ChainIdMismatch { expected, got } => {
                assert_eq!(expected, 42431);
                assert_eq!(got, 1);
            }
            other => panic!("expected ChainIdMismatch, got {other:?}"),
        }
    }

    /// A challenge whose `chainId` matches the pin is accepted.
    #[tokio::test]
    async fn test_matching_chain_id_is_accepted() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_expected_chain_id(42431);

        let challenge = chain_pin_challenge(Some(42431));
        assert!(provider.pay(&challenge).await.is_ok());
    }

    /// An unpinned provider accepts any chain the challenge specifies.
    #[tokio::test]
    async fn test_unpinned_provider_accepts_any_chain_id() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com").unwrap();

        let challenge = chain_pin_challenge(Some(1));
        assert!(provider.pay(&challenge).await.is_ok());
    }

    /// An omitted `chainId` defaults to mainnet; pinning to it accepts.
    #[tokio::test]
    async fn test_omitted_chain_id_matches_default_pin() {
        use crate::protocol::methods::tempo::CHAIN_ID;

        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_expected_chain_id(CHAIN_ID);

        let challenge = chain_pin_challenge(None);
        assert!(provider.pay(&challenge).await.is_ok());
    }

    /// An omitted `chainId` uses the pin (signing on it), not the mainnet
    /// default — matching the mpp-go ABI.
    #[tokio::test]
    async fn test_omitted_chain_id_uses_nondefault_pin() {
        use crate::protocol::methods::tempo::MODERATO_CHAIN_ID;

        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer.clone(), "https://rpc.example.com")
            .unwrap()
            .with_expected_chain_id(MODERATO_CHAIN_ID);

        let challenge = chain_pin_challenge(None);
        let credential = provider.pay(&challenge).await.unwrap();

        // The zero-amount proof source DID encodes the chain it signed on, so it
        // must reflect the pin rather than the mainnet default.
        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(
                MODERATO_CHAIN_ID,
                &signer.address().to_string()
            ))
        );
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
