//! Tempo charge payment provider.

use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};

use super::charge::SignOptions;
use super::routing::SwapCandidate;
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
/// TIP-20 tokens use 6 decimal places.
const TIP20_DECIMALS: u8 = 6;

#[derive(Clone)]
pub struct TempoProvider {
    signer: alloy_signer_local::PrivateKeySigner,
    rpc_url: reqwest::Url,
    client_id: Option<String>,
    signing_mode: TempoSigningMode,
    sign_options_overrides: Option<SignOptions>,
    replace_stuck_txs: bool,
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
            sign_options_overrides: None,
            replace_stuck_txs: false,
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

    /// Override sign options (nonce, gas fees, etc.) for power users
    /// who want to inject pre-resolved values.
    pub fn with_sign_options(mut self, options: SignOptions) -> Self {
        self.sign_options_overrides = Some(options);
        self
    }

    /// Enable stuck-transaction detection and replacement.
    ///
    /// When enabled, compares confirmed vs pending nonce at payment time.
    /// If a stuck transaction is detected, aggressively bumps gas to
    /// replace it. See [`super::gas::resolve_gas_with_stuck_detection`].
    ///
    /// Default: `false`.
    pub fn with_replace_stuck_transactions(mut self, enabled: bool) -> Self {
        self.replace_stuck_txs = enabled;
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

    /// Build swap candidates from known tokens for a chain ID.
    fn swap_candidates_for(chain_id: u64) -> Vec<SwapCandidate> {
        use crate::protocol::methods::tempo::network::TempoNetwork;

        let Some(network) = TempoNetwork::from_chain_id(chain_id) else {
            return Vec::new();
        };
        network
            .known_tokens()
            .iter()
            .filter_map(|(addr, symbol)| {
                Some(SwapCandidate {
                    address: addr.parse().ok()?,
                    symbol: symbol.to_string(),
                })
            })
            .collect()
    }

    /// Look up a token symbol from candidates, falling back to hex address.
    fn token_symbol_for(
        candidates: &[SwapCandidate],
        address: alloy::primitives::Address,
    ) -> String {
        candidates
            .iter()
            .find(|c| c.address == address)
            .map(|c| c.symbol.clone())
            .unwrap_or_else(|| format!("{:#x}", address))
    }
}

impl PaymentProvider for TempoProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == "tempo" && intent == "charge"
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        let charge = super::charge::TempoCharge::from_challenge(challenge)?;
        let from = self.signing_mode.from_address(self.signer.address());
        let swap_candidates = Self::swap_candidates_for(charge.chain_id());

        let mut options = self.sign_options_overrides.clone().unwrap_or_default();
        options.rpc_url = Some(self.rpc_url.to_string());
        if options.signing_mode.is_none() {
            options.signing_mode = Some(self.signing_mode.clone());
        }
        if self.replace_stuck_txs {
            options.replace_stuck_txs = true;
        }

        // Check balance and spending limits regardless of swap config
        // so users get a clear error instead of an opaque on-chain revert.
        let provider = alloy::providers::RootProvider::new_http(self.rpc_url.clone());

        let balance =
            super::balance::query_token_balance(&provider, charge.currency(), from).await?;

        let keychain_info = match &self.signing_mode {
            TempoSigningMode::Keychain { wallet, .. } => Some((*wallet, self.signer.address())),
            TempoSigningMode::Direct => None,
        };
        let local_auth = self.signing_mode.key_authorization();

        let spending_limit = if let Some((wallet_addr, key_addr)) = keychain_info {
            match super::keychain::query_key_spending_limit(
                &provider,
                wallet_addr,
                key_addr,
                charge.currency(),
            )
            .await
            {
                Ok(limit) => limit,
                Err(_) if local_auth.is_some() => super::keychain::local_key_spending_limit(
                    local_auth.unwrap(),
                    charge.currency(),
                ),
                Err(e) => {
                    return Err(MppError::Http(format!(
                        "Cannot verify key spending limit: {}",
                        e
                    )))
                }
            }
        } else {
            None
        };

        let capacity = super::balance::effective_capacity(balance, spending_limit);

        // Direct transfer if sufficient capacity
        if capacity >= charge.amount() {
            let signed = charge.sign_with_options(&self.signer, options).await?;
            return Ok(signed.into_credential());
        }

        // Spending limit is the bottleneck — no swap can help.
        // Only error when the user has enough balance to pay directly but the
        // limit blocks them. When balance is also insufficient, fall through
        // to auto-swap which may find a different token with a higher limit.
        let limit_is_bottleneck = spending_limit
            .map(|limit| limit < charge.amount())
            .unwrap_or(false);

        if limit_is_bottleneck && balance >= charge.amount() {
            let token_symbol = Self::token_symbol_for(&swap_candidates, charge.currency());
            return Err(super::error::TempoClientError::SpendingLimitExceeded {
                token: token_symbol,
                limit: crate::evm::format_u256_with_decimals(
                    spending_limit.unwrap_or(alloy::primitives::U256::ZERO),
                    TIP20_DECIMALS,
                ),
                required: crate::evm::format_u256_with_decimals(charge.amount(), TIP20_DECIMALS),
            }
            .into());
        }

        // No swap candidates available — return a clear insufficient balance error
        if swap_candidates.is_empty() {
            let token_symbol = Self::token_symbol_for(&swap_candidates, charge.currency());
            return Err(super::error::TempoClientError::InsufficientBalance {
                token: token_symbol,
                available: crate::evm::format_u256_with_decimals(balance, TIP20_DECIMALS),
                required: crate::evm::format_u256_with_decimals(charge.amount(), TIP20_DECIMALS),
            }
            .into());
        }

        // Try auto-swap
        let swap_source = super::routing::find_swap_source(
            &provider,
            from,
            charge.currency(),
            charge.amount(),
            &swap_candidates,
            keychain_info,
            local_auth,
        )
        .await?;

        match swap_source {
            Some(source) => {
                let swap_info = super::swap::SwapInfo::new(
                    source.token_address,
                    charge.currency(),
                    charge.amount(),
                );
                let calls = super::swap::build_swap_calls(
                    &swap_info,
                    charge.recipient(),
                    charge.amount(),
                    charge.memo(),
                )?;
                options.fee_token = Some(swap_info.token_in);
                let signed = charge
                    .with_calls(calls)
                    .sign_with_options(&self.signer, options)
                    .await?;
                Ok(signed.into_credential())
            }
            None => {
                let token_symbol = Self::token_symbol_for(&swap_candidates, charge.currency());
                Err(super::error::TempoClientError::InsufficientBalance {
                    token: token_symbol,
                    available: crate::evm::format_u256_with_decimals(balance, TIP20_DECIMALS),
                    required: crate::evm::format_u256_with_decimals(
                        charge.amount(),
                        TIP20_DECIMALS,
                    ),
                }
                .into())
            }
        }
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

    #[test]
    fn test_swap_candidates_for_known_chain() {
        let candidates = TempoProvider::swap_candidates_for(42431); // moderato
        assert!(!candidates.is_empty());
        assert!(candidates.iter().any(|c| c.symbol == "pathUSD"));
    }

    #[test]
    fn test_swap_candidates_for_unknown_chain() {
        let candidates = TempoProvider::swap_candidates_for(999999);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_tempo_provider_with_sign_options() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let opts = SignOptions {
            nonce: Some(42),
            max_fee_per_gas: Some(20_000_000_000),
            ..Default::default()
        };
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_sign_options(opts);

        assert!(provider.sign_options_overrides.is_some());
        assert_eq!(
            provider.sign_options_overrides.as_ref().unwrap().nonce,
            Some(42)
        );
    }

    #[test]
    fn test_token_symbol_lookup() {
        let addr: alloy::primitives::Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let candidates = vec![SwapCandidate {
            address: addr,
            symbol: "pathUSD".to_string(),
        }];

        assert_eq!(
            TempoProvider::token_symbol_for(&candidates, addr),
            "pathUSD"
        );
        assert!(
            TempoProvider::token_symbol_for(&candidates, alloy::primitives::Address::ZERO)
                .starts_with("0x")
        );
    }
}
