//! Tempo charge payment provider.

use std::sync::Arc;

use tokio::sync::OnceCell;

use crate::error::{MppError, ResultExt};
use crate::protocol::core::{PaymentChallenge, PaymentCredential};

use super::autoswap::AutoswapConfig;
use super::charge::{SignOptions, TempoCharge};
use super::signing::{TempoPrimitiveSigner, TempoSigningMode};
use crate::client::PaymentProvider;

pub(super) fn prepare_charge_request(
    challenge: &PaymentChallenge,
    expected_chain_id: Option<u64>,
    client_id: Option<&str>,
) -> Result<TempoCharge, MppError> {
    let mut charge = TempoCharge::from_challenge(challenge)?;

    if let Some(expected) = expected_chain_id {
        use crate::protocol::methods::tempo::charge::TempoChargeExt;
        match challenge
            .request
            .decode::<crate::protocol::intents::ChargeRequest>()?
            .chain_id()
        {
            Some(got) if got != expected => {
                return Err(MppError::ChainIdMismatch { expected, got });
            }
            None => charge = charge.with_chain_id(expected),
            _ => {}
        }
    }

    charge = charge.with_memo(crate::tempo::attribution::encode(
        &challenge.id,
        &challenge.realm,
        client_id,
    ));

    Ok(charge)
}

pub(super) async fn prepare_charge(
    challenge: &PaymentChallenge,
    expected_chain_id: Option<u64>,
    client_id: Option<&str>,
    autoswap: Option<&AutoswapConfig>,
    provider: &impl alloy::providers::Provider<tempo_alloy::TempoNetwork>,
    from: alloy::primitives::Address,
) -> Result<TempoCharge, MppError> {
    let charge = prepare_charge_request(challenge, expected_chain_id, client_id)?;
    apply_funding(charge, autoswap, provider, from).await
}

pub(super) async fn apply_funding(
    charge: TempoCharge,
    autoswap: Option<&AutoswapConfig>,
    provider: &impl alloy::providers::Provider<tempo_alloy::TempoNetwork>,
    from: alloy::primitives::Address,
) -> Result<TempoCharge, MppError> {
    Ok(fund(charge, autoswap, provider, from).await?.0)
}

/// Funds a charge like [`apply_funding`] and returns the token the payer spends: MACH through
/// the machine-token swapper, the autoswap input token, or the charge currency.
pub(super) async fn fund(
    mut charge: TempoCharge,
    autoswap: Option<&AutoswapConfig>,
    provider: &impl alloy::providers::Provider<tempo_alloy::TempoNetwork>,
    from: alloy::primitives::Address,
) -> Result<(TempoCharge, alloy::primitives::Address), MppError> {
    if charge.machine_token_enabled() {
        let transfers = crate::protocol::methods::tempo::transfers::get_transfers(
            charge.amount(),
            charge.recipient(),
            charge.memo(),
            charge.splits(),
        )?;
        if let Some(route) = crate::protocol::methods::tempo::machine_token::find_route(
            provider,
            from,
            charge.chain_id(),
            charge.currency(),
            &transfers,
        )
        .await
        {
            let funding = match route.calls[0].to {
                alloy::primitives::TxKind::Call(token) => token,
                alloy::primitives::TxKind::Create => charge.currency(),
            };
            return Ok((charge.with_calls(route.calls.to_vec()), funding));
        }
    }

    let mut funding = charge.currency();
    if let Some(config) = autoswap {
        if let Some(calls) = super::autoswap::resolve_autoswap_calls(
            provider,
            from,
            charge.currency(),
            charge.amount(),
            config,
        )
        .await?
        {
            funding = config.token_in;
            for call in calls.into_iter().rev() {
                charge = charge.with_prepended_call(call)?;
            }
        }
    }

    Ok((charge, funding))
}

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
/// A provider built with [`new`](Self::new) only pays on one chain: the one set
/// with [`with_expected_chain_id`](Self::with_expected_chain_id), or else the
/// chain its RPC reports. A challenge for any other chain is rejected before
/// signing. A provider built with [`from_signer`](Self::from_signer) has no RPC
/// of its own and, as mppx's client, pays on the chain each challenge names
/// through that chain's default RPC.
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
    rpc_provider: alloy::providers::RootProvider<tempo_alloy::TempoNetwork>,
    client_id: Option<String>,
    signing_mode: TempoSigningMode,
    autoswap: Option<AutoswapConfig>,
    expected_chain_id: Option<u64>,
    rpc_chain_id: Arc<OnceCell<u64>>,
    trusted_tempo_proof_realms: Vec<(reqwest::Url, String)>,
    currencies: Option<Vec<String>>,
    max_amount: Option<alloy::primitives::U256>,
    max_atomic_amount: Option<alloy::primitives::U256>,
    /// No RPC was configured: pay on the challenge's chain via its default RPC.
    follow_challenge_chain: bool,
    allowed_chain_ids: Option<Vec<u64>>,
    chain_providers: Arc<
        std::sync::Mutex<
            std::collections::HashMap<
                u64,
                alloy::providers::RootProvider<tempo_alloy::TempoNetwork>,
            >,
        >,
    >,
}

impl TempoProvider {
    /// Create a Tempo provider without an RPC URL, as mppx's `tempo.charge()`
    /// client without a custom client: it pays on the chain each challenge
    /// names (`methodDetails.chainId`) through that chain's default RPC, or
    /// on the pinned chain ([`with_expected_chain_id`](Self::with_expected_chain_id))
    /// when the challenge names none, else on Tempo mainnet. A challenge for a
    /// chain without a default RPC is rejected; use [`new`](Self::new) for one.
    pub fn from_signer(signer: impl Into<TempoPrimitiveSigner>) -> Self {
        let mut provider = Self::new(signer, crate::protocol::methods::tempo::DEFAULT_RPC_URL)
            .expect("the default Tempo RPC URL is valid");
        provider.follow_challenge_chain = true;
        provider
    }

    /// Create a new Tempo provider with the given signer and RPC URL.
    ///
    /// # Errors
    ///
    /// Returns an error if the RPC URL is invalid.
    pub fn new(
        signer: impl Into<TempoPrimitiveSigner>,
        rpc_url: impl AsRef<str>,
    ) -> Result<Self, MppError> {
        let url: reqwest::Url = rpc_url.as_ref().parse().mpp_config("invalid RPC URL")?;
        let rpc_provider = super::rpc_provider(url.clone());
        Ok(Self {
            signer: signer.into(),
            rpc_url: url,
            rpc_provider,
            client_id: None,
            signing_mode: TempoSigningMode::Direct,
            autoswap: None,
            expected_chain_id: None,
            rpc_chain_id: Arc::new(OnceCell::new()),
            trusted_tempo_proof_realms: Vec::new(),
            currencies: None,
            max_amount: None,
            max_atomic_amount: None,
            follow_challenge_chain: false,
            allowed_chain_ids: None,
            chain_providers: Arc::default(),
        })
    }

    /// Only pay on these chain IDs, as mppx's `allowedChainIds`.
    ///
    /// A challenge naming another chain is skipped during challenge selection
    /// and rejected before signing; the chain actually signed on (the RPC's,
    /// for a challenge that names none) is checked again before signing. An
    /// empty list pays on no chain.
    pub fn with_allowed_chain_ids(mut self, chain_ids: impl IntoIterator<Item = u64>) -> Self {
        self.allowed_chain_ids = Some(chain_ids.into_iter().collect());
        self
    }

    fn ensure_allowed_chain(&self, chain_id: Option<u64>) -> Result<(), MppError> {
        let Some(allowed) = &self.allowed_chain_ids else {
            return Ok(());
        };
        match chain_id {
            Some(chain_id) if allowed.contains(&chain_id) => Ok(()),
            Some(chain_id) => Err(MppError::InvalidConfig(format!(
                "Tempo chain ID {chain_id} is not allowed by the client"
            ))),
            None => Err(MppError::InvalidConfig(
                "Tempo client allows no chain".to_string(),
            )),
        }
    }

    /// The chain to sign on and its RPC client: the challenge's chain via its
    /// default RPC for a [`from_signer`](Self::from_signer) provider, else the
    /// configured RPC's chain (or the pin).
    async fn resolve_chain(
        &self,
        challenge_chain_id: Option<u64>,
    ) -> Result<
        (
            u64,
            alloy::providers::RootProvider<tempo_alloy::TempoNetwork>,
        ),
        MppError,
    > {
        if !self.follow_challenge_chain {
            let chain_id = match self.expected_chain_id {
                Some(chain_id) => chain_id,
                None => self.rpc_chain_id().await?,
            };
            return Ok((chain_id, self.rpc_provider.clone()));
        }
        let single_allowed = match self.allowed_chain_ids.as_deref() {
            Some([chain_id]) => Some(*chain_id),
            _ => None,
        };
        let chain_id = challenge_chain_id
            .or(self.expected_chain_id)
            .or(single_allowed)
            .unwrap_or(crate::protocol::methods::tempo::CHAIN_ID);
        let mut providers = self
            .chain_providers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(provider) = providers.get(&chain_id) {
            return Ok((chain_id, provider.clone()));
        }
        let network =
            crate::protocol::methods::tempo::network::TempoNetwork::from_chain_id(chain_id)
                .ok_or_else(|| {
                    MppError::InvalidConfig(format!(
                        "no default RPC for chain ID {chain_id}: create the provider with TempoProvider::new"
                    ))
                })?;
        let url: reqwest::Url = network
            .default_rpc_url()
            .parse()
            .mpp_config("invalid RPC URL")?;
        let provider = super::rpc_provider(url);
        providers.insert(chain_id, provider.clone());
        Ok((chain_id, provider))
    }

    /// Set an optional client identifier for attribution memos.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Trust a non-hostname proof realm only at the specified HTTP origin.
    pub fn with_trusted_tempo_proof_realm(
        mut self,
        origin: reqwest::Url,
        realm: impl Into<String>,
    ) -> Self {
        self.set_trusted_tempo_proof_realm(origin, realm.into());
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

    fn fee_token(&self) -> Option<alloy::primitives::Address> {
        self.autoswap.as_ref().map(|config| config.token_in)
    }

    /// Pin the chain ID this provider will pay on. When set, [`pay`] rejects any
    /// challenge whose `methodDetails.chainId` differs, before signing.
    ///
    /// Without a pin the provider pays on the chain its RPC reports, which
    /// costs one `eth_chainId` request on the first payment.
    ///
    /// [`pay`]: TempoProvider::pay
    pub fn with_expected_chain_id(mut self, chain_id: u64) -> Self {
        self.expected_chain_id = Some(chain_id);
        self
    }

    /// Only pay in these TIP-20 currencies, compared case-insensitively.
    ///
    /// Offers in other currencies are skipped during challenge selection and
    /// rejected by [`pay`](PaymentProvider::pay) before any RPC or signing work;
    /// an empty list rejects all. Required with
    /// [`with_max_amount`](Self::with_max_amount) and
    /// [`with_max_atomic_amount`](Self::with_max_atomic_amount), which are
    /// denominated in the challenge currency.
    pub fn with_currencies<I, S>(mut self, currencies: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.currencies = Some(currencies.into_iter().map(Into::into).collect());
        self
    }

    /// Cap each charge at `max_amount` in display units (e.g. `"1.5"`), parsed
    /// with the currency's `decimals`, since challenges do not carry them.
    ///
    /// The cap is compared with the challenge amount, which includes splits, and
    /// applies per credential. Larger offers are skipped during selection and
    /// rejected before signing. Requires [`with_currencies`](Self::with_currencies).
    ///
    /// # Errors
    ///
    /// Returns an error if `max_amount` is malformed or has more fractional
    /// digits than `decimals` allow (it is never rounded).
    pub fn with_max_amount(mut self, max_amount: &str, decimals: u8) -> Result<Self, MppError> {
        // Trailing fractional zeros are exact; anything beyond `decimals` is rejected.
        let trimmed = match max_amount.split_once('.') {
            Some((int, frac)) => {
                let frac = frac.trim_end_matches('0');
                if frac.is_empty() {
                    int.to_string()
                } else {
                    format!("{int}.{frac}")
                }
            }
            None => max_amount.to_string(),
        };
        let atomic = crate::protocol::intents::parse_units(&trimmed, decimals).map_err(|_| {
            MppError::InvalidConfig(format!(
                "Tempo charge max_amount {max_amount} is invalid or has more fractional digits than {decimals} decimals allow"
            ))
        })?;
        self.max_amount = Some(crate::evm::parse_amount(&atomic)?);
        Ok(self)
    }

    /// Cap each charge at `max_atomic_amount` raw base units of the challenge
    /// currency. Checked like [`with_max_amount`](Self::with_max_amount).
    /// Requires [`with_currencies`](Self::with_currencies).
    pub fn with_max_atomic_amount(mut self, max_atomic_amount: alloy::primitives::U256) -> Self {
        self.max_atomic_amount = Some(max_atomic_amount);
        self
    }

    /// Reject a challenge whose currency or amount violates the client policy.
    /// Runs during challenge selection and again before any RPC or signing work.
    fn check_policy(&self, challenge: &PaymentChallenge) -> Result<(), MppError> {
        if let Some(allowed) = &self.allowed_chain_ids {
            use crate::protocol::methods::tempo::charge::TempoChargeExt;
            let request: crate::protocol::intents::ChargeRequest = challenge.request.decode()?;
            // A challenge naming no chain is checked against the chain signed
            // on, once it is known (mppx `assertChallengePolicy`).
            if request.chain_id().is_some() || allowed.is_empty() {
                self.ensure_allowed_chain(request.chain_id())
                    .map_err(|error| MppError::InvalidChallenge {
                        id: Some(challenge.id.clone()),
                        reason: Some(error.to_string()),
                    })?;
            }
        }
        if self.max_amount.is_none()
            && self.max_atomic_amount.is_none()
            && self.currencies.is_none()
        {
            return Ok(());
        }
        let Some(currencies) = &self.currencies else {
            return Err(MppError::InvalidConfig(
                "Tempo charge max_amount and max_atomic_amount require currencies".to_string(),
            ));
        };
        let reject = |reason: String| MppError::InvalidChallenge {
            id: Some(challenge.id.clone()),
            reason: Some(reason),
        };
        let request: crate::protocol::intents::ChargeRequest = challenge.request.decode()?;
        if !currencies
            .iter()
            .any(|c| c.eq_ignore_ascii_case(&request.currency))
        {
            return Err(reject(format!(
                "Tempo charge currency is not allowed: {}",
                request.currency
            )));
        }
        let amount = crate::evm::parse_amount(&request.amount)?;
        if self.max_atomic_amount.is_some_and(|max| amount > max) {
            return Err(reject(
                "Tempo charge amount exceeds max_atomic_amount".to_string(),
            ));
        }
        if self.max_amount.is_some_and(|max| amount > max) {
            return Err(reject("Tempo charge amount exceeds max_amount".to_string()));
        }
        Ok(())
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

    /// The chain ID the RPC reports, fetched once and shared by clones.
    async fn rpc_chain_id(&self) -> Result<u64, MppError> {
        self.rpc_chain_id
            .get_or_try_init(|| async {
                alloy::providers::Provider::get_chain_id(&self.rpc_provider)
                    .await
                    .mpp_http("failed to fetch the RPC chain ID")
            })
            .await
            .copied()
    }
}

impl PaymentProvider for TempoProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == crate::protocol::methods::tempo::METHOD_NAME
            && intent == crate::protocol::methods::tempo::INTENT_CHARGE
    }

    fn trusted_tempo_proof_realm(&self, url: &reqwest::Url) -> Option<&str> {
        self.trusted_tempo_proof_realms
            .iter()
            .find(|(origin, _)| origin.origin() == url.origin())
            .map(|(_, realm)| realm.as_str())
    }

    fn set_trusted_tempo_proof_realm(&mut self, origin: reqwest::Url, realm: String) {
        self.trusted_tempo_proof_realms
            .retain(|(existing, _)| existing.origin() != origin.origin());
        self.trusted_tempo_proof_realms.push((origin, realm));
    }

    /// Skip offers that violate the currency or amount policy so an acceptable
    /// offer can be chosen.
    fn select_challenge<'a>(
        &self,
        challenges: &[&'a PaymentChallenge],
    ) -> Option<&'a PaymentChallenge> {
        // A cap without a currency pin is a configuration error, not a policy
        // skip: hand the first offer to `pay`, which reports it.
        if self.currencies.is_none()
            && (self.max_amount.is_some() || self.max_atomic_amount.is_some())
        {
            return challenges.first().copied();
        }
        challenges
            .iter()
            .copied()
            .find(|challenge| self.check_policy(challenge).is_ok())
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        self.check_policy(challenge)?;
        let from = self
            .signing_mode
            .from_address(alloy::signers::Signer::address(&self.signer));
        let challenge_chain_id = {
            use crate::protocol::methods::tempo::charge::TempoChargeExt;
            challenge
                .request
                .decode::<crate::protocol::intents::ChargeRequest>()?
                .chain_id()
        };
        // An explicit pin is enforced against the challenge's chain.
        if let (Some(expected), Some(got)) = (self.expected_chain_id, challenge_chain_id) {
            if expected != got {
                return Err(MppError::ChainIdMismatch { expected, got });
            }
        }
        let (chain_id, rpc_provider) = self.resolve_chain(challenge_chain_id).await?;
        self.ensure_allowed_chain(Some(chain_id))?;
        let charge = prepare_charge(
            challenge,
            Some(chain_id),
            self.client_id.as_deref(),
            self.autoswap.as_ref(),
            &rpc_provider,
            from,
        )
        .await?;

        let options = SignOptions {
            signing_mode: Some(self.signing_mode.clone()),
            fee_token: self.fee_token(),
            ..Default::default()
        };
        let signed = charge
            .sign_with_primitive_provider_options(&self.signer, &rpc_provider, options)
            .await?;
        Ok(signed.into_credential())
    }

    fn accept_payment_header(&self) -> Option<String> {
        Some(crate::protocol::core::accept_payment::from_methods(&[(
            crate::protocol::methods::tempo::METHOD_NAME,
            crate::protocol::methods::tempo::INTENT_CHARGE,
        )]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::providers::Provider;
    use alloy::signers::Signer;
    use axum::{extract::State, routing::post, Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn test_tempo_provider_new() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer.clone(), "https://rpc.example.com").unwrap();

        assert_eq!(provider.rpc_url().as_str(), "https://rpc.example.com/");
        assert_eq!(provider.signer().address(), signer.address());
    }

    #[test]
    fn trusted_proof_realm_is_scoped_to_origin() {
        let provider = TempoProvider::new(
            alloy::signers::local::PrivateKeySigner::random(),
            "https://rpc.example.com",
        )
        .unwrap()
        .with_trusted_tempo_proof_realm("https://api.example.com".parse().unwrap(), "MPP Payment");
        assert_eq!(
            provider.trusted_tempo_proof_realm(&"https://api.example.com/pay".parse().unwrap()),
            Some("MPP Payment")
        );
        assert_eq!(
            provider.trusted_tempo_proof_realm(&"https://attacker.example.com".parse().unwrap()),
            None
        );
        assert_eq!(
            provider.trusted_tempo_proof_realm(&"http://api.example.com".parse().unwrap()),
            None
        );

        let updated = provider.with_trusted_tempo_proof_realm(
            "https://api.example.com/other".parse().unwrap(),
            "new realm",
        );
        assert_eq!(updated.trusted_tempo_proof_realms.len(), 1);
        assert_eq!(
            updated.trusted_tempo_proof_realm(&"https://api.example.com/pay".parse().unwrap()),
            Some("new realm")
        );
    }

    #[test]
    fn test_tempo_provider_clones_share_rpc_client() {
        let provider = TempoProvider::new(
            alloy::signers::local::PrivateKeySigner::random(),
            "https://rpc.example.com",
        )
        .unwrap();
        let cloned = provider.clone();

        assert!(std::ptr::eq(
            provider.rpc_provider.client(),
            cloned.rpc_provider.client()
        ));
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
    fn autoswap_input_token_is_always_used_for_fees() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let token_in = alloy::primitives::Address::repeat_byte(0x11);
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_autoswap(AutoswapConfig::new(token_in, 100));

        assert_eq!(provider.fee_token(), Some(token_in));
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
        let provider = TempoProvider::new(signer.clone(), "https://rpc.example.com")
            .unwrap()
            .with_expected_chain_id(42431);
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
            })
            .with_expected_chain_id(42431);

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

    /// Zero-amount proofs are byte-identical to viem's in mppx: a root key
    /// signs the EIP-712 proof directly, and an access key signs a Keychain V2
    /// envelope naming the wallet (pympp tests/test_tempo_proof.py fixtures).
    #[tokio::test]
    async fn test_zero_amount_proofs_match_viem() {
        use crate::client::tempo::signing::KeychainVersion;
        use crate::protocol::core::Base64UrlJson;

        let key = |byte: u8| {
            alloy::signers::local::PrivateKeySigner::from_bytes(
                &alloy::primitives::B256::repeat_byte(byte),
            )
            .unwrap()
        };
        let root = key(0x11);
        let challenge = PaymentChallenge::new(
            "kM9xPqWvT2nJrHsY4aDfEb",
            "api.example.com",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({
                "amount": "0",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": { "chainId": 42431 }
            }))
            .unwrap(),
        );
        let signature = |credential: PaymentCredential| {
            credential.payload["signature"].as_str().unwrap().to_owned()
        };

        let direct = TempoProvider::new(root.clone(), "https://rpc.example.com")
            .unwrap()
            .with_expected_chain_id(42431);
        assert_eq!(
            signature(direct.pay(&challenge).await.unwrap()),
            "0x3baf02ba159042829a9bcaa17774cecb25b0194cccff0dd076db7474befcaa2b26592fc409ed59c24888f9d3b276debe61696c86793e9a35632cbff79c3496d01c"
        );

        let access = TempoProvider::new(key(0x22), "https://rpc.example.com")
            .unwrap()
            .with_signing_mode(TempoSigningMode::Keychain {
                wallet: root.address(),
                key_authorization: None,
                version: KeychainVersion::V2,
            })
            .with_expected_chain_id(42431);
        let credential = access.pay(&challenge).await.unwrap();
        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(
                42431,
                &root.address().to_string()
            ))
        );
        assert_eq!(
            signature(credential),
            "0x0419e7e376e7c213b7e7e7e46cc70a5dd086daff2aa64ad10a15b8ed2c208c147daf58f5ec3989b4de18173565f10d3acad84fc1cf3ccc20181099d57723b7b9f9ed3821442c44f641e0eb4e8a4f2965d15be9e8621c"
        );
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
            })
            .with_expected_chain_id(42431);
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
            })
            .with_expected_chain_id(42431);
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

    /// Fee-sponsored charge: signed without gas estimation, so the only RPC
    /// request `pay()` can make is the chain ID lookup.
    fn sponsored_challenge(chain_id: Option<u64>) -> PaymentChallenge {
        use crate::protocol::core::Base64UrlJson;

        let mut details = serde_json::json!({ "feePayer": true });
        if let Some(id) = chain_id {
            details["chainId"] = serde_json::json!(id);
        }
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "100",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": details,
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

    /// Serve a JSON-RPC endpoint that answers every request with `chain_id`
    /// and counts the requests it receives.
    async fn chain_id_rpc(chain_id: u64) -> (String, Arc<AtomicUsize>) {
        async fn rpc(
            State((chain_id, requests)): State<(u64, Arc<AtomicUsize>)>,
            Json(request): Json<serde_json::Value>,
        ) -> Json<serde_json::Value> {
            requests.fetch_add(1, Ordering::SeqCst);
            Json(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request.get("id").cloned().unwrap_or_default(),
                "result": format!("{chain_id:#x}"),
            }))
        }

        let requests = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/", post(rpc))
            .with_state((chain_id, requests.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, requests)
    }

    /// An unpinned provider only pays on the chain its RPC serves.
    #[tokio::test]
    async fn test_unpinned_provider_rejects_chain_other_than_rpc_chain() {
        use crate::protocol::methods::tempo::{CHAIN_ID, MODERATO_CHAIN_ID};

        let (rpc_url, _) = chain_id_rpc(MODERATO_CHAIN_ID).await;
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, rpc_url).unwrap();

        let err = provider
            .pay(&sponsored_challenge(Some(CHAIN_ID)))
            .await
            .unwrap_err();

        assert!(
            matches!(
                err,
                MppError::ChainIdMismatch {
                    expected: MODERATO_CHAIN_ID,
                    got: CHAIN_ID
                }
            ),
            "got {err:?}"
        );
    }

    /// The RPC chain ID is looked up once, shared by clones, and used when the
    /// challenge omits `chainId`.
    #[tokio::test]
    async fn test_rpc_chain_id_is_looked_up_once() {
        use crate::protocol::methods::tempo::MODERATO_CHAIN_ID;

        let (rpc_url, requests) = chain_id_rpc(MODERATO_CHAIN_ID).await;
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer.clone(), rpc_url).unwrap();

        provider
            .pay(&sponsored_challenge(Some(MODERATO_CHAIN_ID)))
            .await
            .unwrap();
        let credential = provider
            .clone()
            .pay(&sponsored_challenge(None))
            .await
            .unwrap();

        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(
                MODERATO_CHAIN_ID,
                &signer.address().to_string()
            ))
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_prepare_charge_uses_bound_attribution_with_client_id() {
        let request = crate::protocol::core::Base64UrlJson::from_value(&serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": {
                "memo": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            }
        }))
        .unwrap();
        let challenge =
            PaymentChallenge::new("test-id", "api.example.com", "tempo", "charge", request);
        let charge = prepare_charge_request(&challenge, None, Some("my-client")).unwrap();
        assert_eq!(
            charge.memo(),
            Some(crate::tempo::attribution::encode(
                "test-id",
                "api.example.com",
                Some("my-client")
            ))
        );
    }
    fn policy_challenge(id: &str, amount: &str, currency: &str) -> PaymentChallenge {
        let request = crate::protocol::core::Base64UrlJson::from_value(&serde_json::json!({
            "amount": amount,
            "currency": currency,
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": { "feePayer": true },
        }))
        .unwrap();
        PaymentChallenge::new(id, "api.example.com", "tempo", "charge", request)
    }

    const POLICY_CURRENCY: &str = "0x20c0000000000000000000000000000000000000";
    const OTHER_CURRENCY: &str = "0x20c0000000000000000000000000000000000001";

    fn policy_provider(rpc_url: &str) -> TempoProvider {
        TempoProvider::new(alloy::signers::local::PrivateKeySigner::random(), rpc_url).unwrap()
    }

    #[test]
    fn test_max_amount_rejects_excess_fractional_digits() {
        let provider = policy_provider("https://rpc.example.com");
        assert!(matches!(
            provider.clone().with_max_amount("1.0000001", 6),
            Err(MppError::InvalidConfig(_))
        ));
        let provider = provider.with_max_amount("1.500000000", 6).unwrap();
        assert_eq!(
            provider.max_amount,
            Some(alloy::primitives::U256::from(1_500_000u64))
        );
    }

    #[test]
    fn test_caps_without_currencies_are_config_errors() {
        let challenge = policy_challenge("a", "1", POLICY_CURRENCY);
        for provider in [
            policy_provider("https://rpc.example.com")
                .with_max_amount("1", 6)
                .unwrap(),
            policy_provider("https://rpc.example.com")
                .with_max_atomic_amount(alloy::primitives::U256::from(1u64)),
        ] {
            assert!(matches!(
                provider.check_policy(&challenge),
                Err(MppError::InvalidConfig(_))
            ));
            // Selection keeps the offer so `pay` surfaces the configuration error.
            assert_eq!(
                provider.select_challenge(&[&challenge]).map(|c| &c.id),
                Some(&challenge.id)
            );
        }
    }

    #[test]
    fn test_select_challenge_skips_malformed_amounts() {
        let provider = policy_provider("https://rpc.example.com")
            .with_currencies([POLICY_CURRENCY])
            .with_max_atomic_amount(alloy::primitives::U256::from(100u64));
        let empty = policy_challenge("empty", "", POLICY_CURRENCY);
        let underscore = policy_challenge("underscore", "1_0", POLICY_CURRENCY);
        let valid = policy_challenge("valid", "10", POLICY_CURRENCY);
        assert_eq!(
            provider
                .select_challenge(&[&empty, &underscore, &valid])
                .unwrap()
                .id,
            "valid"
        );
        assert!(matches!(
            provider.check_policy(&underscore),
            Err(MppError::InvalidAmount(_))
        ));
    }

    #[test]
    fn test_select_challenge_skips_disallowed_and_over_cap_offers() {
        let provider = policy_provider("https://rpc.example.com")
            .with_currencies(["0x20C0000000000000000000000000000000000000"])
            .with_max_amount("0.0001", 6)
            .unwrap();
        let other = policy_challenge("other", "1", OTHER_CURRENCY);
        let over = policy_challenge("over", "101", POLICY_CURRENCY);
        let exact = policy_challenge("exact", "100", POLICY_CURRENCY);
        let chosen = provider.select_challenge(&[&other, &over, &exact]).unwrap();
        assert_eq!(chosen.id, "exact");
        assert!(provider.select_challenge(&[&other, &over]).is_none());

        let atomic = policy_provider("https://rpc.example.com")
            .with_currencies([POLICY_CURRENCY])
            .with_max_atomic_amount(alloy::primitives::U256::from(100u64));
        assert_eq!(
            atomic.select_challenge(&[&over, &exact]).unwrap().id,
            "exact"
        );
    }

    #[tokio::test]
    async fn test_pay_rejects_policy_violations_before_rpc() {
        use crate::protocol::methods::tempo::MODERATO_CHAIN_ID;

        let (rpc_url, requests) = chain_id_rpc(MODERATO_CHAIN_ID).await;
        let provider = policy_provider(&rpc_url)
            .with_currencies([POLICY_CURRENCY])
            .with_max_atomic_amount(alloy::primitives::U256::from(99u64));
        for challenge in [
            policy_challenge("over", "100", POLICY_CURRENCY),
            policy_challenge("other", "1", OTHER_CURRENCY),
        ] {
            let err = provider.pay(&challenge).await.unwrap_err();
            assert!(
                matches!(err, MppError::InvalidChallenge { .. }),
                "got {err:?}"
            );
        }
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_pay_allows_amount_equal_to_cap() {
        use crate::protocol::methods::tempo::MODERATO_CHAIN_ID;

        let (rpc_url, _) = chain_id_rpc(MODERATO_CHAIN_ID).await;
        let provider = policy_provider(&rpc_url)
            .with_currencies([POLICY_CURRENCY])
            .with_max_amount("0.0001", 6)
            .unwrap();
        provider
            .pay(&sponsored_challenge(Some(MODERATO_CHAIN_ID)))
            .await
            .unwrap();
    }

    fn proof_challenge(chain_id: Option<u64>) -> PaymentChallenge {
        let mut details = serde_json::Map::new();
        if let Some(chain_id) = chain_id {
            details.insert("chainId".into(), chain_id.into());
        }
        PaymentChallenge::new(
            "chain-follow",
            "api.example.com",
            "tempo",
            "charge",
            crate::protocol::core::Base64UrlJson::from_value(&serde_json::json!({
                "amount": "0",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": details,
            }))
            .unwrap(),
        )
    }

    fn signed_chain(credential: &PaymentCredential) -> u64 {
        crate::protocol::methods::tempo::proof::parse_proof_source(
            credential.source.as_deref().unwrap(),
        )
        .unwrap()
        .chain_id
    }

    /// As mppx, a provider without an RPC of its own pays on the chain the
    /// challenge names through that chain's default RPC, and on mainnet when
    /// the challenge names none.
    #[tokio::test]
    async fn test_from_signer_pays_on_the_challenge_chain() {
        use crate::protocol::methods::tempo::{CHAIN_ID, MODERATO_CHAIN_ID};

        let provider =
            TempoProvider::from_signer(alloy::signers::local::PrivateKeySigner::random());
        let credential = provider
            .pay(&proof_challenge(Some(MODERATO_CHAIN_ID)))
            .await
            .unwrap();
        assert_eq!(signed_chain(&credential), MODERATO_CHAIN_ID);
        assert!(provider
            .chain_providers
            .lock()
            .unwrap()
            .contains_key(&MODERATO_CHAIN_ID));
        let credential = provider.pay(&proof_challenge(None)).await.unwrap();
        assert_eq!(signed_chain(&credential), CHAIN_ID);

        let err = provider.pay(&proof_challenge(Some(999))).await.unwrap_err();
        assert!(matches!(err, MppError::InvalidConfig(_)), "{err:?}");
    }

    /// Explicit pins are still enforced, and pick the chain of a challenge
    /// that names none.
    #[tokio::test]
    async fn test_from_signer_enforces_explicit_pins() {
        use crate::protocol::methods::tempo::{CHAIN_ID, MODERATO_CHAIN_ID};

        let provider =
            TempoProvider::from_signer(alloy::signers::local::PrivateKeySigner::random())
                .with_expected_chain_id(MODERATO_CHAIN_ID);
        let err = provider
            .pay(&proof_challenge(Some(CHAIN_ID)))
            .await
            .unwrap_err();
        assert!(matches!(err, MppError::ChainIdMismatch { .. }), "{err:?}");
        let credential = provider.pay(&proof_challenge(None)).await.unwrap();
        assert_eq!(signed_chain(&credential), MODERATO_CHAIN_ID);
    }

    /// Allowed chain IDs skip other chains' offers and are checked against
    /// the chain actually signed on.
    #[tokio::test]
    async fn test_allowed_chain_ids_are_checked_against_the_signed_chain() {
        use crate::protocol::methods::tempo::{CHAIN_ID, MODERATO_CHAIN_ID};

        let signer = alloy::signers::local::PrivateKeySigner::random();
        let provider =
            TempoProvider::from_signer(signer.clone()).with_allowed_chain_ids([MODERATO_CHAIN_ID]);
        let mainnet = proof_challenge(Some(CHAIN_ID));
        let moderato = proof_challenge(Some(MODERATO_CHAIN_ID));
        assert_eq!(
            provider
                .select_challenge(&[&mainnet, &moderato])
                .unwrap()
                .request
                .raw(),
            moderato.request.raw()
        );
        assert!(provider.pay(&mainnet).await.is_err());
        // The single allowed chain is used for a challenge that names none.
        let credential = provider.pay(&proof_challenge(None)).await.unwrap();
        assert_eq!(signed_chain(&credential), MODERATO_CHAIN_ID);

        // An RPC-pinned provider signs on its RPC's chain, which must be allowed.
        let (rpc_url, _) = chain_id_rpc(MODERATO_CHAIN_ID).await;
        let provider = TempoProvider::new(signer, rpc_url)
            .unwrap()
            .with_allowed_chain_ids([CHAIN_ID]);
        let err = provider.pay(&proof_challenge(None)).await.unwrap_err();
        assert!(err.to_string().contains("not allowed"), "{err}");
    }

    /// Serve a JSON-RPC node for a push payment, answering its broadcast with
    /// a receipt of `status`. Returns its URL and the raw transactions sent.
    async fn push_rpc(status: &'static str) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        use axum::{routing::post, Json, Router};

        let sent: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let app = Router::new().route(
            "/",
            post({
                let sent = sent.clone();
                move |Json(request): Json<serde_json::Value>| {
                    let sent = sent.clone();
                    async move {
                        let result = match request["method"].as_str().unwrap() {
                            "eth_chainId" => serde_json::json!("0xa5bf"),
                            "eth_estimateGas" => serde_json::json!("0x5208"),
                            "eth_sendRawTransactionSync" => {
                                sent.lock()
                                    .unwrap()
                                    .push(request["params"][0].as_str().unwrap().to_owned());
                                serde_json::json!({
                                    "transactionHash": format!("{:#x}", alloy::primitives::B256::repeat_byte(0xab)),
                                    "status": status,
                                })
                            }
                            method => panic!("unexpected RPC {method}"),
                        };
                        Json(serde_json::json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, sent)
    }

    fn modes_challenge(modes: serde_json::Value) -> PaymentChallenge {
        PaymentChallenge::new(
            "push-challenge",
            "api.example.com",
            "tempo",
            "charge",
            crate::protocol::core::Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634c0532925a3b844bC9e7595F8fE00",
                "methodDetails": { "chainId": 42431, "supportedModes": modes, "feePayer": true },
            }))
            .unwrap(),
        )
    }

    /// As mppx's client with a local account, a push-only challenge is paid by
    /// broadcasting the transaction and sending its hash; pull is preferred
    /// when offered.
    #[tokio::test]
    async fn test_push_only_challenge_is_paid_with_a_hash() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let (rpc_url, sent) = push_rpc("0x1").await;
        let provider = TempoProvider::new(signer.clone(), &rpc_url)
            .unwrap()
            .with_expected_chain_id(42431);

        let credential = provider
            .pay(&modes_challenge(serde_json::json!(["push"])))
            .await
            .unwrap();
        assert_eq!(credential.payload["type"], "hash");
        assert_eq!(
            credential.payload["hash"],
            format!("{:#x}", alloy::primitives::B256::repeat_byte(0xab))
        );
        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(
                42431,
                &signer.address().to_string()
            ))
        );
        // A push payment is not sponsored: the client pays its own fees.
        let sent = sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].starts_with("0x76"), "{}", sent[0]);

        let credential = provider
            .pay(&modes_challenge(serde_json::json!(["push", "pull"])))
            .await
            .unwrap();
        assert_eq!(credential.payload["type"], "transaction");
    }

    #[tokio::test]
    async fn test_reverted_push_payment_is_reported() {
        let (rpc_url, _) = push_rpc("0x0").await;
        let provider =
            TempoProvider::new(alloy::signers::local::PrivateKeySigner::random(), &rpc_url)
                .unwrap()
                .with_expected_chain_id(42431);
        let err = provider
            .pay(&modes_challenge(serde_json::json!(["push"])))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("reverted"), "{err}");
    }
}
