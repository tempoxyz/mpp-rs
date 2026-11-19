//! TIP-1166 configurable account voucher signers (T15).
//!
//! From T15 the TIP-1034 channel reserve precompile settles vouchers signed by
//! a TIP-1107 configurable account: a `0x05` signature whose owners' approvals
//! reach the account's threshold. [`ConfigurableVoucherSigner`] holds the
//! account, its configuration and enough owner keys to sign such vouchers.
//!
//! A channel records the signer's configuration commitment as its opening
//! commitment when it opens (the descriptor's salt must equal it), so a channel whose signer later
//! changes its configuration can no longer be topped up: close it and open a
//! new one.

use alloy::primitives::{Address, Bytes, B256};
use alloy::providers::Provider;
use alloy::signers::Signer;
use alloy::sol_types::SolCall;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_alloy::TempoNetwork;

use super::channel_ops::IConfigurableAccount;
use crate::client::tempo::signing::TempoPrimitiveSigner;
use crate::client::tempo::TempoClientError;
use crate::error::{MppError, ResultExt};
use crate::protocol::methods::tempo::configurable_account::{
    configurable_account_digest, ConfigurableAccountConfig, ConfigurableAccountSignature,
    CONFIGURABLE_ACCOUNT_ADDRESS, MAX_CONFIGURABLE_ACCOUNT_SIGNATURES,
};
use crate::protocol::methods::tempo::precompile_voucher::precompile_voucher_signing_hash_with_escrow;

/// Prefix of the error [`signer_config_changed_error`] returns.
const SIGNER_CONFIG_CHANGED: &str = "SignerConfigChanged";

/// A TIP-1107 configurable account that signs TIP-1034 vouchers with `0x05`
/// signatures (TIP-1166).
///
/// It holds the account's current configuration and the owner keys that
/// approve its vouchers: the heaviest owners given that reach the threshold.
#[derive(Clone, Debug)]
pub struct ConfigurableVoucherSigner {
    account: Address,
    config: ConfigurableAccountConfig,
    approvers: Vec<TempoPrimitiveSigner>,
}

impl ConfigurableVoucherSigner {
    /// A voucher signer for `account` with its current `config`, approving
    /// with `owners`, each of which must be an owner in `config` and whose
    /// weights together must reach its threshold.
    pub fn new<S>(
        account: Address,
        config: ConfigurableAccountConfig,
        owners: impl IntoIterator<Item = S>,
    ) -> Result<Self, MppError>
    where
        S: Into<TempoPrimitiveSigner>,
    {
        if account.is_zero() {
            return Err(MppError::InvalidConfig(
                "configurable account address is zero".into(),
            ));
        }
        config
            .validate()
            .map_err(|e| MppError::InvalidConfig(e.to_string()))?;
        let mut weighted = Vec::new();
        for owner in owners {
            let owner: TempoPrimitiveSigner = owner.into();
            let weight = config.owner_weight(owner.address()).ok_or_else(|| {
                MppError::InvalidConfig(format!(
                    "{} is not an owner of configurable account {account}",
                    owner.address()
                ))
            })?;
            if weighted
                .iter()
                .any(|(_, existing): &(u8, TempoPrimitiveSigner)| {
                    existing.address() == owner.address()
                })
            {
                continue;
            }
            weighted.push((weight, owner));
        }
        // Take the heaviest owners until the threshold is reached, so that no
        // approval is spare: dropping the last (lightest) one falls short.
        weighted.sort_by_key(|(weight, _)| std::cmp::Reverse(*weight));
        let mut total = 0u16;
        let mut approvers = Vec::new();
        for (weight, owner) in weighted {
            if total >= u16::from(config.threshold) {
                break;
            }
            total += u16::from(weight);
            approvers.push(owner);
        }
        if total < u16::from(config.threshold) {
            return Err(MppError::InvalidConfig(format!(
                "owners given for configurable account {account} do not reach its threshold"
            )));
        }
        if approvers.len() > MAX_CONFIGURABLE_ACCOUNT_SIGNATURES {
            return Err(MppError::InvalidConfig(format!(
                "configurable account {account} needs more than {MAX_CONFIGURABLE_ACCOUNT_SIGNATURES} approvals"
            )));
        }
        approvers.sort_by_key(|owner| owner.address());
        Ok(Self {
            account,
            config,
            approvers,
        })
    }

    /// The configurable account: the channel's authorized voucher signer.
    pub const fn account(&self) -> Address {
        self.account
    }

    /// The configuration the signer presents.
    pub const fn config(&self) -> &ConfigurableAccountConfig {
        &self.config
    }

    /// The configuration's commitment.
    pub fn commitment(&self) -> B256 {
        self.config
            .commitment()
            .expect("configuration validated at construction")
    }

    /// Sign `inner_digest` as a `0x05` configurable account signature.
    pub async fn sign_digest(&self, inner_digest: B256) -> Result<Bytes, MppError> {
        let digest = configurable_account_digest(inner_digest, self.account, self.config.version);
        let mut approvals = Vec::with_capacity(self.approvers.len());
        for owner in &self.approvers {
            approvals.push(owner.sign_hash(&digest).await.map_err(|e| {
                MppError::InvalidSignature(Some(format!(
                    "failed to sign configurable account approval: {e}"
                )))
            })?);
        }
        let signature =
            ConfigurableAccountSignature::try_new(self.account, self.config.clone(), approvals)
                .map_err(|e| MppError::InvalidConfig(e.to_string()))?;
        Ok(signature.to_bytes())
    }

    /// Check that this signer's `0x05` vouchers settle on a channel opened
    /// with descriptor salt `salt` (TIP-1166).
    ///
    /// A channel opened while the account had a configuration commitment has
    /// that commitment as its salt and opening commitment, so the signer must
    /// present the configuration whose commitment equals the salt. Any other
    /// channel has a zero opening commitment, where the escrow accepts `0x05` only from
    /// the version-0 configuration that derives the account address, and
    /// otherwise only a secp256k1 signature by the account's own key, which
    /// this signer does not hold.
    pub fn ensure_can_sign_channel(&self, salt: B256) -> Result<(), MppError> {
        if !salt.is_zero() && salt == self.commitment() {
            return Ok(());
        }
        if self.derives_account() {
            return Ok(());
        }
        Err(MppError::InvalidConfig(format!(
            "configurable account {} cannot sign vouchers for a channel with salt {salt}: \
             the channel's opening commitment is not the commitment {} of the signer's \
             configuration, and only a version-0 configuration that derives the account \
             address signs on a channel without one; sign with the account's own \
             secp256k1 key, or close the channel and open a new one",
            self.account,
            self.commitment()
        )))
    }

    /// Whether the configuration is the version-0 one that derives the
    /// account address (an account that has not registered a configuration).
    fn derives_account(&self) -> bool {
        self.config.version == 0 && self.config.account_address().ok() == Some(self.account)
    }

    /// Sign a TIP-1034 voucher for the channel reserve precompile at `escrow`.
    ///
    /// This does not check that the voucher settles on the channel; see
    /// [`Self::ensure_can_sign_channel`].
    pub async fn sign_precompile_voucher(
        &self,
        channel_id: B256,
        cumulative_amount: u128,
        escrow: Address,
        chain_id: u64,
    ) -> Result<Bytes, MppError> {
        let hash = precompile_voucher_signing_hash_with_escrow(
            channel_id,
            cumulative_amount,
            escrow,
            chain_id,
        )?;
        self.sign_digest(hash).await
    }

    /// The account's configuration commitment on chain: zero until the
    /// account is upgraded or its configuration changes.
    pub async fn on_chain_commitment<P: Provider<TempoNetwork>>(
        &self,
        provider: &P,
    ) -> Result<B256, MppError> {
        let call = IConfigurableAccount::getConfigCommitmentCall {
            account: self.account,
        };
        let mut request = TempoTransactionRequest::default();
        request.inner = request.inner.to(CONFIGURABLE_ACCOUNT_ADDRESS).input(
            alloy::rpc::types::TransactionInput::new(Bytes::from(call.abi_encode())),
        );
        let output = provider
            .call(request)
            .await
            .mpp_http("failed to read configurable account commitment")?;
        IConfigurableAccount::getConfigCommitmentCall::abi_decode_returns(&output)
            .mpp_http("failed to decode configurable account commitment")
    }

    /// The salt to open a channel with: the account's commitment when it has
    /// one on chain (T15 requires it), else `None` for a random salt.
    ///
    /// The commitment that counts is the one when the open executes. This SDK
    /// signs open transactions with the payer's primitive or keychain key,
    /// never with the configurable account itself (`0x05`), so an open never
    /// registers the account (TIP-1107 registers it only for a transaction it
    /// signs) and the commitment read here is the one the open sees.
    ///
    /// Fails when the signer's configuration is not the one on chain, since
    /// its vouchers could not settle.
    pub async fn open_salt<P: Provider<TempoNetwork>>(
        &self,
        provider: &P,
    ) -> Result<Option<B256>, MppError> {
        let on_chain = self.on_chain_commitment(provider).await?;
        if on_chain.is_zero() {
            if self.derives_account() {
                return Ok(None);
            }
            return Err(MppError::InvalidConfig(format!(
                "configurable account {} has no configuration on chain matching the signer's",
                self.account
            )));
        }
        if on_chain != self.commitment() {
            return Err(signer_config_changed_error(self.account));
        }
        Ok(Some(on_chain))
    }

    /// Check before a nonzero top-up of a channel opened with `salt` that the
    /// account's configuration has not changed since the channel opened,
    /// which the precompile would reject (`SignerConfigChanged` or
    /// `RootKeyRetired`).
    pub async fn ensure_unchanged<P: Provider<TempoNetwork>>(
        &self,
        provider: &P,
        salt: B256,
    ) -> Result<(), MppError> {
        let on_chain = self.on_chain_commitment(provider).await?;
        if on_chain.is_zero() || on_chain == salt {
            return Ok(());
        }
        Err(signer_config_changed_error(self.account))
    }
}

/// The error a top-up of a channel returns when its voucher signer changed
/// its configurable account configuration after the channel opened (the
/// precompile's `SignerConfigChanged` or `RootKeyRetired`). The remedy is to
/// close the channel and open a new one; the SDK does not do it on its own.
///
/// It is a [`TempoClientError::TransactionReverted`];
/// [`is_signer_config_changed`] recognizes it.
pub fn signer_config_changed_error(signer: Address) -> MppError {
    MppError::Tempo(TempoClientError::TransactionReverted(format!(
        "{SIGNER_CONFIG_CHANGED}({signer}): the channel's voucher signer changed its configurable \
         account configuration since the channel opened; close the channel and open a new one"
    )))
}

/// Whether `error` reports that a channel's voucher signer changed its
/// configurable account configuration (see [`signer_config_changed_error`]),
/// including a revert reported by the precompile or a server.
pub fn is_signer_config_changed(error: &MppError) -> bool {
    let message = match error {
        MppError::Tempo(TempoClientError::TransactionReverted(message)) => message.as_str(),
        MppError::Http(message) | MppError::InvalidConfig(message) => message.as_str(),
        _ => return false,
    };
    message.contains(SIGNER_CONFIG_CHANGED)
        || message.contains("RootKeyRetired")
        || message.contains(&alloy::hex::encode(
            <super::channel_ops::ITIP1166ChannelReserve::SignerConfigChanged as alloy::sol_types::SolError>::SELECTOR,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::methods::tempo::configurable_account::ConfigurableAccountOwner;
    use crate::protocol::methods::tempo::precompile_voucher::{
        verify_precompile_voucher_signature_with, VoucherVerifyOptions,
    };
    use alloy::signers::local::PrivateKeySigner;
    use tempo_alloy::contracts::precompiles::TIP20_CHANNEL_RESERVE_ADDRESS;

    fn setup(weights: &[u8], threshold: u8) -> (Vec<PrivateKeySigner>, ConfigurableAccountConfig) {
        let mut owners: Vec<_> = weights.iter().map(|_| PrivateKeySigner::random()).collect();
        owners.sort_by_key(|o| o.address());
        let config = ConfigurableAccountConfig {
            salt: B256::repeat_byte(3),
            version: 0,
            threshold,
            owners: owners
                .iter()
                .zip(weights)
                .map(|(o, w)| ConfigurableAccountOwner {
                    owner: o.address(),
                    weight: *w,
                })
                .collect(),
        };
        (owners, config)
    }

    #[tokio::test]
    async fn signs_vouchers_the_server_accepts() {
        let (owners, config) = setup(&[1, 2, 1], 2);
        let account = config.account_address().unwrap();
        let signer = ConfigurableVoucherSigner::new(account, config, owners).unwrap();
        // The weight-2 owner alone reaches the threshold.
        assert_eq!(signer.approvers.len(), 1);
        let channel_id = B256::repeat_byte(9);
        let sig = signer
            .sign_precompile_voucher(channel_id, 10, TIP20_CHANNEL_RESERVE_ADDRESS, 4217)
            .await
            .unwrap();
        assert_eq!(sig[0], 0x05);
        let options = VoucherVerifyOptions {
            configurable: true,
            opening_commitment: None,
        };
        assert!(verify_precompile_voucher_signature_with(
            &sig,
            account,
            channel_id,
            10,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            4217,
            &options,
        )
        .unwrap());
        let committed = VoucherVerifyOptions {
            configurable: true,
            opening_commitment: Some(signer.commitment()),
        };
        assert!(verify_precompile_voucher_signature_with(
            &sig,
            account,
            channel_id,
            10,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            4217,
            &committed,
        )
        .unwrap());
    }

    #[test]
    fn rejects_owners_short_of_the_threshold_or_unknown() {
        let (owners, config) = setup(&[1, 1, 1], 3);
        let account = config.account_address().unwrap();
        assert!(
            ConfigurableVoucherSigner::new(account, config.clone(), owners[..2].to_vec()).is_err()
        );
        assert!(
            ConfigurableVoucherSigner::new(account, config, vec![PrivateKeySigner::random()])
                .is_err()
        );
    }

    #[test]
    fn signs_only_vouchers_the_channel_opening_commitment_settles() {
        let (owners, config) = setup(&[1], 1);
        let account = config.account_address().unwrap();
        let derived =
            ConfigurableVoucherSigner::new(account, config.clone(), owners.clone()).unwrap();
        // The version-0 config that derives the account signs on a channel
        // with a zero opening commitment (random salt) and on its own commitment.
        derived.ensure_can_sign_channel(B256::random()).unwrap();
        derived.ensure_can_sign_channel(B256::ZERO).unwrap();
        derived
            .ensure_can_sign_channel(derived.commitment())
            .unwrap();

        // A rotated config signs only where the channel recorded it.
        let rotated_config = ConfigurableAccountConfig {
            version: 1,
            ..config
        };
        let rotated = ConfigurableVoucherSigner::new(account, rotated_config, owners).unwrap();
        rotated
            .ensure_can_sign_channel(rotated.commitment())
            .unwrap();
        let err = rotated.ensure_can_sign_channel(B256::random()).unwrap_err();
        assert!(err.to_string().contains("cannot sign vouchers"), "{err}");
        assert!(rotated.ensure_can_sign_channel(B256::ZERO).is_err());
        assert!(rotated
            .ensure_can_sign_channel(derived.commitment())
            .is_err());
    }

    #[test]
    fn recognizes_signer_config_changed() {
        assert!(is_signer_config_changed(&signer_config_changed_error(
            Address::repeat_byte(1)
        )));
        assert!(!is_signer_config_changed(&MppError::Http("timeout".into())));
    }
}
