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
//!     // A 2D nonce lane instead of the default expiring nonce.
//!     nonce_key: Some(U256::from(1)),
//!     nonce: Some(42),
//!     gas_limit: Some(500_000),
//!     max_fee_per_gas: Some(50_000_000_000),
//!     max_priority_fee_per_gas: Some(2_000_000_000),
//!     signing_mode: Some(TempoSigningMode::Keychain {
//!         wallet,
//!         key_authorization: None,
//!         version: KeychainVersion::V2,
//!     }),
//!     rpc_url: Some("https://rpc.tempo.xyz".to_string()),
//!     ..Default::default()
//! }).await?;
//! let credential = signed.into_credential();
//! ```

pub mod tx_builder;

use std::num::NonZeroU64;

use alloy::eips::Encodable2718;
use alloy::network::NetworkWallet;
use alloy::primitives::{Address, TxKind, U256};
use alloy::providers::Provider;
use tempo_alloy::primitives::transaction::{
    Call, SignatureType, SignedKeyAuthorization, TempoTransaction, FEE_PAYER_SIGNATURE_MARKER,
};

use self::tx_builder::{build_charge_credential, build_tempo_tx, estimate_gas, TempoTxOptions};
use crate::client::tempo::signing::{
    build_tempo_signature, build_tempo_signature_primitive, effective_signing_hash,
    encode_signed_fee_payer_envelope, sign_and_encode_async,
    sign_and_encode_fee_payer_envelope_async, sign_and_encode_fee_payer_envelope_primitive_async,
    sign_and_encode_primitive_async, TempoPrimitiveSigner, TempoSigningMode,
};
use crate::error::{MppError, ResultExt};
use crate::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::methods::tempo::charge::TempoChargeExt;
use crate::protocol::methods::tempo::network::TempoNetwork as TempoChain;
use crate::protocol::methods::tempo::proof;
use crate::protocol::methods::tempo::transfers::get_transfers;
use crate::protocol::methods::tempo::types::Split;
use crate::protocol::methods::tempo::{CHAIN_ID, FEE_PAYER_MIN_REMAINING_VALIDITY_SECS};
use alloy::sol_types::SolCall;
use tempo_alloy::accounts::{TempoAccountsWallet, TempoAuthorizationReservation};
use tempo_alloy::contracts::precompiles::ITIP20;
use tempo_alloy::rpc::TempoTransactionRequest;

/// Nonce key for expiring nonce transactions, the default for every charge.
const EXPIRING_NONCE_KEY: U256 = U256::MAX;

/// Default expiring-nonce validity window (in seconds) for charge
/// transactions: `valid_before = now + EXPIRING_NONCE_VALID_BEFORE_SECS`,
/// capped at the challenge `expires`.
///
/// Matches mppx's 25 seconds. Tempo rejects expiring-nonce transactions whose
/// `valid_before` is more than 30 seconds past the block timestamp (TIP-1009,
/// `expiring_nonce_max_expiry_secs` before T11), so a wider default would make
/// every default charge unincludable.
const EXPIRING_NONCE_VALID_BEFORE_SECS: u64 = 25;

/// Encode a TIP-20 token transfer call, optionally with memo.
fn encode_transfer(
    recipient: Address,
    amount: U256,
    memo: Option<[u8; 32]>,
) -> alloy::primitives::Bytes {
    if let Some(memo_bytes) = memo {
        alloy::primitives::Bytes::from(
            ITIP20::transferWithMemoCall {
                to: recipient,
                amount,
                memo: memo_bytes.into(),
            }
            .abi_encode(),
        )
    } else {
        alloy::primitives::Bytes::from(
            ITIP20::transferCall {
                to: recipient,
                amount,
            }
            .abi_encode(),
        )
    }
}

/// Resolve the token that pays an unsponsored charge's gas.
///
/// An explicit fee token wins; otherwise the charge currency pays its own gas.
/// MACH is recipient-restricted and cannot pay fees, so a charge the payer
/// funds with the chain's canonical machine token (`machine_token`: a MACH
/// charge or a MACH swapper route) pays gas in the first supported stablecoin
/// (pathUSD, then the network's default currency) the payer holds, falling
/// back to pathUSD. A sponsored charge's fee token is chosen by the fee payer,
/// so it is left as the currency.
async fn resolve_fee_token(
    explicit: Option<Address>,
    currency: Address,
    machine_token: bool,
    fee_payer: bool,
    chain_id: u64,
    provider: &impl Provider<tempo_alloy::TempoNetwork>,
    from: Address,
) -> Address {
    if let Some(token) = explicit {
        return token;
    }
    if fee_payer || !machine_token {
        return currency;
    }
    let mut candidates: Vec<Address> = Vec::with_capacity(2);
    let defaults = [
        Some(crate::protocol::methods::tempo::PATH_USD),
        TempoChain::from_chain_id(chain_id).map(TempoChain::default_currency),
    ];
    for token in defaults.into_iter().flatten() {
        if let Ok(token) = token.parse::<Address>() {
            if !candidates.contains(&token) {
                candidates.push(token);
            }
        }
    }
    for token in &candidates {
        let balance = ITIP20::new(*token, provider).balanceOf(from).call().await;
        if balance.is_ok_and(|balance| !balance.is_zero()) {
            return *token;
        }
    }
    candidates.first().copied().unwrap_or(currency)
}

/// Whether a non-zero charge is paid in `push` mode.
///
/// As mppx's client with a local account, this client prefers `pull` mode
/// (`type="transaction"`: the server broadcasts) and pays in `push` mode
/// (`type="hash"`: the client broadcasts) when the challenge's
/// `supportedModes` lists only `push`. An omitted `supportedModes` allows
/// every mode.
fn resolve_push_mode(charge: &ChargeRequest) -> Result<bool, MppError> {
    let supported_modes = charge
        .method_details
        .as_ref()
        .and_then(|details| details.get("supportedModes"))
        .filter(|modes| !modes.is_null());
    let Some(supported_modes) = supported_modes else {
        return Ok(false);
    };
    let supports = |wanted: &str| {
        supported_modes
            .as_array()
            .is_some_and(|modes| modes.iter().any(|mode| mode.as_str() == Some(wanted)))
    };
    if supports("pull") {
        Ok(false)
    } else if supports("push") {
        Ok(true)
    } else {
        Err(MppError::UnsupportedPaymentMethod(
            "challenge supports neither pull nor push mode".into(),
        ))
    }
}

/// Resolve the transaction's `validBefore`: the requested timestamp, or
/// [`EXPIRING_NONCE_VALID_BEFORE_SECS`] from now, capped at the second after
/// the challenge `expires`.
fn resolve_valid_before(challenge: &PaymentChallenge, requested: Option<u64>) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    resolve_valid_before_at(challenge, requested, now)
}

fn resolve_valid_before_at(challenge: &PaymentChallenge, requested: Option<u64>, now: u64) -> u64 {
    let valid_before =
        requested.unwrap_or_else(|| now.saturating_add(EXPIRING_NONCE_VALID_BEFORE_SECS));
    let Some(expires) = challenge.expires_at() else {
        return valid_before;
    };
    // `validBefore` is an exclusive whole-second bound, so cap at the second
    // after a (possibly fractional) expiry to stay valid as long as the challenge.
    // This also keeps the cap non-zero: `0` encodes "no validBefore".
    let expires = u64::try_from(expires.unix_timestamp())
        .unwrap_or(0)
        .saturating_add(1);
    if valid_before == 0 {
        expires
    } else {
        valid_before.min(expires)
    }
}

/// Refuse to sign a fee-sponsored challenge that expires in less than
/// [`FEE_PAYER_MIN_REMAINING_VALIDITY_SECS`]: the server would refuse to
/// co-sign or broadcast the transaction, so nothing is signed or sent.
fn ensure_sponsored_expiry_floor(
    challenge: &PaymentChallenge,
    now: time::OffsetDateTime,
) -> Result<(), MppError> {
    let Some(expires) = challenge.expires_at() else {
        return Ok(());
    };
    let remaining = expires - now;
    if remaining < time::Duration::seconds(FEE_PAYER_MIN_REMAINING_VALIDITY_SECS as i64) {
        let expires_in = remaining.whole_seconds();
        return Err(MppError::bad_request(format!(
            "fee-sponsored challenge expires in {expires_in}s, less than the {FEE_PAYER_MIN_REMAINING_VALIDITY_SECS}s the server needs to co-sign and broadcast; request a new challenge"
        )));
    }
    Ok(())
}

/// Refuse to sign a fee-sponsored transaction once less than
/// [`FEE_PAYER_MIN_REMAINING_VALIDITY_SECS`] remain of the challenge expiry or
/// of its `valid_before`. The fee payer enforces the floor on the signed
/// `valid_before`, which is fixed before asynchronous preparation and signing,
/// so this re-check runs just before and again just after signing.
fn ensure_sponsorable_before_signing(
    challenge: &PaymentChallenge,
    valid_before: Option<u64>,
    now: time::OffsetDateTime,
) -> Result<(), MppError> {
    ensure_sponsored_expiry_floor(challenge, now)?;
    let Some(valid_before) = valid_before.filter(|v| *v != 0) else {
        return Ok(());
    };
    // Match the fee payer's `ensure_remaining_validity`: a fractional `now` is
    // rounded up to the next whole second before applying the floor.
    let nanos = now.unix_timestamp_nanos();
    let now_secs =
        nanos.div_euclid(1_000_000_000) + i128::from(nanos.rem_euclid(1_000_000_000) > 0);
    if i128::from(valid_before) < now_secs + i128::from(FEE_PAYER_MIN_REMAINING_VALIDITY_SECS) {
        return Err(MppError::bad_request(format!(
            "sponsored transaction preparation took too long: less than {FEE_PAYER_MIN_REMAINING_VALIDITY_SECS}s of its validity window remain, so the fee payer would reject it; request a new challenge"
        )));
    }
    Ok(())
}

fn apply_estimation_signer_hints(
    request: &mut TempoTransactionRequest,
    signing_mode: &TempoSigningMode,
    signer_address: Address,
    signature_type: SignatureType,
) {
    request.key_type = Some(signature_type);
    if matches!(signing_mode, TempoSigningMode::Keychain { .. }) {
        request.key_id = Some(signer_address);
    }
}

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
    machine_token_enabled: bool,
    splits: Option<Vec<Split>>,
    calls: Option<Vec<Call>>,
    push: bool,
}

impl TempoCharge {
    /// Whether the payer spends the chain's canonical machine token (MACH),
    /// either as the charge currency or through the machine-token swapper
    /// route, whose first call approves MACH.
    fn pays_in_machine_token(&self) -> bool {
        let Some(mach) = crate::protocol::methods::tempo::machine_token::token(self.chain_id)
        else {
            return false;
        };
        self.currency == mach
            || self
                .calls
                .as_ref()
                .and_then(|calls| calls.first())
                .is_some_and(|call| call.to == TxKind::Call(mach))
    }

    /// Parse and validate a [`PaymentChallenge`] into a [`TempoCharge`].
    ///
    /// Validates that the challenge is a Tempo charge, decodes the
    /// [`ChargeRequest`], and extracts all payment fields.
    ///
    /// # Errors
    ///
    /// Returns an error if the challenge is malformed, or if it is a non-zero
    /// charge whose `methodDetails.supportedModes` lists neither `pull` nor
    /// `push`. A charge that lists only `push` is paid by broadcasting the
    /// transaction and sending its hash, without fee sponsorship (see
    /// [`is_push`](Self::is_push)).
    pub fn from_challenge(challenge: &PaymentChallenge) -> Result<Self, MppError> {
        challenge.validate_for_charge("tempo")?;

        let charge_req: ChargeRequest = challenge.request.decode()?;
        let details = charge_req.tempo_method_details()?;

        let recipient = charge_req.recipient_address()?;
        let currency = charge_req.currency_address()?;
        let amount = charge_req.amount_u256()?;
        let push = !amount.is_zero() && resolve_push_mode(&charge_req)?;
        let memo = Some(crate::tempo::attribution::encode(
            &challenge.id,
            &challenge.realm,
            None,
        ));
        let chain_id = details.chain_id.unwrap_or(CHAIN_ID);
        // The client broadcasts a push payment itself and pays its own fees.
        let fee_payer = details.fee_payer() && !push;
        let machine_token_enabled = details.machine_token_enabled();
        let splits = details.splits;

        get_transfers(amount, recipient, memo, splits.as_deref())?;

        Ok(Self {
            challenge: challenge.clone(),
            recipient,
            currency,
            amount,
            memo,
            chain_id,
            fee_payer,
            machine_token_enabled,
            splits,
            calls: None,
            push,
        })
    }

    /// Whether this charge is paid in `push` mode: the signing methods that
    /// reach an RPC broadcast the transaction and return a `hash` credential.
    pub fn is_push(&self) -> bool {
        self.push
    }

    /// The RPC client the simple signing path uses: [`SignOptions::rpc_url`]
    /// or the chain's default RPC.
    fn rpc_for(
        &self,
        options: &SignOptions,
    ) -> Result<alloy::providers::RootProvider<tempo_alloy::TempoNetwork>, MppError> {
        let rpc_url = match options.rpc_url.as_deref() {
            Some(url) => url.parse().mpp_config("invalid RPC URL")?,
            None => {
                let network = TempoChain::from_chain_id(self.chain_id).ok_or_else(|| {
                    MppError::InvalidConfig(format!(
                        "unknown chain ID {}: provide rpc_url in SignOptions",
                        self.chain_id
                    ))
                })?;
                network
                    .default_rpc_url()
                    .parse()
                    .mpp_config("invalid RPC URL")?
            }
        };
        Ok(super::rpc_provider(rpc_url))
    }

    /// Get the chain ID extracted from the challenge.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Override the chain ID (e.g. a client-pinned chain when the challenge
    /// omits `methodDetails.chainId`).
    pub(crate) fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
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

    /// Whether the challenge enables canonical machine-token funding.
    pub fn machine_token_enabled(&self) -> bool {
        self.machine_token_enabled
    }

    /// Get the splits, if present.
    pub fn splits(&self) -> Option<&[Split]> {
        self.splits.as_deref()
    }

    /// Build the transfer calls from the charge fields (primary + splits).
    fn build_transfer_calls(&self) -> Result<Vec<Call>, MppError> {
        let transfers = get_transfers(
            self.amount,
            self.recipient,
            self.memo,
            self.splits.as_deref(),
        )?;

        Ok(transfers
            .into_iter()
            .map(|t| Call {
                to: TxKind::Call(self.currency),
                value: U256::ZERO,
                input: encode_transfer(t.recipient, t.amount, t.memo),
            })
            .collect())
    }

    pub(crate) fn accounts_request(
        &self,
        from: Address,
    ) -> Result<TempoTransactionRequest, MppError> {
        let calls = match &self.calls {
            Some(calls) => calls.clone(),
            None => self.build_transfer_calls()?,
        };
        let mut request = TempoTransactionRequest {
            calls,
            ..Default::default()
        };
        request.inner.from = Some(from);
        request.inner.chain_id = Some(self.chain_id);
        Ok(request)
    }

    /// Prepend a call to the transaction's call list.
    ///
    /// Used by autoswap to insert a DEX swap call before the transfer call.
    /// The swap and transfer then execute atomically in a single AA transaction.
    pub fn with_prepended_call(mut self, call: Call) -> Result<Self, MppError> {
        if self.calls.is_none() {
            self.calls = Some(self.build_transfer_calls()?);
        }
        self.calls.as_mut().unwrap().insert(0, call);
        Ok(self)
    }

    /// Replace the payment calls with one exact atomic route.
    pub(crate) fn with_calls(mut self, calls: Vec<Call>) -> Self {
        self.calls = Some(calls);
        self
    }

    /// Sign the charge with default options.
    ///
    /// This is the simple path — resolves the RPC provider from chain_id,
    /// estimates gas, builds and signs the transaction. The transaction uses
    /// an expiring nonce and Tempo's static gas fees, so neither the account
    /// nonce nor the base fee is fetched. See [`SignOptions`] for the defaults.
    ///
    /// # Errors
    ///
    /// Returns an error if the chain_id is not a known Tempo network, or if
    /// gas estimation fails.
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
    ///
    /// The transaction's `validBefore` is never later than the second after
    /// the challenge `expires`, whatever [`SignOptions::valid_before`] asks for.
    pub async fn sign_with_options(
        self,
        signer: &(impl alloy::signers::Signer + Clone),
        options: SignOptions,
    ) -> Result<SignedTempoCharge, MppError> {
        let push = self.push.then(|| self.rpc_for(&options)).transpose()?;
        let challenge = self.challenge.clone();
        let signed = self
            .prepare(signer.address(), SignatureType::Secp256k1, options)
            .await?
            .sign_secp256k1(signer)
            .await?;
        match push {
            Some(provider) => signed.pushed(&challenge, &provider).await,
            None => Ok(signed),
        }
    }

    /// Sign the charge with a native Tempo primitive signer.
    ///
    /// This accepts either a secp256k1 key or an Accounts SDK-compatible P-256
    /// access key through [`TempoPrimitiveSigner`] and Alloy's existing signer
    /// interface.
    pub async fn sign_with_primitive_options(
        self,
        signer: &TempoPrimitiveSigner,
        options: SignOptions,
    ) -> Result<SignedTempoCharge, MppError> {
        let signature_type = signer.signature_type();
        let push = self.push.then(|| self.rpc_for(&options)).transpose()?;
        let challenge = self.challenge.clone();
        let signed = self
            .prepare(
                alloy::signers::Signer::address(signer),
                signature_type,
                options,
            )
            .await?
            .sign_primitive(signer)
            .await?;
        match push {
            Some(provider) => signed.pushed(&challenge, &provider).await,
            None => Ok(signed),
        }
    }

    pub(crate) async fn sign_with_primitive_provider_options(
        self,
        signer: &TempoPrimitiveSigner,
        provider: &impl Provider<tempo_alloy::TempoNetwork>,
        options: SignOptions,
    ) -> Result<SignedTempoCharge, MppError> {
        let signature_type = signer.signature_type();
        let push = self.push;
        let challenge = self.challenge.clone();
        let signed = self
            .prepare_with_provider(
                alloy::signers::Signer::address(signer),
                signature_type,
                options,
                provider,
            )
            .await?
            .sign_primitive(signer)
            .await?;
        if push {
            signed.pushed(&challenge, provider).await
        } else {
            Ok(signed)
        }
    }

    pub(crate) async fn sign_with_accounts_provider_options(
        self,
        wallet: &TempoAccountsWallet,
        provider: &impl Provider<tempo_alloy::TempoNetwork>,
        from: Address,
        options: SignOptions,
    ) -> Result<SignedTempoCharge, MppError> {
        if options.signing_mode.is_some() || options.key_authorization.is_some() {
            return Err(MppError::InvalidConfig(
                "Tempo Accounts owns access-key selection and authorization".into(),
            ));
        }

        if self.amount.is_zero() {
            let access_key = wallet
                .clone()
                .with_chain_id(self.chain_id)
                .active_access_key()
                .mpp_config("failed to select Tempo Accounts access key")?;
            if access_key.account() != from {
                return Err(MppError::InvalidConfig(
                    "the active Tempo account changed while preparing the charge".into(),
                ));
            }
            if access_key.chain_id() != self.chain_id {
                return Err(MppError::ChainIdMismatch {
                    expected: access_key.chain_id(),
                    got: self.chain_id,
                });
            }
            // An access key signs a Keychain V2 envelope naming the account,
            // as it signs transactions and as viem's access-key accounts sign
            // proofs in mppx.
            let mode = TempoSigningMode::Keychain {
                wallet: from,
                key_authorization: None,
                version: crate::client::tempo::signing::KeychainVersion::V2,
            };
            let hash = effective_signing_hash(
                proof::signing_hash(
                    from,
                    self.chain_id,
                    &self.challenge.id,
                    &self.challenge.realm,
                ),
                &mode,
            );
            let inner = alloy::signers::Signer::sign_hash(&access_key, &hash)
                .await
                .mpp_http("failed to sign proof")?;
            let signature = alloy::hex::encode_prefixed(
                build_tempo_signature_primitive(inner, &mode).to_bytes(),
            );
            let credential = PaymentCredential::with_source(
                self.challenge.to_echo(),
                proof::proof_source(from, self.chain_id),
                PaymentPayload::proof(signature),
            );
            return Ok(SignedTempoCharge {
                credential,
                tx_bytes: None,
                chain_id: self.chain_id,
                from,
                authorization_reservation: None,
            });
        }

        if self.fee_payer {
            ensure_sponsored_expiry_floor(&self.challenge, time::OffsetDateTime::now_utc())?;
        }

        let machine_token = self.pays_in_machine_token();
        let calls = match self.calls {
            Some(calls) => calls,
            None => self.build_transfer_calls()?,
        };
        let fee_token = resolve_fee_token(
            options.fee_token,
            self.currency,
            machine_token,
            self.fee_payer,
            self.chain_id,
            provider,
            from,
        )
        .await;
        let max_fee_per_gas = options
            .max_fee_per_gas
            .unwrap_or(crate::client::tempo::MAX_FEE_PER_GAS);
        let max_priority_fee_per_gas = options
            .max_priority_fee_per_gas
            .unwrap_or(crate::client::tempo::MAX_PRIORITY_FEE_PER_GAS);
        let nonce = options.nonce.unwrap_or(0);
        let nonce_key = options.nonce_key.unwrap_or(EXPIRING_NONCE_KEY);
        let valid_before = Some(resolve_valid_before(&self.challenge, options.valid_before));
        let explicit_gas = options
            .gas_limit
            .or_else(|| self.fee_payer.then_some(1_000_000));

        let mut request = TempoTransactionRequest {
            calls,
            ..Default::default()
        }
        .with_nonce_key(nonce_key);
        if self.fee_payer {
            request.set_fee_payer_signature(FEE_PAYER_SIGNATURE_MARKER);
        } else {
            request.set_fee_token(fee_token);
        }
        if let Some(valid_before) = valid_before.and_then(NonZeroU64::new) {
            request = request.with_valid_before(valid_before);
        }
        request.inner.from = Some(from);
        request.inner.chain_id = Some(self.chain_id);
        request.inner.nonce = Some(nonce);
        request.inner.gas = explicit_gas;
        request.inner.max_fee_per_gas = Some(max_fee_per_gas);
        request.inner.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);

        let access_key = wallet
            .prepare_request(provider, &mut request)
            .await
            .mpp_http("failed to prepare Tempo Accounts access key")?;
        let from = access_key.account();
        request.inner.gas = Some(match explicit_gas {
            Some(gas_limit) => gas_limit,
            None => estimate_gas(provider, request.clone()).await?,
        });
        if self.fee_payer {
            ensure_sponsorable_before_signing(
                &self.challenge,
                valid_before,
                time::OffsetDateTime::now_utc(),
            )?;
        }
        let signed = access_key
            .sign_request(request)
            .await
            .mpp_http("failed to sign Tempo transaction")?;
        // Signing may reserve a pending one-time key authorization. Take it now so
        // an error before the credential is returned releases it: nothing was
        // handed to a transport, and a retry must be able to sign it again.
        let authorization_reservation = access_key.authorization_reservation();
        let encoded = (|| {
            if self.fee_payer {
                // A slow signer (hardware wallet, KMS) can use up the window:
                // re-check so a credential the fee payer would refuse is never
                // returned.
                ensure_sponsorable_before_signing(
                    &self.challenge,
                    valid_before,
                    time::OffsetDateTime::now_utc(),
                )?;
                encode_signed_fee_payer_envelope(signed, from)
            } else {
                Ok(signed.encoded_2718())
            }
        })();
        let tx_bytes = match encoded {
            Ok(tx_bytes) => tx_bytes,
            Err(error) => {
                if let Some(reservation) = authorization_reservation {
                    let _ = access_key.release_authorization(reservation);
                }
                return Err(error);
            }
        };
        let credential = build_charge_credential(&self.challenge, &tx_bytes, self.chain_id, from);
        let signed = SignedTempoCharge {
            credential,
            tx_bytes: Some(tx_bytes),
            chain_id: self.chain_id,
            from,
            authorization_reservation,
        };
        if !self.push {
            return Ok(signed);
        }
        match signed.push(&self.challenge, provider).await {
            // The authorization went on chain with the payment, so it is spent:
            // drop the reservation rather than leave it for a rollback to release.
            Ok(mut pushed) => {
                pushed.authorization_reservation = None;
                Ok(pushed)
            }
            Err(PushError { error, rejected }) => {
                // Only a node that refused the transaction proves the
                // authorization was not used; otherwise keep it reserved.
                if rejected {
                    if let Some(reservation) = authorization_reservation {
                        let _ = access_key.release_authorization(reservation);
                    }
                }
                Err(error)
            }
        }
    }

    async fn prepare(
        self,
        signer_address: Address,
        signature_type: SignatureType,
        options: SignOptions,
    ) -> Result<PreparedTempoCharge, MppError> {
        let provider = self.rpc_for(&options)?;
        self.prepare_with_provider(signer_address, signature_type, options, &provider)
            .await
    }

    async fn prepare_with_provider(
        self,
        signer_address: Address,
        signature_type: SignatureType,
        options: SignOptions,
        provider: &impl Provider<tempo_alloy::TempoNetwork>,
    ) -> Result<PreparedTempoCharge, MppError> {
        let signing_mode = options.signing_mode.unwrap_or_default();
        let from = signing_mode.from_address(signer_address);

        if self.amount.is_zero() {
            return Ok(PreparedTempoCharge {
                challenge: self.challenge,
                chain_id: self.chain_id,
                fee_payer: self.fee_payer,
                from,
                signing_mode,
                transaction: None,
            });
        }

        if self.fee_payer {
            ensure_sponsored_expiry_floor(&self.challenge, time::OffsetDateTime::now_utc())?;
        }

        let managed_key_authorization = if options.key_authorization.is_none() {
            crate::client::tempo::signing::keychain::resolve_key_authorization(
                provider,
                &signing_mode,
                signer_address,
            )
            .await?
        } else {
            None
        };
        let key_authorization = options
            .key_authorization
            .as_deref()
            .cloned()
            .or(managed_key_authorization);

        let machine_token = self.pays_in_machine_token();
        let calls = match self.calls {
            Some(c) => c,
            None => self.build_transfer_calls()?,
        };

        let fee_token = resolve_fee_token(
            options.fee_token,
            self.currency,
            machine_token,
            self.fee_payer,
            self.chain_id,
            provider,
            from,
        )
        .await;

        // All charge payments use expiring nonces (nonceKey=MAX, nonce=0,
        // validBefore=min(now+25s, challenge expires)) so we never need a
        // nonce fetch.
        // Tempo uses a fixed 20 gwei base fee, so gas fees are static.
        let max_fee_per_gas = options
            .max_fee_per_gas
            .unwrap_or(crate::client::tempo::MAX_FEE_PER_GAS);
        let max_priority_fee_per_gas = options
            .max_priority_fee_per_gas
            .unwrap_or(crate::client::tempo::MAX_PRIORITY_FEE_PER_GAS);

        let nonce = options.nonce.unwrap_or(0);
        let nonce_key = options.nonce_key.unwrap_or(EXPIRING_NONCE_KEY);
        let valid_before = Some(resolve_valid_before(&self.challenge, options.valid_before));

        let gas_limit = if let Some(gas) = options.gas_limit {
            gas
        } else if self.fee_payer {
            // In fee-payer mode the client may not hold native gas, so
            // eth_estimateGas would revert. Use a safe default; the server
            // co-signs and pays for gas.
            1_000_000
        } else {
            let mut req = TempoTransactionRequest {
                calls: calls.clone(),
                key_authorization: key_authorization.clone(),
                ..Default::default()
            }
            .with_fee_token(fee_token)
            .with_nonce_key(nonce_key);

            if let Some(vb) = valid_before.and_then(NonZeroU64::new) {
                req = req.with_valid_before(vb);
            }

            req.inner.from = Some(from);
            req.inner.chain_id = Some(self.chain_id);
            req.inner.nonce = Some(nonce);
            req.inner.max_fee_per_gas = Some(max_fee_per_gas);
            req.inner.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
            apply_estimation_signer_hints(&mut req, &signing_mode, signer_address, signature_type);

            estimate_gas(provider, req).await?
        };

        // Build the key_authorization for the transaction
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
            key_authorization,
        });

        Ok(PreparedTempoCharge {
            challenge: self.challenge,
            chain_id: self.chain_id,
            fee_payer: self.fee_payer,
            from,
            signing_mode,
            transaction: Some(tx),
        })
    }
}

struct PreparedTempoCharge {
    challenge: PaymentChallenge,
    chain_id: u64,
    fee_payer: bool,
    from: Address,
    signing_mode: TempoSigningMode,
    transaction: Option<TempoTransaction>,
}

impl PreparedTempoCharge {
    async fn sign_secp256k1(
        mut self,
        signer: &(impl alloy::signers::Signer + Clone),
    ) -> Result<SignedTempoCharge, MppError> {
        let Some(transaction) = self.transaction.take() else {
            let signature = match &self.signing_mode {
                TempoSigningMode::Direct => {
                    proof::sign_proof(
                        signer,
                        self.from,
                        self.chain_id,
                        &self.challenge.id,
                        &self.challenge.realm,
                    )
                    .await?
                }
                mode => {
                    let hash = effective_signing_hash(self.proof_hash(), mode);
                    let inner = signer
                        .sign_hash(&hash)
                        .await
                        .mpp_http("failed to sign proof")?;
                    alloy::hex::encode_prefixed(build_tempo_signature(inner, mode).to_bytes())
                }
            };
            return Ok(self.proof(signature));
        };
        let valid_before = transaction.valid_before.map(NonZeroU64::get);
        self.ensure_sponsorable(valid_before)?;
        let tx_bytes = if self.fee_payer {
            sign_and_encode_fee_payer_envelope_async(transaction, signer, &self.signing_mode)
                .await?
        } else {
            sign_and_encode_async(transaction, signer, &self.signing_mode).await?
        };
        // A slow signer (hardware wallet, KMS) can use up the window: re-check
        // so a credential the fee payer would refuse is never returned.
        self.ensure_sponsorable(valid_before)?;
        Ok(self.transaction(tx_bytes))
    }

    async fn sign_primitive(
        mut self,
        signer: &TempoPrimitiveSigner,
    ) -> Result<SignedTempoCharge, MppError> {
        let Some(transaction) = self.transaction.take() else {
            let hash = effective_signing_hash(self.proof_hash(), &self.signing_mode);
            let inner = alloy::signers::Signer::sign_hash(signer, &hash)
                .await
                .mpp_http("failed to sign proof")?;
            let signature = alloy::hex::encode_prefixed(
                build_tempo_signature_primitive(inner, &self.signing_mode).to_bytes(),
            );
            return Ok(self.proof(signature));
        };
        let valid_before = transaction.valid_before.map(NonZeroU64::get);
        self.ensure_sponsorable(valid_before)?;
        let tx_bytes = if self.fee_payer {
            sign_and_encode_fee_payer_envelope_primitive_async(
                transaction,
                signer,
                &self.signing_mode,
            )
            .await?
        } else {
            sign_and_encode_primitive_async(transaction, signer, &self.signing_mode).await?
        };
        // A slow signer (hardware wallet, KMS) can use up the window: re-check
        // so a credential the fee payer would refuse is never returned.
        self.ensure_sponsorable(valid_before)?;
        Ok(self.transaction(tx_bytes))
    }

    /// The EIP-712 digest of this zero-amount charge's proof, bound to the
    /// paying account (the wallet, for an access key).
    fn proof_hash(&self) -> alloy::primitives::B256 {
        proof::signing_hash(
            self.from,
            self.chain_id,
            &self.challenge.id,
            &self.challenge.realm,
        )
    }

    /// Wrap a proof signature as a credential. An access key's proof is a
    /// Keychain envelope naming the wallet, as viem's access-key accounts sign
    /// it in mppx.
    fn proof(self, signature: String) -> SignedTempoCharge {
        let credential = PaymentCredential::with_source(
            self.challenge.to_echo(),
            proof::proof_source(self.from, self.chain_id),
            PaymentPayload::proof(signature),
        );
        SignedTempoCharge {
            credential,
            tx_bytes: None,
            chain_id: self.chain_id,
            from: self.from,
            authorization_reservation: None,
        }
    }

    fn ensure_sponsorable(&self, valid_before: Option<u64>) -> Result<(), MppError> {
        if !self.fee_payer {
            return Ok(());
        }
        ensure_sponsorable_before_signing(
            &self.challenge,
            valid_before,
            time::OffsetDateTime::now_utc(),
        )
    }

    fn transaction(self, tx_bytes: Vec<u8>) -> SignedTempoCharge {
        let credential =
            build_charge_credential(&self.challenge, &tx_bytes, self.chain_id, self.from);
        SignedTempoCharge {
            credential,
            tx_bytes: Some(tx_bytes),
            chain_id: self.chain_id,
            from: self.from,
            authorization_reservation: None,
        }
    }
}

/// Options for controlling the signing pipeline.
///
/// Power users set these to override the defaults (nonce, gas, signing
/// mode, etc.). All fields are optional — unset fields use the defaults
/// documented on each field.
///
/// By default a charge is signed with an expiring nonce (`nonce_key` =
/// `U256::MAX`, `nonce` = 0, `valid_before` = now + 25 seconds) and Tempo's
/// static gas fees, so neither the account nonce nor the base fee is fetched.
#[derive(Debug, Clone, Default)]
pub struct SignOptions {
    /// Override the RPC URL (otherwise resolved from chain_id).
    pub rpc_url: Option<String>,
    /// Override the transaction nonce (default: `0`).
    ///
    /// The nonce is never fetched from the RPC. `0` is right for the default
    /// expiring nonce key and for the first transaction on an unused 2D nonce
    /// lane. For a [`nonce_key`](Self::nonce_key) that has been used before,
    /// including the protocol nonce (key `0`), set the lane's current nonce
    /// here or the transaction is rejected.
    pub nonce: Option<u64>,
    /// Override the nonce key (default: `U256::MAX`, the expiring nonce key).
    ///
    /// Any other key selects a sequential nonce: `U256::ZERO` is the protocol
    /// nonce and every other value a 2D nonce lane. Set [`nonce`](Self::nonce)
    /// along with it, since the lane's current nonce is not looked up.
    pub nonce_key: Option<U256>,
    /// Override the gas limit (otherwise estimated via `eth_estimateGas`, or
    /// a fixed 1,000,000 for fee-sponsored charges, which are not estimated).
    pub gas_limit: Option<u64>,
    /// Override max fee per gas in wei (default:
    /// [`MAX_FEE_PER_GAS`](crate::client::tempo::MAX_FEE_PER_GAS), 41 gwei).
    pub max_fee_per_gas: Option<u128>,
    /// Override max priority fee per gas in wei (default:
    /// [`MAX_PRIORITY_FEE_PER_GAS`](crate::client::tempo::MAX_PRIORITY_FEE_PER_GAS),
    /// 1 gwei).
    pub max_priority_fee_per_gas: Option<u128>,
    /// Override the fee token address (default: the charge currency). Unused
    /// for fee-sponsored charges, where the server chooses the fee token.
    pub fee_token: Option<Address>,
    /// Override the signing mode (default: [`TempoSigningMode::Direct`]).
    pub signing_mode: Option<TempoSigningMode>,
    /// Provide a key authorization to include in the transaction.
    pub key_authorization: Option<Box<SignedKeyAuthorization>>,
    /// Override the transaction's `validBefore` as a unix timestamp (default:
    /// 25 seconds from now). Applies to every charge, fee-sponsored or not.
    pub valid_before: Option<u64>,
}

/// A signed Tempo charge, ready to be converted into a [`PaymentCredential`].
#[derive(Debug)]
pub struct SignedTempoCharge {
    credential: PaymentCredential,
    tx_bytes: Option<Vec<u8>>,
    chain_id: u64,
    from: Address,
    authorization_reservation: Option<TempoAuthorizationReservation>,
}

/// Whether a failed `eth_sendRawTransactionSync` proves the node never
/// accepted the transaction. EIP-7966's code 4 (pooled, not yet confirmed) and
/// "already known" come after the pool took it, so they are not refusals, and
/// neither is a transport failure.
fn push_refused(error: &alloy::transports::TransportError) -> bool {
    let Some(response) = error.as_error_resp() else {
        return false;
    };
    let message = response.message.to_ascii_lowercase();
    response.code != 4
        && !message.contains("already known")
        && !message.contains("alreadyknown")
        && !message.contains("known transaction")
}

/// A failed push broadcast. `rejected` is true only when the node answered
/// with an error, so the transaction cannot have been included.
struct PushError {
    error: MppError,
    rejected: bool,
}

impl SignedTempoCharge {
    /// Broadcast a `push` payment's transaction and answer with its hash, as
    /// mppx's client does: `{ type: "hash", hash }` with the payer as source.
    async fn pushed(
        self,
        challenge: &PaymentChallenge,
        provider: &impl Provider<tempo_alloy::TempoNetwork>,
    ) -> Result<Self, MppError> {
        self.push(challenge, provider)
            .await
            .map_err(|error| error.error)
    }

    async fn push(
        mut self,
        challenge: &PaymentChallenge,
        provider: &impl Provider<tempo_alloy::TempoNetwork>,
    ) -> Result<Self, PushError> {
        let Some(tx_bytes) = &self.tx_bytes else {
            return Ok(self);
        };
        let receipt: serde_json::Value = provider
            .raw_request(
                "eth_sendRawTransactionSync".into(),
                [alloy::hex::encode_prefixed(tx_bytes)],
            )
            .await
            .map_err(|error| PushError {
                rejected: push_refused(&error),
                error: MppError::Http(format!("failed to broadcast push payment: {error}")),
            })?;
        let hash = receipt
            .get("transactionHash")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| PushError {
                rejected: false,
                error: MppError::Http("No transaction receipt returned.".into()),
            })?;
        if receipt.get("status").and_then(serde_json::Value::as_str) != Some("0x1") {
            return Err(PushError {
                rejected: false,
                error: MppError::Http(format!("push payment transaction {hash} reverted")),
            });
        }
        self.credential = PaymentCredential::with_source(
            challenge.to_echo(),
            PaymentCredential::evm_did(self.chain_id, &self.from.to_string()),
            PaymentPayload::hash(hash),
        );
        Ok(self)
    }

    /// Convert the signed charge into a [`PaymentCredential`].
    pub fn into_credential(self) -> PaymentCredential {
        self.credential
    }

    /// Get the raw signed transaction bytes.
    pub fn tx_bytes(&self) -> &[u8] {
        self.tx_bytes.as_deref().unwrap_or(&[])
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Get the `from` address used for signing.
    pub fn from_address(&self) -> Address {
        self.from
    }

    pub(crate) fn authorization_reservation(&self) -> Option<TempoAuthorizationReservation> {
        self.authorization_reservation
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

    fn mocked_provider(
        asserter: alloy::providers::mock::Asserter,
    ) -> impl Provider<tempo_alloy::TempoNetwork> {
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter)
    }

    fn balance(amount: u64) -> alloy::primitives::Bytes {
        alloy::primitives::Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(&U256::from(
            amount,
        )))
    }

    #[tokio::test]
    async fn test_mach_charge_pays_gas_in_funded_stablecoin() {
        use crate::protocol::methods::tempo::machine_token::MACH;
        let asserter = alloy::providers::mock::Asserter::new();
        asserter.push_success(&balance(0));
        asserter.push_success(&balance(5));
        let provider = mocked_provider(asserter);
        let usdc: Address = crate::protocol::methods::tempo::DEFAULT_CURRENCY_MAINNET
            .parse()
            .unwrap();

        let token = resolve_fee_token(
            None,
            MACH,
            true,
            false,
            CHAIN_ID,
            &provider,
            Address::repeat_byte(1),
        )
        .await;

        assert_eq!(token, usdc);
    }

    #[tokio::test]
    async fn test_mach_charge_falls_back_to_path_usd_gas() {
        use crate::protocol::methods::tempo::machine_token::MACH;
        let asserter = alloy::providers::mock::Asserter::new();
        asserter.push_success(&balance(0));
        asserter.push_success(&balance(0));
        let provider = mocked_provider(asserter);
        let path_usd: Address = crate::protocol::methods::tempo::PATH_USD.parse().unwrap();

        let token = resolve_fee_token(
            None,
            MACH,
            true,
            false,
            CHAIN_ID,
            &provider,
            Address::repeat_byte(1),
        )
        .await;

        assert_eq!(token, path_usd);
    }

    #[test]
    fn test_pays_in_machine_token_on_canonical_deployments_only() {
        use crate::protocol::methods::tempo::machine_token::MACH;
        let charge = |currency: Address, chain_id: u64| {
            let request = Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000000",
                "currency": currency.to_string(),
                "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                "methodDetails": { "chainId": chain_id }
            }))
            .unwrap();
            TempoCharge::from_challenge(&PaymentChallenge::new(
                "id",
                "api.example.com",
                "tempo",
                "charge",
                request,
            ))
            .unwrap()
        };
        let usdc: Address = crate::protocol::methods::tempo::DEFAULT_CURRENCY_MAINNET
            .parse()
            .unwrap();
        let approve_mach = Call {
            to: TxKind::Call(MACH),
            value: U256::ZERO,
            input: Default::default(),
        };

        assert!(charge(MACH, CHAIN_ID).pays_in_machine_token());
        // The same address on a chain without a canonical deployment is not MACH.
        assert!(!charge(MACH, 1337).pays_in_machine_token());
        assert!(!charge(usdc, CHAIN_ID).pays_in_machine_token());
        // A MACH swapper route funds a USDC.e charge with MACH.
        assert!(charge(usdc, CHAIN_ID)
            .with_calls(vec![approve_mach.clone()])
            .pays_in_machine_token());
        assert!(!charge(usdc, 1337)
            .with_calls(vec![approve_mach])
            .pays_in_machine_token());
    }

    #[tokio::test]
    async fn test_fee_token_skips_lookup_unless_unsponsored_mach() {
        use crate::protocol::methods::tempo::machine_token::MACH;
        // No mocked responses: any RPC call would fail the lookup.
        let provider = mocked_provider(alloy::providers::mock::Asserter::new());
        let usdc: Address = crate::protocol::methods::tempo::DEFAULT_CURRENCY_MAINNET
            .parse()
            .unwrap();
        let from = Address::repeat_byte(1);
        let explicit = Address::repeat_byte(0x33);

        assert_eq!(
            resolve_fee_token(None, usdc, false, false, CHAIN_ID, &provider, from).await,
            usdc
        );
        assert_eq!(
            resolve_fee_token(Some(explicit), MACH, true, false, CHAIN_ID, &provider, from).await,
            explicit
        );
        assert_eq!(
            resolve_fee_token(None, MACH, true, true, CHAIN_ID, &provider, from).await,
            MACH
        );
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
    fn test_from_challenge_generates_bound_memo() {
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

        assert_eq!(
            charge.memo(),
            Some(crate::tempo::attribution::encode(
                "test-id",
                "api.example.com",
                None
            ))
        );
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
    fn estimation_hints_direct_signature_type_without_key_id() {
        let signer = Address::repeat_byte(0x11);
        let mut request = TempoTransactionRequest::default();

        apply_estimation_signer_hints(
            &mut request,
            &TempoSigningMode::Direct,
            signer,
            SignatureType::Secp256k1,
        );

        assert_eq!(request.key_type, Some(SignatureType::Secp256k1));
        assert_eq!(request.key_id, None);
    }

    #[test]
    fn estimation_hints_keychain_p256_access_key() {
        use crate::client::tempo::signing::KeychainVersion;

        let signer = Address::repeat_byte(0x11);
        let wallet = Address::repeat_byte(0x22);
        let mode = TempoSigningMode::Keychain {
            wallet,
            version: KeychainVersion::V2,
            key_authorization: None,
        };
        let mut request = TempoTransactionRequest::default();

        apply_estimation_signer_hints(&mut request, &mode, signer, SignatureType::P256);

        assert_eq!(request.key_type, Some(SignatureType::P256));
        assert_eq!(request.key_id, Some(signer));
    }

    #[test]
    fn test_signed_charge_into_credential() {
        let challenge = test_challenge();
        let from: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
            .parse()
            .unwrap();
        let credential = build_charge_credential(&challenge, &[0x76, 0xab, 0xcd], 42431, from);
        let signed = SignedTempoCharge {
            credential,
            tx_bytes: Some(vec![0x76, 0xab, 0xcd]),
            chain_id: 42431,
            from,
            authorization_reservation: None,
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
        let credential = build_charge_credential(&challenge, &[0x76], 4217, from);
        let signed = SignedTempoCharge {
            credential,
            tx_bytes: Some(vec![0x76]),
            chain_id: 4217,
            from,
            authorization_reservation: None,
        };

        assert_eq!(signed.tx_bytes(), &[0x76]);
        assert_eq!(signed.chain_id(), 4217);
        assert_eq!(signed.from_address(), from);
    }

    #[test]
    fn test_from_challenge_with_splits() {
        let request_json = serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": {
                "chainId": 42431,
                "splits": [
                    {
                        "amount": "300000",
                        "recipient": "0x1111111111111111111111111111111111111111"
                    },
                    {
                        "amount": "200000",
                        "recipient": "0x2222222222222222222222222222222222222222",
                        "memo": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                    }
                ]
            }
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let challenge =
            PaymentChallenge::new("test-id", "api.example.com", "tempo", "charge", request);
        let charge = TempoCharge::from_challenge(&challenge).unwrap();

        assert!(charge.splits().is_some());
        assert_eq!(charge.splits().unwrap().len(), 2);
        assert_eq!(charge.amount(), U256::from(1_000_000u64));
    }

    #[test]
    fn test_build_transfer_calls_with_splits() {
        let request_json = serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": {
                "chainId": 42431,
                "splits": [
                    {
                        "amount": "300000",
                        "recipient": "0x1111111111111111111111111111111111111111"
                    }
                ]
            }
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let challenge =
            PaymentChallenge::new("test-id", "api.example.com", "tempo", "charge", request);
        let charge = TempoCharge::from_challenge(&challenge).unwrap();

        let calls = charge.build_transfer_calls().unwrap();
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn test_build_transfer_calls_no_splits() {
        let challenge = test_challenge();
        let charge = TempoCharge::from_challenge(&challenge).unwrap();

        let calls = charge.build_transfer_calls().unwrap();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn test_from_challenge_honours_supported_modes() {
        use serde_json::json;

        let cases = [
            ("1000000", json!(null), true),
            ("1000000", json!(["pull"]), true),
            ("1000000", json!(["push", "pull"]), true),
            ("1000000", json!(["push"]), true),
            ("1000000", json!([]), false),
            ("1000000", json!("pull"), false),
            // Zero-amount charges are answered with a proof, which has no mode.
            ("0", json!(["push"]), true),
        ];

        for (amount, supported_modes, payable) in cases {
            let request = Base64UrlJson::from_value(&json!({
                "amount": amount,
                "currency": "0x20c0000000000000000000000000000000000000",
                "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                "methodDetails": { "chainId": 42431, "supportedModes": supported_modes },
            }))
            .unwrap();
            let challenge =
                PaymentChallenge::new("test-id", "api.example.com", "tempo", "charge", request);

            let result = TempoCharge::from_challenge(&challenge);
            assert_eq!(
                result.is_ok(),
                payable,
                "amount {amount}, supportedModes {supported_modes}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_valid_before_is_capped_at_challenge_expires() {
        use alloy::eips::Decodable2718;
        use tempo_alloy::primitives::transaction::AASigned;

        let signer = alloy::signers::local::PrivateKeySigner::random();
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;

        // `Some(0)` asks for no `validBefore` at all.
        let challenge = test_challenge().with_expires(crate::expires::seconds(5));
        let expires = challenge.expires_at().unwrap().unix_timestamp() as u64;
        assert_eq!(resolve_valid_before(&challenge, Some(0)), expires + 1);

        // (seconds until `expires`, explicit `valid_before` offset from now)
        let cases = [(5, None), (5, Some(600)), (3600, None), (3600, Some(600))];

        for (expires_in, explicit) in cases {
            let challenge = test_challenge().with_expires(crate::expires::seconds(expires_in));
            let expires = challenge.expires_at().unwrap().unix_timestamp() as u64;
            // An explicit gas limit keeps signing off the RPC.
            let options = SignOptions {
                gas_limit: Some(100_000),
                valid_before: explicit.map(|offset| now + offset),
                ..Default::default()
            };

            let signed = TempoCharge::from_challenge(&challenge)
                .unwrap()
                .sign_with_options(&signer, options)
                .await
                .unwrap();
            let tx = AASigned::decode_2718(&mut signed.tx_bytes()).unwrap();
            let valid_before = tx.tx().valid_before.unwrap().get();

            assert!(
                valid_before <= expires + 1,
                "expires in {expires_in}s, explicit {explicit:?}: validBefore is {}s past expires",
                valid_before.saturating_sub(expires)
            );
            if expires_in == 3600 {
                let requested = explicit.unwrap_or(EXPIRING_NONCE_VALID_BEFORE_SECS);
                assert!((now + requested..=now + requested + 5).contains(&valid_before));
            }
        }
    }

    #[test]
    fn test_valid_before_caps_at_second_after_challenge_expires() {
        // 2027-01-15T08:00:00Z
        const BASE: u64 = 1_800_000_000;
        let at = |minutes_seconds: &str| format!("2027-01-15T08:{minutes_seconds}Z");

        // (label, now, challenge expires, expected validBefore)
        let cases = [
            ("no challenge expiry", BASE, None, BASE + 25),
            (
                "expiry after the window",
                BASE,
                Some(at("01:00")),
                BASE + 25,
            ),
            (
                "expiry inside the window",
                BASE,
                Some(at("00:10")),
                BASE + 11,
            ),
            ("fractional expiry", BASE, Some(at("00:10.5")), BASE + 11),
            ("sub-second expiry", BASE, Some(at("00:00.5")), BASE + 1),
            (
                "whole-second expiry is now",
                BASE,
                Some(at("00:00")),
                BASE + 1,
            ),
            ("millisecond expiry", BASE, Some(at("00:00.999")), BASE + 1),
        ];

        for (label, now, expires, expected) in cases {
            let mut challenge = test_challenge();
            if let Some(expires) = expires {
                challenge = challenge.with_expires(expires);
            }
            let valid_before = resolve_valid_before_at(&challenge, None, now);
            assert_eq!(valid_before, expected, "{label}");
            // Still valid at signing time, even when the challenge expires this second.
            assert!(valid_before > now, "{label}");
        }
    }

    fn sponsored_challenge(expires_in: u64) -> PaymentChallenge {
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "1000000",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": { "chainId": 42431, "feePayer": true },
        }))
        .unwrap();
        PaymentChallenge::new("test-id", "api.example.com", "tempo", "charge", request)
            .with_expires(crate::expires::seconds(expires_in))
    }

    async fn sign_valid_before(challenge: &PaymentChallenge) -> Result<u64, MppError> {
        use alloy::eips::Decodable2718;
        use tempo_alloy::primitives::transaction::AASigned;

        let signer = alloy::signers::local::PrivateKeySigner::random();
        let options = SignOptions {
            gas_limit: Some(100_000),
            ..Default::default()
        };
        let signed = TempoCharge::from_challenge(challenge)?
            .sign_with_options(&signer, options)
            .await?;
        let tx_bytes = signed.tx_bytes();
        // A sponsored credential is a fee-payer envelope; unsponsored is 2718.
        let valid_before = match AASigned::decode_2718(&mut &tx_bytes[..]) {
            Ok(tx) => tx.tx().valid_before,
            Err(_) => {
                crate::protocol::methods::tempo::FeePayerEnvelope78::decode_envelope(tx_bytes)
                    .unwrap()
                    .valid_before
                    .and_then(NonZeroU64::new)
            }
        };
        Ok(valid_before.expect("charge sets validBefore").get())
    }

    #[test]
    fn test_default_valid_before_window_is_25_seconds() {
        assert_eq!(EXPIRING_NONCE_VALID_BEFORE_SECS, 25);
        let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
        for challenge in [
            test_challenge(),
            test_challenge().with_expires(crate::expires::seconds(3600)),
            sponsored_challenge(3600),
        ] {
            let valid_before = resolve_valid_before(&challenge, None);
            assert!(
                (now + 25..=now + 26).contains(&valid_before),
                "validBefore {valid_before} is not now ({now}) + 25s"
            );
        }
    }

    #[tokio::test]
    async fn test_sponsored_valid_before_is_capped_at_challenge_expires() {
        let challenge = sponsored_challenge(20);
        let expires = challenge.expires_at().unwrap().unix_timestamp() as u64;
        // Capped at the second after the challenge expiry, as in mppx.
        assert_eq!(resolve_valid_before(&challenge, None), expires + 1);
        assert_eq!(sign_valid_before(&challenge).await.unwrap(), expires + 1);
    }

    #[tokio::test]
    async fn test_sponsored_challenge_expiring_within_floor_is_refused() {
        for expires_in in [5, 14] {
            let challenge = sponsored_challenge(expires_in);
            let error = sign_valid_before(&challenge).await.unwrap_err();
            assert!(
                matches!(error, MppError::BadRequest(_)),
                "expires in {expires_in}s: {error:?}"
            );
            assert!(
                error
                    .to_string()
                    .contains("fee-sponsored challenge expires in"),
                "{error}"
            );
        }

        // Sponsored with room left still signs; unsponsored keeps signing
        // short-lived challenges, capped at the second after their expiry.
        sign_valid_before(&sponsored_challenge(20)).await.unwrap();
        let unsponsored = test_challenge().with_expires(crate::expires::seconds(5));
        let expires = unsponsored.expires_at().unwrap().unix_timestamp() as u64;
        assert_eq!(sign_valid_before(&unsponsored).await.unwrap(), expires + 1);
    }
    #[tokio::test]
    async fn test_sponsored_valid_before_within_floor_is_refused_before_signing() {
        // The fee payer enforces the floor on the signed validBefore, which is
        // fixed before preparation: a slow preparation must not sign it.
        let challenge = sponsored_challenge(300);
        let now = time::OffsetDateTime::from_unix_timestamp(
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .unwrap();
        // Like the fee payer, a fractional `now` rounds up to the next second:
        // floor(now) + 15 is refused just after a whole second.
        let fractional = now + time::Duration::nanoseconds(1);
        let at_floor = (now.unix_timestamp() + 15) as u64;
        assert!(ensure_sponsorable_before_signing(&challenge, Some(at_floor), fractional).is_err());
        ensure_sponsorable_before_signing(&challenge, Some(at_floor + 1), fractional).unwrap();
        let at = |secs: i64| (now.unix_timestamp() + secs) as u64;
        let error = ensure_sponsorable_before_signing(&challenge, Some(at(14)), now).unwrap_err();
        assert!(matches!(error, MppError::BadRequest(_)), "{error:?}");
        assert!(
            error.to_string().contains("preparation took too long"),
            "{error}"
        );
        ensure_sponsorable_before_signing(&challenge, Some(at(15)), now).unwrap();
        ensure_sponsorable_before_signing(&challenge, None, now).unwrap();
        // The challenge expiry floor still applies at signing time.
        let error = ensure_sponsorable_before_signing(
            &challenge,
            Some(at(60)),
            now + time::Duration::seconds(290),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fee-sponsored challenge expires in"),
            "{error}"
        );

        let options = SignOptions {
            valid_before: Some(at(10)),
            ..Default::default()
        };
        let signer: alloy::signers::local::PrivateKeySigner =
            "0x1234567890123456789012345678901234567890123456789012345678901234"
                .parse()
                .unwrap();
        let error = TempoCharge::from_challenge(&challenge)
            .unwrap()
            .sign_with_options(&signer, options)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("preparation took too long"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn test_zero_amount_sign_returns_proof_credential() {
        let request_json = serde_json::json!({
            "amount": "0",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": {
                "chainId": 42431
            }
        });
        let request = Base64UrlJson::from_value(&request_json).unwrap();
        let challenge =
            PaymentChallenge::new("proof-id", "api.example.com", "tempo", "charge", request);
        let signer: alloy::signers::local::PrivateKeySigner =
            "0x1234567890123456789012345678901234567890123456789012345678901234"
                .parse()
                .unwrap();

        let charge = TempoCharge::from_challenge(&challenge).unwrap();
        let signed = charge
            .sign_with_options(&signer, SignOptions::default())
            .await
            .unwrap();
        let credential = signed.into_credential();
        let payload: PaymentPayload = credential.payload_as().unwrap();
        let expected_did = PaymentCredential::evm_did(42431, &signer.address().to_string());

        assert!(payload.is_proof());
        assert!(payload.proof_signature().unwrap().starts_with("0x"));
        assert_eq!(credential.source.as_deref(), Some(expected_did.as_str()));
    }
}
