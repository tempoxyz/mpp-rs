//! Tempo session payment provider.
//!
//! Implements `PaymentProvider` for the session intent, providing automatic
//! channel lifecycle management: open on first request, voucher on subsequent
//! requests, cumulative amount tracking, and channel recovery from on-chain state.
//!
//! Ported from the TypeScript SDK's `Session.ts`.

pub mod channel_ops;
pub mod recovery;
pub mod store;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy::{
    primitives::{Address, B256},
    signers::Signer,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use self::channel_ops::{
    build_credential, create_close_payload, create_open_payload,
    create_precompile_close_payload_with_descriptor_primitive, create_precompile_open_payload,
    create_precompile_top_up_transaction_payload,
    create_precompile_voucher_payload_with_descriptor_primitive, create_voucher_payload,
    is_precompile_escrow, resolve_chain_id, resolve_escrow, try_recover_channel, ChannelEntry,
    OpenPayloadOptions, OpenPrecompilePayloadOptions, TopUpPrecompilePayloadOptions,
};
use self::recovery::{
    hydrate_session_snapshot, read_on_chain_channel_state, recover_stored_channel, RecoveryScope,
};
use self::store::{
    channel_key as persistent_channel_key, ChannelStore, MemoryChannelStore, StoredChannelEntry,
};
use super::signing::TempoPrimitiveSigner;
use crate::client::PaymentProvider;
use crate::error::{MppError, ResultExt};
use crate::protocol::core::{PaymentChallenge, PaymentCredential, Receipt};
use crate::protocol::intents::{ChargeRequest, SessionRequest};
use crate::protocol::methods::tempo::proof::sign_proof_primitive;
use crate::protocol::methods::tempo::session::TempoSessionExt;

/// Tempo session provider with automatic channel management.
///
/// Manages the full channel lifecycle (open, voucher, close) automatically.
/// Channels are tracked in an internal registry keyed by `payee:currency:escrow`.
///
/// # Examples
///
/// ```ignore
/// use mpp::client::TempoSessionProvider;
/// use mpp::PrivateKeySigner;
///
/// let signer = PrivateKeySigner::random();
/// let provider = TempoSessionProvider::new(
///     signer,
///     "https://rpc.moderato.tempo.xyz",
/// )?;
///
/// // First call opens a channel, subsequent calls send vouchers
/// let credential = provider.pay(&challenge).await?;
/// ```
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct TempoSessionProvider {
    signer: TempoPrimitiveSigner,
    rpc_url: reqwest::Url,
    /// Escrow contract address override. If None, resolved from challenge or defaults.
    escrow_contract: Option<Address>,
    /// Address authorized to sign vouchers. Defaults to signer address.
    authorized_signer: Option<Address>,
    /// Signing mode (direct or keychain).
    signing_mode: crate::client::tempo::signing::TempoSigningMode,
    /// Maximum deposit in atomic units. Caps the server's `suggestedDeposit`.
    max_deposit: Option<u128>,
    /// Default deposit in atomic units when no suggestedDeposit is available.
    default_deposit: Option<u128>,
    /// Channel registry: key is `payee:currency:escrow` (lowercase).
    channels: Arc<Mutex<HashMap<String, ChannelEntry>>>,
    /// Durable channel view. Recovery policy remains owned by this provider.
    channel_store: Arc<dyn ChannelStore>,
    /// Maps channel ID hex → channel key for reverse lookup.
    channel_id_to_key: Arc<Mutex<HashMap<String, String>>>,
    /// Optional callback for channel state changes.
    on_channel_update: Option<Arc<dyn Fn(&ChannelEntry) + Send + Sync>>,
    /// Last challenge received from the server, used for `close()`.
    last_challenge: Arc<Mutex<Option<PaymentChallenge>>>,
}

impl TempoSessionProvider {
    /// Create a new Tempo session provider.
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
            escrow_contract: None,
            authorized_signer: None,
            signing_mode: crate::client::tempo::signing::TempoSigningMode::Direct,
            max_deposit: None,
            default_deposit: None,
            channels: Arc::new(Mutex::new(HashMap::new())),
            channel_store: Arc::new(MemoryChannelStore::default()),
            channel_id_to_key: Arc::new(Mutex::new(HashMap::new())),
            on_channel_update: None,
            last_challenge: Arc::new(Mutex::new(None)),
        })
    }

    /// Set the escrow contract address override.
    pub fn with_escrow_contract(mut self, addr: Address) -> Self {
        self.escrow_contract = Some(addr);
        self
    }

    /// Set the authorized signer address (for delegated voucher signing).
    pub fn with_authorized_signer(mut self, addr: Address) -> Self {
        self.authorized_signer = Some(addr);
        self
    }

    /// Set the signing mode (direct or keychain).
    ///
    /// Default is [`TempoSigningMode::Direct`].
    pub fn with_signing_mode(
        mut self,
        mode: crate::client::tempo::signing::TempoSigningMode,
    ) -> Self {
        self.signing_mode = mode;
        self
    }

    /// Set the maximum deposit in atomic units.
    pub fn with_max_deposit(mut self, amount: u128) -> Self {
        self.max_deposit = Some(amount);
        self
    }

    /// Set the default deposit in atomic units.
    pub fn with_default_deposit(mut self, amount: u128) -> Self {
        self.default_deposit = Some(amount);
        self
    }

    /// Persist reusable native MPP channels in `store`.
    ///
    /// The store is only a cache. Every restored channel is checked against
    /// its descriptor, the active challenge, and current on-chain state.
    pub fn with_channel_store(mut self, store: Arc<dyn ChannelStore>) -> Self {
        self.channel_store = store;
        self
    }

    /// Set a callback for channel state changes.
    pub fn with_on_channel_update(
        mut self,
        callback: impl Fn(&ChannelEntry) + Send + Sync + 'static,
    ) -> Self {
        self.on_channel_update = Some(Arc::new(callback));
        self
    }

    /// Get a reference to the signer.
    pub fn signer(&self) -> &TempoPrimitiveSigner {
        &self.signer
    }

    fn secp256k1_signer(&self) -> Result<&alloy::signers::local::PrivateKeySigner, MppError> {
        match &self.signer {
            TempoPrimitiveSigner::Secp256k1(signer) => Ok(signer),
            TempoPrimitiveSigner::P256(_) => Err(MppError::InvalidConfig(
                "P-256 session keys require the native TIP-1034 precompile".into(),
            )),
        }
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &reqwest::Url {
        &self.rpc_url
    }

    /// Get a snapshot of the current channel registry.
    pub fn channels(&self) -> HashMap<String, ChannelEntry> {
        self.channels.lock().unwrap().clone()
    }

    fn notify_update(&self, entry: &ChannelEntry) {
        if let Some(ref cb) = self.on_channel_update {
            cb(entry);
        }
    }

    fn assert_within_max_deposit(&self, cumulative_amount: u128) -> Result<(), MppError> {
        if let Some(max_deposit) = self.max_deposit {
            if cumulative_amount > max_deposit {
                return Err(MppError::InvalidConfig(format!(
                    "requested voucher amount {cumulative_amount} exceeds local max_deposit \
                     {max_deposit}"
                )));
            }
        }
        Ok(())
    }

    fn required_top_up(
        &self,
        required_cumulative: u128,
        deposit: u128,
    ) -> Result<Option<u128>, MppError> {
        self.assert_within_max_deposit(required_cumulative)?;
        Ok(required_cumulative
            .checked_sub(deposit)
            .filter(|additional| *additional > 0))
    }

    fn store_error(error: self::store::ChannelStoreError) -> MppError {
        MppError::InvalidConfig(format!("channel store failed: {error}"))
    }

    fn stored_entry(entry: &ChannelEntry) -> Result<StoredChannelEntry, MppError> {
        let descriptor = entry.descriptor.clone().ok_or_else(|| {
            MppError::InvalidConfig("native MPP channel is missing its descriptor".into())
        })?;
        Ok(StoredChannelEntry {
            channel_id: entry.channel_id,
            cumulative_amount: entry.cumulative_amount,
            deposit: entry.deposit,
            descriptor,
            escrow: entry.escrow_contract,
            chain_id: entry.chain_id,
            opened: entry.opened,
        })
    }

    async fn persist_channel(&self, entry: &ChannelEntry) -> Result<(), MppError> {
        if !is_precompile_escrow(entry.escrow_contract) {
            return Ok(());
        }
        self.channel_store
            .set(&Self::stored_entry(entry)?)
            .await
            .map_err(Self::store_error)
    }

    fn channel_entry(entry: StoredChannelEntry) -> Result<ChannelEntry, MppError> {
        let salt = entry.descriptor.salt.parse().map_err(|error| {
            MppError::InvalidConfig(format!("invalid stored channel salt: {error}"))
        })?;
        Ok(ChannelEntry {
            channel_id: entry.channel_id,
            salt,
            cumulative_amount: entry.cumulative_amount,
            deposit: entry.deposit,
            descriptor: Some(entry.descriptor),
            escrow_contract: entry.escrow,
            chain_id: entry.chain_id,
            opened: entry.opened,
        })
    }

    /// Cache key identifying a channel. Precompile channel ids bind `operator`,
    /// so it is appended for precompile channels; legacy keys are unchanged.
    fn channel_key(
        payee: &Address,
        currency: &Address,
        escrow: &Address,
        operator: Option<Address>,
    ) -> String {
        match operator {
            Some(op) => format!("{:#x}:{:#x}:{:#x}:{:#x}", payee, currency, escrow, op),
            None => format!("{:#x}:{:#x}:{:#x}", payee, currency, escrow),
        }
    }

    /// Operator identity for the cache key: the parsed operator for precompile
    /// escrow, `None` for legacy escrow.
    fn key_operator(
        escrow: &Address,
        session_req: &SessionRequest,
    ) -> Result<Option<Address>, MppError> {
        if is_precompile_escrow(*escrow) {
            Ok(Some(Self::parse_operator(session_req)?))
        } else {
            Ok(None)
        }
    }

    /// Parse `methodDetails.operator` from a precompile session request.
    /// Missing → `Address::ZERO` (payee-only operator).
    fn parse_operator(session_req: &SessionRequest) -> Result<Address, MppError> {
        match session_req
            .method_details
            .as_ref()
            .and_then(|v| v.get("operator"))
        {
            None => Ok(Address::ZERO),
            Some(v) => {
                let s = v.as_str().ok_or_else(|| {
                    MppError::InvalidConfig("methodDetails.operator must be a string".to_string())
                })?;
                s.parse::<Address>()
                    .map_err(|_| MppError::InvalidConfig(format!("invalid operator address: {s}")))
            }
        }
    }

    fn expected_channel_key(
        &self,
        challenge: &PaymentChallenge,
    ) -> Result<(String, u64), MppError> {
        let chain_id = resolve_chain_id(challenge);
        let escrow_contract = resolve_escrow(challenge, chain_id, self.escrow_contract)?;
        let session_req: SessionRequest = challenge
            .request
            .decode()
            .mpp_config("failed to decode session request")?;
        let payee: Address = session_req
            .recipient
            .as_deref()
            .ok_or_else(|| {
                MppError::InvalidConfig("session challenge missing recipient".to_string())
            })?
            .parse()
            .map_err(|_| MppError::InvalidConfig("invalid recipient address".to_string()))?;
        let currency: Address = session_req
            .currency
            .parse()
            .map_err(|_| MppError::InvalidConfig("invalid currency address".to_string()))?;

        let operator = Self::key_operator(&escrow_contract, &session_req)?;

        Ok((
            Self::channel_key(&payee, &currency, &escrow_contract, operator),
            chain_id,
        ))
    }

    async fn restore_precompile_channel<P>(
        &self,
        provider: &P,
        scope: RecoveryScope,
        snapshot: Option<&crate::protocol::methods::tempo::session::SessionSnapshot>,
        request_amount: u128,
    ) -> Result<Option<(ChannelEntry, bool)>, MppError>
    where
        P: alloy::providers::Provider<tempo_alloy::TempoNetwork>,
    {
        let store_key = persistent_channel_key(
            &scope.payee.to_string(),
            &scope.token.to_string(),
            scope.escrow,
            scope.chain_id,
        );
        let stored = self
            .channel_store
            .get(&store_key)
            .await
            .map_err(Self::store_error)?;

        if let Some(snapshot) = snapshot {
            let snapshot_channel_id = snapshot.channel_id.parse().map_err(|error| {
                MppError::InvalidConfig(format!("invalid snapshot channelId: {error}"))
            })?;
            let state = read_on_chain_channel_state(provider, snapshot_channel_id).await?;
            let mut recovered = hydrate_session_snapshot(snapshot, scope, state)?;
            let spent = snapshot.spent.parse::<u128>().map_err(|error| {
                MppError::InvalidConfig(format!("invalid snapshot spent: {error}"))
            })?;
            let request_boundary = spent.checked_add(request_amount).ok_or_else(|| {
                MppError::InvalidConfig("snapshot request cumulative amount overflowed".into())
            })?;
            recovered.cumulative_amount = recovered.cumulative_amount.max(request_boundary);
            if recovered.cumulative_amount > recovered.deposit {
                return Err(MppError::InvalidConfig(
                    "recovered session cumulative amount exceeds channel deposit".into(),
                ));
            }
            if let Some(stored) = stored {
                if stored.channel_id == recovered.channel_id {
                    recovered.cumulative_amount =
                        recovered.cumulative_amount.max(stored.cumulative_amount);
                }
            }
            if recovered.cumulative_amount > recovered.deposit {
                return Err(MppError::InvalidConfig(
                    "recovered session cumulative amount exceeds channel deposit".into(),
                ));
            }
            self.channel_store
                .set(&recovered)
                .await
                .map_err(Self::store_error)?;
            return Self::channel_entry(recovered).map(|entry| Some((entry, true)));
        }

        let Some(stored) = stored else {
            return Ok(None);
        };

        let state = read_on_chain_channel_state(provider, stored.channel_id).await?;
        if state.deposit == 0 || state.close_requested_at != 0 {
            self.channel_store
                .delete(&store_key)
                .await
                .map_err(Self::store_error)?;
            return Ok(None);
        }
        let recovered = recover_stored_channel(stored, scope, state)?;
        self.channel_store
            .set(&recovered)
            .await
            .map_err(Self::store_error)?;
        Self::channel_entry(recovered).map(|entry| Some((entry, false)))
    }

    /// Rehydrate a reusable native session through the server's authenticated
    /// `HEAD` bootstrap flow.
    ///
    /// The first request advertises `tempo/charge`. A supporting server returns
    /// a zero-amount proof challenge, which this provider signs with the same
    /// root/access-key identity used for the session. The authorized response
    /// carries `Payment-Session-Snapshot`; this provider reconciles it with
    /// TIP-1034 on-chain state, persists it, and activates it in memory.
    pub async fn bootstrap(
        &self,
        client: &reqwest::Client,
        url: &str,
    ) -> Result<Option<StoredChannelEntry>, MppError> {
        self.bootstrap_with_headers(client, url, reqwest::header::HeaderMap::new())
            .await
    }

    /// Like [`Self::bootstrap`], preserving caller headers such as routing or
    /// proxy headers on both bootstrap requests.
    pub async fn bootstrap_with_headers(
        &self,
        client: &reqwest::Client,
        url: &str,
        mut headers: reqwest::header::HeaderMap,
    ) -> Result<Option<StoredChannelEntry>, MppError> {
        use alloy::providers::ProviderBuilder;
        use reqwest::header::{HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
        use tempo_alloy::TempoNetwork;

        headers.insert(
            crate::protocol::core::accept_payment::ACCEPT_PAYMENT_HEADER,
            HeaderValue::from_static("tempo/charge"),
        );
        headers.remove(AUTHORIZATION);

        let challenge_response = client
            .head(url)
            .headers(headers.clone())
            .send()
            .await
            .mpp_http("session bootstrap challenge request failed")?;

        let response = if challenge_response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
            let challenge = PaymentChallenge::from_headers(
                challenge_response
                    .headers()
                    .get_all(WWW_AUTHENTICATE)
                    .iter()
                    .filter_map(|value| value.to_str().ok()),
            )
            .into_iter()
            .filter_map(Result::ok)
            .find(|challenge| {
                if challenge.method.as_str() != crate::protocol::methods::tempo::METHOD_NAME
                    || challenge.intent.as_str() != crate::protocol::methods::tempo::INTENT_CHARGE
                {
                    return false;
                }
                challenge
                    .request
                    .decode::<ChargeRequest>()
                    .ok()
                    .and_then(|request| request.parse_amount().ok())
                    == Some(0)
            });
            let Some(challenge) = challenge else {
                return Ok(None);
            };

            let request: ChargeRequest = challenge.request.decode()?;
            let chain_id = request
                .method_details
                .as_ref()
                .and_then(|details| details.get("chainId"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(crate::protocol::methods::tempo::CHAIN_ID);
            let payer = self.signing_mode.from_address(self.signer.address());
            let signature = sign_proof_primitive(
                &self.signer,
                payer,
                chain_id,
                &challenge.id,
                &challenge.realm,
            )
            .await?;
            let credential = PaymentCredential::with_source(
                challenge.to_echo(),
                PaymentCredential::evm_did(chain_id, &payer.to_string()),
                crate::protocol::core::PaymentPayload::proof(signature),
            );
            headers.insert(
                AUTHORIZATION,
                crate::protocol::core::format_authorization(&credential)?
                    .parse()
                    .mpp_config("invalid bootstrap authorization header")?,
            );
            client
                .head(url)
                .headers(headers)
                .send()
                .await
                .mpp_http("authorized session bootstrap request failed")?
        } else {
            challenge_response
        };

        if !response.status().is_success() {
            return Ok(None);
        }
        let Some(snapshot_header) = response.headers().get("payment-session-snapshot") else {
            return Ok(None);
        };
        let snapshot_bytes = STANDARD
            .decode(
                snapshot_header
                    .to_str()
                    .mpp_config("invalid Payment-Session-Snapshot header")?,
            )
            .mpp_config("invalid Payment-Session-Snapshot base64")?;
        let snapshot: crate::protocol::methods::tempo::session::SessionSnapshot =
            serde_json::from_slice(&snapshot_bytes)
                .mpp_config("invalid Payment-Session-Snapshot JSON")?;

        let payer = self.signing_mode.from_address(self.signer.address());
        let authorized_signer = self.authorized_signer.unwrap_or(self.signer.address());
        let payee = snapshot
            .descriptor
            .payee
            .parse()
            .mpp_config("invalid snapshot payee")?;
        let token = snapshot
            .descriptor
            .token
            .parse()
            .mpp_config("invalid snapshot token")?;
        let operator = snapshot
            .descriptor
            .operator
            .parse()
            .mpp_config("invalid snapshot operator")?;
        let escrow = snapshot
            .escrow
            .parse()
            .mpp_config("invalid snapshot escrow")?;
        let channel_id = snapshot
            .channel_id
            .parse()
            .mpp_config("invalid snapshot channelId")?;
        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(self.rpc_url.clone());
        let state = read_on_chain_channel_state(&provider, channel_id).await?;
        let recovered = hydrate_session_snapshot(
            &snapshot,
            RecoveryScope {
                payer,
                authorized_signer,
                payee,
                token,
                escrow,
                chain_id: snapshot.chain_id,
            },
            state,
        )?;
        self.channel_store
            .set(&recovered)
            .await
            .map_err(Self::store_error)?;

        let entry = Self::channel_entry(recovered.clone())?;
        let key = Self::channel_key(&payee, &token, &escrow, Some(operator));
        self.channel_id_to_key
            .lock()
            .unwrap()
            .insert(entry.channel_id.to_string(), key.clone());
        self.channels.lock().unwrap().insert(key, entry.clone());
        self.notify_update(&entry);
        Ok(Some(recovered))
    }

    /// Get the cumulative voucher amount for the first active channel.
    ///
    /// Returns the total cumulative amount across all vouchers sent for the
    /// channel, or 0 if no channel is open.
    pub fn cumulative(&self) -> u128 {
        self.channels
            .lock()
            .unwrap()
            .values()
            .filter(|e| e.opened)
            .map(|e| e.cumulative_amount)
            .next()
            .unwrap_or(0)
    }

    /// Create a signed voucher credential for an active session channel.
    ///
    /// This is used by streaming transports such as SSE and WebSocket, where
    /// the server requests a new cumulative voucher in-band rather than with a
    /// fresh HTTP 402 response.
    pub async fn voucher_credential(
        &self,
        channel_id_hex: &str,
        required_cumulative: u128,
    ) -> Result<PaymentCredential, MppError> {
        let challenge =
            self.last_challenge.lock().unwrap().clone().ok_or_else(|| {
                MppError::InvalidConfig("no challenge available for voucher".into())
            })?;
        self.voucher_credential_for_challenge(&challenge, channel_id_hex, required_cumulative)
            .await
    }

    /// Create a voucher bound to the challenge selected for one transport
    /// connection, avoiding cross-signing during overlapping reconnects.
    pub async fn voucher_credential_for_challenge(
        &self,
        challenge: &PaymentChallenge,
        channel_id_hex: &str,
        required_cumulative: u128,
    ) -> Result<PaymentCredential, MppError> {
        self.assert_within_max_deposit(required_cumulative)?;

        // Find the channel entry by channel ID
        let key = {
            let id_map = self.channel_id_to_key.lock().unwrap();
            id_map.get(channel_id_hex).cloned()
        };
        let key = key.ok_or_else(|| {
            MppError::InvalidConfig(format!("no channel found for id {}", channel_id_hex))
        })?;
        let (expected_key, expected_chain_id) = self.expected_channel_key(challenge)?;
        if key != expected_key {
            return Err(MppError::InvalidConfig(
                "channel does not match active session".into(),
            ));
        }

        let mut entry = {
            let channels = self.channels.lock().unwrap();
            channels.get(&key).cloned()
        }
        .ok_or_else(|| MppError::InvalidConfig("channel not found".into()))?;
        if entry.chain_id != expected_chain_id || entry.channel_id.to_string() != channel_id_hex {
            return Err(MppError::InvalidConfig(
                "channel does not match active session".into(),
            ));
        }

        // Update cumulative to at least the required amount
        if required_cumulative > entry.cumulative_amount {
            entry.cumulative_amount = required_cumulative;
        }
        if entry.cumulative_amount > entry.deposit {
            return Err(MppError::InvalidConfig(
                "voucher cumulative amount exceeds channel deposit".into(),
            ));
        }
        // A need-voucher frame can only be emitted after the server accepted
        // the open credential. Promote a locally pending open at that point;
        // until then a failed authorization must be retried as another open,
        // not as a voucher for a channel that never reached the chain.
        entry.opened = true;

        let payload = if is_precompile_escrow(entry.escrow_contract) {
            create_precompile_voucher_payload_with_descriptor_primitive(
                &self.signer,
                entry.descriptor.clone().ok_or_else(|| {
                    MppError::InvalidConfig("TIP-1034 channel descriptor is missing".into())
                })?,
                entry.cumulative_amount,
                entry.chain_id,
            )
            .await?
        } else {
            create_voucher_payload(
                self.secp256k1_signer()?,
                entry.channel_id,
                entry.cumulative_amount,
                entry.escrow_contract,
                entry.chain_id,
            )
            .await?
        };

        // Persist the signed voucher before exposing it to the transport.
        self.persist_channel(&entry).await?;
        self.channels.lock().unwrap().insert(key, entry.clone());
        self.notify_update(&entry);

        let payer = self.signing_mode.from_address(self.signer.address());
        Ok(build_credential(challenge, payload, entry.chain_id, payer))
    }

    /// Top up the active TIP-1034 channel through the service's HTTP management
    /// endpoint, then update the durable local channel view after acceptance.
    pub async fn top_up_with_headers(
        &self,
        client: &reqwest::Client,
        url: &str,
        headers: reqwest::header::HeaderMap,
        channel_id_hex: &str,
        additional_deposit: u128,
    ) -> Result<Option<Receipt>, MppError> {
        let challenge =
            self.last_challenge.lock().unwrap().clone().ok_or_else(|| {
                MppError::InvalidConfig("no challenge available for top-up".into())
            })?;
        self.top_up_with_headers_for_challenge(
            client,
            url,
            headers,
            &challenge,
            channel_id_hex,
            additional_deposit,
        )
        .await
    }

    /// Top up using the challenge selected for one transport connection.
    pub async fn top_up_with_headers_for_challenge(
        &self,
        client: &reqwest::Client,
        url: &str,
        mut headers: reqwest::header::HeaderMap,
        challenge: &PaymentChallenge,
        channel_id_hex: &str,
        additional_deposit: u128,
    ) -> Result<Option<Receipt>, MppError> {
        use alloy::providers::ProviderBuilder;
        use reqwest::header::AUTHORIZATION;
        use tempo_alloy::TempoNetwork;

        if additional_deposit == 0 {
            return Err(MppError::InvalidConfig(
                "top-up amount must be greater than zero".into(),
            ));
        }
        let key = self
            .channel_id_to_key
            .lock()
            .unwrap()
            .get(channel_id_hex)
            .cloned()
            .ok_or_else(|| {
                MppError::InvalidConfig(format!("no channel found for id {channel_id_hex}"))
            })?;
        let (expected_key, expected_chain_id) = self.expected_channel_key(challenge)?;
        if key != expected_key {
            return Err(MppError::InvalidConfig(
                "channel does not match active session".into(),
            ));
        }
        let mut entry = self
            .channels
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or_else(|| MppError::InvalidConfig("channel not found".into()))?;
        if entry.chain_id != expected_chain_id || entry.channel_id.to_string() != channel_id_hex {
            return Err(MppError::InvalidConfig(
                "channel does not match active session".into(),
            ));
        }
        if !is_precompile_escrow(entry.escrow_contract) {
            return Err(MppError::InvalidConfig(
                "automatic top-up requires the native TIP-1034 precompile".into(),
            ));
        }
        let new_deposit = entry
            .deposit
            .checked_add(additional_deposit)
            .ok_or_else(|| MppError::InvalidConfig("channel deposit overflowed".into()))?;
        let session_req: SessionRequest = challenge
            .request
            .decode()
            .mpp_config("failed to decode session request")?;
        let descriptor = entry.descriptor.clone().ok_or_else(|| {
            MppError::InvalidConfig("TIP-1034 channel descriptor is missing".into())
        })?;
        let payer = self.signing_mode.from_address(self.signer.address());
        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(self.rpc_url.clone());
        let payload = create_precompile_top_up_transaction_payload(
            &provider,
            &self.signer,
            Some(&self.signing_mode),
            payer,
            TopUpPrecompilePayloadOptions {
                descriptor: &descriptor,
                additional_deposit,
                chain_id: entry.chain_id,
                fee_payer: session_req.fee_payer(),
            },
        )
        .await?;
        let credential = build_credential(challenge, payload, entry.chain_id, payer);
        headers.insert(
            AUTHORIZATION,
            crate::protocol::core::format_authorization(&credential)?
                .parse()
                .mpp_config("invalid top-up authorization header")?,
        );
        let response = client
            .post(url)
            .headers(headers)
            .send()
            .await
            .mpp_http("top-up POST failed")?;
        let status = response.status();
        let receipt = response
            .headers()
            .get("payment-receipt")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| crate::protocol::core::parse_receipt(value).ok());
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(MppError::Http(format!(
                "top-up POST returned {status}: {body}"
            )));
        }

        entry.deposit = new_deposit;
        entry.opened = true;
        self.persist_channel(&entry).await?;
        self.channels.lock().unwrap().insert(key, entry.clone());
        self.notify_update(&entry);
        Ok(receipt)
    }

    /// Mirror MPPx need-voucher handling: top up over HTTP when required, then
    /// return the voucher that the WebSocket transport sends in-band.
    pub async fn voucher_credential_with_top_up(
        &self,
        client: &reqwest::Client,
        url: &str,
        headers: reqwest::header::HeaderMap,
        channel_id_hex: &str,
        required_cumulative: u128,
        server_deposit: u128,
    ) -> Result<PaymentCredential, MppError> {
        let challenge =
            self.last_challenge.lock().unwrap().clone().ok_or_else(|| {
                MppError::InvalidConfig("no challenge available for voucher".into())
            })?;
        self.voucher_credential_with_top_up_for_challenge(
            client,
            url,
            headers,
            &challenge,
            channel_id_hex,
            required_cumulative,
            server_deposit,
        )
        .await
    }

    /// Handle a need-voucher event using its socket-bound challenge.
    #[allow(clippy::too_many_arguments)]
    pub async fn voucher_credential_with_top_up_for_challenge(
        &self,
        client: &reqwest::Client,
        url: &str,
        headers: reqwest::header::HeaderMap,
        challenge: &PaymentChallenge,
        channel_id_hex: &str,
        required_cumulative: u128,
        server_deposit: u128,
    ) -> Result<PaymentCredential, MppError> {
        if let Some(additional_deposit) =
            self.required_top_up(required_cumulative, server_deposit)?
        {
            self.top_up_with_headers_for_challenge(
                client,
                url,
                headers,
                challenge,
                channel_id_hex,
                additional_deposit,
            )
            .await?;
        }
        self.voucher_credential_for_challenge(challenge, channel_id_hex, required_cumulative)
            .await
    }

    /// Create the final signed close credential for an active session channel.
    pub async fn close_credential(
        &self,
        channel_id_hex: &str,
    ) -> Result<PaymentCredential, MppError> {
        self.close_credential_inner(channel_id_hex, None).await
    }

    /// Create a signed close credential for an exact server-confirmed spend.
    ///
    /// Canonical bidirectional transports obtain this amount from the
    /// `payment-close-ready` receipt. It may be lower than the latest voucher
    /// ceiling, but it may never exceed the amount this provider authorized.
    pub async fn close_credential_at(
        &self,
        channel_id_hex: &str,
        cumulative_amount: u128,
    ) -> Result<PaymentCredential, MppError> {
        self.close_credential_inner(channel_id_hex, Some(cumulative_amount))
            .await
    }

    /// Create an exact close credential bound to one transport connection.
    pub async fn close_credential_at_for_challenge(
        &self,
        challenge: &PaymentChallenge,
        channel_id_hex: &str,
        cumulative_amount: u128,
    ) -> Result<PaymentCredential, MppError> {
        self.close_credential_for_challenge_inner(
            challenge,
            channel_id_hex,
            Some(cumulative_amount),
        )
        .await
    }

    async fn close_credential_inner(
        &self,
        channel_id_hex: &str,
        requested_cumulative: Option<u128>,
    ) -> Result<PaymentCredential, MppError> {
        let challenge =
            self.last_challenge.lock().unwrap().clone().ok_or_else(|| {
                MppError::InvalidConfig("no challenge available for close".into())
            })?;
        self.close_credential_for_challenge_inner(&challenge, channel_id_hex, requested_cumulative)
            .await
    }

    async fn close_credential_for_challenge_inner(
        &self,
        challenge: &PaymentChallenge,
        channel_id_hex: &str,
        requested_cumulative: Option<u128>,
    ) -> Result<PaymentCredential, MppError> {
        let key = self
            .channel_id_to_key
            .lock()
            .unwrap()
            .get(channel_id_hex)
            .cloned()
            .ok_or_else(|| {
                MppError::InvalidConfig(format!("no channel found for id {channel_id_hex}"))
            })?;
        let (expected_key, expected_chain_id) = self.expected_channel_key(challenge)?;
        if key != expected_key {
            return Err(MppError::InvalidConfig(
                "channel does not match active session".into(),
            ));
        }
        let entry = self
            .channels
            .lock()
            .unwrap()
            .get(&key)
            .filter(|entry| entry.opened || is_precompile_escrow(entry.escrow_contract))
            .cloned()
            .ok_or_else(|| MppError::InvalidConfig("channel not found".into()))?;
        if entry.chain_id != expected_chain_id || entry.channel_id.to_string() != channel_id_hex {
            return Err(MppError::InvalidConfig(
                "channel does not match active session".into(),
            ));
        }
        let cumulative_amount = requested_cumulative.unwrap_or(entry.cumulative_amount);
        if cumulative_amount > entry.cumulative_amount {
            return Err(MppError::InvalidConfig(format!(
                "close amount {cumulative_amount} exceeds locally authorized cumulative amount {}",
                entry.cumulative_amount
            )));
        }

        let payload = if is_precompile_escrow(entry.escrow_contract) {
            create_precompile_close_payload_with_descriptor_primitive(
                &self.signer,
                entry.channel_id,
                entry.descriptor.ok_or_else(|| {
                    MppError::InvalidConfig("TIP-1034 channel descriptor is missing".into())
                })?,
                cumulative_amount,
                entry.chain_id,
            )
            .await?
        } else {
            create_close_payload(
                self.secp256k1_signer()?,
                entry.channel_id,
                cumulative_amount,
                entry.escrow_contract,
                entry.chain_id,
            )
            .await?
        };
        let payer = self.signing_mode.from_address(self.signer.address());
        Ok(build_credential(challenge, payload, entry.chain_id, payer))
    }

    /// Send a voucher for a need-voucher SSE event.
    ///
    /// Called during SSE session metering when the server emits a `payment-need-voucher`
    /// event. Updates the internal cumulative amount and POSTs a signed voucher
    /// credential to the server.
    ///
    /// Mirrors the TypeScript SDK's `SessionManager.sse` need-voucher handling.
    pub async fn send_voucher(
        &self,
        client: &reqwest::Client,
        url: &str,
        channel_id_hex: &str,
        required_cumulative: u128,
    ) -> Result<(), MppError> {
        let credential = self
            .voucher_credential(channel_id_hex, required_cumulative)
            .await?;
        let auth_header = crate::protocol::core::format_authorization(&credential)?;

        let resp = client
            .post(url)
            .header("Authorization", auth_header)
            .send()
            .await
            .mpp_http("voucher POST failed")?;

        if !resp.status().is_success() {
            return Err(MppError::Http(format!(
                "voucher POST returned status {}",
                resp.status()
            )));
        }

        Ok(())
    }

    /// Close the payment channel and settle on-chain.
    ///
    /// Sends a close credential to the server, which triggers on-chain settlement.
    /// The server will submit the highest cumulative voucher to the escrow contract,
    /// transferring the owed amount to the server and refunding the remainder.
    ///
    /// Mirrors the TypeScript SDK's `session.close()` method.
    ///
    /// # Arguments
    ///
    /// * `client` - An HTTP client to send the close request
    /// * `url` - The server endpoint URL (same endpoint used for payments)
    ///
    /// # Returns
    ///
    /// The payment receipt from the server, if available.
    pub async fn close(
        &self,
        client: &reqwest::Client,
        url: &str,
    ) -> Result<Option<Receipt>, MppError> {
        let challenge = self.last_challenge.lock().unwrap().clone();
        let challenge = match challenge {
            Some(c) => c,
            None => return Ok(None),
        };

        {
            let channels = self.channels.lock().unwrap();
            if !channels.values().any(|entry| entry.opened) {
                return Ok(None);
            }
        }

        let (expected_key, expected_chain_id) = self.expected_channel_key(&challenge)?;
        let entry = {
            let channels = self.channels.lock().unwrap();
            channels.get(&expected_key).filter(|e| e.opened).cloned()
        };

        let entry = match entry {
            Some(e) => e,
            None => return Ok(None),
        };
        if entry.chain_id != expected_chain_id {
            return Err(MppError::InvalidConfig(
                "channel does not match active session".into(),
            ));
        }

        let credential = self.close_credential(&entry.channel_id.to_string()).await?;

        let auth_header = crate::protocol::core::format_authorization(&credential)?;

        let resp = client
            .post(url)
            .header("Authorization", auth_header)
            .send()
            .await
            .mpp_http("close request failed")?;

        let status = resp.status();
        let receipt_header = resp
            .headers()
            .get("payment-receipt")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(MppError::Http(format!(
                "close request returned {}: {}",
                status, body
            )));
        }

        let receipt = receipt_header
            .as_deref()
            .and_then(|s| crate::protocol::core::parse_receipt(s).ok());

        if is_precompile_escrow(entry.escrow_contract) {
            let store_key = Self::stored_entry(&entry)?.key();
            self.channel_store
                .delete(&store_key)
                .await
                .map_err(Self::store_error)?;
            self.channels.lock().unwrap().remove(&expected_key);
        }

        Ok(receipt)
    }

    fn resolve_deposit(&self, suggested_deposit: Option<&str>) -> Result<u128, MppError> {
        let suggested = suggested_deposit.and_then(|s| s.parse::<u128>().ok());

        match (suggested, self.max_deposit, self.default_deposit) {
            // Both suggested and max: use the smaller
            (Some(s), Some(max), _) => Ok(s.min(max)),
            // Only suggested
            (Some(s), None, _) => Ok(s),
            // Only max
            (None, Some(max), _) => Ok(max),
            // Only default
            (None, None, Some(def)) => Ok(def),
            // Nothing
            (None, None, None) => Err(MppError::InvalidConfig(
                "No deposit amount available. Set `default_deposit`, `max_deposit`, or ensure the server challenge includes `suggestedDeposit`.".to_string(),
            )),
        }
    }
}

impl PaymentProvider for TempoSessionProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == crate::protocol::methods::tempo::METHOD_NAME
            && intent == crate::protocol::methods::tempo::INTENT_SESSION
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        use alloy::providers::ProviderBuilder;
        use tempo_alloy::TempoNetwork;

        challenge.validate_for_session(crate::protocol::methods::tempo::METHOD_NAME)?;

        *self.last_challenge.lock().unwrap() = Some(challenge.clone());

        let chain_id = resolve_chain_id(challenge);
        let escrow_contract = resolve_escrow(challenge, chain_id, self.escrow_contract)?;

        let session_req: SessionRequest = challenge
            .request
            .decode()
            .mpp_config("failed to decode session request")?;

        let payee: Address = session_req
            .recipient
            .as_deref()
            .ok_or_else(|| {
                MppError::InvalidConfig("session challenge missing recipient".to_string())
            })?
            .parse()
            .map_err(|_| MppError::InvalidConfig("invalid recipient address".to_string()))?;

        let currency: Address = session_req
            .currency
            .parse()
            .map_err(|_| MppError::InvalidConfig("invalid currency address".to_string()))?;

        let amount: u128 = session_req.parse_amount()?;
        let payer = self.signing_mode.from_address(self.signer.address());
        let authorized_signer = self.authorized_signer.unwrap_or(self.signer.address());
        let precompile = is_precompile_escrow(escrow_contract);
        let operator = Self::key_operator(&escrow_contract, &session_req)?;
        let key = Self::channel_key(&payee, &currency, &escrow_contract, operator);
        let session_snapshot = session_req.session_snapshot();

        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(self.rpc_url.clone());

        // Check process memory first, then restore a durable native channel.
        let mut existing = self
            .channels
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .map(|entry| (entry, false));
        if existing.is_none() && precompile {
            existing = self
                .restore_precompile_channel(
                    &provider,
                    RecoveryScope {
                        payer,
                        authorized_signer,
                        payee,
                        token: currency,
                        escrow: escrow_contract,
                        chain_id,
                    },
                    session_snapshot.as_ref(),
                    amount,
                )
                .await?;
            if let Some((entry, _)) = &existing {
                self.channel_id_to_key
                    .lock()
                    .unwrap()
                    .insert(entry.channel_id.to_string(), key.clone());
                self.channels
                    .lock()
                    .unwrap()
                    .insert(key.clone(), entry.clone());
                self.notify_update(entry);
            }
        }

        if let Some((mut entry, includes_request)) = existing {
            if entry.opened {
                // Increment cumulative and sign a voucher
                if !includes_request {
                    entry.cumulative_amount =
                        entry.cumulative_amount.checked_add(amount).ok_or_else(|| {
                            MppError::InvalidConfig("session cumulative amount overflowed".into())
                        })?;
                }
                if entry.cumulative_amount > entry.deposit {
                    return Err(MppError::InvalidConfig(
                        "session cumulative amount exceeds channel deposit".into(),
                    ));
                }

                let payload = if precompile {
                    create_precompile_voucher_payload_with_descriptor_primitive(
                        &self.signer,
                        entry.descriptor.clone().ok_or_else(|| {
                            MppError::InvalidConfig("TIP-1034 channel descriptor is missing".into())
                        })?,
                        entry.cumulative_amount,
                        chain_id,
                    )
                    .await?
                } else {
                    create_voucher_payload(
                        self.secp256k1_signer()?,
                        entry.channel_id,
                        entry.cumulative_amount,
                        escrow_contract,
                        chain_id,
                    )
                    .await?
                };

                // Update the registry
                self.persist_channel(&entry).await?;
                self.channels.lock().unwrap().insert(key, entry.clone());
                self.notify_update(&entry);

                return Ok(build_credential(challenge, payload, chain_id, payer));
            }
        }

        // Try to recover a channel from on-chain state if suggested. Precompile
        // escrow has a different read ABI (TIP-1034); recovery is legacy-only.
        if !precompile {
            let suggested_channel_id = session_req.channel_id();
            if let Some(ref cid_str) = suggested_channel_id {
                if let Ok(cid) = cid_str.parse::<B256>() {
                    let expected_authorized_signer = authorized_signer;
                    if let Some(mut recovered) = try_recover_channel(
                        &provider,
                        escrow_contract,
                        cid,
                        chain_id,
                        payer,
                        payee,
                        currency,
                        expected_authorized_signer,
                    )
                    .await
                    {
                        // Start from recovered settled amount + request amount
                        recovered.cumulative_amount += amount;

                        let payload = create_voucher_payload(
                            self.secp256k1_signer()?,
                            recovered.channel_id,
                            recovered.cumulative_amount,
                            escrow_contract,
                            chain_id,
                        )
                        .await?;

                        self.channel_id_to_key
                            .lock()
                            .unwrap()
                            .insert(recovered.channel_id.to_string(), key.clone());
                        self.channels.lock().unwrap().insert(key, recovered.clone());
                        self.notify_update(&recovered);

                        return Ok(build_credential(challenge, payload, chain_id, payer));
                    }
                }
            }
        }

        // No existing channel — open a new one
        let deposit = self.resolve_deposit(session_req.suggested_deposit.as_deref())?;
        if deposit < amount {
            return Err(MppError::InvalidConfig(format!(
                "opening deposit {deposit} below request amount {amount}"
            )));
        }

        let (mut entry, payload) = if precompile {
            create_precompile_open_payload(
                &provider,
                &self.signer,
                Some(&self.signing_mode),
                payer,
                OpenPrecompilePayloadOptions {
                    operator: operator.unwrap_or(Address::ZERO),
                    authorized_signer: Some(authorized_signer),
                    payee,
                    currency,
                    deposit,
                    initial_amount: amount,
                    chain_id,
                    fee_payer: session_req.fee_payer(),
                },
            )
            .await?
        } else {
            create_open_payload(
                &provider,
                self.secp256k1_signer()?,
                Some(&self.signing_mode),
                payer,
                OpenPayloadOptions {
                    authorized_signer: self.authorized_signer,
                    escrow_contract,
                    payee,
                    currency,
                    deposit,
                    initial_amount: amount,
                    chain_id,
                    fee_payer: session_req.fee_payer(),
                },
            )
            .await?
        };

        // The signed open is only a proposal until the server verifies it and
        // returns a receipt. Keeping it pending prevents a retry after a 402
        // verification failure from signing a voucher for a nonexistent
        // channel. Voucher and close-ready messages promote it implicitly;
        // cold starts reconcile it with the server snapshot and on-chain state.
        if precompile {
            entry.opened = false;
        }

        self.channel_id_to_key
            .lock()
            .unwrap()
            .insert(entry.channel_id.to_string(), key.clone());
        self.persist_channel(&entry).await?;
        self.channels.lock().unwrap().insert(key, entry.clone());
        self.notify_update(&entry);

        Ok(build_credential(challenge, payload, chain_id, payer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;

    #[test]
    fn test_session_provider_new() {
        let signer = PrivateKeySigner::random();
        let provider =
            TempoSessionProvider::new(signer.clone(), "https://rpc.moderato.tempo.xyz").unwrap();

        assert_eq!(
            provider.rpc_url().as_str(),
            "https://rpc.moderato.tempo.xyz/"
        );
        assert_eq!(provider.signer().address(), signer.address());
    }

    #[test]
    fn test_session_provider_invalid_url() {
        let signer = PrivateKeySigner::random();
        let result = TempoSessionProvider::new(signer, "not a url");
        assert!(result.is_err());
    }

    #[test]
    fn test_session_provider_supports() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap();

        assert!(provider.supports("tempo", "session"));
        assert!(!provider.supports("tempo", "charge"));
        assert!(!provider.supports("stripe", "session"));
    }

    #[tokio::test]
    async fn test_pay_rejects_expired_challenge_before_state_mutation() {
        let provider = make_test_provider();
        let challenge = make_test_challenge().with_expires("2020-01-01T00:00:00Z");

        let err = provider.pay(&challenge).await.unwrap_err();

        assert!(matches!(err, MppError::PaymentExpired(_)));
        assert!(provider.last_challenge.lock().unwrap().is_none());
        assert!(provider.channels.lock().unwrap().is_empty());
    }

    #[test]
    fn test_session_provider_builder() {
        let signer = PrivateKeySigner::random();
        let escrow: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let auth_signer: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();

        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_escrow_contract(escrow)
            .with_authorized_signer(auth_signer)
            .with_max_deposit(1_000_000)
            .with_default_deposit(500_000);

        assert_eq!(provider.escrow_contract, Some(escrow));
        assert_eq!(provider.authorized_signer, Some(auth_signer));
        assert_eq!(provider.max_deposit, Some(1_000_000));
        assert_eq!(provider.default_deposit, Some(500_000));
    }

    #[test]
    fn test_resolve_deposit_suggested_and_max() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_max_deposit(5000);

        // suggested < max → use suggested
        assert_eq!(provider.resolve_deposit(Some("3000")).unwrap(), 3000);
        // suggested > max → use max
        assert_eq!(provider.resolve_deposit(Some("8000")).unwrap(), 5000);
    }

    #[test]
    fn test_resolve_deposit_suggested_only() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap();

        assert_eq!(provider.resolve_deposit(Some("3000")).unwrap(), 3000);
    }

    #[test]
    fn test_resolve_deposit_max_only() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_max_deposit(5000);

        assert_eq!(provider.resolve_deposit(None).unwrap(), 5000);
    }

    #[test]
    fn test_resolve_deposit_default_only() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_default_deposit(2000);

        assert_eq!(provider.resolve_deposit(None).unwrap(), 2000);
    }

    #[test]
    fn test_resolve_deposit_none() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap();

        assert!(provider.resolve_deposit(None).is_err());
    }

    #[test]
    fn need_voucher_requires_top_up_before_signing_beyond_deposit() {
        let provider = make_test_provider().with_max_deposit(1_000_000);

        assert_eq!(provider.required_top_up(12_000, 20_000).unwrap(), None);
        assert_eq!(
            provider.required_top_up(25_000, 20_000).unwrap(),
            Some(5_000)
        );
        assert!(provider.required_top_up(1_000_001, 20_000).is_err());
    }

    #[test]
    fn test_channel_key_format() {
        let payee: Address = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .parse()
            .unwrap();
        let currency: Address = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
            .parse()
            .unwrap();
        let escrow: Address = "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
            .parse()
            .unwrap();

        // Legacy: no operator → 3 fields.
        let key = TempoSessionProvider::channel_key(&payee, &currency, &escrow, None);
        assert_eq!(key, key.to_lowercase());
        assert_eq!(key.matches(':').count(), 2);

        // Precompile: operator appended → 4 fields, distinct per operator.
        let op_a = Address::repeat_byte(0x01);
        let op_b = Address::repeat_byte(0x02);
        let key_a = TempoSessionProvider::channel_key(&payee, &currency, &escrow, Some(op_a));
        let key_b = TempoSessionProvider::channel_key(&payee, &currency, &escrow, Some(op_b));
        assert_eq!(key_a.matches(':').count(), 3);
        assert_ne!(key_a, key_b);
        assert_ne!(key_a, key);
    }

    #[test]
    fn test_channels_snapshot() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap();

        // Initially empty
        assert!(provider.channels().is_empty());

        // Insert a channel
        let entry = ChannelEntry {
            channel_id: B256::repeat_byte(0xAB),
            salt: B256::ZERO,
            cumulative_amount: 1000,
            deposit: 0,
            descriptor: None,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened: true,
        };
        provider
            .channels
            .lock()
            .unwrap()
            .insert("test-key".to_string(), entry);

        assert_eq!(provider.channels().len(), 1);
    }

    #[test]
    fn test_on_channel_update_callback() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let signer = PrivateKeySigner::random();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_on_channel_update(move |_entry| {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            });

        let entry = ChannelEntry {
            channel_id: B256::ZERO,
            salt: B256::ZERO,
            cumulative_amount: 0,
            deposit: 0,
            descriptor: None,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened: true,
        };

        provider.notify_update(&entry);
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        provider.notify_update(&entry);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    // --- cumulative() ---

    #[test]
    fn test_cumulative_empty_registry() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap();

        assert_eq!(provider.cumulative(), 0);
    }

    #[test]
    fn test_cumulative_with_opened_channel() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap();

        let entry = ChannelEntry {
            channel_id: B256::ZERO,
            salt: B256::ZERO,
            cumulative_amount: 42_000,
            deposit: 0,
            descriptor: None,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened: true,
        };
        provider
            .channels
            .lock()
            .unwrap()
            .insert("key".to_string(), entry);

        assert_eq!(provider.cumulative(), 42_000);
    }

    #[test]
    fn test_cumulative_ignores_non_opened_channels() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap();

        let entry = ChannelEntry {
            channel_id: B256::ZERO,
            salt: B256::ZERO,
            cumulative_amount: 99_000,
            deposit: 0,
            descriptor: None,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened: false,
        };
        provider
            .channels
            .lock()
            .unwrap()
            .insert("key".to_string(), entry);

        assert_eq!(
            provider.cumulative(),
            0,
            "non-opened channels should not be counted"
        );
    }

    // --- with_signing_mode ---

    #[test]
    fn test_session_provider_with_signing_mode() {
        use crate::client::tempo::signing::{KeychainVersion, TempoSigningMode};

        let signer = PrivateKeySigner::random();
        let wallet: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_signing_mode(TempoSigningMode::Keychain {
                wallet,
                key_authorization: None,
                version: KeychainVersion::V1,
            });

        assert!(matches!(
            provider.signing_mode,
            TempoSigningMode::Keychain { .. }
        ));
    }

    #[test]
    fn test_session_provider_default_signing_mode() {
        use crate::client::tempo::signing::TempoSigningMode;

        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap();

        assert!(matches!(provider.signing_mode, TempoSigningMode::Direct));
    }

    // --- resolve_deposit edge cases ---

    #[test]
    fn test_resolve_deposit_invalid_suggested_falls_back() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_default_deposit(7000);

        // Non-numeric suggested should be ignored (parsed as None)
        assert_eq!(
            provider.resolve_deposit(Some("not-a-number")).unwrap(),
            7000,
            "invalid suggested should fall back to default"
        );
    }

    #[test]
    fn test_resolve_deposit_suggested_zero() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap();

        assert_eq!(provider.resolve_deposit(Some("0")).unwrap(), 0);
    }

    #[test]
    fn test_resolve_deposit_suggested_equals_max() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_max_deposit(5000);

        assert_eq!(
            provider.resolve_deposit(Some("5000")).unwrap(),
            5000,
            "suggested == max should use that value"
        );
    }

    #[test]
    fn test_resolve_deposit_max_and_default_prefers_max() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_max_deposit(5000)
            .with_default_deposit(2000);

        // When no suggested, max takes priority over default
        assert_eq!(provider.resolve_deposit(None).unwrap(), 5000);
    }

    // --- notify_update without callback ---

    #[test]
    fn test_notify_update_no_callback() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap();

        let entry = ChannelEntry {
            channel_id: B256::ZERO,
            salt: B256::ZERO,
            cumulative_amount: 0,
            deposit: 0,
            descriptor: None,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened: true,
        };

        // Should not panic when no callback is set
        provider.notify_update(&entry);
    }

    #[test]
    fn test_session_provider_clone() {
        let signer = PrivateKeySigner::random();
        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_max_deposit(5000);

        let cloned = provider.clone();
        assert!(cloned.supports("tempo", "session"));
        assert_eq!(cloned.max_deposit, Some(5000));

        // Cloned provider shares the same channel registry (Arc)
        let entry = ChannelEntry {
            channel_id: B256::ZERO,
            salt: B256::ZERO,
            cumulative_amount: 0,
            deposit: 0,
            descriptor: None,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened: true,
        };
        provider
            .channels
            .lock()
            .unwrap()
            .insert("key".to_string(), entry);
        assert_eq!(cloned.channels().len(), 1);
    }

    // --- shared test helpers ---

    fn make_test_provider() -> TempoSessionProvider {
        let signer = PrivateKeySigner::random();
        TempoSessionProvider::new(signer, "https://rpc.example.com").unwrap()
    }

    fn make_channel_entry(channel_id_byte: u8, cumulative: u128, opened: bool) -> ChannelEntry {
        ChannelEntry {
            channel_id: B256::repeat_byte(channel_id_byte),
            salt: B256::ZERO,
            cumulative_amount: cumulative,
            deposit: 0,
            descriptor: None,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened,
        }
    }

    fn make_test_challenge() -> PaymentChallenge {
        PaymentChallenge::new(
            "test-id",
            "test-realm",
            "tempo",
            "session",
            crate::protocol::core::Base64UrlJson::from_value(
                &serde_json::json!({"amount": "1000"}),
            )
            .unwrap(),
        )
    }

    fn make_scoped_challenge(
        payee: Address,
        currency: Address,
        escrow: Address,
    ) -> PaymentChallenge {
        PaymentChallenge::new(
            "test-id",
            "test-realm",
            "tempo",
            "session",
            crate::protocol::core::Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "currency": format!("{:#x}", currency),
                "recipient": format!("{:#x}", payee),
                "methodDetails": {
                    "escrowContract": format!("{:#x}", escrow),
                    "chainId": 42431
                }
            }))
            .unwrap(),
        )
    }

    // --- send_voucher error paths ---

    #[tokio::test]
    async fn voucher_request_promotes_pending_open_and_signs_cumulative_voucher() {
        use crate::protocol::methods::tempo::session::SessionCredentialPayload;

        let provider = make_test_provider();
        let payee = Address::repeat_byte(0x11);
        let currency = Address::repeat_byte(0x22);
        let escrow = Address::repeat_byte(0x33);
        let channel_id = B256::repeat_byte(0x44);
        let channel_id_hex = channel_id.to_string();

        *provider.last_challenge.lock().unwrap() =
            Some(make_scoped_challenge(payee, currency, escrow));
        let key = TempoSessionProvider::channel_key(&payee, &currency, &escrow, None);
        provider
            .channel_id_to_key
            .lock()
            .unwrap()
            .insert(channel_id_hex.clone(), key.clone());
        provider.channels.lock().unwrap().insert(
            key.clone(),
            ChannelEntry {
                channel_id,
                salt: B256::ZERO,
                cumulative_amount: 1000,
                deposit: 10_000,
                descriptor: None,
                escrow_contract: escrow,
                chain_id: 42431,
                opened: false,
            },
        );
        assert_eq!(provider.cumulative(), 0);

        let credential = provider
            .voucher_credential(&channel_id_hex, 2000)
            .await
            .unwrap();

        match credential.payload_as::<SessionCredentialPayload>().unwrap() {
            SessionCredentialPayload::Voucher {
                channel_id,
                cumulative_amount,
                ..
            } => {
                assert_eq!(channel_id, channel_id_hex);
                assert_eq!(cumulative_amount, "2000");
            }
            other => panic!("expected voucher payload, got {other:?}"),
        }
        assert_eq!(provider.cumulative(), 2000);
    }

    #[tokio::test]
    async fn test_send_voucher_missing_challenge() {
        let provider = make_test_provider();

        let client = reqwest::Client::new();
        let err = provider
            .send_voucher(&client, "https://example.com/pay", "0xdeadbeef", 1000)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            MppError::InvalidConfig(ref msg) if msg.contains("no challenge available")
        ));
    }

    #[tokio::test]
    async fn test_send_voucher_missing_channel_id_mapping() {
        let provider = make_test_provider();
        *provider.last_challenge.lock().unwrap() = Some(make_test_challenge());

        let client = reqwest::Client::new();
        let err = provider
            .send_voucher(&client, "https://example.com/pay", "0xnosuchid", 1000)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            MppError::InvalidConfig(ref msg) if msg.contains("no channel found")
        ));
    }

    #[tokio::test]
    async fn test_send_voucher_rejects_channel_from_different_session() {
        let provider = make_test_provider();
        let expected_payee = Address::repeat_byte(0x11);
        let other_payee = Address::repeat_byte(0x22);
        let currency = Address::repeat_byte(0x33);
        let escrow = Address::repeat_byte(0x44);
        let channel_id = B256::repeat_byte(0x55).to_string();

        *provider.last_challenge.lock().unwrap() =
            Some(make_scoped_challenge(expected_payee, currency, escrow));

        let other_key = TempoSessionProvider::channel_key(&other_payee, &currency, &escrow, None);
        provider
            .channel_id_to_key
            .lock()
            .unwrap()
            .insert(channel_id.clone(), other_key.clone());
        provider.channels.lock().unwrap().insert(
            other_key,
            ChannelEntry {
                channel_id: B256::repeat_byte(0x55),
                salt: B256::ZERO,
                cumulative_amount: 1000,
                deposit: 0,
                descriptor: None,
                escrow_contract: escrow,
                chain_id: 42431,
                opened: true,
            },
        );

        let client = reqwest::Client::new();
        let err = provider
            .send_voucher(&client, "https://example.com/pay", &channel_id, 2000)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            MppError::InvalidConfig(ref msg) if msg.contains("active session")
        ));
    }

    // --- close early-return paths ---

    #[tokio::test]
    async fn test_close_no_challenge_returns_none() {
        let provider = make_test_provider();

        let client = reqwest::Client::new();
        let result = provider.close(&client, "https://example.com/pay").await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_close_no_open_channel_returns_none() {
        let provider = make_test_provider();
        *provider.last_challenge.lock().unwrap() = Some(make_test_challenge());

        let client = reqwest::Client::new();
        let result = provider.close(&client, "https://example.com/pay").await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_close_ignores_unrelated_open_channel() {
        let provider = make_test_provider();
        let expected_payee = Address::repeat_byte(0x11);
        let other_payee = Address::repeat_byte(0x22);
        let currency = Address::repeat_byte(0x33);
        let escrow = Address::repeat_byte(0x44);

        *provider.last_challenge.lock().unwrap() =
            Some(make_scoped_challenge(expected_payee, currency, escrow));

        let other_key = TempoSessionProvider::channel_key(&other_payee, &currency, &escrow, None);
        provider.channels.lock().unwrap().insert(
            other_key,
            ChannelEntry {
                channel_id: B256::repeat_byte(0x66),
                salt: B256::ZERO,
                cumulative_amount: 1000,
                deposit: 0,
                descriptor: None,
                escrow_contract: escrow,
                chain_id: 42431,
                opened: true,
            },
        );

        let client = reqwest::Client::new();
        let result = provider.close(&client, "https://example.com/pay").await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // --- cumulative() behavior ---
    // Note: send_voucher's cumulative update cannot be integration-tested without
    // a mock HTTP server because the update is written back to the registry only
    // after payload creation, and the method then POSTs to a URL which would fail.

    #[test]
    fn test_cumulative_reflects_channel_state() {
        let provider = make_test_provider();
        provider
            .channels
            .lock()
            .unwrap()
            .insert("key".to_string(), make_channel_entry(0xAB, 1000, true));

        assert_eq!(provider.cumulative(), 1000);

        provider
            .channels
            .lock()
            .unwrap()
            .get_mut("key")
            .unwrap()
            .cumulative_amount = 2000;

        assert_eq!(provider.cumulative(), 2000);
    }

    #[test]
    fn test_cumulative_does_not_decrease() {
        let provider = make_test_provider();
        provider
            .channels
            .lock()
            .unwrap()
            .insert("key".to_string(), make_channel_entry(0x01, 5000, true));

        assert_eq!(provider.cumulative(), 5000);

        // Lowering cumulative_amount in the entry still reflects the stored value;
        // the "never decrease" invariant is enforced by send_voucher (line 219),
        // not by cumulative() itself.
        provider
            .channels
            .lock()
            .unwrap()
            .get_mut("key")
            .unwrap()
            .cumulative_amount = 3000;

        assert_eq!(provider.cumulative(), 3000);
    }

    #[test]
    fn test_cumulative_returns_first_opened_channel_only() {
        let provider = make_test_provider();
        {
            let mut channels = provider.channels.lock().unwrap();
            channels.insert("key-a".to_string(), make_channel_entry(0x01, 5000, true));
            channels.insert("key-b".to_string(), make_channel_entry(0x02, 9000, true));
        }

        let cum = provider.cumulative();
        // cumulative() returns the first opened channel it finds (HashMap iteration
        // order), not a sum. Verify it returns one of the two values.
        assert!(
            cum == 5000 || cum == 9000,
            "expected cumulative to be one channel's value, got: {cum}"
        );
    }

    #[test]
    fn test_channel_registry_multiple_channels() {
        let provider = make_test_provider();
        {
            let mut channels = provider.channels.lock().unwrap();
            channels.insert("key-a".to_string(), make_channel_entry(0x01, 5000, true));
            channels.insert("key-b".to_string(), make_channel_entry(0x02, 3000, false));
        }

        assert_eq!(provider.channels().len(), 2);
        assert_eq!(
            provider.cumulative(),
            5000,
            "cumulative should only count the opened channel"
        );
    }

    #[test]
    fn parse_operator_handles_missing_present_and_malformed() {
        // Missing methodDetails → ZERO.
        let req = SessionRequest::default();
        assert_eq!(
            TempoSessionProvider::parse_operator(&req).unwrap(),
            Address::ZERO
        );

        // Present → parsed.
        let op = Address::repeat_byte(0x42);
        let req = SessionRequest {
            method_details: Some(serde_json::json!({ "operator": op.to_string() })),
            ..Default::default()
        };
        assert_eq!(TempoSessionProvider::parse_operator(&req).unwrap(), op);

        // Malformed string and non-string → error.
        for v in [serde_json::json!("not-an-address"), serde_json::json!(42)] {
            let req = SessionRequest {
                method_details: Some(serde_json::json!({ "operator": v })),
                ..Default::default()
            };
            assert!(TempoSessionProvider::parse_operator(&req).is_err());
        }
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn key_operator_only_applies_to_precompile_escrow() {
        use tempo_alloy::contracts::precompiles::TIP20_CHANNEL_RESERVE_ADDRESS;

        let op = Address::repeat_byte(0x42);
        let req = SessionRequest {
            method_details: Some(serde_json::json!({ "operator": op.to_string() })),
            ..Default::default()
        };

        // Legacy escrow ignores operator → None (keeps legacy key shape).
        let legacy = Address::repeat_byte(0x44);
        assert_eq!(
            TempoSessionProvider::key_operator(&legacy, &req).unwrap(),
            None
        );

        // Precompile escrow binds operator → Some.
        assert_eq!(
            TempoSessionProvider::key_operator(&TIP20_CHANNEL_RESERVE_ADDRESS, &req).unwrap(),
            Some(op)
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn pay_branches_to_precompile_voucher_for_existing_precompile_channel() {
        use alloy::signers::local::PrivateKeySigner;
        use tempo_alloy::contracts::precompiles::TIP20_CHANNEL_RESERVE_ADDRESS;

        use crate::client::tempo::session::channel_ops::{build_channel_descriptor, ChannelEntry};
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};
        use crate::protocol::methods::tempo::precompile_voucher::{
            compute_precompile_channel_id, sign_precompile_voucher,
        };

        let signer = PrivateKeySigner::random();
        let payer = signer.address();
        let payee = Address::repeat_byte(0x11);
        let currency = Address::repeat_byte(0x22);
        let operator = Address::repeat_byte(0x33);
        let salt = B256::repeat_byte(0xab);
        let authorized_signer = payer;
        let chain_id = 42431u64;
        let expiring_nonce_hash = B256::repeat_byte(0xcd);

        let channel_id = compute_precompile_channel_id(
            payer,
            payee,
            operator,
            currency,
            salt,
            authorized_signer,
            expiring_nonce_hash,
            chain_id,
        );
        let descriptor = build_channel_descriptor(
            payer,
            payee,
            operator,
            currency,
            salt,
            authorized_signer,
            expiring_nonce_hash,
        );

        let provider =
            TempoSessionProvider::new(signer.clone(), "https://rpc.example.com").unwrap();

        // Pre-seed an open precompile channel under the registry key.
        let key = TempoSessionProvider::channel_key(
            &payee,
            &currency,
            &TIP20_CHANNEL_RESERVE_ADDRESS,
            Some(operator),
        );
        provider.channels.lock().unwrap().insert(
            key.clone(),
            ChannelEntry {
                channel_id,
                salt,
                cumulative_amount: 1_000,
                deposit: 10_000,
                descriptor: Some(descriptor.clone()),
                escrow_contract: TIP20_CHANNEL_RESERVE_ADDRESS,
                chain_id,
                opened: true,
            },
        );
        provider
            .channel_id_to_key
            .lock()
            .unwrap()
            .insert(channel_id.to_string(), key);

        let req = SessionRequest {
            amount: "500".to_string(),
            currency: currency.to_string(),
            recipient: Some(payee.to_string()),
            method_details: Some(serde_json::json!({
                "chainId": chain_id,
                "escrowContract": TIP20_CHANNEL_RESERVE_ADDRESS.to_string(),
                "operator": operator.to_string(),
            })),
            ..Default::default()
        };
        let challenge = PaymentChallenge::new(
            "test-challenge",
            "rpc.example.com",
            crate::protocol::methods::tempo::METHOD_NAME,
            crate::protocol::methods::tempo::INTENT_SESSION,
            Base64UrlJson::from_typed(&req).unwrap(),
        );

        let credential = provider.pay(&challenge).await.expect("pay succeeds");

        // Expected: precompile EIP-712 voucher signed over cumulative 1500.
        let expected_sig = sign_precompile_voucher(&signer, channel_id, 1_500, chain_id)
            .await
            .unwrap();
        let expected_hex = alloy::hex::encode_prefixed(&expected_sig);

        match credential
            .payload_as::<crate::protocol::methods::tempo::session::SessionCredentialPayload>()
            .unwrap()
        {
            crate::protocol::methods::tempo::session::SessionCredentialPayload::Voucher {
                signature,
                cumulative_amount,
                channel_id: cid,
                descriptor: actual_descriptor,
                ..
            } => {
                assert_eq!(cumulative_amount, "1500");
                assert_eq!(cid, channel_id.to_string());
                assert_eq!(
                    serde_json::to_value(actual_descriptor).unwrap(),
                    serde_json::to_value(Some(descriptor.clone())).unwrap()
                );
                assert_eq!(
                    signature, expected_hex,
                    "voucher must use precompile EIP-712 domain"
                );
            }
            other => panic!("expected voucher payload, got {other:?}"),
        }

        let close_amount = 1_200;
        let expected_close_sig =
            sign_precompile_voucher(&signer, channel_id, close_amount, chain_id)
                .await
                .unwrap();
        let expected_close_hex = alloy::hex::encode_prefixed(&expected_close_sig);
        let close = provider
            .close_credential_at(&channel_id.to_string(), close_amount)
            .await
            .expect("close credential succeeds");
        match close
            .payload_as::<crate::protocol::methods::tempo::session::SessionCredentialPayload>()
            .unwrap()
        {
            crate::protocol::methods::tempo::session::SessionCredentialPayload::Close {
                channel_id: actual_channel_id,
                descriptor: actual_descriptor,
                cumulative_amount,
                signature,
            } => {
                assert_eq!(actual_channel_id, channel_id.to_string());
                assert_eq!(actual_descriptor, Some(descriptor));
                assert_eq!(cumulative_amount, close_amount.to_string());
                assert_eq!(signature, expected_close_hex);
            }
            other => panic!("expected close payload, got {other:?}"),
        }

        let error = provider
            .close_credential_at(&channel_id.to_string(), 1_501)
            .await
            .expect_err("close amount above the voucher ceiling must fail");
        assert!(error
            .to_string()
            .contains("exceeds locally authorized cumulative amount"));
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn pay_signs_native_voucher_with_accounts_sdk_p256_access_key() {
        use tempo_alloy::contracts::precompiles::TIP20_CHANNEL_RESERVE_ADDRESS;

        use crate::client::tempo::{
            session::channel_ops::{build_channel_descriptor, ChannelEntry},
            signing::{KeychainVersion, P256Jwk, TempoP256Signer, TempoSigningMode},
        };
        use crate::protocol::{
            core::{Base64UrlJson, PaymentChallenge},
            methods::tempo::precompile_voucher::{
                compute_precompile_channel_id, verify_precompile_voucher_signature,
            },
        };

        let signer = TempoP256Signer::from_webcrypto_jwk(&P256Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "OtOGGpViE5JRa7WT7wVYPtLlhm9ctiYKMBcjf9ibkK8".into(),
            y: "0JYcfjcHWmeRo5xh9WKVsCttJlZ7YV5gqkHuHI6DOI0".into(),
            d: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI".into(),
        })
        .unwrap();
        let payer = Address::repeat_byte(0x10);
        let payee = Address::repeat_byte(0x11);
        let currency = Address::repeat_byte(0x22);
        let operator = Address::ZERO;
        let salt = B256::repeat_byte(0xab);
        let expiring_nonce_hash = B256::repeat_byte(0xcd);
        let chain_id = 4217;
        let channel_id = compute_precompile_channel_id(
            payer,
            payee,
            operator,
            currency,
            salt,
            signer.address(),
            expiring_nonce_hash,
            chain_id,
        );
        let descriptor = build_channel_descriptor(
            payer,
            payee,
            operator,
            currency,
            salt,
            signer.address(),
            expiring_nonce_hash,
        );
        let provider = TempoSessionProvider::new(signer.clone(), "https://rpc.example.com")
            .unwrap()
            .with_signing_mode(TempoSigningMode::Keychain {
                wallet: payer,
                key_authorization: None,
                version: KeychainVersion::V2,
            });
        let key = TempoSessionProvider::channel_key(
            &payee,
            &currency,
            &TIP20_CHANNEL_RESERVE_ADDRESS,
            Some(operator),
        );
        provider.channels.lock().unwrap().insert(
            key,
            ChannelEntry {
                channel_id,
                salt,
                cumulative_amount: 1_000,
                deposit: 10_000,
                descriptor: Some(descriptor),
                escrow_contract: TIP20_CHANNEL_RESERVE_ADDRESS,
                chain_id,
                opened: true,
            },
        );

        let request = SessionRequest {
            amount: "500".into(),
            currency: currency.to_string(),
            recipient: Some(payee.to_string()),
            method_details: Some(serde_json::json!({
                "chainId": chain_id,
                "escrowContract": TIP20_CHANNEL_RESERVE_ADDRESS.to_string(),
                "operator": operator.to_string(),
            })),
            ..Default::default()
        };
        let challenge = PaymentChallenge::new(
            "p256-session",
            "rpc.example.com",
            crate::protocol::methods::tempo::METHOD_NAME,
            crate::protocol::methods::tempo::INTENT_SESSION,
            Base64UrlJson::from_typed(&request).unwrap(),
        );
        let credential = provider.pay(&challenge).await.unwrap();
        let payload = credential
            .payload_as::<crate::protocol::methods::tempo::session::SessionCredentialPayload>()
            .unwrap();
        let crate::protocol::methods::tempo::session::SessionCredentialPayload::Voucher {
            cumulative_amount,
            signature,
            ..
        } = payload
        else {
            panic!("expected voucher")
        };
        assert_eq!(cumulative_amount, "1500");
        let signature = alloy::hex::decode(signature.trim_start_matches("0x")).unwrap();
        assert!(verify_precompile_voucher_signature(
            &signature,
            signer.address(),
            channel_id,
            1_500,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            chain_id,
        )
        .unwrap());
    }

    #[cfg(feature = "axum")]
    #[tokio::test]
    async fn bootstrap_authenticates_with_wallet_bound_p256_proof() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        use axum::{
            http::{header::AUTHORIZATION, HeaderMap, StatusCode},
            response::IntoResponse,
            routing::head,
            Router,
        };

        use crate::client::tempo::signing::{
            KeychainVersion, P256Jwk, TempoP256Signer, TempoSigningMode,
        };
        use crate::protocol::{
            core::{Base64UrlJson, PaymentChallenge, PaymentCredential},
            methods::tempo::proof::recover_proof_signer,
        };

        let signer = TempoP256Signer::from_webcrypto_jwk(&P256Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "OtOGGpViE5JRa7WT7wVYPtLlhm9ctiYKMBcjf9ibkK8".into(),
            y: "0JYcfjcHWmeRo5xh9WKVsCttJlZ7YV5gqkHuHI6DOI0".into(),
            d: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI".into(),
        })
        .unwrap();
        let root = Address::repeat_byte(0x44);
        let chain_id = 4217;
        let challenge = PaymentChallenge::new(
            "bootstrap-proof",
            "openai.example.com",
            crate::protocol::methods::tempo::METHOD_NAME,
            crate::protocol::methods::tempo::INTENT_CHARGE,
            Base64UrlJson::from_value(&serde_json::json!({
                "amount": "0",
                "currency": Address::repeat_byte(0x20).to_string(),
                "recipient": Address::repeat_byte(0x30).to_string(),
                "methodDetails": { "chainId": chain_id }
            }))
            .unwrap(),
        );
        let challenge_header = challenge.to_header().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let proof_valid = Arc::new(AtomicBool::new(false));
        let access_key = signer.address();
        let app = Router::new().route(
            "/v1/responses",
            head({
                let calls = calls.clone();
                let proof_valid = proof_valid.clone();
                move |headers: HeaderMap| {
                    let calls = calls.clone();
                    let proof_valid = proof_valid.clone();
                    let challenge_header = challenge_header.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        let Some(authorization) = headers.get(AUTHORIZATION) else {
                            return (
                                StatusCode::PAYMENT_REQUIRED,
                                [("www-authenticate", challenge_header)],
                            )
                                .into_response();
                        };
                        let valid = authorization
                            .to_str()
                            .ok()
                            .and_then(|value| PaymentCredential::from_header(value).ok())
                            .and_then(|credential| {
                                let payload = credential.charge_payload().ok()?;
                                let source = credential.source?;
                                let recovered = recover_proof_signer(
                                    root,
                                    chain_id,
                                    "bootstrap-proof",
                                    "openai.example.com",
                                    payload.proof_signature()?,
                                )
                                .ok()?;
                                Some(
                                    source
                                        == PaymentCredential::evm_did(chain_id, &root.to_string())
                                        && recovered == access_key,
                                )
                            })
                            .unwrap_or(false);
                        proof_valid.store(valid, Ordering::SeqCst);
                        if valid {
                            StatusCode::NO_CONTENT.into_response()
                        } else {
                            StatusCode::UNAUTHORIZED.into_response()
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = TempoSessionProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_signing_mode(TempoSigningMode::Keychain {
                wallet: root,
                key_authorization: None,
                version: KeychainVersion::V2,
            });
        let result = provider
            .bootstrap(
                &reqwest::Client::new(),
                &format!("http://{address}/v1/responses"),
            )
            .await
            .unwrap();

        assert!(
            result.is_none(),
            "server intentionally returned no snapshot"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(proof_valid.load(Ordering::SeqCst));
    }
}
