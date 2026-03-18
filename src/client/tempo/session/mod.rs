//! Tempo session payment provider.
//!
//! Implements `PaymentProvider` for the session intent, providing automatic
//! channel lifecycle management: open on first request, voucher on subsequent
//! requests, cumulative amount tracking, and channel recovery from on-chain state.
//!
//! Ported from the TypeScript SDK's `Session.ts`.

pub mod channel_ops;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use alloy::primitives::{Address, B256};

use self::channel_ops::{
    build_credential, create_close_payload, create_open_payload, create_voucher_payload,
    resolve_chain_id, resolve_escrow, try_recover_channel, ChannelEntry, OpenPayloadOptions,
};
use crate::client::PaymentProvider;
use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential, Receipt};
use crate::protocol::intents::SessionRequest;
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
    signer: alloy::signers::local::PrivateKeySigner,
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
        signer: alloy::signers::local::PrivateKeySigner,
        rpc_url: impl AsRef<str>,
    ) -> Result<Self, MppError> {
        let url = rpc_url
            .as_ref()
            .parse()
            .map_err(|e| MppError::InvalidConfig(format!("invalid RPC URL: {}", e)))?;
        Ok(Self {
            signer,
            rpc_url: url,
            escrow_contract: None,
            authorized_signer: None,
            signing_mode: crate::client::tempo::signing::TempoSigningMode::Direct,
            max_deposit: None,
            default_deposit: None,
            channels: Arc::new(Mutex::new(HashMap::new())),
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

    /// Set a callback for channel state changes.
    pub fn with_on_channel_update(
        mut self,
        callback: impl Fn(&ChannelEntry) + Send + Sync + 'static,
    ) -> Self {
        self.on_channel_update = Some(Arc::new(callback));
        self
    }

    /// Get a reference to the signer.
    pub fn signer(&self) -> &alloy::signers::local::PrivateKeySigner {
        &self.signer
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

    fn channel_key(payee: &Address, currency: &Address, escrow: &Address) -> String {
        format!(
            "{}:{}:{}",
            format!("{}", payee).to_lowercase(),
            format!("{}", currency).to_lowercase(),
            format!("{}", escrow).to_lowercase()
        )
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
        let challenge =
            self.last_challenge.lock().unwrap().clone().ok_or_else(|| {
                MppError::InvalidConfig("no challenge available for voucher".into())
            })?;

        // Find the channel entry by channel ID
        let key = {
            let id_map = self.channel_id_to_key.lock().unwrap();
            id_map.get(channel_id_hex).cloned()
        };
        let key = key.ok_or_else(|| {
            MppError::InvalidConfig(format!("no channel found for id {}", channel_id_hex))
        })?;

        let mut entry = {
            let channels = self.channels.lock().unwrap();
            channels.get(&key).cloned()
        }
        .ok_or_else(|| MppError::InvalidConfig("channel not found".into()))?;

        // Update cumulative to at least the required amount
        if required_cumulative > entry.cumulative_amount {
            entry.cumulative_amount = required_cumulative;
        }

        let payload = create_voucher_payload(
            &self.signer,
            entry.channel_id,
            entry.cumulative_amount,
            entry.escrow_contract,
            entry.chain_id,
        )
        .await?;

        // Update the registry
        self.channels.lock().unwrap().insert(key, entry.clone());
        self.notify_update(&entry);

        let credential =
            build_credential(&challenge, payload, entry.chain_id, self.signer.address());
        let auth_header = crate::protocol::core::format_authorization(&credential)?;

        let resp = client
            .post(url)
            .header("Authorization", auth_header)
            .send()
            .await
            .map_err(|e| MppError::Http(format!("voucher POST failed: {}", e)))?;

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

        let entry = {
            let channels = self.channels.lock().unwrap();
            channels.values().find(|e| e.opened).cloned()
        };

        let entry = match entry {
            Some(e) => e,
            None => return Ok(None),
        };

        let payer = self.signer.address();

        let payload = create_close_payload(
            &self.signer,
            entry.channel_id,
            entry.cumulative_amount,
            entry.escrow_contract,
            entry.chain_id,
        )
        .await?;

        let credential = build_credential(&challenge, payload, entry.chain_id, payer);

        let auth_header = crate::protocol::core::format_authorization(&credential)?;

        let resp = client
            .post(url)
            .header("Authorization", auth_header)
            .send()
            .await
            .map_err(|e| MppError::Http(format!("close request failed: {}", e)))?;

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
        method == "tempo" && intent == "session"
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        use alloy::providers::ProviderBuilder;
        use tempo_alloy::TempoNetwork;

        *self.last_challenge.lock().unwrap() = Some(challenge.clone());

        let chain_id = resolve_chain_id(challenge);
        let escrow_contract = resolve_escrow(challenge, chain_id, self.escrow_contract)?;

        let session_req: SessionRequest = challenge.request.decode().map_err(|e| {
            MppError::InvalidConfig(format!("failed to decode session request: {}", e))
        })?;

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
        let key = Self::channel_key(&payee, &currency, &escrow_contract);

        // Check if we already have a channel
        let existing = self.channels.lock().unwrap().get(&key).cloned();

        if let Some(mut entry) = existing {
            if entry.opened {
                // Increment cumulative and sign a voucher
                entry.cumulative_amount += amount;

                let payload = create_voucher_payload(
                    &self.signer,
                    entry.channel_id,
                    entry.cumulative_amount,
                    escrow_contract,
                    chain_id,
                )
                .await?;

                // Update the registry
                self.channels.lock().unwrap().insert(key, entry.clone());
                self.notify_update(&entry);

                return Ok(build_credential(challenge, payload, chain_id, payer));
            }
        }

        // Try to recover a channel from on-chain state if suggested
        let suggested_channel_id = session_req.channel_id();
        if let Some(ref cid_str) = suggested_channel_id {
            if let Ok(cid) = cid_str.parse::<B256>() {
                let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
                    .connect_http(self.rpc_url.clone());

                if let Some(mut recovered) =
                    try_recover_channel(&provider, escrow_contract, cid, chain_id).await
                {
                    // Start from recovered settled amount + request amount
                    recovered.cumulative_amount += amount;

                    let payload = create_voucher_payload(
                        &self.signer,
                        recovered.channel_id,
                        recovered.cumulative_amount,
                        escrow_contract,
                        chain_id,
                    )
                    .await?;

                    self.channel_id_to_key
                        .lock()
                        .unwrap()
                        .insert(format!("{}", recovered.channel_id), key.clone());
                    self.channels.lock().unwrap().insert(key, recovered.clone());
                    self.notify_update(&recovered);

                    return Ok(build_credential(challenge, payload, chain_id, payer));
                }
            }
        }

        // No existing channel — open a new one
        let deposit = self.resolve_deposit(session_req.suggested_deposit.as_deref())?;

        let provider =
            ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(self.rpc_url.clone());

        let (entry, payload) = create_open_payload(
            &provider,
            &self.signer,
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
        .await?;

        self.channel_id_to_key
            .lock()
            .unwrap()
            .insert(format!("{}", entry.channel_id), key.clone());
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

        let key = TempoSessionProvider::channel_key(&payee, &currency, &escrow);
        // Should be lowercase
        assert_eq!(key, key.to_lowercase());
        // Should contain all three addresses separated by colons
        assert_eq!(key.matches(':').count(), 2);
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

    // --- send_voucher error paths ---

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
}
