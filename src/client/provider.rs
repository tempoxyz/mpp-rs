//! Payment provider trait and implementations.
//!
//! The `PaymentProvider` trait abstracts over payment execution, allowing
//! different payment methods (Tempo, Stripe, etc.) to be used with the
//! HTTP client extensions.

use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use std::future::Future;

/// Trait for payment providers that can execute payments for challenges.
///
/// Implement this trait to add support for custom payment methods.
/// PaymentProvider is the client-side counterpart to server-side method traits
/// like [`ChargeMethod`](crate::protocol::traits::ChargeMethod).
///
/// # Examples
///
/// ```ignore
/// use mpp::client::PaymentProvider;
/// use mpp::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};
/// use mpp::MppError;
///
/// #[derive(Clone)]
/// struct MyProvider { /* ... */ }
///
/// impl PaymentProvider for MyProvider {
///     fn supports(&self, method: &str, intent: &str) -> bool {
///         method == "my_network" && intent == "charge"
///     }
///
///     async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
///         // 1. Parse the challenge request
///         // 2. Execute payment (sign tx, call API, etc.)
///         // 3. Return credential with proof
///         let echo = challenge.to_echo();
///         Ok(PaymentCredential::new(echo, PaymentPayload::hash("0x...")))
///     }
/// }
/// ```
pub trait PaymentProvider: Clone + Send + Sync {
    /// Check if this provider supports the given method and intent combination.
    ///
    /// This allows clients to filter providers based on challenge requirements
    /// before attempting payment.
    ///
    /// # Arguments
    ///
    /// * `method` - Payment method name (e.g., "tempo", "stripe")
    /// * `intent` - Payment intent name (e.g., "charge", "authorize")
    ///
    /// # Returns
    ///
    /// `true` if this provider can handle the combination.
    fn supports(&self, method: &str, intent: &str) -> bool;

    /// Execute payment for the given challenge and return a credential.
    ///
    /// This method should:
    /// 1. Parse the challenge request for payment details
    /// 2. Execute the payment (sign transaction, call API, etc.)
    /// 3. Build and return a `PaymentCredential` with the proof
    fn pay(
        &self,
        challenge: &PaymentChallenge,
    ) -> impl Future<Output = Result<PaymentCredential, MppError>> + Send;
}

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
#[cfg(feature = "tempo")]
#[derive(Clone)]
pub struct TempoProvider {
    signer: alloy_signer_local::PrivateKeySigner,
    rpc_url: reqwest::Url,
    client_id: Option<String>,
}

#[cfg(feature = "tempo")]
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
        })
    }

    /// Set an optional client identifier for attribution memos.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
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

#[cfg(feature = "tempo")]
impl PaymentProvider for TempoProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == "tempo" && intent == "charge"
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        use crate::protocol::core::PaymentPayload;
        use crate::protocol::intents::ChargeRequest;
        use crate::protocol::methods::tempo::{TempoChargeExt, CHAIN_ID};
        use alloy::eips::Encodable2718;
        use alloy::primitives::{Bytes, TxKind, B256};
        use alloy::providers::{Provider, ProviderBuilder};
        use alloy::sol_types::SolCall;
        use tempo_alloy::contracts::precompiles::tip20::ITIP20;
        use tempo_alloy::TempoNetwork;
        use tempo_primitives::transaction::Call;
        use tempo_primitives::TempoTransaction;

        let charge: ChargeRequest = challenge.request.decode()?;
        let expected_chain_id = charge.chain_id().unwrap_or(CHAIN_ID);
        let is_fee_payer = charge.fee_payer();
        let address = self.signer.address();

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

        // Use user memo if valid 32-byte hex, otherwise auto-generate attribution memo.
        let memo: B256 = charge
            .memo()
            .and_then(|m| m.parse().ok())
            .unwrap_or_else(|| {
                crate::tempo::attribution::encode(&challenge.realm, self.client_id.as_deref())
                    .into()
            });

        let transfer_data =
            ITIP20::transferWithMemoCall::new((recipient, amount, memo)).abi_encode();

        let nonce = provider
            .get_transaction_count(address)
            .await
            .map_err(|e| MppError::Http(format!("failed to get nonce: {}", e)))?;

        let gas_price = provider
            .get_gas_price()
            .await
            .map_err(|e| MppError::Http(format!("failed to get gas price: {}", e)))?;

        // When feePayer is true, set a placeholder fee_payer_signature so the
        // signing hash commits to "fee payer expected" and the serialized tx
        // includes the 0x00 placeholder byte the server expects.
        let fee_payer_signature = if is_fee_payer {
            Some(alloy::primitives::Signature::new(
                alloy::primitives::U256::ZERO,
                alloy::primitives::U256::ZERO,
                false,
            ))
        } else {
            None
        };

        // Build a Tempo transaction (type 0x76) for proper on-chain processing.
        let tempo_tx = TempoTransaction {
            chain_id: expected_chain_id,
            nonce,
            gas_limit: 1_000_000,
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: gas_price,
            calls: vec![Call {
                to: TxKind::Call(currency),
                value: alloy::primitives::U256::ZERO,
                input: Bytes::from(transfer_data),
            }],
            fee_payer_signature,
            ..Default::default()
        };

        use alloy::signers::SignerSync;
        let sig_hash = tempo_tx.signature_hash();
        let signature = self
            .signer
            .sign_hash_sync(&sig_hash)
            .map_err(|e| MppError::Http(format!("failed to sign transaction: {}", e)))?;

        let signed_tx_hex = if is_fee_payer {
            let tx_bytes =
                encode_fee_payer_proxy_tx(&tempo_tx, &signature, address);
            format!("0x{}", hex::encode(&tx_bytes))
        } else {
            let signed_tx = tempo_tx.into_signed(signature.into());
            let tx_bytes = signed_tx.encoded_2718();
            format!("0x{}", hex::encode(&tx_bytes))
        };

        let echo = challenge.to_echo();

        Ok(PaymentCredential::with_source(
            echo,
            format!("did:pkh:eip155:{}:{}", expected_chain_id, address),
            PaymentPayload::transaction(signed_tx_hex),
        ))
    }
}

/// Encode a fee-payer transaction in the wire format expected by the fee-payer
/// proxy server (viem convention).
///
/// `encoded_2718()` encodes `fee_payer_signature` as a full `[v, r, s]` RLP list,
/// but the proxy expects the `0x00` placeholder byte (same as `encode_for_signing`)
/// so it knows where to inject its own signature.
///
/// Output format: `0x76 || rlp([fields…, 0x00 placeholder, user_sig]) || sender || feefeefeefee`
///
/// TODO: push this into `tempo-primitives` as a first-class encoder so downstream
/// crates don't need to do manual RLP manipulation.
#[cfg(feature = "tempo")]
fn encode_fee_payer_proxy_tx(
    tx: &tempo_primitives::TempoTransaction,
    user_sig: &alloy::primitives::PrimitiveSignature,
    sender: alloy::primitives::Address,
) -> Vec<u8> {
    use alloy::consensus::SignableTransaction;
    use tempo_primitives::transaction::TEMPO_TX_TYPE_ID;

    // encode_for_signing gives us: 0x76 || rlp([fields…, 0x00 placeholder])
    let mut signing_buf = Vec::new();
    tx.encode_for_signing(&mut signing_buf);

    // Strip type byte (0x76), decode the RLP list header to isolate the fields payload.
    let rlp_data = &signing_buf[1..];
    let fields_payload = if rlp_data[0] < 0xf8 {
        let len = (rlp_data[0] - 0xc0) as usize;
        &rlp_data[1..1 + len]
    } else {
        let len_of_len = (rlp_data[0] - 0xf7) as usize;
        let mut len = 0usize;
        for &b in &rlp_data[1..1 + len_of_len] {
            len = (len << 8) | b as usize;
        }
        &rlp_data[1 + len_of_len..1 + len_of_len + len]
    };

    // User signature as 65 bytes (r || s || v).
    let sig_bytes = {
        let mut buf = [0u8; 65];
        buf[..32].copy_from_slice(&user_sig.r().to_be_bytes::<32>());
        buf[32..64].copy_from_slice(&user_sig.s().to_be_bytes::<32>());
        buf[64] = user_sig.v() as u8;
        buf
    };

    // New RLP list = fields_payload ++ RLP-encoded signature bytestring.
    let sig_rlp_len = 1 + 1 + 65; // 0xb8 prefix + length byte + 65 data bytes
    let new_payload_len = fields_payload.len() + sig_rlp_len;

    let mut out = Vec::with_capacity(1 + 4 + new_payload_len + 20 + 6);
    out.push(TEMPO_TX_TYPE_ID);

    // RLP list header.
    if new_payload_len < 56 {
        out.push(0xc0 + new_payload_len as u8);
    } else {
        let len_bytes = new_payload_len.to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num_len_bytes = 8 - start;
        out.push(0xf7 + num_len_bytes as u8);
        out.extend_from_slice(&len_bytes[start..]);
    }

    out.extend_from_slice(fields_payload);

    // Signature as RLP byte string (65 bytes, uses long-string prefix).
    out.push(0xb8);
    out.push(65);
    out.extend_from_slice(&sig_bytes);

    // Viem convention suffix: sender address + fee marker.
    out.extend_from_slice(sender.as_slice());
    out.extend_from_slice(&[0xfe, 0xef, 0xee, 0xfe, 0xef, 0xee]);

    out
}

/// A provider that wraps multiple payment providers and picks the right one.
///
/// `MultiProvider` iterates through its providers and uses the first one that
/// supports the challenge's method and intent combination.
///
/// # Examples
///
/// ```ignore
/// use mpp::client::{MultiProvider, TempoProvider};
///
/// let provider = MultiProvider::new()
///     .with(TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?);
///
/// // Automatically picks the right provider based on challenge.method
/// let resp = client.get(url).send_with_payment(&provider).await?;
/// ```
#[derive(Clone)]
pub struct MultiProvider {
    providers: Vec<Box<dyn DynPaymentProvider>>,
}

impl MultiProvider {
    /// Create a new empty multi-provider.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a provider to the list.
    pub fn with<P: PaymentProvider + 'static>(mut self, provider: P) -> Self {
        self.providers.push(Box::new(provider));
        self
    }

    /// Add a provider to the list (mutable reference version).
    pub fn add<P: PaymentProvider + 'static>(&mut self, provider: P) -> &mut Self {
        self.providers.push(Box::new(provider));
        self
    }

    /// Check if any provider supports the given method and intent.
    pub fn has_support(&self, method: &str, intent: &str) -> bool {
        self.providers
            .iter()
            .any(|p| p.dyn_supports(method, intent))
    }
}

impl Default for MultiProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl PaymentProvider for MultiProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        self.has_support(method, intent)
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        let method = challenge.method.as_str();
        let intent = challenge.intent.as_str();

        for provider in &self.providers {
            if provider.dyn_supports(method, intent) {
                return provider.dyn_pay(challenge).await;
            }
        }

        Err(MppError::UnsupportedPaymentMethod(format!(
            "no provider supports method={}, intent={}",
            method, intent
        )))
    }
}

/// Object-safe version of PaymentProvider for use in MultiProvider.
trait DynPaymentProvider: Send + Sync {
    fn dyn_supports(&self, method: &str, intent: &str) -> bool;
    fn dyn_pay<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PaymentCredential, MppError>> + Send + 'a>>;
    fn clone_box(&self) -> Box<dyn DynPaymentProvider>;
}

impl<P: PaymentProvider + 'static> DynPaymentProvider for P {
    fn dyn_supports(&self, method: &str, intent: &str) -> bool {
        PaymentProvider::supports(self, method, intent)
    }

    fn dyn_pay<'a>(
        &'a self,
        challenge: &'a PaymentChallenge,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<PaymentCredential, MppError>> + Send + 'a>>
    {
        Box::pin(PaymentProvider::pay(self, challenge))
    }

    fn clone_box(&self) -> Box<dyn DynPaymentProvider> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn DynPaymentProvider> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockProvider {
        method: &'static str,
        intent: &'static str,
    }

    impl PaymentProvider for MockProvider {
        fn supports(&self, method: &str, intent: &str) -> bool {
            self.method == method && self.intent == intent
        }

        async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
            use crate::protocol::core::PaymentPayload;
            Ok(PaymentCredential::new(
                challenge.to_echo(),
                PaymentPayload::hash(format!("mock-{}", self.method)),
            ))
        }
    }

    #[test]
    fn test_multi_provider_supports() {
        let multi = MultiProvider::new()
            .with(MockProvider {
                method: "tempo",
                intent: "charge",
            })
            .with(MockProvider {
                method: "stripe",
                intent: "charge",
            });

        assert!(multi.has_support("tempo", "charge"));
        assert!(multi.has_support("stripe", "charge"));
        assert!(!multi.has_support("bitcoin", "charge"));
        assert!(!multi.has_support("tempo", "authorize"));
    }

    #[test]
    fn test_multi_provider_empty() {
        let multi = MultiProvider::new();
        assert!(!multi.has_support("tempo", "charge"));
    }

    #[test]
    fn test_multi_provider_clone() {
        let multi = MultiProvider::new().with(MockProvider {
            method: "tempo",
            intent: "charge",
        });

        let cloned = multi.clone();
        assert!(cloned.has_support("tempo", "charge"));
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_tempo_provider_new() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer.clone(), "https://rpc.example.com").unwrap();

        assert_eq!(provider.rpc_url().as_str(), "https://rpc.example.com/");
        assert_eq!(provider.signer().address(), signer.address());
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_tempo_provider_invalid_url() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let result = TempoProvider::new(signer, "not a url");
        assert!(result.is_err());
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_tempo_provider_with_client_id() {
        let signer = alloy_signer_local::PrivateKeySigner::random();
        let provider = TempoProvider::new(signer, "https://rpc.example.com")
            .unwrap()
            .with_client_id("my-app");

        assert_eq!(provider.client_id.as_deref(), Some("my-app"));
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_auto_generated_memo_is_mpp_memo() {
        let memo = crate::tempo::attribution::encode("api.example.com", Some("my-app"));
        assert!(crate::tempo::attribution::is_mpp_memo(&memo));
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn test_user_memo_takes_precedence() {
        let user_memo = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let hex_str = user_memo.strip_prefix("0x").unwrap();
        let bytes = hex::decode(hex_str).unwrap();
        let memo_bytes: [u8; 32] = bytes.try_into().unwrap();

        assert!(!crate::tempo::attribution::is_mpp_memo(&memo_bytes));
    }
}
