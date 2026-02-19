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
/// Nonce key for expiring nonce transactions (fee payer mode).
#[cfg(feature = "tempo")]
const EXPIRING_NONCE_KEY: alloy::primitives::U256 = alloy::primitives::U256::MAX;

/// Validity window (in seconds) for fee payer transactions.
#[cfg(feature = "tempo")]
const FEE_PAYER_VALID_BEFORE_SECS: u64 = 25;

/// Type byte for the fee payer envelope format.
#[cfg(feature = "tempo")]
const FEE_PAYER_TX_TYPE: u8 = 0x78;

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
        use alloy::primitives::{Bytes, TxKind, B256, U256};
        use alloy::providers::{Provider, ProviderBuilder};
        use alloy::sol_types::SolCall;
        use tempo_alloy::contracts::precompiles::tip20::ITIP20;
        use tempo_alloy::TempoNetwork;
        use tempo_primitives::transaction::Call;
        use tempo_primitives::TempoTransaction;

        let charge: ChargeRequest = challenge.request.decode()?;
        let expected_chain_id = charge.chain_id().unwrap_or(CHAIN_ID);
        let address = self.signer.address();
        let fee_payer = charge.fee_payer();

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

        // Fee payer mode: use expiring nonces to avoid nonce collisions
        // when the server broadcasts on the client's behalf.
        let (nonce_key, nonce, valid_before) = if fee_payer {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| MppError::Http(format!("system clock error: {}", e)))?
                .as_secs();
            // Expiring nonce transactions require nonce=0. Replay protection
            // comes from the valid_before window + tx hash, not the nonce value.
            (
                EXPIRING_NONCE_KEY,
                0u64,
                Some(now + FEE_PAYER_VALID_BEFORE_SECS),
            )
        } else {
            let n = provider
                .get_transaction_count(address)
                .await
                .map_err(|e| MppError::Http(format!("failed to get nonce: {}", e)))?;
            (U256::ZERO, n, None)
        };

        let gas_price = provider
            .get_gas_price()
            .await
            .map_err(|e| MppError::Http(format!("failed to get gas price: {}", e)))?;

        // Build a Tempo transaction (type 0x76) for proper on-chain processing.
        // When fee_payer is true:
        //   - fee_token is None (server chooses at co-sign time)
        //   - fee_payer_signature is a placeholder (triggers skip_fee_token in signing hash)
        //   - nonce_key = U256::MAX (expiring nonce)
        //   - valid_before is set to now + 25s
        let tempo_tx = TempoTransaction {
            chain_id: expected_chain_id,
            nonce,
            nonce_key,
            gas_limit: 1_000_000,
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: gas_price,
            fee_token: None,
            fee_payer_signature: if fee_payer {
                Some(alloy::primitives::Signature::new(
                    U256::ZERO,
                    U256::ZERO,
                    false,
                ))
            } else {
                None
            },
            valid_before,
            calls: vec![Call {
                to: TxKind::Call(currency),
                value: U256::ZERO,
                input: Bytes::from(transfer_data),
            }],
            ..Default::default()
        };

        use alloy::signers::SignerSync;
        let sig_hash = tempo_tx.signature_hash();
        let signature = self
            .signer
            .sign_hash_sync(&sig_hash)
            .map_err(|e| MppError::Http(format!("failed to sign transaction: {}", e)))?;

        let tx_bytes = if fee_payer {
            // Serialize as 0x78 fee payer envelope:
            // The server expects this format so it can co-sign before broadcasting.
            // Format: 0x78 || RLP([...tx_fields_with_sender_addr, client_signature])
            encode_fee_payer_envelope(&tempo_tx, address, signature.into())
        } else {
            let signed_tx = tempo_tx.into_signed(signature.into());
            signed_tx.encoded_2718()
        };
        let signed_tx_hex = format!("0x{}", hex::encode(&tx_bytes));

        let echo = challenge.to_echo();

        Ok(PaymentCredential::with_source(
            echo,
            format!("did:pkh:eip155:{}:{}", expected_chain_id, address),
            PaymentPayload::transaction(signed_tx_hex),
        ))
    }
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

/// Encode a fee payer envelope (0x78 format).
///
/// This produces the serialized bytes that the mppx server expects when
/// `feePayer: true`. The format is:
///
/// ```text
/// 0x78 || RLP([chainId, maxPriorityFeePerGas, maxFeePerGas, gas, calls,
///              accessList, nonceKey, nonce, validBefore, validAfter,
///              feeToken, senderAddress, authorizationList, signature])
/// ```
///
/// Key differences from the standard 0x76 format:
/// - Type prefix is 0x78 instead of 0x76
/// - The fee_payer_signature slot contains the sender address (not a placeholder)
/// - The fee_token is empty (server chooses at co-sign time)
#[cfg(feature = "tempo")]
fn encode_fee_payer_envelope(
    tx: &tempo_primitives::TempoTransaction,
    sender: alloy::primitives::Address,
    signature: tempo_primitives::transaction::TempoSignature,
) -> Vec<u8> {
    use alloy::primitives::bytes::BufMut;
    use alloy::rlp::{Encodable, EMPTY_STRING_CODE};

    let mut fields = Vec::new();

    tx.chain_id.encode(&mut fields);
    tx.max_priority_fee_per_gas.encode(&mut fields);
    tx.max_fee_per_gas.encode(&mut fields);
    tx.gas_limit.encode(&mut fields);
    tx.calls.encode(&mut fields);
    tx.access_list.encode(&mut fields);
    tx.nonce_key.encode(&mut fields);
    tx.nonce.encode(&mut fields);

    if let Some(vb) = tx.valid_before {
        vb.encode(&mut fields);
    } else {
        fields.put_u8(EMPTY_STRING_CODE);
    }
    if let Some(va) = tx.valid_after {
        va.encode(&mut fields);
    } else {
        fields.put_u8(EMPTY_STRING_CODE);
    }
    // feeToken — always empty in fee payer envelope
    fields.put_u8(EMPTY_STRING_CODE);
    // Sender address in the fee_payer_signature slot
    sender.encode(&mut fields);
    tx.tempo_authorization_list.encode(&mut fields);
    if let Some(key_auth) = &tx.key_authorization {
        key_auth.encode(&mut fields);
    }
    signature.encode(&mut fields);

    let rlp_header = alloy::rlp::Header {
        list: true,
        payload_length: fields.len(),
    };

    let mut out = Vec::with_capacity(1 + rlp_header.length() + fields.len());
    out.put_u8(FEE_PAYER_TX_TYPE);
    rlp_header.encode(&mut out);
    out.extend_from_slice(&fields);

    out
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
