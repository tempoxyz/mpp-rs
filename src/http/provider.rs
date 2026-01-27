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
/// use mpay::client::PaymentProvider;
/// use mpay::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};
/// use mpay::MppError;
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
/// Executes payments on the Tempo blockchain by building and signing
/// TempoTransactions (type 0x76) for charge requests.
///
/// This provider:
/// 1. Parses the charge request from the challenge
/// 2. Builds and signs a TempoTransaction using the provided signer
/// 3. Submits it via the Tempo RPC endpoint
/// 4. Returns a credential with the transaction hash
///
/// # Features
///
/// - **ERC-20 Transfers**: Handles both native transfers and ERC-20 token transfers
/// - **Fee Sponsorship**: Supports server-paid fees when `feePayer: true`
///
/// # Examples
///
/// ```ignore
/// use mpay::client::tempo::Provider;
/// use mpay::PrivateKeySigner;
///
/// let signer = PrivateKeySigner::from_bytes(&key)?;
/// let provider = Provider::new(signer, "https://rpc.moderato.tempo.xyz")?;
///
/// // Use with PaymentExt
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
        })
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
        use crate::protocol::methods::tempo::{TempoChargeExt, TempoTransactionRequest, CHAIN_ID};
        use alloy::network::{EthereumWallet, ReceiptResponse, TransactionBuilder};
        use alloy::providers::{Provider, ProviderBuilder};
        use tempo_alloy::TempoNetwork;

        let charge: ChargeRequest = challenge.request.decode()?;
        let expected_chain_id = charge.chain_id().unwrap_or(CHAIN_ID);
        let address = self.signer.address();

        let wallet = EthereumWallet::from(self.signer.clone());
        let provider = ProviderBuilder::new_with_network::<TempoNetwork>()
            .wallet(wallet)
            .connect_http(self.rpc_url.clone());

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

        let tx_hash = if currency == alloy::primitives::Address::ZERO {
            let mut tx = TempoTransactionRequest::default();
            tx.set_to(recipient);
            tx.set_value(amount);

            let pending = provider
                .send_transaction(tx)
                .await
                .map_err(|e| MppError::Http(format!("transaction send failed: {}", e)))?;

            let tx_hash = *pending.tx_hash();

            let receipt = pending
                .get_receipt()
                .await
                .map_err(|e| MppError::Http(format!("failed to get receipt: {}", e)))?;

            if !receipt.status() {
                return Err(MppError::TransactionReverted(format!(
                    "transaction {:#x} reverted",
                    tx_hash
                )));
            }

            tx_hash
        } else {
            use alloy::sol;

            sol! {
                #[sol(rpc)]
                interface IERC20 {
                    function transfer(address to, uint256 amount) external returns (bool);
                }
            }

            let token = IERC20::new(currency, &provider);
            let call = token.transfer(recipient, amount);

            let pending = call
                .send()
                .await
                .map_err(|e| MppError::Http(format!("token transfer send failed: {}", e)))?;

            let tx_hash = *pending.tx_hash();

            let receipt = pending
                .get_receipt()
                .await
                .map_err(|e| MppError::Http(format!("failed to get receipt: {}", e)))?;

            if !receipt.status() {
                return Err(MppError::TransactionReverted(format!(
                    "token transfer {:#x} reverted",
                    tx_hash
                )));
            }

            tx_hash
        };

        let echo = challenge.to_echo();

        Ok(PaymentCredential::with_source(
            echo,
            format!("did:pkh:eip155:{}:{}", expected_chain_id, address),
            PaymentPayload::hash(format!("{:#x}", tx_hash)),
        ))
    }
}

#[cfg(all(test, feature = "tempo"))]
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
}
