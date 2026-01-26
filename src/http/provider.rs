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
///
/// # Examples
///
/// ```ignore
/// use mpay::http::PaymentProvider;
/// use mpay::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};
/// use mpay::MppError;
///
/// #[derive(Clone)]
/// struct MyProvider { /* ... */ }
///
/// impl PaymentProvider for MyProvider {
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
/// transactions for the charge request.
///
/// This provider:
/// 1. Parses the charge request from the challenge
/// 2. Builds and signs a transaction using the provided signer
/// 3. Submits it via the RPC endpoint
/// 4. Returns a credential with the transaction hash
///
/// # Examples
///
/// ```ignore
/// use mpay::http::TempoProvider;
/// use mpay::PrivateKeySigner;
///
/// let signer = PrivateKeySigner::from_bytes(&key)?;
/// let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz");
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
    rpc_url: String,
}

#[cfg(feature = "tempo")]
impl TempoProvider {
    /// Create a new Tempo provider with the given signer and RPC URL.
    pub fn new(signer: alloy_signer_local::PrivateKeySigner, rpc_url: impl Into<String>) -> Self {
        Self {
            signer,
            rpc_url: rpc_url.into(),
        }
    }

    /// Get a reference to the signer.
    pub fn signer(&self) -> &alloy_signer_local::PrivateKeySigner {
        &self.signer
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &str {
        &self.rpc_url
    }
}

#[cfg(feature = "tempo")]
impl PaymentProvider for TempoProvider {
    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        use crate::protocol::core::{ChallengeEcho, PaymentPayload};
        use crate::protocol::intents::ChargeRequest;
        use crate::protocol::methods::tempo::{TempoChargeExt, CHAIN_ID};
        use alloy::network::EthereumWallet;
        use alloy::providers::{Provider, ProviderBuilder};


        let charge: ChargeRequest = challenge.request.decode()?;
        let chain_id = charge.chain_id().unwrap_or(CHAIN_ID);
        let address = self.signer.address();

        let wallet = EthereumWallet::from(self.signer.clone());
        let url: reqwest::Url = self
            .rpc_url
            .parse()
            .map_err(|e| MppError::Http(format!("Invalid RPC URL: {}", e)))?;

        let provider = ProviderBuilder::new().wallet(wallet).connect_http(url);

        let recipient = charge.recipient_address()?;
        let amount = charge.amount_u256()?;
        let currency = charge.currency_address()?;

        let tx_hash = if currency == alloy::primitives::Address::ZERO {
            let tx = alloy::rpc::types::TransactionRequest::default()
                .to(recipient)
                .value(amount);

            provider
                .send_transaction(tx)
                .await
                .map_err(|e| MppError::Http(format!("Transaction failed: {}", e)))?
                .watch()
                .await
                .map_err(|e| MppError::Http(format!("Transaction not confirmed: {}", e)))?
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

            call.send()
                .await
                .map_err(|e| MppError::Http(format!("Token transfer failed: {}", e)))?
                .watch()
                .await
                .map_err(|e| MppError::Http(format!("Token transfer not confirmed: {}", e)))?
        };

        let echo = ChallengeEcho {
            id: challenge.id.clone(),
            realm: challenge.realm.clone(),
            method: challenge.method.clone(),
            intent: challenge.intent.clone(),
            request: challenge.request.raw().to_string(),
            digest: challenge.digest.clone(),
            expires: challenge.expires.clone(),
        };

        Ok(PaymentCredential::with_source(
            echo,
            format!("did:pkh:eip155:{}:{}", chain_id, address),
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
        let provider = TempoProvider::new(signer.clone(), "https://rpc.example.com");

        assert_eq!(provider.rpc_url(), "https://rpc.example.com");
        assert_eq!(provider.signer().address(), signer.address());
    }
}
