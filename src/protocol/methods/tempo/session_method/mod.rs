//! Server-side session payment verification for Tempo.
//!
//! Implements the `SessionMethod` trait for Tempo session payments (pay-as-you-go).
//! Handles four channel lifecycle actions: open, topUp, voucher, close.
//!
//! Ported from the TypeScript SDK's `Session.ts`.

mod chain;
mod close;
mod open;
mod payload;
mod receipt;
mod state;
mod store;
mod top_up;
mod voucher;

pub use chain::OnChainChannel;
pub(crate) use store::normalize_channel_id;
pub use store::{deduct_from_channel, ChannelState, ChannelStore, InMemoryChannelStore};

use alloy::primitives::Address;
use std::sync::Arc;

use alloy::providers::Provider;
use tempo_alloy::TempoNetwork;

use super::session::{SessionCredentialPayload, TempoSessionMethodDetails};
use super::{INTENT_SESSION, METHOD_NAME};
use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::SessionRequest;
use crate::protocol::traits::{SessionMethod as SessionMethodTrait, VerificationError};

/// Configuration for the Tempo session method.
#[derive(Debug, Clone)]
pub struct SessionMethodConfig {
    /// Default escrow contract address.
    pub escrow_contract: Address,
    /// Default chain ID.
    pub chain_id: u64,
    /// Minimum voucher delta to accept (in base units). Default: 0.
    pub min_voucher_delta: u128,
}

/// Tempo session method for server-side session payment verification.
///
/// Handles four channel lifecycle actions:
/// - `open`: verify open tx and initial voucher, broadcast, create channel in store
/// - `topUp`: verify topUp tx, broadcast, update deposit in store
/// - `voucher`: verify voucher signature, check monotonicity/bounds/delta, update store
/// - `close`: verify final voucher, close on-chain, finalize in store
///
/// Every action returns a session receipt: the [`Receipt`] references the
/// channel and carries the [`SessionReceipt`](super::SessionReceipt) fields (`challengeId`,
/// `acceptedCumulative`, `spent`, `txHash`, ...) as extension fields.
#[derive(Clone)]
pub struct SessionMethod<P> {
    provider: Arc<P>,
    store: Arc<dyn ChannelStore>,
    config: SessionMethodConfig,
    /// Signer for submitting on-chain close transactions. `close` is rejected
    /// when unset.
    close_signer: Option<Arc<super::DynSigner>>,
}

impl<P> SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    /// Create a new Tempo session method.
    ///
    /// Call [`with_close_signer`](Self::with_close_signer) to let the method
    /// settle `close` credentials on-chain; without it they are rejected.
    pub fn new(provider: P, store: Arc<dyn ChannelStore>, config: SessionMethodConfig) -> Self {
        Self {
            provider: Arc::new(provider),
            store,
            config,
            close_signer: None,
        }
    }

    /// Set the signer used for submitting on-chain close transactions.
    ///
    /// Required to accept `close` credentials: a channel is only finalized
    /// once its close transaction succeeded on-chain.
    pub fn with_close_signer<S>(mut self, signer: S) -> Self
    where
        S: alloy::signers::Signer + Send + Sync + 'static,
    {
        self.close_signer = Some(Arc::new(signer));
        self
    }

    /// Get the session method configuration.
    pub fn config(&self) -> &SessionMethodConfig {
        &self.config
    }

    /// Get the method details from the session request, with fallbacks to config.
    fn resolve_method_details(
        &self,
        request: &SessionRequest,
    ) -> Result<TempoSessionMethodDetails, VerificationError> {
        use super::session::TempoSessionExt;

        match request.tempo_session_details() {
            Ok(details) => Ok(details),
            Err(_) => Ok(TempoSessionMethodDetails {
                escrow_contract: format!("{:#x}", self.config.escrow_contract),
                chain_id: Some(self.config.chain_id),
                channel_id: None,
                min_voucher_delta: None,
                fee_payer: None,
                machine_token_enabled: None,
                settlement_adapter: None,
                settlement_recipient: None,
                settlement_token: None,
                operator: None,
                session_protocol: None,
                session_snapshot: None,
            }),
        }
    }

    /// Resolve the escrow contract address from method details or config.
    fn resolve_escrow(
        &self,
        details: &TempoSessionMethodDetails,
    ) -> Result<Address, VerificationError> {
        Self::parse_address(&details.escrow_contract)
    }

    /// Resolve the chain ID from method details or config.
    fn resolve_chain_id(&self, details: &TempoSessionMethodDetails) -> u64 {
        details.chain_id.unwrap_or(self.config.chain_id)
    }

    /// Resolve the effective minimum voucher delta.
    fn resolve_min_delta(&self, details: &TempoSessionMethodDetails) -> u128 {
        details
            .min_voucher_delta
            .as_ref()
            .and_then(|s| s.parse::<u128>().ok())
            .unwrap_or(self.config.min_voucher_delta)
    }
}

impl<P> SessionMethodTrait for SessionMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    fn method(&self) -> &str {
        METHOD_NAME
    }

    fn challenge_method_details(&self) -> Option<serde_json::Value> {
        let details = super::session::TempoSessionMethodDetails {
            escrow_contract: format!("{:#x}", self.config.escrow_contract),
            chain_id: Some(self.config.chain_id),
            min_voucher_delta: Some(self.config.min_voucher_delta.to_string()),
            channel_id: None,
            fee_payer: None,
            machine_token_enabled: None,
            settlement_adapter: None,
            settlement_recipient: None,
            settlement_token: None,
            operator: None,
            session_protocol: None,
            session_snapshot: None,
        };
        serde_json::to_value(details).ok()
    }

    fn respond(
        &self,
        credential: &PaymentCredential,
        _receipt: &Receipt,
    ) -> Option<serde_json::Value> {
        // Management actions (open, topUp, close) short-circuit normal response handling.
        // Only voucher actions proceed to content delivery.
        let payload: SessionCredentialPayload = credential.payload_as().ok()?;
        match payload {
            SessionCredentialPayload::Voucher { .. } => None,
            _ => Some(serde_json::json!({ "status": "ok" })),
        }
    }

    async fn verify_session(
        &self,
        credential: &PaymentCredential,
        request: &SessionRequest,
    ) -> Result<Receipt, VerificationError> {
        if credential.challenge.method.as_str() != METHOD_NAME {
            return Err(VerificationError::credential_mismatch(format!(
                "Method mismatch: expected {}, got {}",
                METHOD_NAME, credential.challenge.method
            )));
        }
        if credential.challenge.intent.as_str() != INTENT_SESSION {
            return Err(VerificationError::credential_mismatch(format!(
                "Intent mismatch: expected {}, got {}",
                INTENT_SESSION, credential.challenge.intent
            )));
        }

        let details = self.resolve_method_details(request)?;

        let merchant = request
            .recipient
            .as_deref()
            .ok_or_else(|| {
                VerificationError::invalid_payload("session challenge missing recipient")
            })
            .and_then(Self::parse_address)?;
        let target_token = Self::parse_address(&request.currency)?;
        let (expected_payee, expected_token) = if details.machine_token_enabled == Some(true) {
            let (_, swapper) = crate::protocol::methods::tempo::machine_token::session_addresses(
                self.resolve_chain_id(&details),
            )
            .ok_or_else(|| {
                VerificationError::invalid_payload(
                    "machine tokens are unsupported on the session chain",
                )
            })?;
            if details.settlement_adapter.as_deref() != Some(&swapper.to_string())
                || details.settlement_recipient.as_deref() != Some(&merchant.to_string())
                || details.settlement_token.as_deref() != Some(&target_token.to_string())
            {
                return Err(VerificationError::credential_mismatch(
                    "machine-token settlement route does not match the session request",
                ));
            }
            crate::protocol::methods::tempo::machine_token::session_addresses(
                self.resolve_chain_id(&details),
            )
            .map(|(token, swapper)| (swapper, token))
            .ok_or_else(|| {
                VerificationError::invalid_payload(
                    "machine tokens are unsupported on the session chain",
                )
            })?
        } else {
            (merchant, target_token)
        };

        let payload: SessionCredentialPayload = credential.payload_as().map_err(|e| {
            VerificationError::invalid_payload(format!("Expected session payload: {}", e))
        })?;

        match &payload {
            SessionCredentialPayload::Open { .. } => {
                let amount = request.parse_amount().map_err(|_| {
                    VerificationError::invalid_challenge(format!(
                        "invalid session amount: {}",
                        request.amount
                    ))
                })?;
                self.handle_open(
                    credential,
                    &payload,
                    &details,
                    expected_payee,
                    expected_token,
                    amount,
                )
                .await
            }
            SessionCredentialPayload::TopUp { .. } => {
                self.handle_top_up(
                    credential,
                    &payload,
                    &details,
                    expected_payee,
                    expected_token,
                )
                .await
            }
            SessionCredentialPayload::Voucher { .. } => {
                self.handle_voucher(
                    credential,
                    &payload,
                    &details,
                    expected_payee,
                    expected_token,
                )
                .await
            }
            SessionCredentialPayload::Close { .. } => {
                self.handle_close(
                    credential,
                    &payload,
                    &details,
                    expected_payee,
                    expected_token,
                )
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests;
