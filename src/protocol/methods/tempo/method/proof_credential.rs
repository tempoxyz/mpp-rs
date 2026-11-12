//! Proof credentials: a signed proof of account control for zero-amount challenges.

use std::sync::Arc;

use alloy::primitives::Address;
use alloy::providers::Provider;
use tempo_alloy::contracts::precompiles::{IAccountKeychain, ACCOUNT_KEYCHAIN_ADDRESS};
use tempo_alloy::TempoNetwork;

use crate::protocol::core::PaymentCredential;
use crate::protocol::traits::VerificationError;
use crate::store::Store;

use super::super::proof;
use super::ChargeMethod;

const AUTHENTICATED_PROOF_DOMAIN: &str = "mpp:charge:proof-domain:authenticated-expiry";

/// Whether an AccountKeychain `getKey` answer names an active access key
/// for `signer` at `now_secs`, as Tempo's precompile defines it: the key ID
/// is non-zero and equals the signer, the key is not revoked, and it has not
/// expired. `getKey` answers a missing or revoked key with a blank entry
/// (key ID and expiry zero), so an expiry of 0 means the key does not exist;
/// a key that never expires is stored with `u64::MAX`. A key expires once
/// the time reaches its expiry.
pub(super) fn is_active_access_key(
    key_info: &IAccountKeychain::KeyInfo,
    signer: Address,
    now_secs: u64,
) -> bool {
    !key_info.keyId.is_zero()
        && key_info.keyId == signer
        && !key_info.isRevoked
        && key_info.expiry != 0
        && now_secs < key_info.expiry
}

impl<P> ChargeMethod<P>
where
    P: Provider<TempoNetwork> + Clone + Send + Sync + 'static,
{
    pub(super) async fn validate_proof_credential(
        &self,
        credential: &PaymentCredential,
        signature: &str,
        expected_chain_id: u64,
    ) -> Result<Address, VerificationError> {
        let source = credential
            .source
            .as_deref()
            .ok_or_else(|| VerificationError::new("Proof credential must include a source."))?;
        let parsed_source = proof::parse_proof_source(source)
            .map_err(|_| VerificationError::new("Proof credential source is invalid."))?;

        if parsed_source.chain_id != expected_chain_id {
            return Err(VerificationError::new(
                "Proof credential source is invalid.",
            ));
        }

        if !proof::verify_proof(
            parsed_source.address,
            expected_chain_id,
            &credential.challenge.id,
            &credential.challenge.realm,
            signature,
            parsed_source.address,
        ) {
            let recovered = proof::recover_proof_signer(
                parsed_source.address,
                expected_chain_id,
                &credential.challenge.id,
                &credential.challenge.realm,
                signature,
            )
            .map_err(|_| VerificationError::new("Proof signature does not match source."))?;

            let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, &*self.provider);
            let key_info = keychain
                .getKey(parsed_source.address, recovered)
                .call()
                .await
                .map_err(|_| VerificationError::new("Proof signature does not match source."))?;
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if !is_active_access_key(&key_info, recovered, now_secs) {
                return Err(VerificationError::new(
                    "Proof signature does not match source.",
                ));
            }
        }

        Ok(parsed_source.address)
    }

    /// The configured proof store, else the default one, which only
    /// HMAC-authenticated verification uses.
    pub(super) fn active_proof_store(&self) -> Option<&Arc<dyn Store>> {
        self.proof_store.as_ref().or(self
            .authenticated_proof_store
            .as_ref()
            .filter(|_| self.authenticated_expiry))
    }

    pub(super) async fn reserve_proof_credential(
        &self,
        credential: &PaymentCredential,
    ) -> Result<(), VerificationError> {
        let Some(store) = self.active_proof_store() else {
            return Ok(());
        };
        self.ensure_proof_domain().await?;
        let key = Self::proof_replay_key(credential);
        let value = serde_json::Value::Bool(true);
        let reservation = if let Some(expires) = credential
            .challenge
            .expires
            .as_deref()
            .filter(|_| self.authenticated_expiry)
        {
            let expires = time::OffsetDateTime::parse(
                expires,
                &time::format_description::well_known::Rfc3339,
            )
            .map_err(|_| VerificationError::invalid_challenge("Invalid proof challenge expiry."))?;
            // Retain beyond the challenge's acceptance window, including clock skew.
            let remaining = expires - time::OffsetDateTime::now_utc() + time::Duration::seconds(30);
            let ttl = std::time::Duration::try_from(remaining)
                .map_err(|_| VerificationError::expired("Proof challenge has expired."))?;
            store
                .put_if_absent(AUTHENTICATED_PROOF_DOMAIN, serde_json::Value::Bool(true))
                .await
                .map_err(|e| {
                    VerificationError::internal(format!("Failed to record proof domain: {e}"))
                })?;
            store.put_if_absent_with_ttl(&key, value, ttl)
        } else {
            // A challenge that never expires requires a permanent replay reservation.
            store.put_if_absent(&key, value)
        };
        let reserved = reservation
            .await
            .map_err(|e| VerificationError::internal(format!("Failed to record proof: {e}")))?;
        // A concurrent authenticated verifier may have enabled expiry while we awaited insertion.
        self.ensure_proof_domain().await?;
        if !reserved {
            return Err(VerificationError::credential_replayed(
                "Proof credential has already been used.",
            ));
        }
        Ok(())
    }

    async fn ensure_proof_domain(&self) -> Result<(), VerificationError> {
        if !self.authenticated_expiry {
            if let Some(store) = self.active_proof_store() {
                let authenticated = store.get(AUTHENTICATED_PROOF_DOMAIN).await.map_err(|e| {
                    VerificationError::internal(format!("Failed to read proof domain: {e}"))
                })?;
                if authenticated.is_some() {
                    return Err(VerificationError::invalid_challenge(
                        "This replay store requires HMAC-authenticated proof verification.",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Replay key for a proof credential: a challenge id is single-use, no
    /// matter which account or signature proves it.
    pub(super) fn proof_replay_key(credential: &PaymentCredential) -> String {
        format!("mpp:charge:proof:{}", credential.challenge.id)
    }
}
