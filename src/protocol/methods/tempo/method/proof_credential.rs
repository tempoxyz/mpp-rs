//! Proof credentials: a signed proof of account control for zero-amount challenges.

use alloy::primitives::Address;
use alloy::providers::Provider;
use tempo_alloy::contracts::precompiles::{IAccountKeychain, ACCOUNT_KEYCHAIN_ADDRESS};
use tempo_alloy::TempoNetwork;

use crate::protocol::core::PaymentCredential;
use crate::protocol::traits::VerificationError;

use super::super::proof;
use super::ChargeMethod;

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
            if key_info.expiry == 0 || key_info.isRevoked || key_info.expiry <= now_secs {
                return Err(VerificationError::new(
                    "Proof signature does not match source.",
                ));
            }
        }

        Ok(parsed_source.address)
    }

    pub(super) async fn reserve_proof_credential(
        &self,
        credential: &PaymentCredential,
    ) -> Result<(), VerificationError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let reserved = store
            .put_if_absent(
                &Self::proof_replay_key(credential),
                serde_json::Value::Bool(true),
            )
            .await
            .map_err(|e| VerificationError::internal(format!("Failed to record proof: {e}")))?;
        if !reserved {
            return Err(VerificationError::new(
                "Proof credential has already been used.",
            ));
        }
        Ok(())
    }

    /// Replay key for a proof credential: a challenge id is single-use, no
    /// matter which account or signature proves it.
    pub(super) fn proof_replay_key(credential: &PaymentCredential) -> String {
        format!("mpp:charge:proof:{}", credential.challenge.id)
    }
}
