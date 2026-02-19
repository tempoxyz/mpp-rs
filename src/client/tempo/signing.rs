//! Tempo transaction signing strategies.
//!
//! Provides [`TempoSigningMode`] for choosing between direct key signing
//! and keychain (access key) signing, plus helpers to sign and encode
//! Tempo transactions.

use alloy::primitives::Address;
use tempo_primitives::transaction::SignedKeyAuthorization;

use crate::error::MppError;

/// How to sign Tempo transactions.
///
/// # Variants
///
/// - `Direct` — the signer's address *is* the on-chain account.
/// - `Keychain` — the signer is an access key authorized to act on behalf
///   of `wallet`. Optionally includes a [`SignedKeyAuthorization`] to
///   atomically provision the key in the same transaction.
#[derive(Clone, Debug, Default)]
pub enum TempoSigningMode {
    /// Sign directly with the private key (signer IS the account).
    #[default]
    Direct,
    /// Sign via keychain (signer is an access key for `wallet`).
    Keychain {
        /// The wallet/account address that the signer is authorized to act for.
        wallet: Address,
        /// Optional signed key authorization to provision the key on-chain
        /// atomically with the first transaction.
        key_authorization: Option<Box<SignedKeyAuthorization>>,
    },
}

impl TempoSigningMode {
    /// Returns the effective `from` address for transactions.
    ///
    /// For `Direct` mode, returns the signer's own address.
    /// For `Keychain` mode, returns the wallet address.
    pub fn from_address(&self, signer_address: Address) -> Address {
        match self {
            TempoSigningMode::Direct => signer_address,
            TempoSigningMode::Keychain { wallet, .. } => *wallet,
        }
    }

    /// Returns the `key_authorization` if present (Keychain mode only).
    pub fn key_authorization(&self) -> Option<&SignedKeyAuthorization> {
        match self {
            TempoSigningMode::Direct => None,
            TempoSigningMode::Keychain {
                key_authorization, ..
            } => key_authorization.as_deref(),
        }
    }
}

/// Sign a [`TempoTransaction`] and return the EIP-2718 encoded bytes.
///
/// Uses the provided signing mode to produce either a primitive ECDSA
/// signature (direct) or a keychain envelope signature.
pub fn sign_and_encode(
    tx: tempo_primitives::transaction::TempoTransaction,
    signer: &impl alloy::signers::SignerSync,
    mode: &TempoSigningMode,
) -> Result<Vec<u8>, MppError> {
    use alloy::eips::Encodable2718;
    use tempo_primitives::transaction::{KeychainSignature, PrimitiveSignature, TempoSignature};

    let sig_hash = tx.signature_hash();
    let inner_signature = signer
        .sign_hash_sync(&sig_hash)
        .map_err(|e| MppError::Http(format!("failed to sign transaction: {}", e)))?;

    let tempo_signature = match mode {
        TempoSigningMode::Direct => {
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(inner_signature))
        }
        TempoSigningMode::Keychain { wallet, .. } => {
            let keychain_sig =
                KeychainSignature::new(*wallet, PrimitiveSignature::Secp256k1(inner_signature));
            TempoSignature::Keychain(keychain_sig)
        }
    };

    let signed_tx = tx.into_signed(tempo_signature);
    Ok(signed_tx.encoded_2718())
}

/// Async version of [`sign_and_encode`] for signers that require async signing.
pub async fn sign_and_encode_async(
    tx: tempo_primitives::transaction::TempoTransaction,
    signer: &(impl alloy::signers::Signer + Clone),
    mode: &TempoSigningMode,
) -> Result<Vec<u8>, MppError> {
    use alloy::eips::Encodable2718;
    use tempo_primitives::transaction::{KeychainSignature, PrimitiveSignature, TempoSignature};

    let sig_hash = tx.signature_hash();
    let inner_signature = signer
        .sign_hash(&sig_hash)
        .await
        .map_err(|e| MppError::Http(format!("failed to sign transaction: {}", e)))?;

    let tempo_signature = match mode {
        TempoSigningMode::Direct => {
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(inner_signature))
        }
        TempoSigningMode::Keychain { wallet, .. } => {
            let keychain_sig =
                KeychainSignature::new(*wallet, PrimitiveSignature::Secp256k1(inner_signature));
            TempoSignature::Keychain(keychain_sig)
        }
    };

    let signed_tx = tx.into_signed(tempo_signature);
    Ok(signed_tx.encoded_2718())
}
