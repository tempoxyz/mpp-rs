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

/// Build the [`TempoSignature`] for a given inner signature and signing mode.
fn build_tempo_signature(
    inner_signature: alloy::signers::Signature,
    mode: &TempoSigningMode,
) -> tempo_primitives::transaction::TempoSignature {
    use tempo_primitives::transaction::{KeychainSignature, PrimitiveSignature, TempoSignature};

    match mode {
        TempoSigningMode::Direct => {
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(inner_signature))
        }
        TempoSigningMode::Keychain { wallet, .. } => {
            let keychain_sig =
                KeychainSignature::new(*wallet, PrimitiveSignature::Secp256k1(inner_signature));
            TempoSignature::Keychain(keychain_sig)
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

    let sig_hash = tx.signature_hash();
    let inner_signature = signer
        .sign_hash_sync(&sig_hash)
        .map_err(|e| MppError::Http(format!("failed to sign transaction: {}", e)))?;

    let signed_tx = tx.into_signed(build_tempo_signature(inner_signature, mode));
    Ok(signed_tx.encoded_2718())
}

/// Async version of [`sign_and_encode`] for signers that require async signing.
pub async fn sign_and_encode_async(
    tx: tempo_primitives::transaction::TempoTransaction,
    signer: &(impl alloy::signers::Signer + Clone),
    mode: &TempoSigningMode,
) -> Result<Vec<u8>, MppError> {
    use alloy::eips::Encodable2718;

    let sig_hash = tx.signature_hash();
    let inner_signature = signer
        .sign_hash(&sig_hash)
        .await
        .map_err(|e| MppError::Http(format!("failed to sign transaction: {}", e)))?;

    let signed_tx = tx.into_signed(build_tempo_signature(inner_signature, mode));
    Ok(signed_tx.encoded_2718())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Bytes, TxKind, U256};
    use alloy::signers::local::PrivateKeySigner;
    use tempo_primitives::transaction::{AASigned, Call, TempoTransaction};

    fn test_signer() -> PrivateKeySigner {
        "0x1234567890123456789012345678901234567890123456789012345678901234"
            .parse()
            .unwrap()
    }

    fn test_tx() -> TempoTransaction {
        TempoTransaction {
            chain_id: 42431,
            nonce: 1,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_token: Some(Address::repeat_byte(0x33)),
            calls: vec![Call {
                to: TxKind::Call(Address::repeat_byte(0x22)),
                value: U256::ZERO,
                input: Bytes::from_static(&[0xaa, 0xbb]),
            }],
            nonce_key: U256::ZERO,
            key_authorization: None,
            access_list: Default::default(),
            fee_payer_signature: None,
            valid_before: None,
            valid_after: None,
            tempo_authorization_list: vec![],
        }
    }

    // --- TempoSigningMode ---

    #[test]
    fn test_default_is_direct() {
        assert!(matches!(
            TempoSigningMode::default(),
            TempoSigningMode::Direct
        ));
    }

    #[test]
    fn test_from_address_direct() {
        let mode = TempoSigningMode::Direct;
        let signer_addr = Address::repeat_byte(0x01);
        assert_eq!(mode.from_address(signer_addr), signer_addr);
    }

    #[test]
    fn test_from_address_keychain() {
        let wallet = Address::repeat_byte(0xAA);
        let mode = TempoSigningMode::Keychain {
            wallet,
            key_authorization: None,
        };
        let signer_addr = Address::repeat_byte(0x01);
        assert_eq!(mode.from_address(signer_addr), wallet);
    }

    #[test]
    fn test_key_authorization_direct_returns_none() {
        let mode = TempoSigningMode::Direct;
        assert!(mode.key_authorization().is_none());
    }

    #[test]
    fn test_key_authorization_keychain_none() {
        let mode = TempoSigningMode::Keychain {
            wallet: Address::ZERO,
            key_authorization: None,
        };
        assert!(mode.key_authorization().is_none());
    }

    #[test]
    fn test_key_authorization_keychain_some() {
        use alloy::signers::SignerSync;
        use tempo_primitives::transaction::{KeyAuthorization, PrimitiveSignature, SignatureType};

        let signer = test_signer();
        let auth = KeyAuthorization {
            chain_id: 42431,
            key_type: SignatureType::Secp256k1,
            key_id: signer.address(),
            expiry: Some(9999999999),
            limits: None,
        };
        let sig = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        let signed = auth.into_signed(PrimitiveSignature::Secp256k1(sig));

        let mode = TempoSigningMode::Keychain {
            wallet: Address::ZERO,
            key_authorization: Some(Box::new(signed)),
        };
        assert!(mode.key_authorization().is_some());
    }

    // --- sign_and_encode (sync) ---

    #[test]
    fn test_sign_and_encode_direct_produces_valid_2718() {
        use alloy::eips::eip2718::Decodable2718;

        let signer = test_signer();
        let tx = test_tx();
        let bytes = sign_and_encode(tx, &signer, &TempoSigningMode::Direct).unwrap();

        // Must start with Tempo tx type 0x76
        assert_eq!(bytes[0], 0x76, "should start with Tempo tx type byte");

        // Must be decodable back
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.tx().chain_id, 42431);
        assert_eq!(decoded.tx().nonce, 1);
        assert_eq!(decoded.tx().gas_limit, 500_000);
    }

    #[test]
    fn test_sign_and_encode_keychain_produces_valid_2718() {
        use alloy::eips::eip2718::Decodable2718;

        let signer = test_signer();
        let wallet = Address::repeat_byte(0xAA);
        let mode = TempoSigningMode::Keychain {
            wallet,
            key_authorization: None,
        };
        let tx = test_tx();
        let bytes = sign_and_encode(tx, &signer, &mode).unwrap();

        assert_eq!(bytes[0], 0x76);
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.tx().chain_id, 42431);
    }

    #[test]
    fn test_sign_and_encode_keychain_larger_than_direct() {
        let signer = test_signer();
        let direct_bytes = sign_and_encode(test_tx(), &signer, &TempoSigningMode::Direct).unwrap();

        let keychain_bytes = sign_and_encode(
            test_tx(),
            &signer,
            &TempoSigningMode::Keychain {
                wallet: Address::repeat_byte(0xAA),
                key_authorization: None,
            },
        )
        .unwrap();

        assert!(
            keychain_bytes.len() > direct_bytes.len(),
            "keychain envelope should be larger than direct signature"
        );
    }

    #[test]
    fn test_sign_and_encode_deterministic() {
        let signer = test_signer();
        let mode = TempoSigningMode::Direct;
        let bytes1 = sign_and_encode(test_tx(), &signer, &mode).unwrap();
        let bytes2 = sign_and_encode(test_tx(), &signer, &mode).unwrap();
        assert_eq!(bytes1, bytes2, "same tx + signer should produce same bytes");
    }

    #[test]
    fn test_sign_and_encode_different_signers_produce_different_bytes() {
        let signer1 = test_signer();
        let signer2 = PrivateKeySigner::random();
        let mode = TempoSigningMode::Direct;
        let bytes1 = sign_and_encode(test_tx(), &signer1, &mode).unwrap();
        let bytes2 = sign_and_encode(test_tx(), &signer2, &mode).unwrap();
        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn test_sign_and_encode_preserves_tx_fields() {
        use alloy::eips::eip2718::Decodable2718;

        let signer = test_signer();
        let bytes = sign_and_encode(test_tx(), &signer, &TempoSigningMode::Direct).unwrap();
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();
        let tx = decoded.tx();

        assert_eq!(tx.chain_id, 42431);
        assert_eq!(tx.nonce, 1);
        assert_eq!(tx.gas_limit, 500_000);
        assert_eq!(tx.max_fee_per_gas, 1_000_000_000);
        assert_eq!(tx.max_priority_fee_per_gas, 100_000_000);
        assert_eq!(tx.calls.len(), 1);
        assert_eq!(tx.calls[0].input.as_ref(), &[0xaa, 0xbb]);
    }

    // --- sign_and_encode_async ---

    #[tokio::test]
    async fn test_sign_and_encode_async_direct() {
        use alloy::eips::eip2718::Decodable2718;

        let signer = test_signer();
        let bytes = sign_and_encode_async(test_tx(), &signer, &TempoSigningMode::Direct)
            .await
            .unwrap();

        assert_eq!(bytes[0], 0x76);
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.tx().chain_id, 42431);
    }

    #[tokio::test]
    async fn test_sign_and_encode_async_keychain() {
        use alloy::eips::eip2718::Decodable2718;

        let signer = test_signer();
        let mode = TempoSigningMode::Keychain {
            wallet: Address::repeat_byte(0xBB),
            key_authorization: None,
        };
        let bytes = sign_and_encode_async(test_tx(), &signer, &mode)
            .await
            .unwrap();

        assert_eq!(bytes[0], 0x76);
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.tx().chain_id, 42431);
    }

    #[tokio::test]
    async fn test_sync_and_async_produce_same_output() {
        let signer = test_signer();
        let mode = TempoSigningMode::Direct;
        let sync_bytes = sign_and_encode(test_tx(), &signer, &mode).unwrap();
        let async_bytes = sign_and_encode_async(test_tx(), &signer, &mode)
            .await
            .unwrap();
        assert_eq!(
            sync_bytes, async_bytes,
            "sync and async should produce identical output"
        );
    }

    // --- sign_and_encode with key_authorization in tx ---

    #[test]
    fn test_sign_and_encode_with_key_authorization_in_tx() {
        use alloy::eips::eip2718::Decodable2718;
        use alloy::signers::SignerSync;
        use tempo_primitives::transaction::{KeyAuthorization, PrimitiveSignature, SignatureType};

        let signer = test_signer();
        let auth = KeyAuthorization {
            chain_id: 42431,
            key_type: SignatureType::Secp256k1,
            key_id: signer.address(),
            expiry: Some(9999999999),
            limits: None,
        };
        let sig = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        let signed_auth = auth.into_signed(PrimitiveSignature::Secp256k1(sig));

        let mut tx = test_tx();
        tx.key_authorization = Some(signed_auth);

        let mode = TempoSigningMode::Keychain {
            wallet: Address::repeat_byte(0xAA),
            key_authorization: None,
        };

        let bytes = sign_and_encode(tx, &signer, &mode).unwrap();
        assert_eq!(bytes[0], 0x76);

        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();
        assert!(
            decoded.tx().key_authorization.is_some(),
            "key_authorization should survive encode/decode roundtrip"
        );
    }

    // --- Multiple calls ---

    #[test]
    fn test_sign_and_encode_multiple_calls() {
        use alloy::eips::eip2718::Decodable2718;

        let signer = test_signer();
        let mut tx = test_tx();
        tx.calls.push(Call {
            to: TxKind::Call(Address::repeat_byte(0x44)),
            value: U256::from(42u64),
            input: Bytes::from_static(&[0xcc, 0xdd]),
        });
        tx.calls.push(Call {
            to: TxKind::Call(Address::repeat_byte(0x55)),
            value: U256::ZERO,
            input: Bytes::new(),
        });

        let bytes = sign_and_encode(tx, &signer, &TempoSigningMode::Direct).unwrap();
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.tx().calls.len(), 3);
        assert_eq!(decoded.tx().calls[1].value, U256::from(42u64));
    }

    // --- Empty calls ---

    #[test]
    fn test_sign_and_encode_empty_calls_still_encodes() {
        // Tempo transactions require at least one call; sign_and_encode
        // produces bytes but they may fail to decode due to RLP validation.
        let signer = test_signer();
        let mut tx = test_tx();
        tx.calls = vec![];

        // sign_and_encode succeeds (signing doesn't validate calls)
        let result = sign_and_encode(tx, &signer, &TempoSigningMode::Direct);
        // The result is bytes but decoding will reject empty calls
        assert!(
            result.is_ok(),
            "signing should succeed even with empty calls"
        );
    }

    // --- Boundary tx field values ---

    #[test]
    fn test_sign_and_encode_zero_gas_fields() {
        use alloy::eips::eip2718::Decodable2718;

        let signer = test_signer();
        let mut tx = test_tx();
        tx.gas_limit = 0;
        tx.max_fee_per_gas = 0;
        tx.max_priority_fee_per_gas = 0;
        tx.nonce = 0;

        let bytes = sign_and_encode(tx, &signer, &TempoSigningMode::Direct).unwrap();
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.tx().gas_limit, 0);
        assert_eq!(decoded.tx().max_fee_per_gas, 0);
        assert_eq!(decoded.tx().max_priority_fee_per_gas, 0);
        assert_eq!(decoded.tx().nonce, 0);
    }

    // --- Determinism for Keychain mode ---

    #[test]
    fn test_sign_and_encode_deterministic_keychain() {
        let signer = test_signer();
        let mode = TempoSigningMode::Keychain {
            wallet: Address::repeat_byte(0xAA),
            key_authorization: None,
        };
        let bytes1 = sign_and_encode(test_tx(), &signer, &mode).unwrap();
        let bytes2 = sign_and_encode(test_tx(), &signer, &mode).unwrap();
        assert_eq!(
            bytes1, bytes2,
            "keychain mode: same tx + signer should produce same bytes"
        );
    }

    // --- Signature variant correctness ---

    #[test]
    fn test_sign_and_encode_direct_produces_primitive_signature() {
        use alloy::eips::eip2718::Decodable2718;
        use tempo_primitives::transaction::TempoSignature;

        let signer = test_signer();
        let bytes = sign_and_encode(test_tx(), &signer, &TempoSigningMode::Direct).unwrap();
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();

        assert!(
            matches!(decoded.signature(), TempoSignature::Primitive(_)),
            "Direct mode should produce Primitive signature"
        );
    }

    #[test]
    fn test_sign_and_encode_keychain_produces_keychain_signature() {
        use alloy::eips::eip2718::Decodable2718;
        use tempo_primitives::transaction::TempoSignature;

        let wallet = Address::repeat_byte(0xAA);
        let mode = TempoSigningMode::Keychain {
            wallet,
            key_authorization: None,
        };
        let signer = test_signer();
        let bytes = sign_and_encode(test_tx(), &signer, &mode).unwrap();
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();

        match decoded.signature() {
            TempoSignature::Keychain(ks) => {
                assert_eq!(
                    ks.user_address, wallet,
                    "keychain signature should embed the wallet address"
                );
            }
            other => panic!("Expected Keychain signature, got {:?}", other),
        }
    }

    // --- Async signature variant correctness ---

    #[tokio::test]
    async fn test_sign_and_encode_async_direct_produces_primitive_signature() {
        use alloy::eips::eip2718::Decodable2718;
        use tempo_primitives::transaction::TempoSignature;

        let signer = test_signer();
        let bytes = sign_and_encode_async(test_tx(), &signer, &TempoSigningMode::Direct)
            .await
            .unwrap();
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();

        assert!(
            matches!(decoded.signature(), TempoSignature::Primitive(_)),
            "Async Direct mode should produce Primitive signature"
        );
    }

    #[tokio::test]
    async fn test_sign_and_encode_async_keychain_produces_keychain_signature() {
        use alloy::eips::eip2718::Decodable2718;
        use tempo_primitives::transaction::TempoSignature;

        let wallet = Address::repeat_byte(0xBB);
        let mode = TempoSigningMode::Keychain {
            wallet,
            key_authorization: None,
        };
        let signer = test_signer();
        let bytes = sign_and_encode_async(test_tx(), &signer, &mode)
            .await
            .unwrap();
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();

        match decoded.signature() {
            TempoSignature::Keychain(ks) => {
                assert_eq!(ks.user_address, wallet);
            }
            other => panic!("Expected Keychain signature, got {:?}", other),
        }
    }

    // --- TempoSigningMode clone + debug ---

    #[test]
    fn test_signing_mode_clone() {
        let mode = TempoSigningMode::Keychain {
            wallet: Address::repeat_byte(0xAA),
            key_authorization: None,
        };
        let cloned = mode.clone();
        assert_eq!(
            mode.from_address(Address::ZERO),
            cloned.from_address(Address::ZERO)
        );
    }

    #[test]
    fn test_signing_mode_debug() {
        let mode = TempoSigningMode::Direct;
        let debug = format!("{:?}", mode);
        assert!(debug.contains("Direct"));
    }
}
