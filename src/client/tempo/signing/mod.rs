//! Tempo transaction signing strategies.
//!
//! Provides [`TempoSigningMode`] for choosing between direct key signing
//! and keychain (access key) signing, plus helpers to sign and encode
//! Tempo transactions.

pub mod keychain;

use alloy::primitives::Address;
use tempo_primitives::transaction::SignedKeyAuthorization;

// Re-export so callers can set the version without importing tempo_primitives directly.
pub use tempo_primitives::transaction::KeychainVersion;

use crate::error::{MppError, ResultExt};
use crate::protocol::methods::tempo::FeePayerEnvelope78;

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
        /// Keychain signature version. V1 signs `sig_hash` directly (legacy,
        /// deprecated at T1C). V2 signs `keccak256(0x04 || sig_hash || user_address)`.
        version: KeychainVersion,
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

/// Compute the hash that the signer should sign, given the tx sig_hash and mode.
///
/// - `Direct` / `Keychain` V1: signs the raw `sig_hash`.
/// - `Keychain` V2: signs `keccak256(0x04 || sig_hash || user_address)`.
fn effective_signing_hash(
    sig_hash: alloy::primitives::B256,
    mode: &TempoSigningMode,
) -> alloy::primitives::B256 {
    use tempo_primitives::transaction::KeychainSignature;

    match mode {
        TempoSigningMode::Direct => sig_hash,
        TempoSigningMode::Keychain {
            wallet, version, ..
        } => match version {
            KeychainVersion::V1 => sig_hash,
            KeychainVersion::V2 => KeychainSignature::signing_hash(sig_hash, *wallet),
        },
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
        TempoSigningMode::Keychain {
            wallet, version, ..
        } => {
            let primitive = PrimitiveSignature::Secp256k1(inner_signature);
            let keychain_sig = match version {
                KeychainVersion::V1 => KeychainSignature::new_v1(*wallet, primitive),
                KeychainVersion::V2 => KeychainSignature::new(*wallet, primitive),
            };
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
    let hash_to_sign = effective_signing_hash(sig_hash, mode);
    let inner_signature = signer
        .sign_hash_sync(&hash_to_sign)
        .mpp_http("failed to sign transaction")?;

    let signed_tx = tx.into_signed(build_tempo_signature(inner_signature, mode));
    Ok(signed_tx.encoded_2718())
}

/// Sign a [`TempoTransaction`] and return the **fee payer envelope** encoded bytes.
///
/// The resulting bytes start with `0x78` and are meant to be sent to an MPPx server
/// (or fee payer proxy) which will co-sign and broadcast.
pub fn sign_and_encode_fee_payer_envelope(
    tx: tempo_primitives::transaction::TempoTransaction,
    signer: &(impl alloy::signers::SignerSync + alloy::signers::Signer),
    mode: &TempoSigningMode,
) -> Result<Vec<u8>, MppError> {
    use alloy::primitives::U256;

    let sender = mode.from_address(signer.address());
    if tx.fee_payer_signature.is_none() {
        return Err(MppError::InvalidConfig(
            "fee payer envelope requires fee_payer_signature placeholder; build tx with TempoTxOptions { fee_payer: true }"
                .to_string(),
        ));
    }
    if tx.fee_token.is_some() {
        return Err(MppError::InvalidConfig(
            "fee payer envelope must not include fee_token (server chooses)".to_string(),
        ));
    }
    if tx.nonce_key != U256::MAX {
        return Err(MppError::InvalidConfig(
            "fee payer envelope must use expiring nonce key (U256::MAX)".to_string(),
        ));
    }
    if tx.valid_before.is_none() {
        return Err(MppError::InvalidConfig(
            "fee payer envelope must include valid_before".to_string(),
        ));
    }

    let sig_hash = tx.signature_hash();
    let hash_to_sign = effective_signing_hash(sig_hash, mode);
    let inner_signature = signer
        .sign_hash_sync(&hash_to_sign)
        .mpp_http("failed to sign transaction")?;
    let signature = build_tempo_signature(inner_signature, mode);
    Ok(FeePayerEnvelope78::from_signing_tx(tx, sender, signature).encoded_envelope())
}

/// Async version of [`sign_and_encode`] for signers that require async signing.
pub async fn sign_and_encode_async(
    tx: tempo_primitives::transaction::TempoTransaction,
    signer: &impl alloy::signers::Signer,
    mode: &TempoSigningMode,
) -> Result<Vec<u8>, MppError> {
    use alloy::eips::Encodable2718;

    let sig_hash = tx.signature_hash();
    let hash_to_sign = effective_signing_hash(sig_hash, mode);
    let inner_signature = signer
        .sign_hash(&hash_to_sign)
        .await
        .mpp_http("failed to sign transaction")?;

    let signed_tx = tx.into_signed(build_tempo_signature(inner_signature, mode));
    Ok(signed_tx.encoded_2718())
}

/// Async version of [`sign_and_encode_fee_payer_envelope`].
pub async fn sign_and_encode_fee_payer_envelope_async(
    tx: tempo_primitives::transaction::TempoTransaction,
    signer: &impl alloy::signers::Signer,
    mode: &TempoSigningMode,
) -> Result<Vec<u8>, MppError> {
    use alloy::primitives::U256;

    let sender = mode.from_address(signer.address());
    if tx.fee_payer_signature.is_none() {
        return Err(MppError::InvalidConfig(
            "fee payer envelope requires fee_payer_signature placeholder; build tx with TempoTxOptions { fee_payer: true }"
                .to_string(),
        ));
    }
    if tx.fee_token.is_some() {
        return Err(MppError::InvalidConfig(
            "fee payer envelope must not include fee_token (server chooses)".to_string(),
        ));
    }
    if tx.nonce_key != U256::MAX {
        return Err(MppError::InvalidConfig(
            "fee payer envelope must use expiring nonce key (U256::MAX)".to_string(),
        ));
    }
    if tx.valid_before.is_none() {
        return Err(MppError::InvalidConfig(
            "fee payer envelope must include valid_before".to_string(),
        ));
    }

    let sig_hash = tx.signature_hash();
    let hash_to_sign = effective_signing_hash(sig_hash, mode);
    let inner_signature = signer
        .sign_hash(&hash_to_sign)
        .await
        .mpp_http("failed to sign transaction")?;
    let signature = build_tempo_signature(inner_signature, mode);
    Ok(FeePayerEnvelope78::from_signing_tx(tx, sender, signature).encoded_envelope())
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
            version: KeychainVersion::V1,
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
            version: KeychainVersion::V1,
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
            version: KeychainVersion::V1,
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
    fn test_sign_and_encode_fee_payer_envelope_encodes_sender_address() {
        let signer = test_signer();

        // The tx must have `fee_payer_signature.is_some()` so the user's
        // signature_hash skips feeToken commitment (fee sponsorship flow).
        let mut tx = test_tx();
        tx.fee_token = None;
        tx.nonce_key = alloy::primitives::U256::MAX;
        tx.valid_before = Some(9999999999);
        tx.fee_payer_signature = Some(alloy::primitives::Signature::new(
            alloy::primitives::U256::ZERO,
            alloy::primitives::U256::ZERO,
            false,
        ));

        let mode = TempoSigningMode::Keychain {
            wallet: Address::repeat_byte(0xAB),
            key_authorization: None,
            version: KeychainVersion::V1,
        };

        let bytes = sign_and_encode_fee_payer_envelope(tx, &signer, &mode).unwrap();
        assert_eq!(
            bytes[0],
            crate::protocol::methods::tempo::TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID,
            "fee payer envelope must start with 0x78"
        );

        let env = FeePayerEnvelope78::decode_envelope(&bytes).unwrap();
        assert_eq!(env.sender, Address::repeat_byte(0xAB));
    }

    #[test]
    fn test_sign_and_encode_fee_payer_envelope_v2() {
        let signer = test_signer();

        let mut tx = test_tx();
        tx.fee_token = None;
        tx.nonce_key = alloy::primitives::U256::MAX;
        tx.valid_before = Some(9999999999);
        tx.fee_payer_signature = Some(alloy::primitives::Signature::new(
            alloy::primitives::U256::ZERO,
            alloy::primitives::U256::ZERO,
            false,
        ));

        let v1_mode = TempoSigningMode::Keychain {
            wallet: Address::repeat_byte(0xAB),
            key_authorization: None,
            version: KeychainVersion::V1,
        };
        let v2_mode = TempoSigningMode::Keychain {
            wallet: Address::repeat_byte(0xAB),
            key_authorization: None,
            version: KeychainVersion::V2,
        };

        let v1_bytes = sign_and_encode_fee_payer_envelope(tx.clone(), &signer, &v1_mode).unwrap();
        let v2_bytes = sign_and_encode_fee_payer_envelope(tx, &signer, &v2_mode).unwrap();

        // Both should be valid fee payer envelopes with same sender
        assert_eq!(
            v1_bytes[0],
            crate::protocol::methods::tempo::TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID
        );
        assert_eq!(
            v2_bytes[0],
            crate::protocol::methods::tempo::TEMPO_FEE_PAYER_ENVELOPE_TYPE_ID
        );
        let v2_env = FeePayerEnvelope78::decode_envelope(&v2_bytes).unwrap();
        assert_eq!(v2_env.sender, Address::repeat_byte(0xAB));

        // V1 and V2 should produce different signatures
        assert_ne!(v1_bytes, v2_bytes, "fee payer V1 and V2 should differ");
    }

    #[test]
    fn test_sign_and_encode_keychain_produces_valid_2718() {
        use alloy::eips::eip2718::Decodable2718;

        let signer = test_signer();
        let wallet = Address::repeat_byte(0xAA);
        let mode = TempoSigningMode::Keychain {
            wallet,
            key_authorization: None,
            version: KeychainVersion::V1,
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
                version: KeychainVersion::V1,
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
            version: KeychainVersion::V1,
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
            version: KeychainVersion::V1,
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
            version: KeychainVersion::V1,
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
            version: KeychainVersion::V1,
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
            version: KeychainVersion::V1,
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

    // --- Keychain V1 vs V2 ---

    fn keychain_mode(version: KeychainVersion) -> TempoSigningMode {
        TempoSigningMode::Keychain {
            wallet: Address::repeat_byte(0xAA),
            key_authorization: None,
            version,
        }
    }

    #[test]
    fn test_v1_and_v2_produce_different_bytes() {
        let signer = test_signer();
        let v1 = sign_and_encode(test_tx(), &signer, &keychain_mode(KeychainVersion::V1)).unwrap();
        let v2 = sign_and_encode(test_tx(), &signer, &keychain_mode(KeychainVersion::V2)).unwrap();
        assert_ne!(
            v1, v2,
            "V1 and V2 should sign different hashes and produce different bytes"
        );
    }

    #[test]
    fn test_v2_encode_decode_roundtrip() {
        use alloy::eips::eip2718::Decodable2718;

        let signer = test_signer();
        let mode = keychain_mode(KeychainVersion::V2);
        let bytes = sign_and_encode(test_tx(), &signer, &mode).unwrap();
        assert_eq!(bytes[0], 0x76);
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();
        assert_eq!(decoded.tx().chain_id, 42431);
    }

    #[test]
    fn test_v1_key_id_recovers_signer() {
        use alloy::eips::eip2718::Decodable2718;
        use tempo_primitives::transaction::TempoSignature;

        let signer = test_signer();
        let mode = keychain_mode(KeychainVersion::V1);
        let tx = test_tx();
        let sig_hash = tx.signature_hash();
        let bytes = sign_and_encode(tx, &signer, &mode).unwrap();
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();

        match decoded.signature() {
            TempoSignature::Keychain(ks) => {
                assert!(
                    ks.is_legacy(),
                    "V1 should produce legacy keychain signature"
                );
                let key_id = ks
                    .key_id(&sig_hash)
                    .expect("V1 key_id recovery should succeed");
                assert_eq!(key_id, signer.address());
            }
            other => panic!("Expected Keychain, got {:?}", other),
        }
    }

    #[test]
    fn test_v2_key_id_recovers_signer() {
        use alloy::eips::eip2718::Decodable2718;
        use tempo_primitives::transaction::TempoSignature;

        let signer = test_signer();
        let mode = keychain_mode(KeychainVersion::V2);
        let tx = test_tx();
        let sig_hash = tx.signature_hash();
        let bytes = sign_and_encode(tx, &signer, &mode).unwrap();
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();

        match decoded.signature() {
            TempoSignature::Keychain(ks) => {
                assert!(
                    !ks.is_legacy(),
                    "V2 should produce non-legacy keychain signature"
                );
                let key_id = ks
                    .key_id(&sig_hash)
                    .expect("V2 key_id recovery should succeed");
                assert_eq!(key_id, signer.address());
            }
            other => panic!("Expected Keychain, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_v2_async_key_id_recovers_signer() {
        use alloy::eips::eip2718::Decodable2718;
        use tempo_primitives::transaction::TempoSignature;

        let signer = test_signer();
        let mode = keychain_mode(KeychainVersion::V2);
        let tx = test_tx();
        let sig_hash = tx.signature_hash();
        let bytes = sign_and_encode_async(tx, &signer, &mode).await.unwrap();
        let decoded = AASigned::decode_2718(&mut bytes.as_slice()).unwrap();

        match decoded.signature() {
            TempoSignature::Keychain(ks) => {
                let key_id = ks
                    .key_id(&sig_hash)
                    .expect("async V2 key_id recovery should succeed");
                assert_eq!(key_id, signer.address());
            }
            other => panic!("Expected Keychain, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_v2_sync_and_async_produce_same_output() {
        let signer = test_signer();
        let mode = keychain_mode(KeychainVersion::V2);
        let sync_bytes = sign_and_encode(test_tx(), &signer, &mode).unwrap();
        let async_bytes = sign_and_encode_async(test_tx(), &signer, &mode)
            .await
            .unwrap();
        assert_eq!(
            sync_bytes, async_bytes,
            "V2 sync and async should produce identical output"
        );
    }

    // --- TempoSigningMode clone + debug ---

    #[test]
    fn test_signing_mode_clone() {
        let mode = TempoSigningMode::Keychain {
            wallet: Address::repeat_byte(0xAA),
            key_authorization: None,
            version: KeychainVersion::V1,
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
