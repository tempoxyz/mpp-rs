//! Voucher signing and channel ID computation for Tempo session payments.
//!
//! Client-side helpers for EIP-712 voucher signing and channel ID computation,
//! matching the TypeScript SDK's `Voucher.ts` and `Channel.ts`.

/// EIP-712 domain name for voucher signing (must match on-chain contract).
pub const DOMAIN_NAME: &str = "Tempo Stream Channel";

/// EIP-712 domain version for voucher signing (must match on-chain contract).
pub const DOMAIN_VERSION: &str = "1";

/// Compute a channel ID from its parameters.
///
/// Mirrors the on-chain `computeChannelId` function:
/// `keccak256(abi.encode(payer, payee, token, salt, authorizedSigner, escrowContract, chainId))`
#[cfg(feature = "evm")]
pub fn compute_channel_id(
    payer: alloy::primitives::Address,
    payee: alloy::primitives::Address,
    token: alloy::primitives::Address,
    salt: alloy::primitives::B256,
    authorized_signer: alloy::primitives::Address,
    escrow_contract: alloy::primitives::Address,
    chain_id: u64,
) -> alloy::primitives::B256 {
    use alloy::primitives::{keccak256, U256};
    use alloy::sol_types::SolValue;

    let encoded = (
        payer,
        payee,
        token,
        salt,
        authorized_signer,
        escrow_contract,
        U256::from(chain_id),
    )
        .abi_encode();
    keccak256(&encoded)
}

#[cfg(feature = "evm")]
alloy::sol! {
    #[derive(Debug)]
    struct Voucher {
        bytes32 channelId;
        uint128 cumulativeAmount;
    }
}

/// Sign a voucher using EIP-712 typed data signing.
///
/// Returns the 65-byte signature as `Bytes`.
#[cfg(feature = "evm")]
pub async fn sign_voucher(
    signer: &impl alloy::signers::Signer,
    channel_id: alloy::primitives::B256,
    cumulative_amount: u128,
    escrow_contract: alloy::primitives::Address,
    chain_id: u64,
) -> crate::error::Result<alloy::primitives::Bytes> {
    use alloy::sol_types::{eip712_domain, SolStruct};

    let domain = eip712_domain! {
        name: DOMAIN_NAME,
        version: DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: escrow_contract,
    };

    let voucher = Voucher {
        channelId: channel_id,
        cumulativeAmount: cumulative_amount,
    };

    let signing_hash = voucher.eip712_signing_hash(&domain);
    let signature = signer.sign_hash(&signing_hash).await.map_err(|e| {
        crate::error::MppError::InvalidSignature(Some(format!("failed to sign voucher: {}", e)))
    })?;

    Ok(alloy::primitives::Bytes::from(
        signature.as_bytes().to_vec(),
    ))
}

/// Parse a voucher signature into its canonical 65-byte `r || s || v` encoding.
///
/// Accepts the two encodings the escrow contract can settle: 65-byte
/// `r || s || v` with `v` of 27 or 28, and 64-byte EIP-2098 compact. Both must
/// be low-s. Everything else is rejected, including Tempo signature envelopes
/// (keychain, P-256, WebAuthn) and signatures with trailing bytes.
#[cfg(feature = "evm")]
pub(super) fn canonical_voucher_signature(signature: &[u8]) -> Option<[u8; 65]> {
    use alloy::primitives::Signature;

    let signature = match signature.len() {
        65 if matches!(signature[64], 27 | 28) => Signature::from_raw(signature).ok()?,
        64 => Signature::from_erc2098(signature),
        _ => return None,
    };
    if signature.normalize_s().is_some() {
        return None;
    }
    Some(signature.as_bytes())
}

/// Verify a voucher signature matches the expected signer.
///
/// Only canonical raw secp256k1 signatures are accepted: 65-byte
/// `r || s || v` (`v` of 27 or 28) or 64-byte EIP-2098 compact, with a low
/// `s` value. Tempo `SignatureEnvelope` encodings (keychain, P-256, WebAuthn)
/// and signatures with trailing bytes are rejected, because the escrow
/// contract verifies vouchers with `ecrecover` and cannot settle them.
/// Matches the TS SDK (mppx), which requires the canonical serialization.
///
/// Returns `true` if the signature is valid for `expected_signer`, `false`
/// otherwise (including on any parse/recovery error).
#[cfg(feature = "evm")]
pub fn verify_voucher(
    escrow_contract: alloy::primitives::Address,
    chain_id: u64,
    channel_id: alloy::primitives::B256,
    cumulative_amount: u128,
    signature_bytes: &[u8],
    expected_signer: alloy::primitives::Address,
) -> bool {
    let Some(signature) = canonical_voucher_signature(signature_bytes) else {
        return false;
    };

    verify_voucher_ecdsa(
        escrow_contract,
        chain_id,
        channel_id,
        cumulative_amount,
        &signature,
        expected_signer,
    )
}

/// Verify a raw ECDSA voucher signature via EIP-712 recovery.
#[cfg(feature = "evm")]
fn verify_voucher_ecdsa(
    escrow_contract: alloy::primitives::Address,
    chain_id: u64,
    channel_id: alloy::primitives::B256,
    cumulative_amount: u128,
    signature_bytes: &[u8],
    expected_signer: alloy::primitives::Address,
) -> bool {
    use alloy::sol_types::{eip712_domain, SolStruct};

    let domain = eip712_domain! {
        name: DOMAIN_NAME,
        version: DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: escrow_contract,
    };

    let voucher = Voucher {
        channelId: channel_id,
        cumulativeAmount: cumulative_amount,
    };

    let signing_hash = voucher.eip712_signing_hash(&domain);

    let signature = match alloy::signers::Signature::try_from(signature_bytes) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    match signature.recover_address_from_prehash(&signing_hash) {
        Ok(recovered) => recovered == expected_signer,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "evm")]
    #[test]
    fn test_compute_channel_id_deterministic() {
        use alloy::primitives::{Address, B256};

        let payer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let salt = B256::ZERO;
        let authorized_signer: Address = "0x4444444444444444444444444444444444444444"
            .parse()
            .unwrap();
        let escrow_contract: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let chain_id = 42431u64;

        let id1 = compute_channel_id(
            payer,
            payee,
            token,
            salt,
            authorized_signer,
            escrow_contract,
            chain_id,
        );
        let id2 = compute_channel_id(
            payer,
            payee,
            token,
            salt,
            authorized_signer,
            escrow_contract,
            chain_id,
        );

        assert_eq!(
            id1, id2,
            "Same parameters should produce the same channel ID"
        );
        assert_ne!(id1, B256::ZERO, "Channel ID should not be zero");
    }

    #[cfg(feature = "evm")]
    #[test]
    fn test_compute_channel_id_differs_for_different_params() {
        use alloy::primitives::{Address, B256};

        let payer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let token: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let salt = B256::ZERO;
        let authorized_signer: Address = "0x4444444444444444444444444444444444444444"
            .parse()
            .unwrap();
        let escrow_contract: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let id1 = compute_channel_id(
            payer,
            payee,
            token,
            salt,
            authorized_signer,
            escrow_contract,
            42431,
        );
        let id2 = compute_channel_id(
            payer,
            payee,
            token,
            salt,
            authorized_signer,
            escrow_contract,
            4217, // Different chain ID
        );

        assert_ne!(
            id1, id2,
            "Different chain IDs should produce different channel IDs"
        );
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_sign_voucher_roundtrip() {
        use alloy::primitives::{Address, B256};
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xAB);
        let cumulative_amount = 1000u128;
        let escrow_contract: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let chain_id = 42431u64;

        let sig_bytes = sign_voucher(
            &signer,
            channel_id,
            cumulative_amount,
            escrow_contract,
            chain_id,
        )
        .await
        .expect("signing should succeed");

        // EIP-712 signature is 65 bytes (r + s + v)
        assert_eq!(sig_bytes.len(), 65, "Signature should be 65 bytes");

        // Verify the signature recovers the correct signer
        use alloy::sol_types::eip712_domain;
        let domain = eip712_domain! {
            name: DOMAIN_NAME,
            version: DOMAIN_VERSION,
            chain_id: chain_id,
            verifying_contract: escrow_contract,
        };

        let voucher = Voucher {
            channelId: channel_id,
            cumulativeAmount: cumulative_amount,
        };

        use alloy::sol_types::SolStruct;
        let signing_hash = voucher.eip712_signing_hash(&domain);
        let signature = alloy::signers::Signature::try_from(sig_bytes.as_ref())
            .expect("should parse signature");
        let recovered = signature
            .recover_address_from_prehash(&signing_hash)
            .expect("should recover address");

        assert_eq!(
            recovered,
            signer.address(),
            "Recovered address should match signer"
        );
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_verify_voucher_roundtrip() {
        use alloy::primitives::{Address, B256};
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xCD);
        let cumulative_amount = 5000u128;
        let escrow_contract: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let chain_id = 42431u64;

        let sig_bytes = sign_voucher(
            &signer,
            channel_id,
            cumulative_amount,
            escrow_contract,
            chain_id,
        )
        .await
        .expect("signing should succeed");

        // Correct signer should verify
        assert!(verify_voucher(
            escrow_contract,
            chain_id,
            channel_id,
            cumulative_amount,
            &sig_bytes,
            signer.address(),
        ));

        // Wrong signer should fail
        let wrong_signer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        assert!(!verify_voucher(
            escrow_contract,
            chain_id,
            channel_id,
            cumulative_amount,
            &sig_bytes,
            wrong_signer,
        ));

        // Wrong amount should fail
        assert!(!verify_voucher(
            escrow_contract,
            chain_id,
            channel_id,
            9999u128,
            &sig_bytes,
            signer.address(),
        ));

        // Garbage signature should fail
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert!(!verify_voucher(
            escrow_contract,
            chain_id,
            channel_id,
            cumulative_amount,
            &garbage,
            signer.address(),
        ));
    }

    #[cfg(feature = "evm")]
    #[test]
    fn test_verify_voucher_keychain_envelope() {
        use alloy::primitives::{Address, B256};

        let user_address: Address = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
            .parse()
            .unwrap();
        let escrow_contract: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let channel_id = B256::repeat_byte(0xCD);
        let cumulative_amount = 5000u128;
        let chain_id = 42431u64;

        // Build a keychain envelope: 0x03 + userAddress (20 bytes) + inner sig (65 bytes)
        let mut envelope = vec![0x03];
        envelope.extend_from_slice(user_address.as_slice());
        envelope.extend_from_slice(&[0xAA; 65]); // dummy inner signature

        // Keychain envelopes must be rejected — the escrow contract only
        // supports raw ECDSA via ecrecover, so accepting keychain envelopes
        // without verifying the inner signature would allow trivial forgery.
        assert!(!verify_voucher(
            escrow_contract,
            chain_id,
            channel_id,
            cumulative_amount,
            &envelope,
            user_address,
        ));
    }

    #[cfg(feature = "evm")]
    #[test]
    fn test_verify_voucher_keychain_with_magic_trailer() {
        use alloy::primitives::{Address, B256};

        let user_address: Address = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
            .parse()
            .unwrap();
        let escrow_contract: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let channel_id = B256::repeat_byte(0xCD);
        let cumulative_amount = 5000u128;
        let chain_id = 42431u64;

        // Build a keychain envelope with trailing magic bytes
        let mut envelope = vec![0x03];
        envelope.extend_from_slice(user_address.as_slice());
        envelope.extend_from_slice(&[0xAA; 65]);
        envelope.extend_from_slice(&[0x77; 32]);

        // Keychain envelopes are rejected even with magic trailer
        assert!(!verify_voucher(
            escrow_contract,
            chain_id,
            channel_id,
            cumulative_amount,
            &envelope,
            user_address,
        ));
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_verify_voucher_signature_encodings() {
        use alloy::primitives::{Address, Signature, B256, U256};
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xAB);
        let cumulative_amount = 1000u128;
        let escrow_contract: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let chain_id = 42431u64;

        let sig = sign_voucher(
            &signer,
            channel_id,
            cumulative_amount,
            escrow_contract,
            chain_id,
        )
        .await
        .unwrap()
        .to_vec();
        let parsed = Signature::from_raw(&sig).unwrap();

        let order = U256::from_str_radix(
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            16,
        )
        .unwrap();
        let high_s = Signature::new(parsed.r(), order - parsed.s(), !parsed.v());
        assert!(high_s.s() > order >> 1);

        let with_suffix = |suffix: &[u8]| [sig.as_slice(), suffix].concat();
        let with_v = |v: u8| [&sig[..64], &[v]].concat();

        let cases = [
            ("65-byte r||s||v", sig.clone(), true),
            ("EIP-2098 compact", parsed.as_erc2098().to_vec(), true),
            ("high-s", high_s.as_bytes().to_vec(), false),
            ("magic trailer", with_suffix(&[0x77; 32]), false),
            ("trailing byte", with_suffix(&[0x00]), false),
            ("y-parity v", with_v(sig[64] - 27), false),
            ("EIP-155 v", with_v(sig[64] + 8), false),
            ("truncated", sig[..63].to_vec(), false),
            ("empty", Vec::new(), false),
        ];
        for (name, signature, accepted) in cases {
            assert_eq!(
                verify_voucher(
                    escrow_contract,
                    chain_id,
                    channel_id,
                    cumulative_amount,
                    &signature,
                    signer.address(),
                ),
                accepted,
                "{name}"
            );
        }

        let canonical: [u8; 65] = sig.as_slice().try_into().unwrap();
        assert_eq!(canonical_voucher_signature(&sig), Some(canonical));
        assert_eq!(
            canonical_voucher_signature(&parsed.as_erc2098()),
            Some(canonical)
        );
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_verify_voucher_ecdsa_still_works() {
        use alloy::primitives::{Address, B256};
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xEE);
        let cumulative_amount = 42u128;
        let escrow_contract: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let chain_id = 42431u64;

        let sig_bytes = sign_voucher(
            &signer,
            channel_id,
            cumulative_amount,
            escrow_contract,
            chain_id,
        )
        .await
        .expect("signing should succeed");

        // Raw ECDSA path should still work
        assert!(verify_voucher(
            escrow_contract,
            chain_id,
            channel_id,
            cumulative_amount,
            &sig_bytes,
            signer.address(),
        ));

        // Wrong signer should still fail
        let wrong: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        assert!(!verify_voucher(
            escrow_contract,
            chain_id,
            channel_id,
            cumulative_amount,
            &sig_bytes,
            wrong,
        ));
    }
}
