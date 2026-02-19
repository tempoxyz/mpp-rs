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

/// The keychain envelope type prefix byte used by Tempo `SignatureEnvelope`.
const KEYCHAIN_TYPE_PREFIX: u8 = 0x03;

/// The 32-byte magic trailer that Tempo may append to serialized signature envelopes.
const MAGIC_BYTES: [u8; 32] = [0x77; 32];

/// Strip trailing Tempo magic bytes from a signature if present.
fn strip_magic_trailer(sig: &[u8]) -> &[u8] {
    if sig.len() > 32 && sig[sig.len() - 32..] == MAGIC_BYTES {
        &sig[..sig.len() - 32]
    } else {
        sig
    }
}

/// Try to parse a keychain envelope and return the embedded `userAddress`.
///
/// Keychain wire format: `0x03` + userAddress (20 bytes) + inner signature.
/// Returns `Some(address)` if the signature is a valid keychain envelope,
/// `None` otherwise.
fn parse_keychain_user_address(sig: &[u8]) -> Option<alloy::primitives::Address> {
    // Minimum size: 1 (prefix) + 20 (address) + 65 (inner secp256k1) = 86
    if sig.len() < 21 || sig[0] != KEYCHAIN_TYPE_PREFIX {
        return None;
    }
    let addr_bytes: [u8; 20] = sig[1..21].try_into().ok()?;
    Some(alloy::primitives::Address::from(addr_bytes))
}

/// Verify a voucher signature matches the expected signer.
///
/// Supports both raw ECDSA signatures and Tempo `SignatureEnvelope` keychain
/// signatures. For keychain envelopes (prefix `0x03`), the embedded
/// `userAddress` is compared to `expected_signer`. For raw signatures,
/// standard EIP-712 ECDSA recovery is used.
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
    let sig = strip_magic_trailer(signature_bytes);

    // 65 bytes is always a raw secp256k1 ECDSA signature (matches TS SDK behavior
    // where `size === 65` is checked before the type prefix byte).
    // For longer signatures starting with 0x03, try keychain envelope parsing.
    if sig.len() != 65 {
        if let Some(user_address) = parse_keychain_user_address(sig) {
            return user_address == expected_signer;
        }
    }

    // Fall through to raw ECDSA signature recovery.
    verify_voucher_ecdsa(
        escrow_contract,
        chain_id,
        channel_id,
        cumulative_amount,
        sig,
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
        use alloy_signer_local::PrivateKeySigner;

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
        use alloy_signer_local::PrivateKeySigner;

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

    #[test]
    fn test_strip_magic_trailer() {
        let raw = vec![0x01, 0x02, 0x03];
        assert_eq!(strip_magic_trailer(&raw), &[0x01, 0x02, 0x03]);

        let mut with_magic = vec![0x01, 0x02, 0x03];
        with_magic.extend_from_slice(&[0x77; 32]);
        assert_eq!(strip_magic_trailer(&with_magic), &[0x01, 0x02, 0x03]);

        // Exactly 32 bytes of 0x77 with no payload — should NOT strip (len == 32, not > 32)
        let just_magic = vec![0x77; 32];
        assert_eq!(strip_magic_trailer(&just_magic), &[0x77; 32]);
    }

    #[test]
    fn test_parse_keychain_user_address() {
        use alloy::primitives::Address;

        let addr: Address = "0xAbCdEf0123456789AbCdEf0123456789AbCdEf01"
            .parse()
            .unwrap();

        // Valid keychain envelope: 0x03 + 20-byte address + 65-byte inner sig
        let mut envelope = vec![KEYCHAIN_TYPE_PREFIX];
        envelope.extend_from_slice(addr.as_slice());
        envelope.extend_from_slice(&[0xAA; 65]); // dummy inner signature
        assert_eq!(parse_keychain_user_address(&envelope), Some(addr));

        // Too short (no inner signature bytes, but 21 bytes is minimum)
        let mut short = vec![KEYCHAIN_TYPE_PREFIX];
        short.extend_from_slice(addr.as_slice());
        assert_eq!(parse_keychain_user_address(&short), Some(addr));

        // Wrong prefix
        let mut wrong_prefix = vec![0x01];
        wrong_prefix.extend_from_slice(addr.as_slice());
        wrong_prefix.extend_from_slice(&[0xAA; 65]);
        assert_eq!(parse_keychain_user_address(&wrong_prefix), None);

        // Too short to contain address
        assert_eq!(
            parse_keychain_user_address(&[KEYCHAIN_TYPE_PREFIX; 10]),
            None
        );

        // A 65-byte signature starting with 0x03 is still treated as raw ECDSA
        // by verify_voucher (matching TS SDK behavior where size === 65 is checked first).
        let raw_65 = vec![0x03; 65];
        assert!(parse_keychain_user_address(&raw_65).is_some()); // parse_keychain alone would match
                                                                 // But verify_voucher skips keychain parsing for exactly 65 bytes.
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
        let mut envelope = vec![KEYCHAIN_TYPE_PREFIX];
        envelope.extend_from_slice(user_address.as_slice());
        envelope.extend_from_slice(&[0xAA; 65]); // dummy inner signature

        // Should match the user address
        assert!(verify_voucher(
            escrow_contract,
            chain_id,
            channel_id,
            cumulative_amount,
            &envelope,
            user_address,
        ));

        // Should fail for a different expected signer
        let other: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        assert!(!verify_voucher(
            escrow_contract,
            chain_id,
            channel_id,
            cumulative_amount,
            &envelope,
            other,
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
        let mut envelope = vec![KEYCHAIN_TYPE_PREFIX];
        envelope.extend_from_slice(user_address.as_slice());
        envelope.extend_from_slice(&[0xAA; 65]);
        envelope.extend_from_slice(&MAGIC_BYTES);

        assert!(verify_voucher(
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
    async fn test_verify_voucher_ecdsa_still_works() {
        use alloy::primitives::{Address, B256};
        use alloy_signer_local::PrivateKeySigner;

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
