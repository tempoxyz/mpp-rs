//! EIP-3009 `TransferWithAuthorization` signing and verification for the
//! native `evm/charge` method.
//!
//! The credential is an EIP-712 signature over the token's
//! `TransferWithAuthorization` struct. The EIP-712 domain is bound to the token
//! contract (`verifyingContract = currency`) and chain, and for native MPP
//! challenges the authorization `nonce` is bound to the challenge.

use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::sol_types::{eip712_domain, SolStruct};

use crate::error::{MppError, Result, ResultExt};

alloy::sol! {
    #[derive(Debug)]
    struct TransferWithAuthorization {
        address from;
        address to;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
    }
}

/// Build the canonical DID source for an EVM authorization credential:
/// `did:pkh:eip155:{chainId}:{address}`.
pub fn evm_source(address: Address, chain_id: u64) -> String {
    format!("did:pkh:eip155:{chain_id}:{address}")
}

/// Compute the challenge-bound authorization nonce for a native MPP challenge:
/// `keccak256(challengeId ++ realm)`.
pub fn challenge_nonce(challenge_id: &str, realm: &str) -> B256 {
    let mut buf = Vec::with_capacity(challenge_id.len() + realm.len());
    buf.extend_from_slice(challenge_id.as_bytes());
    buf.extend_from_slice(realm.as_bytes());
    keccak256(&buf)
}

/// Compute the EIP-712 signing hash for a `TransferWithAuthorization`.
///
/// `name` and `version` are the token's EIP-712 domain fields and
/// `verifying_contract` is the token (`currency`) address.
#[allow(clippy::too_many_arguments)]
pub fn signing_hash(
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: Address,
    from: Address,
    to: Address,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
) -> B256 {
    let domain = eip712_domain! {
        name: name.to_string(),
        version: version.to_string(),
        chain_id: chain_id,
        verifying_contract: verifying_contract,
    };

    TransferWithAuthorization {
        from,
        to,
        value,
        validAfter: valid_after,
        validBefore: valid_before,
        nonce,
    }
    .eip712_signing_hash(&domain)
}

/// Sign a `TransferWithAuthorization` and return the 0x-prefixed signature hex.
#[allow(clippy::too_many_arguments)]
pub async fn sign_authorization(
    signer: &impl alloy::signers::Signer,
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: Address,
    from: Address,
    to: Address,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
) -> Result<String> {
    let hash = signing_hash(
        name,
        version,
        chain_id,
        verifying_contract,
        from,
        to,
        value,
        valid_after,
        valid_before,
        nonce,
    );
    let signature = signer
        .sign_hash(&hash)
        .await
        .mpp_http("failed to sign authorization")?;
    Ok(alloy::hex::encode_prefixed(signature.as_bytes()))
}

/// Recover the signer address from a `TransferWithAuthorization` signature.
#[allow(clippy::too_many_arguments)]
pub fn recover_authorization_signer(
    name: &str,
    version: &str,
    chain_id: u64,
    verifying_contract: Address,
    from: Address,
    to: Address,
    value: U256,
    valid_after: U256,
    valid_before: U256,
    nonce: B256,
    signature_hex: &str,
) -> Result<Address> {
    let signature_bytes: alloy::primitives::Bytes = signature_hex
        .parse()
        .map_err(|_| MppError::invalid_payload("invalid authorization signature hex"))?;
    // Accept only canonical 65-byte signatures with a typed-data `v` of
    // 0/1/27/28. Reject EIP-155 transaction `v` (>= 35), which on-chain
    // ecrecover rejects for typed data.
    let bytes = signature_bytes.as_ref();
    if bytes.len() != 65 {
        return Err(MppError::invalid_payload(
            "invalid authorization signature length",
        ));
    }
    if !matches!(bytes[64], 0 | 1 | 27 | 28) {
        return Err(MppError::invalid_payload(
            "invalid authorization signature v",
        ));
    }
    let signature = alloy::signers::Signature::try_from(bytes)
        .map_err(|_| MppError::invalid_payload("invalid authorization signature"))?;
    let hash = signing_hash(
        name,
        version,
        chain_id,
        verifying_contract,
        from,
        to,
        value,
        valid_after,
        valid_before,
        nonce,
    );
    signature
        .recover_address_from_prehash(&hash)
        .map_err(|_| MppError::invalid_payload("authorization signature recovery failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn token() -> Address {
        Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap()
    }

    #[test]
    fn test_challenge_nonce_depends_on_inputs() {
        let a = challenge_nonce("id-1", "api.example.com");
        let b = challenge_nonce("id-2", "api.example.com");
        let c = challenge_nonce("id-1", "other.example.com");
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_challenge_nonce_golden_vector() {
        // Golden vector: keccak256(utf8("challenge-123" ++ "api.example.com")),
        // independently produced by `cast keccak "challenge-123api.example.com"`.
        let nonce = challenge_nonce("challenge-123", "api.example.com");
        assert_eq!(
            alloy::hex::encode_prefixed(nonce),
            "0x6e75bcb5df1f8022ad4eecac5da5620c2c1db72d885bca54897f41a782c65b3a"
        );
    }

    #[test]
    fn test_evm_source_format() {
        let addr = Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2").unwrap();
        // The address is rendered in EIP-55 checksummed form.
        assert_eq!(
            evm_source(addr, 84532),
            "did:pkh:eip155:84532:0x742D35Cc6634c0532925a3b844bc9e7595F1b0F2"
        );
    }

    #[tokio::test]
    async fn test_sign_and_recover_roundtrip() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let from = signer.address();
        let to = Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2").unwrap();
        let nonce = challenge_nonce("challenge-123", "api.example.com");

        let sig = sign_authorization(
            &signer,
            "USD Coin",
            "2",
            84532,
            token(),
            from,
            to,
            U256::from(1_000_000u64),
            U256::ZERO,
            U256::from(9_999_999_999u64),
            nonce,
        )
        .await
        .unwrap();

        let recovered = recover_authorization_signer(
            "USD Coin",
            "2",
            84532,
            token(),
            from,
            to,
            U256::from(1_000_000u64),
            U256::ZERO,
            U256::from(9_999_999_999u64),
            nonce,
            &sig,
        )
        .unwrap();
        assert_eq!(recovered, from);
    }

    #[tokio::test]
    async fn test_recover_detects_tampered_value() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let from = signer.address();
        let to = Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2").unwrap();
        let nonce = challenge_nonce("challenge-123", "api.example.com");

        let sig = sign_authorization(
            &signer,
            "USD Coin",
            "2",
            84532,
            token(),
            from,
            to,
            U256::from(1_000_000u64),
            U256::ZERO,
            U256::from(9_999_999_999u64),
            nonce,
        )
        .await
        .unwrap();

        // Recover with a different value → recovered signer will not match.
        let recovered = recover_authorization_signer(
            "USD Coin",
            "2",
            84532,
            token(),
            from,
            to,
            U256::from(2_000_000u64),
            U256::ZERO,
            U256::from(9_999_999_999u64),
            nonce,
            &sig,
        )
        .unwrap();
        assert_ne!(recovered, from);
    }

    #[tokio::test]
    async fn test_recover_rejects_eip155_v() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let from = signer.address();
        let to = Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2").unwrap();
        let nonce = challenge_nonce("challenge-123", "api.example.com");

        let sig = sign_authorization(
            &signer,
            "USD Coin",
            "2",
            84532,
            token(),
            from,
            to,
            U256::from(1u64),
            U256::ZERO,
            U256::from(2u64),
            nonce,
        )
        .await
        .unwrap();

        // Re-encode the signature with an EIP-155 transaction `v` (37), which
        // on-chain ecrecover rejects for typed data.
        let mut bytes = alloy::hex::decode(&sig).unwrap();
        bytes[64] = 37;
        let tampered = alloy::hex::encode_prefixed(&bytes);

        let err = recover_authorization_signer(
            "USD Coin",
            "2",
            84532,
            token(),
            from,
            to,
            U256::from(1u64),
            U256::ZERO,
            U256::from(2u64),
            nonce,
            &tampered,
        );
        assert!(err.is_err());
    }

    #[test]
    fn test_recover_rejects_wrong_length() {
        let from = Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2").unwrap();
        let nonce = challenge_nonce("id", "realm");
        let err = recover_authorization_signer(
            "USD Coin",
            "2",
            84532,
            token(),
            from,
            from,
            U256::from(1u64),
            U256::ZERO,
            U256::from(2u64),
            nonce,
            "0x1234",
        );
        assert!(err.is_err());
    }

    #[test]
    fn test_signing_hash_depends_on_domain() {
        let from = Address::from_str("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2").unwrap();
        let to = Address::from_str("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48").unwrap();
        let nonce = challenge_nonce("id", "realm");
        let base = signing_hash(
            "USD Coin",
            "2",
            84532,
            token(),
            from,
            to,
            U256::from(1u64),
            U256::ZERO,
            U256::from(2u64),
            nonce,
        );
        // Different chain id → different hash.
        let other_chain = signing_hash(
            "USD Coin",
            "2",
            1,
            token(),
            from,
            to,
            U256::from(1u64),
            U256::ZERO,
            U256::from(2u64),
            nonce,
        );
        assert_ne!(base, other_chain);
    }
}
