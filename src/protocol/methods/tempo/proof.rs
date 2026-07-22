//! EIP-712 proof signing for zero-amount Tempo charge flows.

use alloy::primitives::{keccak256, Address, B256};
use alloy::sol_types::{eip712_domain, SolStruct};
#[cfg(feature = "evm")]
use tempo_primitives::transaction::{PrimitiveSignature, TempoSignature};

use crate::error::{MppError, ResultExt};

/// EIP-712 domain name for zero-amount proof credentials.
pub const DOMAIN_NAME: &str = "MPP";

/// EIP-712 domain version for zero-amount proof credentials.
pub const DOMAIN_VERSION: &str = "3";

alloy::sol! {
    #[derive(Debug)]
    struct Proof {
        address account;
        string challengeId;
        string realm;
    }
}

/// Build the canonical DID source for a proof credential.
pub fn proof_source(address: Address, chain_id: u64) -> String {
    format!("did:pkh:eip155:{chain_id}:{address}")
}

/// Parsed proof credential source DID.
pub struct ProofSource {
    pub address: Address,
    pub chain_id: u64,
}

/// Extract the signer address and chain ID from a proof credential source DID.
///
/// Enforces canonical DID format matching mppx: `did:pkh:eip155:{chainId}:{address}`
/// where chain ID has no leading zeros (except literal `0`) and the address is
/// a valid EIP-55 hex address with no extra colon segments.
pub fn parse_proof_source(source: &str) -> crate::error::Result<ProofSource> {
    let rest = source
        .strip_prefix("did:pkh:eip155:")
        .ok_or_else(|| MppError::invalid_payload("proof source must be a did:pkh:eip155 DID"))?;
    // Use split_once (not rsplit_once) so extra colons in the address segment are rejected.
    let (chain_id_str, address_str) = rest
        .split_once(':')
        .ok_or_else(|| MppError::invalid_payload("proof source is missing an address"))?;
    // Reject leading zeros (e.g. "01") — only "0" itself is valid for zero.
    if chain_id_str.len() > 1 && chain_id_str.starts_with('0') {
        return Err(MppError::invalid_payload(
            "proof source chain id has leading zeros",
        ));
    }
    let chain_id: u64 = chain_id_str
        .parse()
        .map_err(|e| MppError::invalid_payload(format!("invalid proof source chain id: {e}")))?;
    // Reject addresses containing extra colons.
    if address_str.contains(':') {
        return Err(MppError::invalid_payload(
            "proof source address contains invalid characters",
        ));
    }
    let address: Address = address_str
        .parse()
        .map_err(|e| MppError::invalid_payload(format!("invalid proof source address: {e}")))?;
    Ok(ProofSource { address, chain_id })
}

/// Compute a canonical single-use replay fingerprint for a proof credential.
///
/// Hashes canonical parsed values rather than raw strings so equivalent
/// spellings (address/signature hex casing, `0x` prefix) map to the same key.
#[cfg(feature = "evm")]
pub fn proof_fingerprint(
    challenge_id: &str,
    source_address: Address,
    chain_id: u64,
    signature_hex: &str,
) -> crate::error::Result<B256> {
    let signature = parse_signature(signature_hex)?;
    let signature_bytes = signature.to_bytes();

    let mut buf = Vec::with_capacity(challenge_id.len() + 1 + 20 + 8 + signature_bytes.len());
    buf.extend_from_slice(challenge_id.as_bytes());
    buf.push(0xff); // separator: variable-length id from fixed-width fields
    buf.extend_from_slice(source_address.as_slice());
    buf.extend_from_slice(&chain_id.to_be_bytes());
    buf.extend_from_slice(&signature_bytes);
    Ok(keccak256(&buf))
}

/// Compute the EIP-712 signing hash for a proof credential.
pub fn signing_hash(account: Address, chain_id: u64, challenge_id: &str, realm: &str) -> B256 {
    let domain = eip712_domain! {
        name: DOMAIN_NAME,
        version: DOMAIN_VERSION,
        chain_id: chain_id,
    };

    Proof {
        account,
        challengeId: challenge_id.to_string(),
        realm: realm.to_string(),
    }
    .eip712_signing_hash(&domain)
}

/// Sign a zero-amount charge proof for the given challenge ID and realm.
#[cfg(feature = "evm")]
pub async fn sign_proof(
    signer: &impl alloy::signers::Signer,
    account: Address,
    chain_id: u64,
    challenge_id: &str,
    realm: &str,
) -> crate::error::Result<String> {
    let signature = signer
        .sign_hash(&signing_hash(account, chain_id, challenge_id, realm))
        .await
        .mpp_http("failed to sign proof")?;

    Ok(alloy::hex::encode_prefixed(signature.as_bytes()))
}

/// Sign a wallet-bound proof with any native Tempo primitive signer.
///
/// This supports secp256k1, P-256, and WebAuthn-shaped primitive signatures.
/// When `account` is a root wallet and the signer is an access key, the server
/// verifies the recovered primitive signer against that wallet's on-chain
/// keychain authorization.
#[cfg(feature = "evm")]
pub async fn sign_proof_primitive(
    signer: &impl alloy::signers::Signer<PrimitiveSignature>,
    account: Address,
    chain_id: u64,
    challenge_id: &str,
    realm: &str,
) -> crate::error::Result<String> {
    let signature = signer
        .sign_hash(&signing_hash(account, chain_id, challenge_id, realm))
        .await
        .mpp_http("failed to sign proof")?;
    let envelope = TempoSignature::Primitive(signature);
    Ok(alloy::hex::encode_prefixed(envelope.to_bytes()))
}

/// Verify a zero-amount charge proof against the expected signer.
#[cfg(feature = "evm")]
pub fn verify_proof(
    account: Address,
    chain_id: u64,
    challenge_id: &str,
    realm: &str,
    signature_hex: &str,
    expected_signer: Address,
) -> bool {
    let signature = match parse_signature(signature_hex) {
        Ok(signature) => signature,
        Err(_) => return false,
    };

    match signature {
        TempoSignature::Primitive(signature) => signature
            .recover_signer(&signing_hash(account, chain_id, challenge_id, realm))
            .is_ok_and(|recovered| recovered == expected_signer),
        // Keychain envelopes require a separate on-chain authorization check.
        TempoSignature::Keychain(_) => false,
    }
}

/// Recover the signer address from a zero-amount charge proof.
///
/// Returns `Ok(address)` on success, or `Err` if the signature is malformed.
#[cfg(feature = "evm")]
pub fn recover_proof_signer(
    account: Address,
    chain_id: u64,
    challenge_id: &str,
    realm: &str,
    signature_hex: &str,
) -> Result<Address, crate::error::MppError> {
    let signature = parse_signature(signature_hex)?;
    let hash = signing_hash(account, chain_id, challenge_id, realm);
    match signature {
        TempoSignature::Primitive(signature) => signature.recover_signer(&hash),
        TempoSignature::Keychain(signature) => signature.key_id(&hash),
    }
    .map_err(|_| MppError::invalid_payload("proof signature recovery failed"))
}

#[cfg(feature = "evm")]
fn parse_signature(signature_hex: &str) -> crate::error::Result<TempoSignature> {
    let signature_bytes: alloy::primitives::Bytes = signature_hex
        .parse()
        .map_err(|_| MppError::invalid_payload("invalid proof signature hex"))?;
    TempoSignature::from_bytes(signature_bytes.as_ref())
        .map_err(|_| MppError::invalid_payload("invalid proof signature"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_source_roundtrip() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let source = proof_source(signer.address(), 42431);
        let parsed = parse_proof_source(&source).unwrap();
        assert_eq!(parsed.address, signer.address());
        assert_eq!(parsed.chain_id, 42431);
    }

    #[test]
    fn test_parse_proof_source_rejects_leading_zero_chain_id() {
        assert!(parse_proof_source(
            "did:pkh:eip155:042431:0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
        )
        .is_err());
    }

    #[test]
    fn test_parse_proof_source_rejects_extra_colons() {
        assert!(parse_proof_source(
            "did:pkh:eip155:42431:extra:0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
        )
        .is_err());
    }

    #[test]
    fn test_parse_proof_source_rejects_missing_prefix() {
        assert!(
            parse_proof_source("did:pkh:eip155:0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2")
                .is_err()
        );
    }

    #[test]
    fn test_parse_proof_source_accepts_chain_id_zero() {
        let parsed =
            parse_proof_source("did:pkh:eip155:0:0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2")
                .unwrap();
        assert_eq!(parsed.chain_id, 0);
    }

    #[tokio::test]
    async fn test_sign_and_verify_proof_roundtrip() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let signature = sign_proof(
            &signer,
            signer.address(),
            42431,
            "challenge-123",
            "api.example.com",
        )
        .await
        .unwrap();

        assert!(verify_proof(
            signer.address(),
            42431,
            "challenge-123",
            "api.example.com",
            &signature,
            signer.address(),
        ));
    }

    #[tokio::test]
    async fn test_verify_proof_rejects_wrong_challenge_id() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let signature = sign_proof(
            &signer,
            signer.address(),
            42431,
            "challenge-123",
            "api.example.com",
        )
        .await
        .unwrap();

        assert!(!verify_proof(
            signer.address(),
            42431,
            "challenge-456",
            "api.example.com",
            &signature,
            signer.address(),
        ));
    }

    #[tokio::test]
    async fn test_verify_proof_rejects_wrong_realm() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let signature = sign_proof(
            &signer,
            signer.address(),
            42431,
            "challenge-123",
            "api.example.com",
        )
        .await
        .unwrap();

        assert!(!verify_proof(
            signer.address(),
            42431,
            "challenge-123",
            "payments.example.com",
            &signature,
            signer.address(),
        ));
    }

    #[tokio::test]
    async fn test_verify_proof_rejects_wrong_signer() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let other = alloy::signers::local::PrivateKeySigner::random();
        let signature = sign_proof(
            &signer,
            signer.address(),
            42431,
            "challenge-123",
            "api.example.com",
        )
        .await
        .unwrap();

        assert!(!verify_proof(
            signer.address(),
            42431,
            "challenge-123",
            "api.example.com",
            &signature,
            other.address(),
        ));
    }

    #[tokio::test]
    async fn test_recover_proof_signer_returns_signer() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let signature = sign_proof(
            &signer,
            signer.address(),
            42431,
            "challenge-123",
            "api.example.com",
        )
        .await
        .unwrap();

        let recovered = recover_proof_signer(
            signer.address(),
            42431,
            "challenge-123",
            "api.example.com",
            &signature,
        )
        .unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[tokio::test]
    async fn test_proof_fingerprint_is_spelling_invariant() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let signature = sign_proof(
            &signer,
            signer.address(),
            42431,
            "challenge-123",
            "api.example.com",
        )
        .await
        .unwrap();

        // Canonical spelling vs. uppercase signature hex — same proof.
        let upper_sig = signature.to_uppercase().replace("0X", "0x");
        assert_ne!(signature, upper_sig);

        let a = proof_fingerprint("challenge-123", signer.address(), 42431, &signature).unwrap();
        let b = proof_fingerprint("challenge-123", signer.address(), 42431, &upper_sig).unwrap();
        assert_eq!(a, b, "re-encoded signature must yield the same fingerprint");

        // Different challenge id must change the fingerprint.
        let c = proof_fingerprint("challenge-456", signer.address(), 42431, &signature).unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn test_signing_hash_depends_on_chain_id() {
        let account = Address::repeat_byte(0x11);
        assert_ne!(
            signing_hash(account, 1, "challenge-123", "api.example.com"),
            signing_hash(account, 42431, "challenge-123", "api.example.com")
        );
    }

    #[test]
    fn test_signing_hash_depends_on_realm() {
        let account = Address::repeat_byte(0x11);
        assert_ne!(
            signing_hash(account, 42431, "challenge-123", "api.example.com"),
            signing_hash(account, 42431, "challenge-123", "payments.example.com")
        );
    }

    #[test]
    fn test_signing_hash_matches_mppx_v3_vector() {
        let account = "0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1"
            .parse()
            .unwrap();
        assert_eq!(
            signing_hash(account, 42431, "kM9xPqWvT2nJrHsY4aDfEb", "api.example.com"),
            "0x3860a700a55e02ad3c2dc047e92489feceecbdb0a801d948e1d9f0b61ea9bc3f"
                .parse::<B256>()
                .unwrap()
        );
    }
}
