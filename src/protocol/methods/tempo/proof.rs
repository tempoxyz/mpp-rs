//! EIP-712 proof signing for zero-amount Tempo charge flows.

use alloy::primitives::{Address, B256};
use alloy::sol_types::{eip712_domain, SolStruct};

use crate::error::{MppError, ResultExt};

/// EIP-712 domain name for zero-amount proof credentials.
pub const DOMAIN_NAME: &str = "MPP";

/// EIP-712 domain version for zero-amount proof credentials.
pub const DOMAIN_VERSION: &str = "1";

alloy::sol! {
    #[derive(Debug)]
    struct Proof {
        string challengeId;
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

/// Compute the EIP-712 signing hash for a proof credential.
pub fn signing_hash(chain_id: u64, challenge_id: &str) -> B256 {
    let domain = eip712_domain! {
        name: DOMAIN_NAME,
        version: DOMAIN_VERSION,
        chain_id: chain_id,
    };

    Proof {
        challengeId: challenge_id.to_string(),
    }
    .eip712_signing_hash(&domain)
}

/// Sign a zero-amount charge proof for the given challenge ID.
#[cfg(feature = "evm")]
pub async fn sign_proof(
    signer: &impl alloy::signers::Signer,
    chain_id: u64,
    challenge_id: &str,
) -> crate::error::Result<String> {
    let signature = signer
        .sign_hash(&signing_hash(chain_id, challenge_id))
        .await
        .mpp_http("failed to sign proof")?;

    Ok(alloy::hex::encode_prefixed(signature.as_bytes()))
}

/// Verify a zero-amount charge proof against the expected signer.
#[cfg(feature = "evm")]
pub fn verify_proof(
    chain_id: u64,
    challenge_id: &str,
    signature_hex: &str,
    expected_signer: Address,
) -> bool {
    let signature_bytes = match signature_hex.parse::<alloy::primitives::Bytes>() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let signature = match alloy::signers::Signature::try_from(signature_bytes.as_ref()) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    match signature.recover_address_from_prehash(&signing_hash(chain_id, challenge_id)) {
        Ok(recovered) => recovered == expected_signer,
        Err(_) => false,
    }
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
        let signature = sign_proof(&signer, 42431, "challenge-123").await.unwrap();

        assert!(verify_proof(
            42431,
            "challenge-123",
            &signature,
            signer.address(),
        ));
    }

    #[tokio::test]
    async fn test_verify_proof_rejects_wrong_challenge_id() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let signature = sign_proof(&signer, 42431, "challenge-123").await.unwrap();

        assert!(!verify_proof(
            42431,
            "challenge-456",
            &signature,
            signer.address(),
        ));
    }

    #[tokio::test]
    async fn test_verify_proof_rejects_wrong_signer() {
        let signer = alloy::signers::local::PrivateKeySigner::random();
        let other = alloy::signers::local::PrivateKeySigner::random();
        let signature = sign_proof(&signer, 42431, "challenge-123").await.unwrap();

        assert!(!verify_proof(
            42431,
            "challenge-123",
            &signature,
            other.address(),
        ));
    }

    #[test]
    fn test_signing_hash_depends_on_chain_id() {
        assert_ne!(
            signing_hash(1, "challenge-123"),
            signing_hash(42431, "challenge-123")
        );
    }
}
