//! Spending limit queries for Tempo access keys.
//!
//! Provides functions to query on-chain key status and spending limits
//! via the `IAccountKeychain` precompile, and to resolve limits locally
//! from a `SignedKeyAuthorization`.

use alloy::primitives::{Address, U256};
use alloy::sol;
use tempo_primitives::transaction::SignedKeyAuthorization;

use crate::client::tempo::TempoClientError;
use crate::error::MppError;

sol! {
    #[sol(rpc)]
    interface IAccountKeychain {
        struct KeyInfo {
            uint8 signatureType;
            address keyId;
            uint64 expiry;
            bool enforceLimits;
            bool isRevoked;
        }

        function getKey(address account, address keyId) external view returns (KeyInfo memory);
        function getRemainingLimit(address account, address keyId, address token) external view returns (uint256);
    }
}

/// IAccountKeychain precompile address on Tempo networks.
pub const KEYCHAIN_ADDRESS: Address = Address::new([
    0xAA, 0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
]);

/// Query the key's remaining spending limit for a token.
///
/// Returns `Ok(None)` if the key doesn't enforce limits (unlimited spending),
/// or `Ok(Some(remaining))` if limits are enforced.
///
/// Returns `Err` if the key is not authorized on-chain (missing, expired, or
/// revoked) or on RPC failure.
pub async fn query_key_spending_limit<P: alloy::providers::Provider>(
    provider: &P,
    wallet_address: Address,
    key_address: Address,
    token: Address,
) -> Result<Option<U256>, MppError> {
    let keychain = IAccountKeychain::new(KEYCHAIN_ADDRESS, provider);

    let key_info = keychain
        .getKey(wallet_address, key_address)
        .call()
        .await
        .map_err(|e| MppError::Http(format!("Failed to query key info: {}", e)))?;

    if key_info.expiry == 0 {
        return Err(MppError::Tempo(TempoClientError::AccessKeyNotProvisioned));
    }

    if key_info.isRevoked {
        return Err(MppError::Http("Access key is revoked".to_string()));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if key_info.expiry <= now {
        return Err(MppError::Http("Access key has expired".to_string()));
    }

    if !key_info.enforceLimits {
        return Ok(None);
    }

    let result = keychain
        .getRemainingLimit(wallet_address, key_address, token)
        .call()
        .await
        .map_err(|e| MppError::Http(format!("Failed to query remaining limit: {}", e)))?;

    Ok(Some(result))
}

/// Resolve the spending limit for a token from a key authorization.
///
/// When the key is not yet provisioned on-chain (authorization will be
/// included in the transaction), this checks the authorization's limits locally
/// instead of querying on-chain.
///
/// Returns `None` if the authorization has unlimited spending,
/// `Some(limit)` if the token has a specific limit, or
/// `Some(U256::ZERO)` if limits are enforced but the token is not listed.
pub fn local_key_spending_limit(auth: &SignedKeyAuthorization, token: Address) -> Option<U256> {
    match &auth.authorization.limits {
        None => None,
        Some(limits) => {
            let token_limit = limits.iter().find(|tl| tl.token == token);
            Some(token_limit.map(|tl| tl.limit).unwrap_or(U256::ZERO))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::signers::{local::PrivateKeySigner, SignerSync};
    use tempo_primitives::transaction::{
        KeyAuthorization, PrimitiveSignature, SignatureType, TokenLimit,
    };

    fn test_signer() -> PrivateKeySigner {
        "0x1234567890123456789012345678901234567890123456789012345678901234"
            .parse()
            .unwrap()
    }

    fn make_signed_auth(
        signer: &PrivateKeySigner,
        limits: Option<Vec<TokenLimit>>,
    ) -> SignedKeyAuthorization {
        let auth = KeyAuthorization {
            chain_id: 42431,
            key_type: SignatureType::Secp256k1,
            key_id: signer.address(),
            expiry: Some(9999999999),
            limits,
        };
        let inner_sig = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        auth.into_signed(PrimitiveSignature::Secp256k1(inner_sig))
    }

    #[test]
    fn test_local_key_spending_limit_unlimited() {
        let signer = test_signer();
        let signed = make_signed_auth(&signer, None);
        let token = Address::repeat_byte(0x01);
        assert_eq!(local_key_spending_limit(&signed, token), None);
    }

    #[test]
    fn test_local_key_spending_limit_with_matching_token() {
        let signer = test_signer();
        let token = Address::repeat_byte(0x01);
        let limit = U256::from(1_000_000u64);

        let signed = make_signed_auth(&signer, Some(vec![TokenLimit { token, limit }]));
        assert_eq!(local_key_spending_limit(&signed, token), Some(limit));
    }

    #[test]
    fn test_local_key_spending_limit_token_not_in_limits() {
        let signer = test_signer();
        let allowed_token = Address::repeat_byte(0x01);
        let disallowed_token = Address::repeat_byte(0x02);

        let signed = make_signed_auth(
            &signer,
            Some(vec![TokenLimit {
                token: allowed_token,
                limit: U256::from(1_000_000u64),
            }]),
        );
        assert_eq!(
            local_key_spending_limit(&signed, disallowed_token),
            Some(U256::ZERO)
        );
    }

    #[test]
    fn test_local_key_spending_limit_empty_limits() {
        let signer = test_signer();
        let signed = make_signed_auth(&signer, Some(vec![]));
        let token = Address::repeat_byte(0x01);
        assert_eq!(local_key_spending_limit(&signed, token), Some(U256::ZERO));
    }

    #[test]
    fn test_keychain_address() {
        assert_eq!(
            format!("{:#x}", KEYCHAIN_ADDRESS),
            "0xaaaaaaaa00000000000000000000000000000000"
        );
    }
}
