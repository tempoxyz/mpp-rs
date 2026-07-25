//! Spending limit queries for Tempo access keys.
//!
//! Provides functions to query on-chain key status and spending limits
//! via the `IAccountKeychain` precompile, and to resolve limits locally
//! from a `SignedKeyAuthorization`.

use alloy::primitives::{Address, U256};
use tempo_alloy::contracts::precompiles::{IAccountKeychain, ACCOUNT_KEYCHAIN_ADDRESS};
use tempo_alloy::TempoNetwork;
use tempo_primitives::transaction::SignedKeyAuthorization;

use crate::client::tempo::TempoClientError;
use crate::error::{MppError, ResultExt};

use super::TempoSigningMode;

/// Validate key info returned from the keychain precompile.
///
/// Returns `Ok(true)` if the key enforces spending limits,
/// `Ok(false)` if the key has unlimited spending,
/// or `Err` if the key is not provisioned, revoked, or expired.
fn validate_key_info(
    key_info: &IAccountKeychain::KeyInfo,
    now_secs: u64,
) -> Result<bool, MppError> {
    if key_info.expiry == 0 {
        return Err(MppError::Tempo(TempoClientError::AccessKeyNotProvisioned));
    }
    if key_info.isRevoked {
        return Err(MppError::Http("Access key is revoked".to_string()));
    }
    if key_info.expiry <= now_secs {
        return Err(MppError::Http("Access key has expired".to_string()));
    }
    Ok(key_info.enforceLimits)
}

/// Resolve a stored one-time key authorization against authoritative chain state.
///
/// Tempo Wallet persists the signed authorization so a newly created access key
/// can provision itself with its first transaction. Once the key exists on-chain,
/// replaying that authorization fails with `KeyAlreadyExists`. Match viem's Tempo
/// transaction preparation: attach the stored authorization only while the access
/// key is not currently active on the wallet's keychain.
pub(crate) async fn resolve_key_authorization<P: alloy::providers::Provider<TempoNetwork>>(
    provider: &P,
    signing_mode: &TempoSigningMode,
    key_address: Address,
) -> Result<Option<SignedKeyAuthorization>, MppError> {
    let TempoSigningMode::Keychain {
        wallet,
        key_authorization: Some(key_authorization),
        ..
    } = signing_mode
    else {
        return Ok(None);
    };

    let now_secs = unix_time_secs();
    if key_authorization
        .authorization
        .expiry
        .is_some_and(|expiry| expiry.get() <= now_secs)
    {
        return Ok(None);
    }

    let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, provider);
    let key_info = keychain
        .getKey(*wallet, key_address)
        .call()
        .await
        .mpp_http("failed to query key authorization state")?;

    if should_attach_key_authorization(key_authorization, &key_info, key_address, now_secs) {
        Ok(Some(key_authorization.as_ref().clone()))
    } else {
        Ok(None)
    }
}

fn should_attach_key_authorization(
    key_authorization: &SignedKeyAuthorization,
    key_info: &IAccountKeychain::KeyInfo,
    key_address: Address,
    now_secs: u64,
) -> bool {
    if key_authorization
        .authorization
        .expiry
        .is_some_and(|expiry| expiry.get() <= now_secs)
    {
        return false;
    }

    key_info.keyId != key_address || key_info.isRevoked || key_info.expiry <= now_secs
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

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
    let keychain = IAccountKeychain::new(ACCOUNT_KEYCHAIN_ADDRESS, provider);

    let now_secs = unix_time_secs();

    let key_info = keychain
        .getKey(wallet_address, key_address)
        .call()
        .await
        .mpp_http("failed to query key info")?;

    let enforces_limits = validate_key_info(&key_info, now_secs)?;
    if !enforces_limits {
        return Ok(None);
    }

    let result = keychain
        .getRemainingLimit(wallet_address, key_address, token)
        .call()
        .await
        .mpp_http("failed to query remaining limit")?;

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
    use std::num::NonZeroU64;

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
            expiry: NonZeroU64::new(9999999999),
            limits,
            allowed_calls: None,
            witness: None,
            is_admin: false,
            account: None,
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

        let signed = make_signed_auth(
            &signer,
            Some(vec![TokenLimit {
                token,
                limit,
                period: 0,
            }]),
        );
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
                period: 0,
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
    fn test_local_key_spending_limit_multiple_tokens_finds_correct() {
        let signer = test_signer();
        let token_a = Address::repeat_byte(0x01);
        let token_b = Address::repeat_byte(0x02);
        let token_c = Address::repeat_byte(0x03);

        let signed = make_signed_auth(
            &signer,
            Some(vec![
                TokenLimit {
                    token: token_a,
                    limit: U256::from(100u64),
                    period: 0,
                },
                TokenLimit {
                    token: token_b,
                    limit: U256::from(200u64),
                    period: 0,
                },
                TokenLimit {
                    token: token_c,
                    limit: U256::from(300u64),
                    period: 0,
                },
            ]),
        );
        assert_eq!(
            local_key_spending_limit(&signed, token_b),
            Some(U256::from(200u64))
        );
    }

    #[test]
    fn test_local_key_spending_limit_duplicate_first_match_wins() {
        let signer = test_signer();
        let token_a = Address::repeat_byte(0x01);

        let signed = make_signed_auth(
            &signer,
            Some(vec![
                TokenLimit {
                    token: token_a,
                    limit: U256::from(100u64),
                    period: 0,
                },
                TokenLimit {
                    token: token_a,
                    limit: U256::from(500u64),
                    period: 0,
                },
            ]),
        );
        assert_eq!(
            local_key_spending_limit(&signed, token_a),
            Some(U256::from(100u64))
        );
    }

    #[test]
    fn test_local_key_spending_limit_large_u256() {
        let signer = test_signer();
        let token = Address::repeat_byte(0x01);
        let large_limit = U256::MAX - U256::from(1);

        let signed = make_signed_auth(
            &signer,
            Some(vec![TokenLimit {
                token,
                limit: large_limit,
                period: 0,
            }]),
        );
        assert_eq!(local_key_spending_limit(&signed, token), Some(large_limit));
    }

    #[test]
    fn test_local_key_spending_limit_zero_limit() {
        let signer = test_signer();
        let token = Address::repeat_byte(0x01);

        let signed = make_signed_auth(
            &signer,
            Some(vec![TokenLimit {
                token,
                limit: U256::ZERO,
                period: 0,
            }]),
        );
        assert_eq!(local_key_spending_limit(&signed, token), Some(U256::ZERO));
    }

    #[test]
    fn test_keychain_address() {
        assert_eq!(
            format!("{:#x}", ACCOUNT_KEYCHAIN_ADDRESS),
            "0xaaaaaaaa00000000000000000000000000000000"
        );
    }

    #[test]
    fn test_pending_authorization_is_dropped_for_active_on_chain_key() {
        let signer = test_signer();
        let key_authorization = make_signed_auth(&signer, None);
        let mut key_info = make_key_info(9_999_999_999, false, false);
        key_info.keyId = signer.address();

        assert!(!should_attach_key_authorization(
            &key_authorization,
            &key_info,
            signer.address(),
            1_000,
        ));
    }

    #[test]
    fn test_pending_authorization_is_kept_for_missing_on_chain_key() {
        let signer = test_signer();
        let key_authorization = make_signed_auth(&signer, None);
        let key_info = make_key_info(0, false, false);

        assert!(should_attach_key_authorization(
            &key_authorization,
            &key_info,
            signer.address(),
            1_000,
        ));
    }

    #[test]
    fn test_expired_pending_authorization_is_dropped() {
        let signer = test_signer();
        let authorization = KeyAuthorization {
            chain_id: 42431,
            key_type: SignatureType::Secp256k1,
            key_id: signer.address(),
            expiry: NonZeroU64::new(1_000),
            limits: None,
            allowed_calls: None,
            witness: None,
            is_admin: false,
            account: None,
        };
        let signature = signer
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        let key_authorization = authorization.into_signed(PrimitiveSignature::Secp256k1(signature));
        let key_info = make_key_info(0, false, false);

        assert!(!should_attach_key_authorization(
            &key_authorization,
            &key_info,
            signer.address(),
            1_000,
        ));
    }

    // --- validate_key_info tests ---

    fn make_key_info(
        expiry: u64,
        is_revoked: bool,
        enforce_limits: bool,
    ) -> IAccountKeychain::KeyInfo {
        IAccountKeychain::KeyInfo {
            signatureType: IAccountKeychain::SignatureType::Secp256k1,
            keyId: Address::ZERO,
            expiry,
            enforceLimits: enforce_limits,
            isRevoked: is_revoked,
        }
    }

    #[test]
    fn test_validate_key_info_expiry_zero_not_provisioned() {
        let key_info = make_key_info(0, true, false);
        let result = validate_key_info(&key_info, 1000);
        assert!(matches!(
            result,
            Err(MppError::Tempo(TempoClientError::AccessKeyNotProvisioned))
        ));
    }

    #[test]
    fn test_validate_key_info_revoked() {
        let key_info = make_key_info(9999999999, true, false);
        let result = validate_key_info(&key_info, 1000);
        match result {
            Err(MppError::Http(msg)) => {
                assert!(msg.contains("revoked"), "expected 'revoked' in: {msg}")
            }
            other => panic!("expected Err(MppError::Http) with 'revoked', got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_key_info_expired() {
        let key_info = make_key_info(1000, false, false);
        let result = validate_key_info(&key_info, 2000);
        match result {
            Err(MppError::Http(msg)) => {
                assert!(msg.contains("expired"), "expected 'expired' in: {msg}")
            }
            other => panic!("expected Err(MppError::Http) with 'expired', got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_key_info_expiry_equals_now() {
        let key_info = make_key_info(1000, false, false);
        let result = validate_key_info(&key_info, 1000);
        match result {
            Err(MppError::Http(msg)) => {
                assert!(msg.contains("expired"), "expected 'expired' in: {msg}")
            }
            other => panic!("expected Err(MppError::Http) with 'expired', got: {other:?}"),
        }
    }

    #[test]
    fn test_validate_key_info_unlimited() {
        let key_info = make_key_info(9999999999, false, false);
        let result = validate_key_info(&key_info, 1000);
        assert!(!result.unwrap());
    }

    #[test]
    fn test_validate_key_info_enforced() {
        let key_info = make_key_info(9999999999, false, true);
        let result = validate_key_info(&key_info, 1000);
        assert!(result.unwrap());
    }
}
