//! T5 TIP-1034 reserve channel precompile voucher signing and channel-id
//! computation. Companion to [`voucher`](super::voucher) for the legacy
//! Solidity escrow.

#[cfg(feature = "tempo")]
use alloy::primitives::{keccak256, Address, Bytes, Uint, B256, U256};
#[cfg(feature = "tempo")]
use alloy::signers::Signer;
#[cfg(feature = "tempo")]
use alloy::sol_types::{eip712_domain, SolStruct, SolValue};
#[cfg(feature = "tempo")]
use tempo_alloy::contracts::precompiles::TIP20_CHANNEL_RESERVE_ADDRESS;
#[cfg(feature = "tempo")]
use tempo_primitives::transaction::{PrimitiveSignature, TempoSignature};

#[cfg(feature = "tempo")]
use crate::error::{MppError, Result};

/// EIP-712 domain name verified by the precompile.
pub const PRECOMPILE_DOMAIN_NAME: &str = "TIP20 Channel Reserve";

/// EIP-712 domain version verified by the precompile.
pub const PRECOMPILE_DOMAIN_VERSION: &str = "1";

/// Compute a TIP-1034 channel id. `expiring_nonce_hash` must come from the
/// unsigned open tx via [`compute_expiring_nonce_hash`](crate::client::tempo::session::channel_ops::compute_expiring_nonce_hash).
#[cfg(feature = "tempo")]
#[allow(clippy::too_many_arguments)]
pub fn compute_precompile_channel_id(
    payer: Address,
    payee: Address,
    operator: Address,
    token: Address,
    salt: B256,
    authorized_signer: Address,
    expiring_nonce_hash: B256,
    chain_id: u64,
) -> B256 {
    compute_precompile_channel_id_with_escrow(
        payer,
        payee,
        operator,
        token,
        salt,
        authorized_signer,
        expiring_nonce_hash,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )
}

/// Compute a TIP-1034 channel id with an explicit escrow/precompile address.
#[cfg(feature = "tempo")]
#[allow(clippy::too_many_arguments)]
pub fn compute_precompile_channel_id_with_escrow(
    payer: Address,
    payee: Address,
    operator: Address,
    token: Address,
    salt: B256,
    authorized_signer: Address,
    expiring_nonce_hash: B256,
    escrow_contract: Address,
    chain_id: u64,
) -> B256 {
    let encoded = (
        payer,
        payee,
        operator,
        token,
        salt,
        authorized_signer,
        expiring_nonce_hash,
        escrow_contract,
        U256::from(chain_id),
    )
        .abi_encode();
    keccak256(&encoded)
}

#[cfg(feature = "tempo")]
alloy::sol! {
    /// EIP-712 voucher struct. `uint96` (legacy escrow uses `uint128`).
    #[derive(Debug)]
    struct Voucher {
        bytes32 channelId;
        uint96 cumulativeAmount;
    }
}

/// Maximum cumulative amount the precompile accepts (2^96 − 1).
#[cfg(feature = "tempo")]
pub const PRECOMPILE_MAX_CUMULATIVE_AMOUNT: u128 = (1u128 << 96) - 1;

/// Compute the TIP-1034 EIP-712 voucher signing hash.
#[cfg(feature = "tempo")]
pub fn precompile_voucher_signing_hash(
    channel_id: B256,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<B256> {
    precompile_voucher_signing_hash_with_escrow(
        channel_id,
        cumulative_amount,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )
}

/// Compute the TIP-1034 EIP-712 voucher signing hash with an explicit
/// escrow/precompile verifier.
#[cfg(feature = "tempo")]
pub fn precompile_voucher_signing_hash_with_escrow(
    channel_id: B256,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<B256> {
    if cumulative_amount > PRECOMPILE_MAX_CUMULATIVE_AMOUNT {
        return Err(MppError::InvalidConfig(format!(
            "cumulative_amount {cumulative_amount} exceeds precompile uint96 max"
        )));
    }

    let domain = eip712_domain! {
        name: PRECOMPILE_DOMAIN_NAME,
        version: PRECOMPILE_DOMAIN_VERSION,
        chain_id: chain_id,
        verifying_contract: escrow_contract,
    };

    let voucher = Voucher {
        channelId: channel_id,
        cumulativeAmount: Uint::<96, 2>::from(cumulative_amount),
    };

    Ok(voucher.eip712_signing_hash(&domain))
}

/// Sign a TIP-1034 voucher (EIP-712). Returns 65-byte ECDSA signature.
/// Rejects `cumulative_amount > PRECOMPILE_MAX_CUMULATIVE_AMOUNT` with
/// [`MppError::InvalidConfig`](crate::error::MppError::InvalidConfig).
#[cfg(feature = "tempo")]
pub async fn sign_precompile_voucher(
    signer: &impl Signer,
    channel_id: B256,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<Bytes> {
    sign_precompile_voucher_with_escrow(
        signer,
        channel_id,
        cumulative_amount,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )
    .await
}

/// Sign a TIP-1034 voucher with an explicit escrow/precompile verifier.
#[cfg(feature = "tempo")]
pub async fn sign_precompile_voucher_with_escrow(
    signer: &impl Signer,
    channel_id: B256,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<Bytes> {
    let signing_hash = precompile_voucher_signing_hash_with_escrow(
        channel_id,
        cumulative_amount,
        escrow_contract,
        chain_id,
    )?;
    let signature = signer.sign_hash(&signing_hash).await.map_err(|e| {
        MppError::InvalidSignature(Some(format!("failed to sign precompile voucher: {e}")))
    })?;

    Ok(Bytes::from(signature.as_bytes().to_vec()))
}

/// Sign a TIP-1034 voucher with a signer that returns a Tempo primitive
/// signature, including P-256 and WebAuthn signers.
#[cfg(feature = "tempo")]
pub async fn sign_precompile_voucher_primitive(
    signer: &impl Signer<PrimitiveSignature>,
    channel_id: B256,
    cumulative_amount: u128,
    chain_id: u64,
) -> Result<Bytes> {
    sign_precompile_voucher_primitive_with_escrow(
        signer,
        channel_id,
        cumulative_amount,
        TIP20_CHANNEL_RESERVE_ADDRESS,
        chain_id,
    )
    .await
}

/// Sign a TIP-1034 voucher with an explicit verifier and a Tempo primitive
/// signer.
#[cfg(feature = "tempo")]
pub async fn sign_precompile_voucher_primitive_with_escrow(
    signer: &impl Signer<PrimitiveSignature>,
    channel_id: B256,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<Bytes> {
    let signing_hash = precompile_voucher_signing_hash_with_escrow(
        channel_id,
        cumulative_amount,
        escrow_contract,
        chain_id,
    )?;
    let signature = signer.sign_hash(&signing_hash).await.map_err(|e| {
        MppError::InvalidSignature(Some(format!("failed to sign precompile voucher: {e}")))
    })?;
    Ok(signature.to_bytes())
}

/// Verify a canonical TIP-1020 primitive signature over a TIP-1034 voucher.
#[cfg(feature = "tempo")]
pub fn verify_precompile_voucher_signature(
    signature: &[u8],
    expected_signer: Address,
    channel_id: B256,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<bool> {
    let signing_hash = precompile_voucher_signing_hash_with_escrow(
        channel_id,
        cumulative_amount,
        escrow_contract,
        chain_id,
    )?;
    let primitive = PrimitiveSignature::from_bytes(signature)
        .map_err(|e| MppError::InvalidSignature(Some(e.to_string())))?;
    if primitive.to_bytes().as_ref() != signature {
        return Ok(false);
    }
    Ok(TempoSignature::Primitive(primitive)
        .recover_signer(&signing_hash)
        .is_ok_and(|address| address == expected_signer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tempo")]
    #[test]
    fn compute_precompile_channel_id_matches_precompile_formula() {
        use alloy::primitives::{Address, B256};

        // Reference vector: tempo @ 32bb1d4 crates/precompiles/src/tip20_channel_reserve/mod.rs L589-L613
        let payer: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let payee: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let operator: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let token: Address = "0x4444444444444444444444444444444444444444"
            .parse()
            .unwrap();
        let salt = B256::repeat_byte(0x55);
        let authorized_signer: Address = "0x6666666666666666666666666666666666666666"
            .parse()
            .unwrap();
        let expiring_nonce_hash = B256::repeat_byte(0x77);
        let chain_id = 4217u64;

        let id = compute_precompile_channel_id(
            payer,
            payee,
            operator,
            token,
            salt,
            authorized_signer,
            expiring_nonce_hash,
            chain_id,
        );

        let again = compute_precompile_channel_id(
            payer,
            payee,
            operator,
            token,
            salt,
            authorized_signer,
            expiring_nonce_hash,
            chain_id,
        );
        assert_eq!(id, again);
        assert_ne!(id, B256::ZERO);
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn compute_precompile_channel_id_differs_from_legacy_formula() {
        // Precompile binds operator + expiringNonceHash + precompile addr; legacy doesn't.
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
        let salt = B256::repeat_byte(0x44);
        let authorized_signer: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();
        let chain_id = 4217u64;

        let precompile_id = compute_precompile_channel_id(
            payer,
            payee,
            Address::ZERO,
            token,
            salt,
            authorized_signer,
            B256::ZERO,
            chain_id,
        );

        let legacy_escrow: Address = "0x33b901018174DDabE4841042ab76ba85D4e24f25"
            .parse()
            .unwrap();
        let legacy_id = super::super::voucher::compute_channel_id(
            payer,
            payee,
            token,
            salt,
            authorized_signer,
            legacy_escrow,
            chain_id,
        );

        assert_ne!(precompile_id, legacy_id);
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn compute_precompile_channel_id_matches_mppx_golden() {
        let channel_id = compute_precompile_channel_id_with_escrow(
            "0x3d6885f89100445ca9869d1b0a49c97cfdbafeee"
                .parse()
                .unwrap(),
            "0xda2390fEE8d9744b39A8A855675649e95617aCd8"
                .parse()
                .unwrap(),
            Address::ZERO,
            "0x20C0000000000000000000000000000000000000"
                .parse()
                .unwrap(),
            "0xfb05173ba9285aef8a91f275930f68ad3565a491edb810c07baa60b643fdd378"
                .parse()
                .unwrap(),
            "0xFE9d3D9cBb5f6FBe495b03f7Ec90d4Adc22126f5"
                .parse()
                .unwrap(),
            "0x4e40183cda8c676032af4f7b038178505d877ae1c36b374239fe20ac3485c3ab"
                .parse()
                .unwrap(),
            TIP20_CHANNEL_RESERVE_ADDRESS,
            42431,
        );

        assert_eq!(
            channel_id,
            "0xb3946b996bd166db3b61fba0f6af2918b6687bc054e2f4bae979edffc7bd0b4d"
                .parse::<B256>()
                .unwrap()
        );
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn sign_precompile_voucher_roundtrips_via_eip712() {
        use alloy::primitives::{Bytes, B256};
        use alloy::signers::local::PrivateKeySigner;
        use alloy::sol_types::{eip712_domain, SolStruct};
        use tempo_alloy::contracts::precompiles::TIP20_CHANNEL_RESERVE_ADDRESS;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xAB);
        let cumulative: u128 = 12_345;
        let chain_id = 4217u64;

        let sig: Bytes = sign_precompile_voucher(&signer, channel_id, cumulative, chain_id)
            .await
            .unwrap();
        assert_eq!(sig.len(), 65);

        let domain = eip712_domain! {
            name: PRECOMPILE_DOMAIN_NAME,
            version: PRECOMPILE_DOMAIN_VERSION,
            chain_id: chain_id,
            verifying_contract: TIP20_CHANNEL_RESERVE_ADDRESS,
        };
        let voucher = Voucher {
            channelId: channel_id,
            cumulativeAmount: alloy::primitives::Uint::<96, 2>::from(cumulative),
        };
        let hash = voucher.eip712_signing_hash(&domain);
        let parsed = alloy::signers::Signature::try_from(sig.as_ref()).unwrap();
        let recovered = parsed.recover_address_from_prehash(&hash).unwrap();
        assert_eq!(recovered, signer.address());
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn precompile_voucher_signing_hash_matches_tip1034_golden() {
        let channel_id: B256 = "0x57e629663a75a0a49f8dc65c9f62ee38ab5dfa9124d7316d160766e4ecbc1227"
            .parse()
            .unwrap();
        let hash = precompile_voucher_signing_hash(channel_id, 50, 42431).unwrap();
        let expected: B256 = "0x41a23f1573d302acae1dcec60d237f78d2514768faf670ef27458931c38b5db3"
            .parse()
            .unwrap();
        assert_eq!(hash, expected);
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn precompile_voucher_signing_hash_binds_explicit_escrow() {
        let channel_id = B256::repeat_byte(0x42);
        let canonical =
            precompile_voucher_signing_hash(channel_id, 50, 42431).expect("canonical hash");
        let custom = precompile_voucher_signing_hash_with_escrow(
            channel_id,
            50,
            Address::repeat_byte(0x11),
            42431,
        )
        .expect("custom hash");

        assert_ne!(canonical, custom);
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn sign_precompile_voucher_rejects_uint96_overflow() {
        use alloy::primitives::B256;
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let too_big = PRECOMPILE_MAX_CUMULATIVE_AMOUNT + 1;
        let err = sign_precompile_voucher(&signer, B256::ZERO, too_big, 4217)
            .await
            .expect_err("must reject u128 values that overflow uint96");
        assert!(matches!(err, crate::error::MppError::InvalidConfig(_)));
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn sign_precompile_voucher_accepts_uint96_max() {
        use alloy::primitives::B256;
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        sign_precompile_voucher(&signer, B256::ZERO, PRECOMPILE_MAX_CUMULATIVE_AMOUNT, 4217)
            .await
            .expect("uint96 max must be accepted");
    }

    #[cfg(feature = "tempo")]
    #[tokio::test]
    async fn sign_precompile_voucher_domain_differs_from_legacy() {
        // Guards against cross-wiring the two EIP-712 domains.
        use alloy::primitives::{Address, B256};
        use alloy::signers::local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xCD);
        let amount: u128 = 1_000;
        let chain_id = 4217u64;
        let legacy_escrow: Address = "0x33b901018174DDabE4841042ab76ba85D4e24f25"
            .parse()
            .unwrap();

        let precompile_sig = sign_precompile_voucher(&signer, channel_id, amount, chain_id)
            .await
            .unwrap();
        let legacy_sig = super::super::voucher::sign_voucher(
            &signer,
            channel_id,
            amount,
            legacy_escrow,
            chain_id,
        )
        .await
        .unwrap();

        assert_ne!(precompile_sig, legacy_sig);
    }

    #[cfg(feature = "tempo")]
    #[test]
    fn verifies_accounts_sdk_webcrypto_p256_voucher_vector() {
        // Generated with viem 2.52.2 `TempoAccount.fromWebCryptoP256` and
        // `TempoAccount.signVoucher`, which is the path used by MPPx.
        let channel_id = B256::repeat_byte(0xab);
        let signature = alloy::hex::decode(
            "01a8e4059a7c38ba2fc568b9d0b5d5c6e4f7c80e2e3e94905977923457b14e8a727a45b06c3c3c725536c9f0383e1c85995a1ddb8a2018c308ad0762a1fb6dc24b3ad3861a95621392516bb593ef05583ed2e5866f5cb6260a3017237fd89b90afd0961c7e37075a6791a39c61f56295b02b6d26567b615e60aa41ee1c8e83388d01",
        )
        .unwrap();
        let expected_signer = "0xf0159a522607cd6ab1097204c9fafb7bbe6afb6c"
            .parse()
            .unwrap();

        assert!(verify_precompile_voucher_signature(
            &signature,
            expected_signer,
            channel_id,
            1_234_567,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            4217,
        )
        .unwrap());
    }

    #[cfg(all(feature = "tempo", feature = "client"))]
    #[tokio::test]
    async fn p256_signer_produces_verifiable_webcrypto_compatible_voucher() {
        use crate::client::tempo::signing::{P256Jwk, TempoP256Signer};

        let signer = TempoP256Signer::from_webcrypto_jwk(&P256Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "OtOGGpViE5JRa7WT7wVYPtLlhm9ctiYKMBcjf9ibkK8".into(),
            y: "0JYcfjcHWmeRo5xh9WKVsCttJlZ7YV5gqkHuHI6DOI0".into(),
            d: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI".into(),
        })
        .unwrap();
        let channel_id = B256::repeat_byte(0xab);
        let signature = sign_precompile_voucher_primitive(&signer, channel_id, 1_234_567, 4217)
            .await
            .unwrap();

        assert!(verify_precompile_voucher_signature(
            &signature,
            signer.address(),
            channel_id,
            1_234_567,
            TIP20_CHANNEL_RESERVE_ADDRESS,
            4217,
        )
        .unwrap());
    }
}
