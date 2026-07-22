//! Local P-256 signing for Tempo primitive signatures.
//!
//! Tempo's P-256 signature envelope carries the public-key coordinates and a
//! flag indicating whether SHA-256 was applied before ECDSA. The latter is
//! required when importing an extractable WebCrypto key from the Tempo
//! Accounts SDK because WebCrypto's ECDSA operation always hashes its input.

use std::fmt;

use alloy::primitives::{Address, ChainId, B256};
use alloy::signers::{local::PrivateKeySigner, Signer, SignerSync};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempo_primitives::transaction::{
    derive_p256_address, tt_signature::P256SignatureWithPreHash, PrimitiveSignature,
};

/// An extractable P-256 JSON Web Key, as persisted by the Tempo Accounts SDK.
#[derive(Clone, Deserialize)]
pub struct P256Jwk {
    /// Key type. Must be `EC`.
    pub kty: String,
    /// Curve. Must be `P-256`.
    pub crv: String,
    /// Base64url-encoded public x-coordinate.
    pub x: String,
    /// Base64url-encoded public y-coordinate.
    pub y: String,
    /// Base64url-encoded private scalar.
    pub d: String,
}

impl fmt::Debug for P256Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("P256Jwk")
            .field("kty", &self.kty)
            .field("crv", &self.crv)
            .field("x", &self.x)
            .field("y", &self.y)
            .field("d", &"<redacted>")
            .finish()
    }
}

/// Errors returned while materializing an Accounts SDK P-256 access key.
#[derive(Debug, thiserror::Error)]
pub enum P256SignerError {
    /// The JWK does not describe a P-256 elliptic-curve key.
    #[error("expected an EC P-256 JWK")]
    UnsupportedJwk,
    /// A JWK coordinate or private scalar is not valid base64url.
    #[error("invalid base64url in P-256 JWK field {field}: {source}")]
    InvalidBase64 {
        /// JWK field name.
        field: &'static str,
        /// Decode error.
        source: base64::DecodeError,
    },
    /// The decoded field was not exactly 32 bytes.
    #[error("P-256 JWK field {field} must decode to 32 bytes")]
    InvalidLength {
        /// JWK field name.
        field: &'static str,
    },
    /// The private scalar is not a valid P-256 key.
    #[error("invalid P-256 private key")]
    InvalidPrivateKey,
    /// The JWK public coordinates do not match its private scalar.
    #[error("P-256 JWK public key does not match its private key")]
    PublicKeyMismatch,
}

/// A local P-256 signer producing canonical Tempo primitive signatures.
///
/// This implements Alloy's existing generic [`Signer`] and [`SignerSync`]
/// interfaces with [`PrimitiveSignature`] as the output type.
#[derive(Clone)]
pub struct TempoP256Signer {
    signing_key: SigningKey,
    pub_key_x: B256,
    pub_key_y: B256,
    address: Address,
    chain_id: Option<ChainId>,
    pre_hash: bool,
}

/// Concrete primitive signer used by Tempo session clients.
///
/// This is an adapter over Alloy's existing generic [`Signer`] interface, not
/// a parallel signer trait. It lets one session provider accept both normal
/// secp256k1 keys and Accounts SDK P-256 access keys.
#[derive(Clone, Debug)]
pub enum TempoPrimitiveSigner {
    /// Standard EVM secp256k1 key.
    Secp256k1(PrivateKeySigner),
    /// Native Tempo P-256 key.
    P256(TempoP256Signer),
}

impl From<PrivateKeySigner> for TempoPrimitiveSigner {
    fn from(value: PrivateKeySigner) -> Self {
        Self::Secp256k1(value)
    }
}

impl From<TempoP256Signer> for TempoPrimitiveSigner {
    fn from(value: TempoP256Signer) -> Self {
        Self::P256(value)
    }
}

#[async_trait::async_trait]
impl Signer<PrimitiveSignature> for TempoPrimitiveSigner {
    async fn sign_hash(&self, hash: &B256) -> alloy::signers::Result<PrimitiveSignature> {
        match self {
            Self::Secp256k1(signer) => signer
                .sign_hash(hash)
                .await
                .map(PrimitiveSignature::Secp256k1),
            Self::P256(signer) => signer.sign_hash(hash).await,
        }
    }

    fn address(&self) -> Address {
        match self {
            Self::Secp256k1(signer) => signer.address(),
            Self::P256(signer) => signer.address(),
        }
    }

    fn chain_id(&self) -> Option<ChainId> {
        match self {
            Self::Secp256k1(signer) => signer.chain_id(),
            Self::P256(signer) => signer.chain_id(),
        }
    }

    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        match self {
            Self::Secp256k1(signer) => signer.set_chain_id(chain_id),
            Self::P256(signer) => signer.set_chain_id(chain_id),
        }
    }
}

impl SignerSync<PrimitiveSignature> for TempoPrimitiveSigner {
    fn sign_hash_sync(&self, hash: &B256) -> alloy::signers::Result<PrimitiveSignature> {
        match self {
            Self::Secp256k1(signer) => signer
                .sign_hash_sync(hash)
                .map(PrimitiveSignature::Secp256k1),
            Self::P256(signer) => signer.sign_hash_sync(hash),
        }
    }

    fn chain_id_sync(&self) -> Option<ChainId> {
        self.chain_id()
    }
}

impl fmt::Debug for TempoP256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TempoP256Signer")
            .field("address", &self.address)
            .field("chain_id", &self.chain_id)
            .field("pre_hash", &self.pre_hash)
            .finish_non_exhaustive()
    }
}

impl TempoP256Signer {
    /// Create a signer from a raw private scalar.
    ///
    /// The resulting signatures cover the supplied digest directly, matching
    /// `TempoAccount.fromP256` in viem.
    pub fn from_slice(private_key: &[u8]) -> Result<Self, P256SignerError> {
        Self::from_slice_with_pre_hash(private_key, false)
    }

    /// Create a signer from an Accounts SDK WebCrypto JWK.
    ///
    /// WebCrypto ECDSA applies SHA-256 internally, so signatures produced from
    /// this key set the Tempo `preHash` flag and sign `SHA-256(digest)`.
    pub fn from_webcrypto_jwk(jwk: &P256Jwk) -> Result<Self, P256SignerError> {
        if jwk.kty != "EC" || jwk.crv != "P-256" {
            return Err(P256SignerError::UnsupportedJwk);
        }

        let private_key = decode_jwk_field("d", &jwk.d)?;
        let expected_x = decode_jwk_field("x", &jwk.x)?;
        let expected_y = decode_jwk_field("y", &jwk.y)?;
        let signer = Self::from_slice_with_pre_hash(&private_key, true)?;

        if signer.pub_key_x.as_slice() != expected_x || signer.pub_key_y.as_slice() != expected_y {
            return Err(P256SignerError::PublicKeyMismatch);
        }
        Ok(signer)
    }

    fn from_slice_with_pre_hash(
        private_key: &[u8],
        pre_hash: bool,
    ) -> Result<Self, P256SignerError> {
        let signing_key =
            SigningKey::from_slice(private_key).map_err(|_| P256SignerError::InvalidPrivateKey)?;
        let point = signing_key.verifying_key().to_encoded_point(false);
        let pub_key_x = point.x().ok_or(P256SignerError::InvalidPrivateKey)?;
        let pub_key_y = point.y().ok_or(P256SignerError::InvalidPrivateKey)?;
        let pub_key_x = B256::from_slice(pub_key_x);
        let pub_key_y = B256::from_slice(pub_key_y);
        let address = derive_p256_address(&pub_key_x, &pub_key_y);

        Ok(Self {
            signing_key,
            pub_key_x,
            pub_key_y,
            address,
            chain_id: None,
            pre_hash,
        })
    }

    /// Return whether this signer applies SHA-256 before ECDSA.
    pub const fn pre_hash(&self) -> bool {
        self.pre_hash
    }

    fn sign_primitive(&self, hash: &B256) -> alloy::signers::Result<PrimitiveSignature> {
        let digest = if self.pre_hash {
            B256::from_slice(&Sha256::digest(hash.as_slice()))
        } else {
            *hash
        };
        let signature: Signature = self
            .signing_key
            .sign_prehash(digest.as_slice())
            .map_err(alloy::signers::Error::other)?;
        let signature = signature.normalize_s().unwrap_or(signature);
        let bytes = signature.to_bytes();

        Ok(PrimitiveSignature::P256(P256SignatureWithPreHash {
            r: B256::from_slice(&bytes[..32]),
            s: B256::from_slice(&bytes[32..]),
            pub_key_x: self.pub_key_x,
            pub_key_y: self.pub_key_y,
            pre_hash: self.pre_hash,
        }))
    }
}

#[async_trait::async_trait]
impl Signer<PrimitiveSignature> for TempoP256Signer {
    async fn sign_hash(&self, hash: &B256) -> alloy::signers::Result<PrimitiveSignature> {
        self.sign_primitive(hash)
    }

    fn address(&self) -> Address {
        self.address
    }

    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }

    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}

impl SignerSync<PrimitiveSignature> for TempoP256Signer {
    fn sign_hash_sync(&self, hash: &B256) -> alloy::signers::Result<PrimitiveSignature> {
        self.sign_primitive(hash)
    }

    fn chain_id_sync(&self) -> Option<ChainId> {
        self.chain_id
    }
}

fn decode_jwk_field(field: &'static str, value: &str) -> Result<[u8; 32], P256SignerError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|source| P256SignerError::InvalidBase64 { field, source })?;
    decoded
        .try_into()
        .map_err(|_| P256SignerError::InvalidLength { field })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn webcrypto_vector_jwk() -> P256Jwk {
        P256Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: "OtOGGpViE5JRa7WT7wVYPtLlhm9ctiYKMBcjf9ibkK8".into(),
            y: "0JYcfjcHWmeRo5xh9WKVsCttJlZ7YV5gqkHuHI6DOI0".into(),
            d: "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI".into(),
        }
    }

    #[test]
    fn imports_accounts_sdk_webcrypto_jwk() {
        let signer = TempoP256Signer::from_webcrypto_jwk(&webcrypto_vector_jwk()).unwrap();
        assert_eq!(
            signer.address(),
            "0xf0159a522607cd6ab1097204c9fafb7bbe6afb6c"
                .parse::<Address>()
                .unwrap()
        );
        assert!(signer.pre_hash());
    }

    #[test]
    fn rejects_mismatched_public_coordinates() {
        let mut jwk = webcrypto_vector_jwk();
        jwk.x = URL_SAFE_NO_PAD.encode([0u8; 32]);
        assert!(matches!(
            TempoP256Signer::from_webcrypto_jwk(&jwk),
            Err(P256SignerError::PublicKeyMismatch)
        ));
    }
}
