//! Cryptographic utilities for key generation

use crate::error::{MppError, Result};

/// EVM private key length in bytes
const EVM_PRIVATE_KEY_BYTES: usize = 32;

/// Trait for wallet key generation
///
/// # Examples
///
/// ```
/// use mpay::crypto::{KeyGenerator, EvmKeyGenerator};
///
/// // Generate an EVM key
/// let (private_key, address) = EvmKeyGenerator::generate().unwrap();
/// assert_eq!(private_key.len(), 64); // 32 bytes as hex
/// assert!(address.starts_with("0x"));
///
/// // Check key formats
/// assert_eq!(EvmKeyGenerator::key_format(), "hex");
/// ```
pub trait KeyGenerator {
    /// Generate a new key pair
    /// Returns (private_key, public_key_or_address)
    fn generate() -> Result<(String, String)>;

    /// Validate a private key
    fn validate_key(key: &str) -> Result<()>;

    /// Get the key format name
    fn key_format() -> &'static str;
}

/// EVM (Ethereum Virtual Machine) key generator
///
/// Generates secp256k1 private keys and derives Ethereum-compatible addresses.
/// Private keys are returned as 64-character hexadecimal strings (32 bytes).
///
/// # Examples
///
/// ```
/// use mpay::crypto::{KeyGenerator, EvmKeyGenerator};
///
/// let (private_key, address) = EvmKeyGenerator::generate().unwrap();
/// assert_eq!(private_key.len(), 64);
/// assert!(address.starts_with("0x"));
/// ```
pub struct EvmKeyGenerator;

impl KeyGenerator for EvmKeyGenerator {
    fn generate() -> Result<(String, String)> {
        generate_evm_key()
    }

    fn validate_key(key: &str) -> Result<()> {
        validate_evm_key(key)
    }

    fn key_format() -> &'static str {
        "hex"
    }
}

/// Generate a new EVM private key
/// Returns (private_key_hex, address)
pub fn generate_evm_key() -> Result<(String, String)> {
    use alloy_signer_local::PrivateKeySigner;
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let key_bytes: [u8; EVM_PRIVATE_KEY_BYTES] = rng.gen();
    let key_hex = hex::encode(key_bytes);

    // Parse to get the address
    let signer: PrivateKeySigner = key_hex
        .parse()
        .map_err(|e| MppError::InvalidKey(format!("Failed to parse generated key: {e}")))?;

    let address = format!("{:#x}", signer.address());

    Ok((key_hex, address))
}

/// Derive an EVM address from private key bytes
///
/// Takes 32 bytes of private key data and returns the derived Ethereum address.
///
/// # Example
/// ```
/// use mpay::crypto::derive_evm_address;
///
/// let key_bytes = hex::decode("1234567890123456789012345678901234567890123456789012345678901234").unwrap();
/// let address = derive_evm_address(&key_bytes).unwrap();
/// assert!(address.starts_with("0x"));
/// ```
pub fn derive_evm_address(private_key_bytes: &[u8]) -> Result<String> {
    use alloy_signer_local::PrivateKeySigner;

    if private_key_bytes.len() != EVM_PRIVATE_KEY_BYTES {
        return Err(MppError::InvalidKey(format!(
            "Private key must be {} bytes, got {}",
            EVM_PRIVATE_KEY_BYTES,
            private_key_bytes.len()
        )));
    }

    let key_hex = hex::encode(private_key_bytes);
    let signer: PrivateKeySigner = key_hex
        .parse()
        .map_err(|e| MppError::InvalidKey(format!("Failed to parse private key: {e}")))?;

    Ok(format!("{:#x}", signer.address()))
}

/// Validate an EVM private key hex string
pub fn validate_evm_key(key: &str) -> Result<()> {
    let key = crate::utils::strip_0x_prefix(key);
    let key_bytes =
        hex::decode(key).map_err(|e| MppError::InvalidKey(format!("Invalid hex: {e}")))?;

    if key_bytes.len() != EVM_PRIVATE_KEY_BYTES {
        return Err(MppError::InvalidKey(format!(
            "Private key must be {} bytes, got {}",
            EVM_PRIVATE_KEY_BYTES,
            key_bytes.len()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_evm_key() {
        let result = generate_evm_key();
        assert!(result.is_ok());

        let (key, address) = result.expect("Failed to generate EVM key");
        assert_eq!(key.len(), 64); // 32 bytes as hex
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn test_validate_evm_key() {
        let valid_key = "0x1234567890123456789012345678901234567890123456789012345678901234";
        assert!(validate_evm_key(valid_key).is_ok());

        let invalid_key = "0x12345";
        assert!(validate_evm_key(invalid_key).is_err());
    }

    #[test]
    fn test_derive_evm_address_invalid_length() {
        let too_short = vec![0u8; 16];
        let result = derive_evm_address(&too_short);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"));

        let too_long = vec![0u8; 64];
        let result = derive_evm_address(&too_long);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("must be 32 bytes"));
    }
}
