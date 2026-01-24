//! Keystore encryption and decryption for EVM private keys.
//!
//! This module provides functionality for encrypting private keys into
//! Ethereum keystore format (V3) and decrypting them back.
//!
//! This module is only available with the `keystore` feature.

use crate::error::{MppError, Result};
use serde_json::Value;

/// Represents a parsed keystore file.
#[derive(Debug, Clone)]
pub struct Keystore {
    /// Parsed JSON content of the keystore.
    pub content: Value,
}

impl Keystore {
    /// Load a keystore from JSON bytes.
    pub fn from_bytes(json: &[u8]) -> Result<Self> {
        let content: Value = serde_json::from_slice(json).map_err(|e| {
            MppError::InvalidConfig(format!("Invalid keystore JSON: {e}"))
        })?;

        Ok(Self { content })
    }

    /// Get the raw address from the keystore (without 0x prefix).
    pub fn address(&self) -> Option<&str> {
        self.content["address"].as_str()
    }

    /// Get the address with 0x prefix.
    pub fn formatted_address(&self) -> Option<String> {
        self.address().map(|addr| {
            if addr.starts_with("0x") || addr.starts_with("0X") {
                addr.to_string()
            } else {
                format!("0x{addr}")
            }
        })
    }

    /// Decrypt the keystore with the given password.
    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>> {
        let keystore_bytes = serde_json::to_vec(&self.content)
            .map_err(|e| MppError::InvalidConfig(format!("Failed to serialize keystore: {e}")))?;
        
        decrypt_keystore(&keystore_bytes, password)
    }

    /// Validate that this is a properly formatted keystore file.
    pub fn validate(&self) -> Result<()> {
        if !self.content.is_object() {
            return Err(MppError::InvalidConfig(
                "Keystore must be a JSON object".to_string(),
            ));
        }

        // Support both 'crypto' and 'Crypto' (standard v3 keystore uses 'crypto')
        if !self.content["crypto"].is_object() && !self.content["Crypto"].is_object() {
            return Err(MppError::InvalidConfig(
                "Keystore missing crypto field".to_string(),
            ));
        }

        Ok(())
    }
}

const EVM_PRIVATE_KEY_BYTES: usize = 32;

/// Encrypt a private key into keystore JSON format.
///
/// # Arguments
///
/// * `private_key` - The 32-byte private key to encrypt
/// * `password` - The password to use for encryption
///
/// # Returns
///
/// The encrypted keystore as JSON bytes.
pub fn encrypt_keystore(private_key: &[u8], password: &str) -> Result<Vec<u8>> {
    if private_key.len() != EVM_PRIVATE_KEY_BYTES {
        return Err(MppError::InvalidKey(format!(
            "Private key must be {EVM_PRIVATE_KEY_BYTES} bytes, got {}",
            private_key.len()
        )));
    }

    let temp_dir = std::env::temp_dir();
    let mut rng = rand::thread_rng();
    
    let keystore_name = eth_keystore::encrypt_key(
        &temp_dir,
        &mut rng,
        private_key,
        password,
        None,
    )
    .map_err(|e| MppError::InvalidKey(format!("Failed to encrypt keystore: {e}")))?;
    
    let keystore_path = temp_dir.join(&keystore_name);
    let keystore_bytes = std::fs::read(&keystore_path)
        .map_err(|e| MppError::InvalidKey(format!("Failed to read keystore: {e}")))?;
    
    let _ = std::fs::remove_file(&keystore_path);
    
    Ok(keystore_bytes)
}

/// Decrypt a keystore JSON to get the private key bytes.
///
/// # Arguments
///
/// * `keystore_json` - The encrypted keystore as JSON bytes
/// * `password` - The password to use for decryption
///
/// # Returns
///
/// The decrypted 32-byte private key.
pub fn decrypt_keystore(keystore_json: &[u8], password: &str) -> Result<Vec<u8>> {
    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join(format!("mpp-keystore-{}.json", std::process::id()));
    
    std::fs::write(&temp_file, keystore_json)
        .map_err(|e| MppError::InvalidKey(format!("Failed to write temp keystore: {e}")))?;
    
    let result = eth_keystore::decrypt_key(&temp_file, password)
        .map_err(|e| MppError::InvalidKey(format!("Failed to decrypt keystore: {e}")));
    
    let _ = std::fs::remove_file(&temp_file);
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PRIVATE_KEY: [u8; 32] = [
        0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56,
        0x78, 0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12,
        0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x78,
        0x90, 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34,
    ];

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "test_password";
        
        let encrypted = encrypt_keystore(&TEST_PRIVATE_KEY, password)
            .expect("Failed to encrypt keystore");
        
        let decrypted = decrypt_keystore(&encrypted, password)
            .expect("Failed to decrypt keystore");
        
        assert_eq!(decrypted, TEST_PRIVATE_KEY);
    }

    #[test]
    fn test_encrypt_invalid_key_length() {
        let short_key = [0u8; 16];
        let result = encrypt_keystore(&short_key, "password");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_decrypt_wrong_password() {
        let password = "correct_password";
        
        let encrypted = encrypt_keystore(&TEST_PRIVATE_KEY, password)
            .expect("Failed to encrypt keystore");
        
        let result = decrypt_keystore(&encrypted, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_json() {
        let result = decrypt_keystore(b"not valid json", "password");
        assert!(result.is_err());
    }

    #[test]
    fn test_keystore_from_bytes_valid() {
        let keystore_json = r#"{
            "address": "abc123",
            "crypto": {
                "cipher": "aes-128-ctr"
            }
        }"#;
        
        let keystore = Keystore::from_bytes(keystore_json.as_bytes())
            .expect("Failed to parse keystore");
        
        assert_eq!(keystore.address(), Some("abc123"));
    }

    #[test]
    fn test_keystore_from_bytes_invalid_json() {
        let result = Keystore::from_bytes(b"not valid json {{{");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid keystore JSON"));
    }

    #[test]
    fn test_keystore_address() {
        let keystore_json = r#"{
            "address": "1234567890abcdef",
            "crypto": {}
        }"#;
        
        let keystore = Keystore::from_bytes(keystore_json.as_bytes())
            .expect("Failed to parse keystore");
        
        assert_eq!(keystore.address(), Some("1234567890abcdef"));
    }

    #[test]
    fn test_keystore_address_missing() {
        let keystore_json = r#"{"crypto": {}}"#;
        
        let keystore = Keystore::from_bytes(keystore_json.as_bytes())
            .expect("Failed to parse keystore");
        
        assert_eq!(keystore.address(), None);
    }

    #[test]
    fn test_keystore_formatted_address() {
        let keystore_json = r#"{
            "address": "1234567890abcdef",
            "crypto": {}
        }"#;
        
        let keystore = Keystore::from_bytes(keystore_json.as_bytes())
            .expect("Failed to parse keystore");
        
        assert_eq!(keystore.formatted_address(), Some("0x1234567890abcdef".to_string()));
    }

    #[test]
    fn test_keystore_formatted_address_already_prefixed() {
        let keystore_json = r#"{
            "address": "0x1234567890abcdef",
            "crypto": {}
        }"#;
        
        let keystore = Keystore::from_bytes(keystore_json.as_bytes())
            .expect("Failed to parse keystore");
        
        assert_eq!(keystore.formatted_address(), Some("0x1234567890abcdef".to_string()));
    }

    #[test]
    fn test_keystore_formatted_address_missing() {
        let keystore_json = r#"{"crypto": {}}"#;
        
        let keystore = Keystore::from_bytes(keystore_json.as_bytes())
            .expect("Failed to parse keystore");
        
        assert_eq!(keystore.formatted_address(), None);
    }

    #[test]
    fn test_keystore_validate_not_object() {
        let keystore = Keystore::from_bytes(b"[]")
            .expect("Failed to parse keystore");
        
        let result = keystore.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be a JSON object"));
    }

    #[test]
    fn test_keystore_validate_missing_crypto_field() {
        let keystore_json = r#"{
            "address": "abc123",
            "version": 3
        }"#;
        
        let keystore = Keystore::from_bytes(keystore_json.as_bytes())
            .expect("Failed to parse keystore");
        
        let result = keystore.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("missing crypto field"));
    }

    #[test]
    fn test_keystore_validate_with_lowercase_crypto() {
        let keystore_json = r#"{
            "address": "abc123",
            "crypto": {
                "cipher": "aes-128-ctr"
            }
        }"#;
        
        let keystore = Keystore::from_bytes(keystore_json.as_bytes())
            .expect("Failed to parse keystore");
        
        assert!(keystore.validate().is_ok());
    }

    #[test]
    fn test_keystore_validate_with_uppercase_crypto() {
        let keystore_json = r#"{
            "address": "abc123",
            "Crypto": {
                "cipher": "aes-128-ctr"
            }
        }"#;
        
        let keystore = Keystore::from_bytes(keystore_json.as_bytes())
            .expect("Failed to parse keystore");
        
        assert!(keystore.validate().is_ok());
    }

    #[test]
    fn test_keystore_decrypt_method() {
        let password = "test_password";
        
        let encrypted = encrypt_keystore(&TEST_PRIVATE_KEY, password)
            .expect("Failed to encrypt keystore");
        
        let keystore = Keystore::from_bytes(&encrypted)
            .expect("Failed to parse keystore");
        
        let decrypted = keystore.decrypt(password)
            .expect("Failed to decrypt keystore");
        
        assert_eq!(decrypted, TEST_PRIVATE_KEY);
    }
}
