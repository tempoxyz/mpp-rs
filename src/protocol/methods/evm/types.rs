//! EVM-specific types for Web Payment Auth methods.
//!
//! This module provides shared types for all EVM-based payment methods.
//! Chain-specific extensions (Tempo, etc.) are in their own modules.

use serde::{Deserialize, Serialize};

/// EVM method-specific details in payment requests.
///
/// These are the minimal fields common to all EVM-based methods.
/// Chain-specific fields (like Tempo's `feePayer`, `nonceKey`) belong
/// in their respective method modules.
///
/// # Examples
///
/// ```
/// use mpp_rs::protocol::methods::evm::EvmMethodDetails;
///
/// let details = EvmMethodDetails {
///     chain_id: Some(1),
/// };
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvmMethodDetails {
    /// Chain ID for EVM-based methods
    #[serde(rename = "chainId", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evm_method_details_serialization() {
        let details = EvmMethodDetails { chain_id: Some(1) };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"chainId\":1"));

        let parsed: EvmMethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_id, Some(1));
    }
}
