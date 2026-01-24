//! Tempo-specific types for Web Payment Auth.

use serde::{Deserialize, Serialize};

use super::CHAIN_ID;
use crate::evm::U256;

/// Tempo method-specific details in payment requests.
///
/// Extends the base EVM method details with Tempo-specific features:
/// - 2D nonces (nonce_key for parallel transaction streams)
/// - TIP-20 token support (fee_token for gas payment in tokens)
///
/// # Examples
///
/// ```
/// use mpay::protocol::methods::tempo::TempoMethodDetails;
///
/// let details = TempoMethodDetails {
///     chain_id: Some(88153),
///     fee_payer: Some(true),
///     nonce_key: None, // Uses default nonce stream
///     fee_token: None, // Uses same token as payment
///     valid_from: None,
///     valid_before: None,
/// };
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempoMethodDetails {
    /// Chain ID (should be 88153 for Tempo Moderato)
    #[serde(rename = "chainId", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    /// Whether server pays transaction fees
    #[serde(rename = "feePayer", skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,

    /// 2D nonce key for parallel transaction streams.
    /// If not specified, uses the default nonce stream (0).
    #[serde(rename = "nonceKey", skip_serializing_if = "Option::is_none")]
    pub nonce_key: Option<String>,

    /// Token address for gas payment (TIP-20 fee payment).
    /// If not specified, uses the same token as the payment currency.
    #[serde(rename = "feeToken", skip_serializing_if = "Option::is_none")]
    pub fee_token: Option<String>,

    /// Valid from time (ISO 8601, for authorize/subscription)
    #[serde(rename = "validFrom", skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,

    /// Valid before time (ISO 8601, for time-bounded transactions)
    #[serde(rename = "validBefore", skip_serializing_if = "Option::is_none")]
    pub valid_before: Option<String>,
}

impl TempoMethodDetails {
    /// Check if server pays transaction fees.
    pub fn fee_payer(&self) -> bool {
        self.fee_payer.unwrap_or(false)
    }

    /// Get the nonce key as U256 for 2D nonces.
    ///
    /// Returns U256::ZERO if not specified (default nonce stream).
    pub fn nonce_key_u256(&self) -> U256 {
        self.nonce_key
            .as_ref()
            .and_then(|s| s.parse::<u128>().ok())
            .map(U256::from)
            .unwrap_or(U256::ZERO)
    }

    /// Check if this is for the Tempo Moderato network.
    pub fn is_tempo_moderato(&self) -> bool {
        self.chain_id == Some(CHAIN_ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tempo_method_details_serialization() {
        let details = TempoMethodDetails {
            chain_id: Some(88153),
            fee_payer: Some(true),
            nonce_key: Some("1".to_string()),
            fee_token: Some("0x123".to_string()),
            valid_from: None,
            valid_before: Some("2025-01-01T00:00:00Z".to_string()),
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"chainId\":88153"));
        assert!(json.contains("\"feePayer\":true"));
        assert!(json.contains("\"nonceKey\":\"1\""));
        assert!(json.contains("\"feeToken\":\"0x123\""));
        assert!(json.contains("\"validBefore\":"));
        assert!(!json.contains("validFrom"));

        let parsed: TempoMethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_id, Some(88153));
        assert!(parsed.fee_payer());
        assert!(parsed.is_tempo_moderato());
    }

    #[test]
    fn test_nonce_key_u256() {
        let details = TempoMethodDetails {
            nonce_key: Some("12345".to_string()),
            ..Default::default()
        };
        assert_eq!(details.nonce_key_u256(), U256::from(12345u64));

        let default_details = TempoMethodDetails::default();
        assert_eq!(default_details.nonce_key_u256(), U256::ZERO);
    }

    #[test]
    fn test_fee_payer_default() {
        let details = TempoMethodDetails::default();
        assert!(!details.fee_payer());
    }

    #[test]
    fn test_is_tempo_moderato() {
        let tempo = TempoMethodDetails {
            chain_id: Some(88153),
            ..Default::default()
        };
        assert!(tempo.is_tempo_moderato());

        let other = TempoMethodDetails {
            chain_id: Some(1),
            ..Default::default()
        };
        assert!(!other.is_tempo_moderato());
    }
}
