//! Tempo-specific types for Web Payment Auth.

use serde::{Deserialize, Serialize};

use super::MODERATO_CHAIN_ID;

/// Tempo method-specific details in payment requests.
///
/// Per the IETF spec, Tempo methodDetails contains only `chainId` and `feePayer`.
///
/// # Fee Sponsorship Flow
///
/// When `fee_payer` is `true`:
///
/// 1. **Server** sends a challenge with `feePayer: true`
/// 2. **Client** builds a TempoTransaction (type 0x76) with fee payer placeholder,
///    signs it, and returns it as a `transaction` credential
/// 3. **Server** adds fee payer signature and broadcasts the transaction
///
/// # Examples
///
/// ```
/// use mpp::protocol::methods::tempo::TempoMethodDetails;
///
/// let details = TempoMethodDetails {
///     chain_id: Some(42431),
///     fee_payer: Some(true),
///     memo: None,
/// };
/// assert!(details.fee_payer());
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TempoMethodDetails {
    /// Chain ID (42431 for Tempo Moderato)
    #[serde(rename = "chainId", skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,

    /// Whether fee sponsorship is enabled.
    ///
    /// When true, the client signs a TempoTransaction with a fee payer placeholder.
    /// The server adds its fee payer signature before broadcasting.
    #[serde(rename = "feePayer", skip_serializing_if = "Option::is_none")]
    pub fee_payer: Option<bool>,

    /// Optional memo for `transferWithMemo` calls.
    ///
    /// When present, the server verifies `TransferWithMemo` logs instead of `Transfer`.
    /// Must be a 32-byte hex string (with or without 0x prefix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

impl TempoMethodDetails {
    /// Check if fee sponsorship is enabled.
    pub fn fee_payer(&self) -> bool {
        self.fee_payer.unwrap_or(false)
    }

    /// Check if this is for the Tempo Moderato network.
    pub fn is_tempo_moderato(&self) -> bool {
        self.chain_id == Some(MODERATO_CHAIN_ID)
    }

    /// Get the memo as a reference, if present.
    pub fn memo(&self) -> Option<&str> {
        self.memo.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tempo_method_details_serialization() {
        let details = TempoMethodDetails {
            chain_id: Some(42431),
            fee_payer: Some(true),
            memo: None,
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"chainId\":42431"));
        assert!(json.contains("\"feePayer\":true"));

        let parsed: TempoMethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_id, Some(42431));
        assert!(parsed.fee_payer());
        assert!(parsed.is_tempo_moderato());
    }

    #[test]
    fn test_fee_payer_default() {
        let details = TempoMethodDetails::default();
        assert!(!details.fee_payer());
    }

    #[test]
    fn test_is_tempo_moderato() {
        let tempo = TempoMethodDetails {
            chain_id: Some(42431),
            ..Default::default()
        };
        assert!(tempo.is_tempo_moderato());

        let other = TempoMethodDetails {
            chain_id: Some(1),
            ..Default::default()
        };
        assert!(!other.is_tempo_moderato());
    }

    #[test]
    fn test_memo() {
        let details = TempoMethodDetails::default();
        assert!(details.memo().is_none());

        let details_with_memo = TempoMethodDetails {
            memo: Some(
                "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
            ),
            ..Default::default()
        };
        assert_eq!(
            details_with_memo.memo(),
            Some("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
        );
    }

    #[test]
    fn test_serialization_with_memo() {
        let details = TempoMethodDetails {
            chain_id: Some(42431),
            fee_payer: Some(true),
            memo: Some("0xabcdef".to_string()),
        };

        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"memo\":\"0xabcdef\""));

        let parsed: TempoMethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.memo(), Some("0xabcdef"));
    }
}
