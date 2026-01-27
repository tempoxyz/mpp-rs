//! Tempo-specific types for Web Payment Auth.

use serde::{Deserialize, Serialize};

use super::CHAIN_ID;

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
/// use mpay::protocol::methods::tempo::TempoMethodDetails;
///
/// let details = TempoMethodDetails {
///     chain_id: Some(42431),
///     fee_payer: Some(true),
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
}

impl TempoMethodDetails {
    /// Check if fee sponsorship is enabled.
    pub fn fee_payer(&self) -> bool {
        self.fee_payer.unwrap_or(false)
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
            chain_id: Some(42431),
            fee_payer: Some(true),
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
}
