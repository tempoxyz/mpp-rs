//! Wire types for the native `evm/charge` payment method.
//!
//! These mirror the generic EVM charge schemas: an `evm`-method `charge` intent
//! whose `methodDetails` carry the EVM-specific parameters, and an
//! `authorization` credential payload carrying an EIP-3009
//! `TransferWithAuthorization` signature.

use serde::{Deserialize, Serialize};

/// Payment method identifier for the native EVM charge method.
pub const METHOD: &str = "evm";

/// The only credential type currently implemented for `evm/charge`.
pub const CREDENTIAL_TYPE_AUTHORIZATION: &str = "authorization";

/// A single split in a split payment.
///
/// Each split directs a portion of the total charge amount to a different
/// recipient. Note: the `authorization` credential type authorizes a single
/// EIP-3009 transfer and therefore does not support splits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Split {
    /// Amount in atomic units.
    pub amount: String,

    /// Recipient address for this split.
    pub recipient: String,
}

/// EVM method-specific details nested under `methodDetails` in the charge request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvmMethodDetails {
    /// EVM chain ID (CAIP-2 `eip155:<chainId>`).
    #[serde(rename = "chainId")]
    pub chain_id: u64,

    /// Credential types the server accepts (e.g. `["authorization"]`).
    #[serde(rename = "credentialTypes", skip_serializing_if = "Option::is_none")]
    pub credential_types: Option<Vec<String>>,

    /// Token decimals for amount conversion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decimals: Option<u8>,

    /// Permit2 contract address (reserved; permit2 credentials are not implemented).
    #[serde(rename = "permit2Address", skip_serializing_if = "Option::is_none")]
    pub permit2_address: Option<String>,

    /// Optional split payouts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub splits: Option<Vec<Split>>,
}

impl EvmMethodDetails {
    /// Whether the challenge explicitly accepts the `authorization` credential
    /// type. An absent `credentialTypes` is treated as *not* accepting
    /// authorization.
    pub fn accepts_authorization(&self) -> bool {
        self.credential_types
            .as_ref()
            .is_some_and(|types| types.iter().any(|t| t == CREDENTIAL_TYPE_AUTHORIZATION))
    }
}

/// Credential type discriminant. Only `authorization` is implemented; modeling
/// it as a single-variant enum makes any other wire value a parse error.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthorizationPayloadType {
    /// EIP-3009 `TransferWithAuthorization` credential.
    #[default]
    #[serde(rename = "authorization")]
    Authorization,
}

/// Client credential payload for the `authorization` credential type.
///
/// Carries the fields of an EIP-3009 `TransferWithAuthorization` plus the
/// signature over its EIP-712 hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationPayload {
    /// Discriminant; always `authorization`.
    #[serde(rename = "type")]
    pub payload_type: AuthorizationPayloadType,

    /// Authorizing account (payer) address.
    pub from: String,

    /// Recipient (payee) address.
    pub to: String,

    /// Atomic amount authorized.
    pub value: String,

    /// Unix-seconds (as a string) before which the authorization is invalid.
    #[serde(rename = "validAfter")]
    pub valid_after: String,

    /// Unix-seconds (as a string) after which the authorization is invalid.
    #[serde(rename = "validBefore")]
    pub valid_before: String,

    /// 32-byte authorization nonce (hex). For native challenges this is the
    /// challenge-bound nonce; see [`super::authorization::challenge_nonce`].
    pub nonce: String,

    /// Signature over the EIP-712 `TransferWithAuthorization` hash.
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_payload_serde_camel_case() {
        let payload = AuthorizationPayload {
            payload_type: AuthorizationPayloadType::Authorization,
            from: "0xfrom".to_string(),
            to: "0xto".to_string(),
            value: "1000000".to_string(),
            valid_after: "0".to_string(),
            valid_before: "9999999999".to_string(),
            nonce: "0xabc".to_string(),
            signature: "0xsig".to_string(),
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"type\":\"authorization\""));
        assert!(json.contains("\"validAfter\":\"0\""));
        assert!(json.contains("\"validBefore\":\"9999999999\""));

        let parsed: AuthorizationPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn test_authorization_payload_rejects_unknown_type() {
        let json = r#"{"type":"permit2","from":"0xf","to":"0xt","value":"1","validAfter":"0","validBefore":"2","nonce":"0xabc","signature":"0xsig"}"#;
        assert!(serde_json::from_str::<AuthorizationPayload>(json).is_err());
    }

    #[test]
    fn test_method_details_serde_camel_case() {
        let details = EvmMethodDetails {
            chain_id: 84532,
            credential_types: Some(vec!["authorization".to_string()]),
            decimals: Some(6),
            permit2_address: None,
            splits: None,
        };
        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"chainId\":84532"));
        assert!(json.contains("\"credentialTypes\":[\"authorization\"]"));
        assert!(!json.contains("permit2Address"));

        let parsed: EvmMethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.chain_id, 84532);
        assert!(parsed.accepts_authorization());
    }

    #[test]
    fn test_accepts_authorization_false_when_absent() {
        // Absent credentialTypes does not accept authorization.
        let details = EvmMethodDetails {
            chain_id: 1,
            credential_types: None,
            ..Default::default()
        };
        assert!(!details.accepts_authorization());
    }

    #[test]
    fn test_method_details_serde_permit2_and_splits() {
        let details = EvmMethodDetails {
            chain_id: 1,
            credential_types: Some(vec!["authorization".to_string()]),
            decimals: None,
            permit2_address: Some("0x000000000022D473030F116dDEE9F6B43aC78BA3".to_string()),
            splits: Some(vec![Split {
                amount: "500".to_string(),
                recipient: "0xrecipient".to_string(),
            }]),
        };
        let json = serde_json::to_string(&details).unwrap();
        assert!(json.contains("\"permit2Address\":\"0x000000000022D473030F116dDEE9F6B43aC78BA3\""));
        assert!(json.contains("\"splits\":[{\"amount\":\"500\",\"recipient\":\"0xrecipient\"}]"));

        let parsed: EvmMethodDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.splits.unwrap().len(), 1);
    }

    #[test]
    fn test_accepts_authorization_false_when_not_listed() {
        let details = EvmMethodDetails {
            chain_id: 1,
            credential_types: Some(vec!["permit2".to_string()]),
            ..Default::default()
        };
        assert!(!details.accepts_authorization());
    }
}
