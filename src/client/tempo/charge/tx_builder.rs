//! Tempo transaction building utilities.
//!
//! Provides [`build_tempo_tx`] and [`build_charge_credential`] for constructing
//! Tempo transactions and wrapping them in [`PaymentCredential`]s.

use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use tempo_alloy::rpc::TempoTransactionRequest;
use tempo_alloy::TempoNetwork;
use tempo_primitives::transaction::{Call, SignedKeyAuthorization, TempoTransaction};

use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};

/// Options for building a Tempo transaction.
#[derive(Debug, Clone)]
pub struct TempoTxOptions {
    /// Calls to include in the transaction.
    pub calls: Vec<Call>,
    /// Chain ID for the transaction.
    pub chain_id: u64,
    /// Fee token address.
    pub fee_token: Address,
    /// Transaction nonce.
    pub nonce: u64,
    /// Nonce key (use `U256::MAX` for expiring nonce / fee payer mode).
    pub nonce_key: U256,
    /// Gas limit for the transaction.
    pub gas_limit: u64,
    /// Max fee per gas (EIP-1559 style).
    pub max_fee_per_gas: u128,
    /// Max priority fee per gas (EIP-1559 style).
    pub max_priority_fee_per_gas: u128,
    /// Whether the server pays fees (fee payer / fee sponsorship mode).
    pub fee_payer: bool,
    /// Optional validity window upper bound (unix timestamp).
    pub valid_before: Option<u64>,
    /// Optional key authorization to include in the transaction.
    pub key_authorization: Option<SignedKeyAuthorization>,
}

/// Build a [`TempoTransaction`] from options.
pub fn build_tempo_tx(options: TempoTxOptions) -> TempoTransaction {
    TempoTransaction {
        chain_id: options.chain_id,
        // Fee payer mode: fee_token is None (server chooses at co-sign time)
        fee_token: if options.fee_payer {
            None
        } else {
            Some(options.fee_token)
        },
        max_priority_fee_per_gas: options.max_priority_fee_per_gas,
        max_fee_per_gas: options.max_fee_per_gas,
        gas_limit: options.gas_limit,
        calls: options.calls,
        nonce_key: options.nonce_key,
        nonce: options.nonce,
        key_authorization: options.key_authorization,
        access_list: Default::default(),
        // Fee payer mode: placeholder signature triggers skip_fee_token in signing hash
        fee_payer_signature: if options.fee_payer {
            Some(alloy::primitives::Signature::new(
                U256::ZERO,
                U256::ZERO,
                false,
            ))
        } else {
            None
        },
        valid_before: options.valid_before,
        valid_after: None,
        tempo_authorization_list: vec![],
    }
}

/// Default gas cap for `eth_estimateGas` requests.
///
/// Without an explicit `gas` field, Tempo nodes use the block gas limit (~500M)
/// as the simulation cap. This causes the fee-token balance reservation
/// (`gasCap × baseFee / conversionRate`) to exceed moderate wallet balances,
/// triggering spurious `InsufficientBalance` errors during estimation.
///
/// 3M covers key provisioning (~1M intrinsic) with headroom for execution,
/// while keeping the fee-token reservation manageable (~0.06 USDC at 20 gwei).
const GAS_ESTIMATION_CAP: u64 = 3_000_000;

/// Safety buffer added to gas estimates to account for estimation variance.
const GAS_ESTIMATE_BUFFER: u64 = 5_000;

/// Estimate gas for a Tempo AA transaction with error classification and a safety buffer.
///
/// Sets a gas cap on the request to prevent the node from reserving the full block gas
/// limit worth of fee tokens during simulation, then adds a small buffer (+5000) to the
/// estimate to account for variance.
pub async fn estimate_gas(
    provider: &impl Provider<TempoNetwork>,
    mut req: TempoTransactionRequest,
) -> Result<u64, MppError> {
    req.inner.gas = Some(GAS_ESTIMATION_CAP);

    provider
        .estimate_gas(req)
        .await
        .map(|gas| gas.saturating_add(GAS_ESTIMATE_BUFFER))
        .map_err(
            |e| match crate::client::tempo::TempoClientError::from_transport_error(&e) {
                Some(tempo_err) => MppError::from(tempo_err),
                None => MppError::Http(format!("gas estimation failed: {e}")),
            },
        )
}

/// Build a [`PaymentCredential`] from a signed Tempo transaction.
///
/// This is the final step: wrapping a signed, encoded transaction into
/// an MPP credential with the challenge echo and DID source.
pub fn build_charge_credential(
    challenge: &PaymentChallenge,
    signed_tx_bytes: &[u8],
    chain_id: u64,
    from: Address,
) -> PaymentCredential {
    let signed_tx_hex = alloy::hex::encode_prefixed(signed_tx_bytes);
    let did = PaymentCredential::evm_did(chain_id, &from.to_string());
    PaymentCredential::with_source(
        challenge.to_echo(),
        did,
        PaymentPayload::transaction(signed_tx_hex),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::TxKind;

    // --- build_charge_credential ---

    #[test]
    fn test_build_charge_credential() {
        use crate::protocol::core::Base64UrlJson;
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let tx_bytes = vec![0x76, 0xab, 0xcd];
        let from: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let cred = build_charge_credential(&challenge, &tx_bytes, 42431, from);

        assert!(cred.source.as_ref().unwrap().contains("42431"));
        let tx_hex = cred
            .payload
            .get("signature")
            .or_else(|| cred.payload.get("transaction"))
            .and_then(|v| v.as_str())
            .unwrap();
        assert!(tx_hex.starts_with("0x"));
    }

    #[test]
    fn test_build_charge_credential_did_format() {
        use crate::protocol::core::Base64UrlJson;
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let from: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
            .parse()
            .unwrap();
        let cred = build_charge_credential(&challenge, &[0x76, 0xab], 4217, from);

        let did = cred.source.as_ref().unwrap();
        assert!(
            did.starts_with("did:pkh:eip155:4217:"),
            "DID should use eip155 format with chain ID"
        );
    }

    #[test]
    fn test_build_charge_credential_tx_hex_encoding() {
        use crate::protocol::core::Base64UrlJson;
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let tx_bytes = vec![0x76, 0xab, 0xcd, 0xef];
        let cred = build_charge_credential(&challenge, &tx_bytes, 42431, Address::ZERO);

        let tx_hex = cred
            .payload
            .get("signature")
            .or_else(|| cred.payload.get("transaction"))
            .and_then(|v| v.as_str())
            .unwrap();

        assert_eq!(
            tx_hex, "0x76abcdef",
            "tx bytes should be hex-encoded with 0x prefix"
        );
    }

    #[test]
    fn test_build_charge_credential_echoes_challenge() {
        use crate::protocol::core::Base64UrlJson;
        let challenge = PaymentChallenge {
            id: "unique-challenge-id".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let cred = build_charge_credential(&challenge, &[0x76], 42431, Address::ZERO);

        // The echo should contain the challenge ID
        let echo_str = serde_json::to_string(&cred.challenge).unwrap();
        assert!(echo_str.contains("unique-challenge-id"));
    }

    // --- build_tempo_tx ---

    #[test]
    fn test_build_tempo_tx() {
        let calls = vec![Call {
            to: TxKind::Call(Address::repeat_byte(0x22)),
            value: U256::ZERO,
            input: alloy::primitives::Bytes::new(),
        }];

        let tx = build_tempo_tx(TempoTxOptions {
            calls,
            chain_id: 42431,
            fee_token: Address::repeat_byte(0x33),
            nonce: 5,
            nonce_key: U256::ZERO,
            gas_limit: 500_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_payer: false,
            valid_before: None,
            key_authorization: None,
        });

        assert_eq!(tx.chain_id, 42431);
        assert_eq!(tx.nonce, 5);
        assert_eq!(tx.gas_limit, 500_000);
        assert_eq!(tx.max_fee_per_gas, 1_000_000_000);
        assert_eq!(tx.max_priority_fee_per_gas, 100_000_000);
        assert_eq!(tx.fee_token, Some(Address::repeat_byte(0x33)));
        assert_eq!(tx.calls.len(), 1);
        assert_eq!(tx.nonce_key, U256::ZERO);
        assert!(tx.key_authorization.is_none());
        assert!(tx.fee_payer_signature.is_none());
        assert!(tx.valid_before.is_none());
        assert!(tx.valid_after.is_none());
        assert!(tx.tempo_authorization_list.is_empty());
    }

    #[test]
    fn test_build_tempo_tx_with_key_authorization() {
        use alloy::signers::{local::PrivateKeySigner, SignerSync};
        use tempo_primitives::transaction::{KeyAuthorization, PrimitiveSignature, SignatureType};

        let signer: PrivateKeySigner =
            "0x1234567890123456789012345678901234567890123456789012345678901234"
                .parse()
                .unwrap();

        let auth = KeyAuthorization {
            chain_id: 42431,
            key_type: SignatureType::Secp256k1,
            key_id: signer.address(),
            expiry: Some(9999999999),
            limits: None,
        };
        let sig = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        let signed_auth = auth.into_signed(PrimitiveSignature::Secp256k1(sig));

        let tx = build_tempo_tx(TempoTxOptions {
            calls: vec![],
            chain_id: 42431,
            fee_token: Address::ZERO,
            nonce: 0,
            nonce_key: U256::ZERO,
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_payer: false,
            valid_before: None,
            key_authorization: Some(signed_auth),
        });

        assert!(tx.key_authorization.is_some());
    }

    #[test]
    fn test_build_tempo_tx_empty_calls() {
        let tx = build_tempo_tx(TempoTxOptions {
            calls: vec![],
            chain_id: 42431,
            fee_token: Address::ZERO,
            nonce: 0,
            nonce_key: U256::ZERO,
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_payer: false,
            valid_before: None,
            key_authorization: None,
        });

        assert!(tx.calls.is_empty());
        assert_eq!(tx.chain_id, 42431);
    }

    #[test]
    fn test_build_tempo_tx_zero_fields() {
        let tx = build_tempo_tx(TempoTxOptions {
            calls: vec![],
            chain_id: 0,
            fee_token: Address::ZERO,
            nonce: 0,
            nonce_key: U256::ZERO,
            gas_limit: 0,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            fee_payer: false,
            valid_before: None,
            key_authorization: None,
        });

        assert_eq!(tx.chain_id, 0);
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.gas_limit, 0);
        assert_eq!(tx.max_fee_per_gas, 0);
        assert_eq!(tx.max_priority_fee_per_gas, 0);
    }

    // --- build_charge_credential edge cases ---

    #[test]
    fn test_build_charge_credential_empty_tx_bytes() {
        use crate::protocol::core::Base64UrlJson;
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let cred = build_charge_credential(&challenge, &[], 42431, Address::ZERO);
        let tx_hex = cred
            .payload
            .get("signature")
            .or_else(|| cred.payload.get("transaction"))
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(tx_hex, "0x", "empty bytes should produce '0x'");
    }

    #[test]
    fn test_build_charge_credential_did_exact_format() {
        use crate::protocol::core::Base64UrlJson;
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let from: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
            .parse()
            .unwrap();
        let cred = build_charge_credential(&challenge, &[0x76], 4217, from);
        let did = cred.source.as_ref().unwrap();
        let expected = format!("did:pkh:eip155:4217:{}", from);
        assert_eq!(did, &expected, "DID should match exact format");
    }

    #[test]
    fn test_build_tempo_tx_multiple_calls() {
        let calls = vec![
            Call {
                to: TxKind::Call(Address::repeat_byte(0x01)),
                value: U256::ZERO,
                input: alloy::primitives::Bytes::new(),
            },
            Call {
                to: TxKind::Call(Address::repeat_byte(0x02)),
                value: U256::from(100u64),
                input: alloy::primitives::Bytes::from_static(&[0xab]),
            },
        ];

        let tx = build_tempo_tx(TempoTxOptions {
            calls,
            chain_id: 4217,
            fee_token: Address::repeat_byte(0x33),
            nonce: 0,
            nonce_key: U256::ZERO,
            gas_limit: 2_000_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            fee_payer: false,
            valid_before: None,
            key_authorization: None,
        });

        assert_eq!(tx.calls.len(), 2);
        assert_eq!(tx.chain_id, 4217);
        assert_eq!(tx.calls[1].value, U256::from(100u64));
    }
}
