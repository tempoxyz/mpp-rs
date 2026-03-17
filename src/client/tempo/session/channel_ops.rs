//! Shared client-side channel operations for Tempo session payments.
//!
//! Provides low-level helpers for escrow resolution, channel ID computation,
//! voucher/close/open payload construction, channel recovery from on-chain state,
//! and credential serialization.
//!
//! Ported from the TypeScript SDK's `ChannelOps.ts`.

use alloy::primitives::{Address, Bytes, TxKind, B256, U256};
use alloy::providers::Provider;
use alloy::signers::Signer;
use alloy::sol_types::{SolCall, SolValue};
use tempo_alloy::TempoNetwork;

use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential};
use crate::protocol::intents::SessionRequest;
use crate::protocol::methods::tempo::session::{SessionCredentialPayload, TempoSessionExt};
use crate::protocol::methods::tempo::voucher::{compute_channel_id, sign_voucher};
use crate::protocol::methods::tempo::MODERATO_CHAIN_ID;

/// Default escrow contract addresses per chain ID.
pub fn default_escrow_contract(chain_id: u64) -> Option<Address> {
    match chain_id {
        4217 => Some(
            "0x33b901018174DDabE4841042ab76ba85D4e24f25"
                .parse()
                .unwrap(),
        ),
        42431 => Some(
            "0xe1c4d3dce17bc111181ddf716f75bae49e61a336"
                .parse()
                .unwrap(),
        ),
        _ => None,
    }
}

/// Client-side channel entry tracking channel state.
#[derive(Debug, Clone)]
pub struct ChannelEntry {
    /// On-chain channel ID (keccak256 of channel parameters).
    pub channel_id: B256,
    /// Random salt used during channel creation.
    pub salt: B256,
    /// Running cumulative amount of all vouchers issued.
    pub cumulative_amount: u128,
    /// Escrow contract address.
    pub escrow_contract: Address,
    /// Chain ID where the escrow contract is deployed.
    pub chain_id: u64,
    /// Whether the channel has been opened on-chain.
    pub opened: bool,
}

/// Resolve chain ID from a session challenge's methodDetails.
pub fn resolve_chain_id(challenge: &PaymentChallenge) -> u64 {
    let session: Result<SessionRequest, _> = challenge.request.decode();
    session
        .ok()
        .and_then(|r| r.chain_id())
        .unwrap_or(MODERATO_CHAIN_ID)
}

/// Resolve escrow contract address from challenge methodDetails, an override, or defaults.
pub fn resolve_escrow(
    challenge: &PaymentChallenge,
    chain_id: u64,
    escrow_override: Option<Address>,
) -> Result<Address, MppError> {
    // Try challenge methodDetails first
    if let Ok(req) = challenge.request.decode::<SessionRequest>() {
        if let Ok(addr_str) = req.escrow_contract() {
            if let Ok(addr) = addr_str.parse::<Address>() {
                return Ok(addr);
            }
        }
    }

    // Then override
    if let Some(addr) = escrow_override {
        return Ok(addr);
    }

    // Then defaults
    default_escrow_contract(chain_id).ok_or_else(|| {
        MppError::InvalidConfig(
            "No escrowContract available. Provide it in parameters or ensure the server challenge includes it.".to_string(),
        )
    })
}

/// Build a `PaymentCredential` from a challenge and session payload.
pub fn build_credential(
    challenge: &PaymentChallenge,
    payload: SessionCredentialPayload,
    chain_id: u64,
    signer_address: Address,
) -> PaymentCredential {
    let echo = challenge.to_echo();
    let source = format!("did:pkh:eip155:{}:{}", chain_id, signer_address);
    PaymentCredential::with_source(echo, source, payload)
}

/// Create a voucher payload by signing a voucher.
pub async fn create_voucher_payload(
    signer: &impl Signer,
    channel_id: B256,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let sig = sign_voucher(
        signer,
        channel_id,
        cumulative_amount,
        escrow_contract,
        chain_id,
    )
    .await?;

    Ok(SessionCredentialPayload::Voucher {
        channel_id: format!("{}", channel_id),
        cumulative_amount: cumulative_amount.to_string(),
        signature: format!("0x{}", hex::encode(&sig)),
    })
}

/// Create a close payload by signing a voucher with close action.
pub async fn create_close_payload(
    signer: &impl Signer,
    channel_id: B256,
    cumulative_amount: u128,
    escrow_contract: Address,
    chain_id: u64,
) -> Result<SessionCredentialPayload, MppError> {
    let sig = sign_voucher(
        signer,
        channel_id,
        cumulative_amount,
        escrow_contract,
        chain_id,
    )
    .await?;

    Ok(SessionCredentialPayload::Close {
        channel_id: format!("{}", channel_id),
        cumulative_amount: cumulative_amount.to_string(),
        signature: format!("0x{}", hex::encode(&sig)),
    })
}

/// Options for creating an open payload.
pub struct OpenPayloadOptions {
    pub authorized_signer: Option<Address>,
    pub escrow_contract: Address,
    pub payee: Address,
    pub currency: Address,
    pub deposit: u128,
    pub initial_amount: u128,
    pub chain_id: u64,
    pub fee_payer: bool,
}

/// Create an open payload: builds approve+open multicall transaction, signs it,
/// and signs the initial voucher.
///
/// Builds a Tempo transaction (type 0x76) containing:
/// 1. `TIP20.approve(escrow, deposit)`
/// 2. `escrow.open(payee, token, deposit, salt, authorizedSigner)`
///
/// Then signs an initial voucher for `initial_amount`.
pub async fn create_open_payload<P, S>(
    provider: &P,
    signer: &S,
    signing_mode: Option<&crate::client::tempo::signing::TempoSigningMode>,
    payer: Address,
    options: OpenPayloadOptions,
) -> Result<(ChannelEntry, SessionCredentialPayload), MppError>
where
    P: Provider<TempoNetwork>,
    S: Signer + Clone,
{
    use alloy::sol;
    use tempo_primitives::transaction::Call;

    let default_mode = crate::client::tempo::signing::TempoSigningMode::Direct;
    let signing_mode = signing_mode.unwrap_or(&default_mode);

    let authorized_signer = options.authorized_signer.unwrap_or(payer);

    // Generate random salt
    let salt = B256::random();

    // Compute channel ID
    let channel_id = compute_channel_id(
        payer,
        options.payee,
        options.currency,
        salt,
        authorized_signer,
        options.escrow_contract,
        options.chain_id,
    );

    // Build approve calldata
    use crate::client::tempo::abi::ITIP20;

    sol! {
        interface IEscrow {
            function open(
                address payee,
                address token,
                uint128 deposit,
                bytes32 salt,
                address authorizedSigner
            ) external;
        }
    }

    let approve_data =
        ITIP20::approveCall::new((options.escrow_contract, U256::from(options.deposit)))
            .abi_encode();

    let open_data = IEscrow::openCall::new((
        options.payee,
        options.currency,
        options.deposit,
        salt,
        authorized_signer,
    ))
    .abi_encode();

    // Build Tempo multicall transaction
    let calls = vec![
        Call {
            to: TxKind::Call(options.currency),
            value: U256::ZERO,
            input: Bytes::from(approve_data),
        },
        Call {
            to: TxKind::Call(options.escrow_contract),
            value: U256::ZERO,
            input: Bytes::from(open_data),
        },
    ];

    let nonce = provider
        .get_transaction_count(payer)
        .await
        .map_err(|e| MppError::Http(format!("failed to get nonce: {}", e)))?;

    let gas_price = provider
        .get_gas_price()
        .await
        .map_err(|e| MppError::Http(format!("failed to get gas price: {}", e)))?;

    let tempo_tx = crate::client::tempo::charge::tx_builder::build_tempo_tx(
        crate::client::tempo::charge::tx_builder::TempoTxOptions {
            calls,
            chain_id: options.chain_id,
            fee_token: options.currency,
            nonce,
            nonce_key: U256::ZERO,
            gas_limit: 2_000_000,
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: gas_price,
            fee_payer: options.fee_payer,
            valid_before: None,
            key_authorization: signing_mode.key_authorization().cloned(),
        },
    );

    let tx_bytes =
        crate::client::tempo::signing::sign_and_encode_async(tempo_tx, signer, signing_mode)
            .await?;
    let signed_tx_hex = format!("0x{}", hex::encode(&tx_bytes));

    // Sign the initial voucher
    let voucher_sig = sign_voucher(
        signer,
        channel_id,
        options.initial_amount,
        options.escrow_contract,
        options.chain_id,
    )
    .await?;

    let entry = ChannelEntry {
        channel_id,
        salt,
        cumulative_amount: options.initial_amount,
        escrow_contract: options.escrow_contract,
        chain_id: options.chain_id,
        opened: true,
    };

    let payload = SessionCredentialPayload::Open {
        payload_type: "transaction".to_string(),
        channel_id: format!("{}", channel_id),
        transaction: signed_tx_hex,
        authorized_signer: Some(format!("{}", authorized_signer)),
        cumulative_amount: options.initial_amount.to_string(),
        signature: format!("0x{}", hex::encode(&voucher_sig)),
    };

    Ok((entry, payload))
}

/// On-chain channel state returned by the escrow contract.
#[derive(Debug, Clone)]
pub struct OnChainChannel {
    pub payer: Address,
    pub payee: Address,
    pub token: Address,
    pub authorized_signer: Address,
    pub deposit: u128,
    pub settled: u128,
    pub close_requested_at: u64,
    pub finalized: bool,
}

/// Read on-chain channel state from the escrow contract.
pub async fn get_on_chain_channel<P: Provider<TempoNetwork>>(
    provider: &P,
    escrow_contract: Address,
    channel_id: B256,
) -> Result<OnChainChannel, MppError> {
    use alloy::sol;

    sol! {
        interface IEscrowRead {
            function getChannel(bytes32 channelId) external view returns (
                bool finalized,
                uint64 closeRequestedAt,
                address payer,
                address payee,
                address token,
                address authorizedSigner,
                uint128 deposit,
                uint128 settled
            );
        }
    }

    let call_data = IEscrowRead::getChannelCall::new((channel_id,)).abi_encode();

    use tempo_alloy::rpc::TempoTransactionRequest;

    let mut tx_req = TempoTransactionRequest::default();
    tx_req.inner =
        tx_req
            .inner
            .to(escrow_contract)
            .input(alloy::rpc::types::TransactionInput::new(Bytes::from(
                call_data,
            )));

    let result = provider
        .call(tx_req)
        .await
        .map_err(|e| MppError::Http(format!("failed to read channel: {}", e)))?;

    let decoded =
        <(bool, u64, Address, Address, Address, Address, u128, u128)>::abi_decode(&result)
            .map_err(|e| MppError::Http(format!("failed to decode channel data: {}", e)))?;

    Ok(OnChainChannel {
        finalized: decoded.0,
        close_requested_at: decoded.1,
        payer: decoded.2,
        payee: decoded.3,
        token: decoded.4,
        authorized_signer: decoded.5,
        deposit: decoded.6,
        settled: decoded.7,
    })
}

/// Attempt to recover an existing on-chain channel.
///
/// If the channel has a positive deposit and is not finalized, returns a
/// [`ChannelEntry`] with `cumulative_amount` set to the on-chain settled
/// amount (the safe starting point for new vouchers).
///
/// Returns `None` if the channel doesn't exist, has zero deposit,
/// or is already finalized.
pub async fn try_recover_channel<P: Provider<TempoNetwork>>(
    provider: &P,
    escrow_contract: Address,
    channel_id: B256,
    chain_id: u64,
) -> Option<ChannelEntry> {
    let on_chain = get_on_chain_channel(provider, escrow_contract, channel_id)
        .await
        .ok()?;

    if on_chain.deposit > 0 && !on_chain.finalized {
        Some(ChannelEntry {
            channel_id,
            salt: B256::ZERO,
            cumulative_amount: on_chain.settled,
            escrow_contract,
            chain_id,
            opened: true,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_escrow_contract() {
        assert!(default_escrow_contract(4217).is_some());
        assert!(default_escrow_contract(42431).is_some());
        assert!(default_escrow_contract(1).is_none());
    }

    #[test]
    fn test_channel_entry_clone() {
        let entry = ChannelEntry {
            channel_id: B256::ZERO,
            salt: B256::ZERO,
            cumulative_amount: 1000,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened: true,
        };
        let cloned = entry.clone();
        assert_eq!(cloned.cumulative_amount, 1000);
        assert!(cloned.opened);
    }

    #[test]
    fn test_resolve_escrow_from_override() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let override_addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let result = resolve_escrow(&challenge, 42431, Some(override_addr)).unwrap();
        assert_eq!(result, override_addr);
    }

    #[test]
    fn test_resolve_escrow_from_default() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let result = resolve_escrow(&challenge, 42431, None).unwrap();
        assert_eq!(result, default_escrow_contract(42431).unwrap());
    }

    #[test]
    fn test_resolve_escrow_from_challenge() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let escrow_addr = "0x2222222222222222222222222222222222222222";
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123",
                "methodDetails": {
                    "escrowContract": escrow_addr
                }
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let result = resolve_escrow(&challenge, 42431, None).unwrap();
        assert_eq!(result, escrow_addr.parse::<Address>().unwrap());
    }

    #[test]
    fn test_resolve_escrow_no_source() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let result = resolve_escrow(&challenge, 9999, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_credential() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test-id".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let payload = SessionCredentialPayload::Voucher {
            channel_id: "0xabc".to_string(),
            cumulative_amount: "5000".to_string(),
            signature: "0xdef".to_string(),
        };

        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let cred = build_credential(&challenge, payload, 42431, addr);
        assert!(cred.source.is_some());
        assert!(cred.source.unwrap().contains("42431"));
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_create_voucher_payload() {
        use alloy_signer_local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xAB);
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let payload = create_voucher_payload(&signer, channel_id, 1000, escrow, 42431)
            .await
            .unwrap();

        match payload {
            SessionCredentialPayload::Voucher {
                channel_id: cid,
                cumulative_amount,
                signature,
            } => {
                assert!(cid.starts_with("0x"));
                assert_eq!(cumulative_amount, "1000");
                assert!(signature.starts_with("0x"));
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_create_close_payload() {
        use alloy_signer_local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xCD);
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let payload = create_close_payload(&signer, channel_id, 2000, escrow, 42431)
            .await
            .unwrap();

        match payload {
            SessionCredentialPayload::Close {
                channel_id: cid,
                cumulative_amount,
                signature,
            } => {
                assert!(cid.starts_with("0x"));
                assert_eq!(cumulative_amount, "2000");
                assert!(signature.starts_with("0x"));
            }
            _ => panic!("Expected Close variant"),
        }
    }

    #[test]
    fn test_resolve_chain_id_from_challenge() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123",
                "methodDetails": { "escrowContract": "0xabc", "chainId": 4217 }
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        assert_eq!(resolve_chain_id(&challenge), 4217);
    }

    #[test]
    fn test_resolve_chain_id_default() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        assert_eq!(resolve_chain_id(&challenge), MODERATO_CHAIN_ID);
    }

    #[test]
    fn test_resolve_chain_id_malformed_request_falls_back() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "not_a_valid_field": true
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        // Should fall back to MODERATO_CHAIN_ID on decode failure
        assert_eq!(resolve_chain_id(&challenge), MODERATO_CHAIN_ID);
    }

    #[test]
    fn test_resolve_escrow_challenge_has_invalid_address() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        // escrowContract present but not a valid address
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123",
                "methodDetails": {
                    "escrowContract": "not-an-address"
                }
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        // Invalid address in challenge should fall back to default
        let result = resolve_escrow(&challenge, 42431, None).unwrap();
        assert_eq!(result, default_escrow_contract(42431).unwrap());
    }

    #[test]
    fn test_resolve_escrow_override_takes_precedence_over_default() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let override_addr: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let result = resolve_escrow(&challenge, 42431, Some(override_addr)).unwrap();
        assert_eq!(
            result, override_addr,
            "override should take precedence over default"
        );
        assert_ne!(result, default_escrow_contract(42431).unwrap());
    }

    #[test]
    fn test_default_escrow_contract_known_chains() {
        let mainnet = default_escrow_contract(4217).unwrap();
        assert_eq!(
            mainnet,
            "0x33b901018174DDabE4841042ab76ba85D4e24f25"
                .parse::<Address>()
                .unwrap()
        );

        let moderato = default_escrow_contract(42431).unwrap();
        assert_eq!(
            moderato,
            "0xe1c4d3dce17bc111181ddf716f75bae49e61a336"
                .parse::<Address>()
                .unwrap()
        );
    }

    #[test]
    fn test_default_escrow_contract_unknown_chain() {
        assert!(default_escrow_contract(0).is_none());
        assert!(default_escrow_contract(999999).is_none());
    }

    #[test]
    fn test_build_credential_did_format() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        let challenge = PaymentChallenge {
            id: "test-id".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123"
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let payload = SessionCredentialPayload::Voucher {
            channel_id: "0xabc".to_string(),
            cumulative_amount: "5000".to_string(),
            signature: "0xdef".to_string(),
        };

        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let cred = build_credential(&challenge, payload, 4217, addr);
        let did = cred.source.as_ref().unwrap();
        let expected = format!("did:pkh:eip155:4217:{}", addr);
        assert_eq!(did, &expected, "DID should match exact pkh format");
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_create_voucher_payload_zero_amount() {
        use alloy_signer_local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xAB);
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let payload = create_voucher_payload(&signer, channel_id, 0, escrow, 42431)
            .await
            .unwrap();

        match payload {
            SessionCredentialPayload::Voucher {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, "0");
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_create_close_payload_zero_amount() {
        use alloy_signer_local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xCD);
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let payload = create_close_payload(&signer, channel_id, 0, escrow, 42431)
            .await
            .unwrap();

        match payload {
            SessionCredentialPayload::Close {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, "0");
            }
            _ => panic!("Expected Close variant"),
        }
    }

    #[cfg(feature = "evm")]
    #[tokio::test]
    async fn test_create_voucher_payload_large_amount() {
        use alloy_signer_local::PrivateKeySigner;

        let signer = PrivateKeySigner::random();
        let channel_id = B256::repeat_byte(0xAB);
        let escrow: Address = "0x5555555555555555555555555555555555555555"
            .parse()
            .unwrap();

        let large_amount = u128::MAX;
        let payload = create_voucher_payload(&signer, channel_id, large_amount, escrow, 42431)
            .await
            .unwrap();

        match payload {
            SessionCredentialPayload::Voucher {
                cumulative_amount, ..
            } => {
                assert_eq!(cumulative_amount, u128::MAX.to_string());
            }
            _ => panic!("Expected Voucher variant"),
        }
    }

    #[test]
    fn test_channel_entry_debug() {
        let entry = ChannelEntry {
            channel_id: B256::ZERO,
            salt: B256::ZERO,
            cumulative_amount: 0,
            escrow_contract: Address::ZERO,
            chain_id: 42431,
            opened: false,
        };
        let debug = format!("{:?}", entry);
        assert!(debug.contains("ChannelEntry"));
        assert!(debug.contains("42431"));
    }

    #[test]
    fn test_resolve_escrow_challenge_priority_order() {
        use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

        // Challenge has a valid escrow, override is also present.
        // Challenge should take priority.
        let escrow_addr = "0x2222222222222222222222222222222222222222";
        let override_addr: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let challenge = PaymentChallenge {
            id: "test".to_string(),
            realm: "test".to_string(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_value(&serde_json::json!({
                "amount": "1000",
                "unitType": "second",
                "currency": "0x123",
                "methodDetails": {
                    "escrowContract": escrow_addr
                }
            }))
            .unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
        };

        let result = resolve_escrow(&challenge, 42431, Some(override_addr)).unwrap();
        assert_eq!(
            result,
            escrow_addr.parse::<Address>().unwrap(),
            "challenge escrow should take priority over override"
        );
    }
}
