//! Canonical first-party machine-token settlement routes.
//!
//! A machine-token payment approves the canonical swapper and calls `swapTo`
//! atomically. The merchant continues to receive the challenge currency while
//! the payer spends machineUSD.

use alloy::primitives::{address, Address, Bytes, TxKind, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use alloy::sol_types::SolValue;
use tempo_alloy::contracts::precompiles::ITIP20;
use tempo_alloy::primitives::transaction::Call;
use tempo_alloy::rpc::TempoTransactionRequest;

use super::{transfers::Transfer, CHAIN_ID, MODERATO_CHAIN_ID};

alloy::sol! {
    interface IMachineTokenSwapper {
        function swapTo(
            address inputToken,
            uint256 amount,
            address targetToken,
            address recipient,
            bytes32 memo
        ) external;

        struct ChannelDescriptor {
            address payer;
            address payee;
            address operator;
            address token;
            bytes32 salt;
            address authorizedSigner;
            bytes32 expiringNonceHash;
        }

        function settleSession(
            ChannelDescriptor calldata descriptor,
            address recipient,
            address targetToken,
            bytes32 routeSalt
        ) external;
    }
}

/// Resolve the canonical machine-token and swapper for a supported chain.
pub fn session_addresses(chain_id: u64) -> Option<(Address, Address)> {
    deployment(chain_id).map(|deployment| (deployment.token, deployment.swapper))
}

/// Bind a logical merchant settlement route into a TIP-1034 descriptor salt.
pub fn compute_session_salt(
    merchant: Address,
    target_token: Address,
    route_salt: alloy::primitives::B256,
) -> alloy::primitives::B256 {
    let typehash = alloy::primitives::keccak256(
        b"MachineUsdSessionRoute(address merchant,address targetToken,bytes32 routeSalt)",
    );
    alloy::primitives::keccak256((typehash, merchant, target_token, route_salt).abi_encode())
}

/// Encode a canonical machine-token session settlement call.
pub fn settle_session_call(
    chain_id: u64,
    descriptor: &super::session::ChannelDescriptor,
    route: &super::session::SettlementRoute,
) -> Result<Call, crate::error::MppError> {
    let (_, swapper) = session_addresses(chain_id).ok_or_else(|| {
        crate::error::MppError::InvalidConfig(format!(
            "machine tokens are not supported on chain ID {chain_id}"
        ))
    })?;
    let parse_address = |name: &str, value: &str| {
        value.parse::<Address>().map_err(|error| {
            crate::error::MppError::InvalidConfig(format!(
                "invalid session descriptor {name}: {error}"
            ))
        })
    };
    let parse_b256 = |name: &str, value: &str| {
        value.parse::<alloy::primitives::B256>().map_err(|error| {
            crate::error::MppError::InvalidConfig(format!(
                "invalid session descriptor {name}: {error}"
            ))
        })
    };
    if route.adapter.parse::<Address>().ok() != Some(swapper) {
        return Err(crate::error::MppError::InvalidConfig(
            "session settlement adapter is not canonical".into(),
        ));
    }
    let merchant = parse_address("settlement recipient", &route.recipient)?;
    let target_token = parse_address("settlement targetToken", &route.target_token)?;
    let route_salt = parse_b256("settlement routeSalt", &route.route_salt)?;
    let descriptor_salt = parse_b256("salt", &descriptor.salt)?;
    if descriptor_salt != compute_session_salt(merchant, target_token, route_salt) {
        return Err(crate::error::MppError::InvalidConfig(
            "session descriptor salt does not bind the settlement route".into(),
        ));
    }
    let descriptor = IMachineTokenSwapper::ChannelDescriptor {
        payer: parse_address("payer", &descriptor.payer)?,
        payee: parse_address("payee", &descriptor.payee)?,
        operator: parse_address("operator", &descriptor.operator)?,
        token: parse_address("token", &descriptor.token)?,
        salt: parse_b256("salt", &descriptor.salt)?,
        authorizedSigner: parse_address("authorizedSigner", &descriptor.authorized_signer)?,
        expiringNonceHash: parse_b256("expiringNonceHash", &descriptor.expiring_nonce_hash)?,
    };
    Ok(Call {
        to: TxKind::Call(swapper),
        value: U256::ZERO,
        input: Bytes::from(
            IMachineTokenSwapper::settleSessionCall {
                descriptor,
                recipient: merchant,
                targetToken: target_token,
                routeSalt: route_salt,
            }
            .abi_encode(),
        ),
    })
}

/// machineUSD on Tempo mainnet.
pub const MACHINE_TOKEN_MAINNET: Address = address!("20C0000000000000000000003793c39601711f19");
/// Canonical machineUSD swapper on Tempo mainnet.
pub const MACHINE_TOKEN_SWAPPER_MAINNET: Address =
    address!("C6D32f013E0fA3e83B63Dc680E99826761595732");
/// machineUSD on Tempo Moderato.
pub const MACHINE_TOKEN_TESTNET: Address = address!("20c000000000000000000000f85bbCa724044De0");
/// Canonical machineUSD swapper on Tempo Moderato.
pub const MACHINE_TOKEN_SWAPPER_TESTNET: Address =
    address!("07f1FE0467Ae01DE340024aa4b7DD9729b1c169b");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Deployment {
    token: Address,
    swapper: Address,
}

/// The exact canonical calls and settlement sender for a machine-token payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineTokenRoute {
    /// `approve` followed by `swapTo`.
    pub calls: [Call; 2],
    /// The swapper that emits the merchant-facing TIP-20 transfer.
    pub settlement_sender: Address,
    /// The single merchant transfer settled by the route.
    pub transfer: Transfer,
}

fn deployment(chain_id: u64) -> Option<Deployment> {
    match chain_id {
        CHAIN_ID => Some(Deployment {
            token: MACHINE_TOKEN_MAINNET,
            swapper: MACHINE_TOKEN_SWAPPER_MAINNET,
        }),
        MODERATO_CHAIN_ID => Some(Deployment {
            token: MACHINE_TOKEN_TESTNET,
            swapper: MACHINE_TOKEN_SWAPPER_TESTNET,
        }),
        _ => None,
    }
}

/// Returns whether a canonical machine-token route exists on `chain_id`.
pub fn is_supported(chain_id: u64) -> bool {
    deployment(chain_id).is_some()
}

/// Returns the trusted settlement sender for a supported chain.
pub fn settlement_sender(chain_id: u64) -> Option<Address> {
    deployment(chain_id).map(|deployment| deployment.swapper)
}

/// Build the canonical route for a compatible charge.
///
/// The route intentionally supports exactly one memo-bearing transfer. Split
/// payments and unbound transfers fall back to ordinary funding behavior.
pub fn route(
    chain_id: u64,
    currency: Address,
    transfers: &[Transfer],
) -> Option<MachineTokenRoute> {
    let deployment = deployment(chain_id)?;
    let transfer = match transfers {
        [transfer] if transfer.memo.is_some() => transfer.clone(),
        _ => return None,
    };
    let memo = transfer.memo?;
    let approve = Call {
        to: TxKind::Call(deployment.token),
        value: U256::ZERO,
        input: Bytes::from(
            ITIP20::approveCall {
                spender: deployment.swapper,
                amount: transfer.amount,
            }
            .abi_encode(),
        ),
    };
    let swap = Call {
        to: TxKind::Call(deployment.swapper),
        value: U256::ZERO,
        input: Bytes::from(
            IMachineTokenSwapper::swapToCall {
                inputToken: deployment.token,
                amount: transfer.amount,
                targetToken: currency,
                recipient: transfer.recipient,
                memo: memo.into(),
            }
            .abi_encode(),
        ),
    };

    Some(MachineTokenRoute {
        calls: [approve, swap],
        settlement_sender: deployment.swapper,
        transfer,
    })
}

/// Match only the exact canonical route for a charge.
pub fn match_route(
    calls: &[Call],
    chain_id: u64,
    currency: Address,
    transfers: &[Transfer],
) -> Option<MachineTokenRoute> {
    let transfer = match transfers {
        [transfer] => transfer.clone(),
        _ => return None,
    };
    let swap = calls.get(1)?;
    let decoded = IMachineTokenSwapper::swapToCall::abi_decode_raw(swap.input.get(4..)?).ok()?;
    let mut transfer_with_memo = transfer;
    if transfer_with_memo.memo.is_none() {
        transfer_with_memo.memo = Some(decoded.memo.0);
    }
    let expected = route(chain_id, currency, &[transfer_with_memo])?;
    if calls == expected.calls.as_slice() {
        Some(expected)
    } else {
        None
    }
}

/// Prefer machine-token funding when the payer has sufficient balance and the
/// complete route simulates successfully. Any failure falls back to the
/// client's existing funding behavior.
pub async fn find_route<P: Provider<tempo_alloy::TempoNetwork>>(
    provider: &P,
    account: Address,
    chain_id: u64,
    currency: Address,
    transfers: &[Transfer],
) -> Option<MachineTokenRoute> {
    let route = route(chain_id, currency, transfers)?;
    let token = match route.calls[0].to {
        TxKind::Call(token) => token,
        TxKind::Create => return None,
    };
    let balance = ITIP20::new(token, provider)
        .balanceOf(account)
        .call()
        .await
        .ok()?;
    if balance < route.transfer.amount {
        return None;
    }

    let mut request = TempoTransactionRequest {
        calls: route.calls.to_vec(),
        ..Default::default()
    };
    request.inner.from = Some(account);
    request.inner.chain_id = Some(chain_id);
    provider.call(request).await.ok()?;
    Some(route)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolCall;

    fn transfer() -> Transfer {
        Transfer {
            amount: U256::from(1_000_000),
            recipient: Address::repeat_byte(0x22),
            memo: Some([0xab; 32]),
        }
    }

    #[test]
    fn builds_and_matches_exact_canonical_route() {
        let currency = Address::repeat_byte(0x33);
        let route = route(MODERATO_CHAIN_ID, currency, &[transfer()]).unwrap();

        assert_eq!(route.calls[0].to, TxKind::Call(MACHINE_TOKEN_TESTNET));
        assert_eq!(
            route.calls[1].to,
            TxKind::Call(MACHINE_TOKEN_SWAPPER_TESTNET)
        );
        assert_eq!(
            match_route(&route.calls, MODERATO_CHAIN_ID, currency, &[transfer()]),
            Some(route.clone())
        );

        let approve = ITIP20::approveCall::abi_decode_raw(&route.calls[0].input[4..]).unwrap();
        assert_eq!(approve.spender, MACHINE_TOKEN_SWAPPER_TESTNET);
        assert_eq!(approve.amount, U256::from(1_000_000));
        let swap =
            IMachineTokenSwapper::swapToCall::abi_decode_raw(&route.calls[1].input[4..]).unwrap();
        assert_eq!(swap.inputToken, MACHINE_TOKEN_TESTNET);
        assert_eq!(swap.targetToken, currency);
        assert_eq!(swap.recipient, Address::repeat_byte(0x22));
    }

    #[test]
    fn rejects_mutated_and_incompatible_routes() {
        let currency = Address::repeat_byte(0x33);
        let canonical = route(MODERATO_CHAIN_ID, currency, &[transfer()]).unwrap();
        let mut mutated = canonical.calls.to_vec();
        mutated[0].value = U256::from(1);

        assert!(match_route(&mutated, MODERATO_CHAIN_ID, currency, &[transfer()]).is_none());
        assert!(route(1, currency, &[transfer()]).is_none());
        assert!(route(MODERATO_CHAIN_ID, currency, &[]).is_none());
        let mut without_memo = transfer();
        without_memo.memo = None;
        assert!(route(MODERATO_CHAIN_ID, currency, &[without_memo]).is_none());
        assert!(route(MODERATO_CHAIN_ID, currency, &[transfer(), transfer()]).is_none());
    }

    #[test]
    fn encodes_session_settlement_with_the_full_bound_descriptor() {
        let descriptor = super::super::session::ChannelDescriptor {
            payer: Address::repeat_byte(0x11).to_string(),
            payee: MACHINE_TOKEN_SWAPPER_TESTNET.to_string(),
            operator: Address::repeat_byte(0x22).to_string(),
            token: MACHINE_TOKEN_TESTNET.to_string(),
            salt: alloy::primitives::B256::repeat_byte(0x33).to_string(),
            authorized_signer: Address::repeat_byte(0x44).to_string(),
            expiring_nonce_hash: alloy::primitives::B256::repeat_byte(0x55).to_string(),
        };
        let route = super::super::session::SettlementRoute {
            adapter: MACHINE_TOKEN_SWAPPER_TESTNET.to_string(),
            recipient: Address::repeat_byte(0x22).to_string(),
            target_token: Address::repeat_byte(0x66).to_string(),
            route_salt: alloy::primitives::B256::repeat_byte(0x77).to_string(),
        };
        let expected_salt = compute_session_salt(
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x66),
            alloy::primitives::B256::repeat_byte(0x77),
        );
        let descriptor = super::super::session::ChannelDescriptor {
            salt: expected_salt.to_string(),
            ..descriptor
        };
        let call = settle_session_call(MODERATO_CHAIN_ID, &descriptor, &route).unwrap();

        assert_eq!(call.to, TxKind::Call(MACHINE_TOKEN_SWAPPER_TESTNET));
        let decoded = IMachineTokenSwapper::settleSessionCall::abi_decode(&call.input).unwrap();
        assert_eq!(decoded.descriptor.payee, MACHINE_TOKEN_SWAPPER_TESTNET);
        assert_eq!(decoded.descriptor.operator, Address::repeat_byte(0x22));
        assert_eq!(decoded.descriptor.token, MACHINE_TOKEN_TESTNET);
        assert_eq!(decoded.recipient, Address::repeat_byte(0x22));
        assert_eq!(decoded.targetToken, Address::repeat_byte(0x66));
    }

    #[test]
    fn rejects_session_settlement_on_an_unsupported_chain() {
        let descriptor = super::super::session::ChannelDescriptor {
            payer: Address::ZERO.to_string(),
            payee: Address::ZERO.to_string(),
            operator: Address::ZERO.to_string(),
            token: Address::ZERO.to_string(),
            salt: alloy::primitives::B256::ZERO.to_string(),
            authorized_signer: Address::ZERO.to_string(),
            expiring_nonce_hash: alloy::primitives::B256::ZERO.to_string(),
        };
        let route = super::super::session::SettlementRoute {
            adapter: Address::ZERO.to_string(),
            recipient: Address::ZERO.to_string(),
            target_token: Address::ZERO.to_string(),
            route_salt: alloy::primitives::B256::ZERO.to_string(),
        };
        assert!(settle_session_call(1, &descriptor, &route).is_err());
    }

    #[tokio::test]
    async fn finds_a_funded_route_after_successful_simulation() {
        use alloy::providers::{mock::Asserter, ProviderBuilder};

        let asserter = Asserter::new();
        asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
            &U256::from(1_000_000),
        )));
        asserter.push_success(&Bytes::new());
        let provider = ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);

        let found = find_route(
            &provider,
            Address::repeat_byte(0x11),
            MODERATO_CHAIN_ID,
            Address::repeat_byte(0x33),
            &[transfer()],
        )
        .await;

        assert!(found.is_some());
    }

    #[tokio::test]
    async fn falls_back_when_machine_token_balance_is_insufficient() {
        use alloy::providers::{mock::Asserter, ProviderBuilder};

        let asserter = Asserter::new();
        asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
            &U256::from(999_999),
        )));
        let provider = ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);

        let found = find_route(
            &provider,
            Address::repeat_byte(0x11),
            MODERATO_CHAIN_ID,
            Address::repeat_byte(0x33),
            &[transfer()],
        )
        .await;

        assert!(found.is_none());
    }
}
