//! Canonical first-party machine-token charge routes.
//!
//! A machine-token charge approves the canonical MACH swapper and calls
//! `swapTo` atomically. The merchant continues to receive the challenge
//! currency while the payer spends MACH, matching mppx's charge deployment.
//!
//! Machine-token funding applies only to charges. Sessions denominated in MACH
//! are ordinary TIP-1034 channels whose token is MACH and whose payee is the
//! merchant: TIP-1095 applies MACH's recipient policy to the logical payer to
//! payee path and returns refunds to the payer, so they need no swapper route.

use alloy::primitives::{address, Address, Bytes, TxKind, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
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
    }
}

/// MACH, the canonical machine token on Tempo mainnet and Moderato.
pub const MACH: Address = address!("20c000000000000000000000f37de3740ADec032");
/// Canonical MACH swapper on Tempo mainnet.
pub const MACH_SWAPPER_MAINNET: Address = address!("F72E5107c32C655ffA7539a3C8e97B7C3cE16A3F");
/// Canonical MACH swapper on Tempo Moderato.
pub const MACH_SWAPPER_TESTNET: Address = address!("d05f8EdFBB54Da0d765C9fE9b2B3f7d2E3a8C466");

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
            token: MACH,
            swapper: MACH_SWAPPER_MAINNET,
        }),
        MODERATO_CHAIN_ID => Some(Deployment {
            token: MACH,
            swapper: MACH_SWAPPER_TESTNET,
        }),
        _ => None,
    }
}

/// Returns the canonical machine token that funds charges on `chain_id`.
pub fn token(chain_id: u64) -> Option<Address> {
    deployment(chain_id).map(|deployment| deployment.token)
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
    let mut request = TempoTransactionRequest {
        calls: route.calls.to_vec(),
        ..Default::default()
    };
    request.inner.from = Some(account);
    request.inner.chain_id = Some(chain_id);
    // Both reads gate the same decision, so issue them together.
    let token = ITIP20::new(token, provider);
    let balance = token.balanceOf(account);
    let (balance, simulation) = tokio::join!(balance.call(), provider.call(request));
    (balance.ok()? >= route.transfer.amount && simulation.is_ok()).then_some(route)
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

        assert_eq!(route.calls[0].to, TxKind::Call(MACH));
        assert_eq!(route.calls[1].to, TxKind::Call(MACH_SWAPPER_TESTNET));
        assert_eq!(
            match_route(&route.calls, MODERATO_CHAIN_ID, currency, &[transfer()]),
            Some(route.clone())
        );

        let approve = ITIP20::approveCall::abi_decode_raw(&route.calls[0].input[4..]).unwrap();
        assert_eq!(approve.spender, MACH_SWAPPER_TESTNET);
        assert_eq!(approve.amount, U256::from(1_000_000));
        let swap =
            IMachineTokenSwapper::swapToCall::abi_decode_raw(&route.calls[1].input[4..]).unwrap();
        assert_eq!(swap.inputToken, MACH);
        assert_eq!(token(CHAIN_ID), Some(MACH));
        assert_eq!(settlement_sender(CHAIN_ID), Some(MACH_SWAPPER_MAINNET));
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
