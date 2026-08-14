//! First-party machine-token settlement routes.

use alloy::primitives::{address, Address, Bytes, TxKind, U256};
use alloy::sol;
use alloy::sol_types::SolCall;
use tempo_alloy::contracts::precompiles::ITIP20;
use tempo_alloy::primitives::transaction::Call;

use super::{transfers::Transfer, CHAIN_ID, MODERATO_CHAIN_ID};

sol! {
    function swapTo(address inputToken, uint256 amount, address targetToken, address recipient, bytes32 memo);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deployment {
    pub swap: Address,
    pub token: Address,
}

pub const MAINNET: Deployment = Deployment {
    swap: address!("C6D32f013E0fA3e83B63Dc680E99826761595732"),
    token: address!("20C0000000000000000000003793c39601711f19"),
};
pub const MODERATO: Deployment = Deployment {
    swap: address!("07f1FE0467Ae01DE340024aa4b7DD9729b1c169b"),
    token: address!("20c000000000000000000000f85bbCa724044De0"),
};

pub fn deployment(chain_id: u64) -> Option<Deployment> {
    match chain_id {
        CHAIN_ID => Some(MAINNET),
        MODERATO_CHAIN_ID => Some(MODERATO),
        _ => None,
    }
}

pub fn route(chain_id: u64, currency: Address, transfers: &[Transfer]) -> Option<[Call; 2]> {
    let deployment = deployment(chain_id)?;
    let [transfer] = transfers else { return None };
    let memo = transfer.memo?;
    Some([
        Call {
            to: TxKind::Call(deployment.token),
            value: U256::ZERO,
            input: Bytes::from(
                ITIP20::approveCall::new((deployment.swap, transfer.amount)).abi_encode(),
            ),
        },
        Call {
            to: TxKind::Call(deployment.swap),
            value: U256::ZERO,
            input: Bytes::from(
                swapToCall::new((
                    deployment.token,
                    transfer.amount,
                    currency,
                    transfer.recipient,
                    memo.into(),
                ))
                .abi_encode(),
            ),
        },
    ])
}

pub fn matches_route(
    calls: &[Call],
    chain_id: u64,
    currency: Address,
    transfers: &[Transfer],
) -> bool {
    let [transfer] = transfers else { return false };
    let Some(swap) = calls.get(1) else {
        return false;
    };
    if swap.input.len() < 4 || swap.input[..4] != swapToCall::SELECTOR {
        return false;
    }
    let Ok(decoded) = swapToCall::abi_decode_raw(&swap.input[4..]) else {
        return false;
    };
    let transfer = Transfer {
        memo: Some(decoded.memo.into()),
        ..transfer.clone()
    };
    let Some(expected) = route(chain_id, currency, &[transfer]) else {
        return false;
    };
    calls == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_matches_the_canonical_route() {
        let transfers = [Transfer {
            amount: U256::from(42),
            recipient: Address::repeat_byte(1),
            memo: Some([2; 32]),
        }];
        let calls = route(MODERATO_CHAIN_ID, Address::repeat_byte(3), &transfers).unwrap();
        assert!(matches_route(
            &calls,
            MODERATO_CHAIN_ID,
            Address::repeat_byte(3),
            &transfers
        ));
        let transfer_without_bound_memo = Transfer {
            memo: None,
            ..transfers[0].clone()
        };
        assert!(matches_route(
            &calls,
            MODERATO_CHAIN_ID,
            Address::repeat_byte(3),
            &[transfer_without_bound_memo]
        ));
        assert_eq!(calls[0].to, TxKind::Call(MODERATO.token));
        assert_eq!(calls[1].to, TxKind::Call(MODERATO.swap));
    }

    #[test]
    fn rejects_unsupported_or_non_single_transfer_routes() {
        assert!(route(1, Address::ZERO, &[]).is_none());
        let transfer = Transfer {
            amount: U256::from(1),
            recipient: Address::repeat_byte(1),
            memo: None,
        };
        assert!(route(MODERATO_CHAIN_ID, Address::ZERO, &[transfer]).is_none());
    }
}
