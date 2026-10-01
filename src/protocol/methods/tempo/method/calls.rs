//! Call-shape validation for charge transactions.

use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::sol_types::SolCall;
use tempo_alloy::contracts::precompiles::{IStablecoinDEX, ITIP20, STABLECOIN_DEX_ADDRESS};

use crate::protocol::traits::VerificationError;

use super::super::transfers::Transfer;

/// TIP-20 transfer function selector: bytes4(keccak256("transfer(address,uint256)"))
pub(super) const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// TIP-20 transferWithMemo function selector: bytes4(keccak256("transferWithMemo(address,uint256,bytes32)"))
pub(super) const TRANSFER_WITH_MEMO_SELECTOR: [u8; 4] = [0x95, 0x77, 0x7d, 0x59];

fn no_matching_payment_call_error() -> VerificationError {
    VerificationError::new("Invalid transaction: no matching payment call found".to_string())
}

fn disallowed_fee_payer_call_pattern_error() -> VerificationError {
    VerificationError::new("Fee-sponsored transaction contains disallowed call pattern".to_string())
}

fn call_selector(data: &Bytes) -> Option<[u8; 4]> {
    if data.len() < 4 {
        None
    } else {
        data[..4].try_into().ok()
    }
}

fn decode_approve(call: &tempo_alloy::primitives::transaction::Call) -> Option<(Address, U256)> {
    if call_selector(&call.input) != Some(ITIP20::approveCall::SELECTOR) || call.input.len() != 68 {
        return None;
    }

    Some((
        Address::from_slice(&call.input[16..36]),
        U256::from_be_slice(&call.input[36..68]),
    ))
}

fn decode_swap(
    call: &tempo_alloy::primitives::transaction::Call,
) -> Option<IStablecoinDEX::swapExactAmountOutCall> {
    if call_selector(&call.input) != Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR) {
        return None;
    }

    IStablecoinDEX::swapExactAmountOutCall::abi_decode_raw(&call.input[4..]).ok()
}

fn transfer_call_offset(
    calls: &[tempo_alloy::primitives::transaction::Call],
) -> Result<usize, VerificationError> {
    let first_selector = calls.first().and_then(|call| call_selector(&call.input));

    if first_selector == Some(ITIP20::approveCall::SELECTOR) {
        let second_selector = calls.get(1).and_then(|call| call_selector(&call.input));
        if second_selector != Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR) {
            return Err(no_matching_payment_call_error());
        }
        Ok(2)
    } else if first_selector == Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR) {
        Err(no_matching_payment_call_error())
    } else {
        Ok(0)
    }
}

pub(super) fn get_transfer_calls(
    calls: &[tempo_alloy::primitives::transaction::Call],
) -> Result<&[tempo_alloy::primitives::transaction::Call], VerificationError> {
    let offset = transfer_call_offset(calls)?;
    let transfer_calls = &calls[offset..];

    if transfer_calls.is_empty()
        || transfer_calls.iter().any(|call| {
            !matches!(
                call_selector(&call.input),
                Some(TRANSFER_SELECTOR) | Some(TRANSFER_WITH_MEMO_SELECTOR)
            )
        })
    {
        return Err(no_matching_payment_call_error());
    }

    Ok(transfer_calls)
}

pub(super) fn validate_fee_payer_calls(
    calls: &[tempo_alloy::primitives::transaction::Call],
    currency: Address,
    expected: &[Transfer],
) -> Result<(), VerificationError> {
    if calls.is_empty() {
        return Err(disallowed_fee_payer_call_pattern_error());
    }

    let has_swap_prefix = calls.first().and_then(|call| call_selector(&call.input))
        == Some(ITIP20::approveCall::SELECTOR);

    if has_swap_prefix {
        if calls.get(1).and_then(|call| call_selector(&call.input))
            != Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR)
        {
            return Err(disallowed_fee_payer_call_pattern_error());
        }
    } else if calls.first().and_then(|call| call_selector(&call.input))
        == Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR)
    {
        return Err(disallowed_fee_payer_call_pattern_error());
    }

    let transfer_calls = &calls[if has_swap_prefix { 2 } else { 0 }..];
    if transfer_calls.is_empty()
        || transfer_calls.len() > 11
        || transfer_calls.iter().any(|call| {
            !matches!(
                call_selector(&call.input),
                Some(TRANSFER_SELECTOR) | Some(TRANSFER_WITH_MEMO_SELECTOR)
            )
        })
    {
        return Err(disallowed_fee_payer_call_pattern_error());
    }

    if has_swap_prefix {
        let approve_target = match &calls[0].to {
            TxKind::Call(address) => *address,
            _ => return Err(disallowed_fee_payer_call_pattern_error()),
        };
        let swap = decode_swap(&calls[1]).ok_or_else(disallowed_fee_payer_call_pattern_error)?;
        if approve_target != swap.tokenIn {
            return Err(VerificationError::new(
                "Fee-sponsored transaction approve target is not the swap input token".to_string(),
            ));
        }

        let (approve_spender, approve_amount) =
            decode_approve(&calls[0]).ok_or_else(disallowed_fee_payer_call_pattern_error)?;
        if approve_spender != STABLECOIN_DEX_ADDRESS {
            return Err(VerificationError::new(
                "Fee-sponsored transaction approve spender is not the DEX".to_string(),
            ));
        }
        if approve_amount != U256::from(swap.maxAmountIn) {
            return Err(VerificationError::new(
                "Fee-sponsored transaction approve amount does not match the swap max input"
                    .to_string(),
            ));
        }

        match &calls[1].to {
            TxKind::Call(address) if *address == STABLECOIN_DEX_ADDRESS => {}
            _ => {
                return Err(VerificationError::new(
                    "Fee-sponsored transaction swap target is not the DEX".to_string(),
                ));
            }
        }

        if swap.tokenOut != currency {
            return Err(VerificationError::new(
                "Fee-sponsored transaction swap output token is not the payment currency"
                    .to_string(),
            ));
        }
        let payment_amount = expected.iter().fold(U256::ZERO, |sum, transfer| {
            sum.saturating_add(transfer.amount)
        });
        if U256::from(swap.amountOut) != payment_amount {
            return Err(VerificationError::new(
                "Fee-sponsored transaction swap output does not match the payment amount"
                    .to_string(),
            ));
        }
    }

    Ok(())
}
