//! Call-shape validation for charge transactions.

use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::sol_types::SolCall;
use tempo_alloy::contracts::precompiles::{IStablecoinDEX, ITIP20, STABLECOIN_DEX_ADDRESS};
use tempo_alloy::primitives::transaction::Call;

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

fn decode_approve(call: &Call) -> Option<(Address, U256)> {
    if call_selector(&call.input) != Some(ITIP20::approveCall::SELECTOR) || call.input.len() != 68 {
        return None;
    }

    Some((
        Address::from_slice(&call.input[16..36]),
        U256::from_be_slice(&call.input[36..68]),
    ))
}

fn decode_swap(call: &Call) -> Option<IStablecoinDEX::swapExactAmountOutCall> {
    if call_selector(&call.input) != Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR) {
        return None;
    }

    IStablecoinDEX::swapExactAmountOutCall::abi_decode_raw(&call.input[4..]).ok()
}

/// The calls of a charge transaction: an optional `approve` +
/// `swapExactAmountOut` prefix that buys the payment currency, followed by
/// TIP-20 `transfer` / `transferWithMemo` calls.
pub(super) struct PaymentCalls<'a> {
    swap_prefix: Option<(&'a Call, &'a Call)>,
    /// The transfer calls, never empty.
    pub(super) transfers: &'a [Call],
}

impl<'a> PaymentCalls<'a> {
    /// Split `calls` into the swap prefix and the transfers. Any other call
    /// is rejected.
    pub(super) fn parse(calls: &'a [Call]) -> Result<Self, VerificationError> {
        let selector = |index: usize| calls.get(index).and_then(|call| call_selector(&call.input));

        let swap_prefix = if selector(0) == Some(ITIP20::approveCall::SELECTOR) {
            if selector(1) != Some(IStablecoinDEX::swapExactAmountOutCall::SELECTOR) {
                return Err(no_matching_payment_call_error());
            }
            Some((&calls[0], &calls[1]))
        } else {
            None
        };

        // The remaining calls must all be transfers, which also rejects a
        // swap that does not follow an approve.
        let transfers = &calls[if swap_prefix.is_some() { 2 } else { 0 }..];
        if transfers.is_empty()
            || transfers.iter().any(|call| {
                !matches!(
                    call_selector(&call.input),
                    Some(TRANSFER_SELECTOR) | Some(TRANSFER_WITH_MEMO_SELECTOR)
                )
            })
        {
            return Err(no_matching_payment_call_error());
        }

        Ok(Self {
            swap_prefix,
            transfers,
        })
    }
}

/// Checks that only apply to a fee-sponsored transaction: at most 11
/// transfers, and a swap prefix that buys exactly the payment.
pub(super) fn validate_fee_payer_calls(
    calls: &PaymentCalls<'_>,
    currency: Address,
    expected: &[Transfer],
) -> Result<(), VerificationError> {
    if calls.transfers.len() > 11 {
        return Err(disallowed_fee_payer_call_pattern_error());
    }

    if let Some((approve, swap_call)) = calls.swap_prefix {
        let approve_target = match &approve.to {
            TxKind::Call(address) => *address,
            _ => return Err(disallowed_fee_payer_call_pattern_error()),
        };
        let swap = decode_swap(swap_call).ok_or_else(disallowed_fee_payer_call_pattern_error)?;
        if approve_target != swap.tokenIn {
            return Err(VerificationError::new(
                "Fee-sponsored transaction approve target is not the swap input token".to_string(),
            ));
        }

        let (approve_spender, approve_amount) =
            decode_approve(approve).ok_or_else(disallowed_fee_payer_call_pattern_error)?;
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

        match &swap_call.to {
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
