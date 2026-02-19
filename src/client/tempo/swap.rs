//! Swap types, slippage constants, and call builders for Tempo payments.

use alloy::primitives::{Address, TxKind, U256};
use tempo_primitives::transaction::Call;

use crate::error::MppError;
use crate::protocol::methods::tempo::abi::{
    encode_approve, encode_swap_exact_amount_out, encode_transfer, DEX_ADDRESS,
};

/// Slippage tolerance in basis points (0.5% = 50 bps).
pub const SWAP_SLIPPAGE_BPS: u128 = 50;

/// Basis points denominator (10000 bps = 100%).
pub const BPS_DENOMINATOR: u128 = 10000;

/// Information about a token swap to perform before payment.
#[derive(Debug, Clone)]
pub struct SwapInfo {
    /// Token to swap from (the token the user holds).
    pub token_in: Address,
    /// Token to swap to (the token the merchant wants).
    pub token_out: Address,
    /// Exact amount of token_out needed.
    pub amount_out: U256,
    /// Maximum amount of token_in to spend (includes slippage).
    pub max_amount_in: U256,
}

impl SwapInfo {
    /// Create a new SwapInfo with slippage calculation.
    ///
    /// The `max_amount_in` is calculated as `amount_out + (amount_out * SWAP_SLIPPAGE_BPS / BPS_DENOMINATOR)`.
    pub fn new(token_in: Address, token_out: Address, amount_out: U256) -> Self {
        let slippage = amount_out * U256::from(SWAP_SLIPPAGE_BPS) / U256::from(BPS_DENOMINATOR);
        let max_amount_in = amount_out + slippage;

        Self {
            token_in,
            token_out,
            amount_out,
            max_amount_in,
        }
    }
}

/// Build the 3 calls for a swap transaction: approve → swap → transfer.
///
/// Constructs an atomic 3-call sequence:
/// 1. `approve(DEX_ADDRESS, max_amount_in)` on `token_in`
/// 2. `swapExactAmountOut(token_in, token_out, amount_out, max_amount_in)` on DEX
/// 3. `transfer(recipient, amount)` on `token_out` (with optional memo)
pub fn build_swap_calls(
    swap_info: &SwapInfo,
    recipient: Address,
    amount: U256,
    memo: Option<[u8; 32]>,
) -> Result<Vec<Call>, MppError> {
    let amount_out_u128: u128 = swap_info
        .amount_out
        .try_into()
        .map_err(|_| MppError::InvalidAmount("Amount too large for u128".to_string()))?;
    let max_amount_in_u128: u128 = swap_info
        .max_amount_in
        .try_into()
        .map_err(|_| MppError::InvalidAmount("Max amount too large for u128".to_string()))?;

    let approve_data = encode_approve(DEX_ADDRESS, swap_info.max_amount_in);
    let swap_data = encode_swap_exact_amount_out(
        swap_info.token_in,
        swap_info.token_out,
        amount_out_u128,
        max_amount_in_u128,
    );
    let transfer_data = encode_transfer(recipient, amount, memo);

    Ok(vec![
        Call {
            to: TxKind::Call(swap_info.token_in),
            value: U256::ZERO,
            input: approve_data,
        },
        Call {
            to: TxKind::Call(DEX_ADDRESS),
            value: U256::ZERO,
            input: swap_data,
        },
        Call {
            to: TxKind::Call(swap_info.token_out),
            value: U256::ZERO,
            input: transfer_data,
        },
    ])
}

/// Build the 2 calls for opening an escrow channel: approve → open.
///
/// Constructs a 2-call sequence:
/// 1. `approve(escrow_contract, deposit)` on the currency token
/// 2. `IEscrow::open(payee, currency, deposit, salt, authorizedSigner)` on the escrow contract
pub fn build_open_calls(
    currency: Address,
    escrow_contract: Address,
    deposit: u128,
    payee: Address,
    salt: alloy::primitives::B256,
    authorized_signer: Address,
) -> Vec<Call> {
    use alloy::sol;
    use alloy::sol_types::SolCall;

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

    let approve_data = encode_approve(escrow_contract, U256::from(deposit));
    let open_data =
        IEscrow::openCall::new((payee, currency, deposit, salt, authorized_signer)).abi_encode();

    vec![
        Call {
            to: TxKind::Call(currency),
            value: U256::ZERO,
            input: approve_data,
        },
        Call {
            to: TxKind::Call(escrow_contract),
            value: U256::ZERO,
            input: alloy::primitives::Bytes::from(open_data),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swap_info_slippage_calculation() {
        let token_in: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let token_out: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let amount_out = U256::from(1_000_000u64);

        let swap_info = SwapInfo::new(token_in, token_out, amount_out);

        assert_eq!(swap_info.amount_out, U256::from(1_000_000u64));
        assert_eq!(swap_info.max_amount_in, U256::from(1_005_000u64));
    }

    #[test]
    fn test_swap_info_slippage_with_large_amount() {
        let token_in = Address::ZERO;
        let token_out = Address::repeat_byte(0x01);
        let amount_out = U256::from(1_000_000_000u64);

        let swap_info = SwapInfo::new(token_in, token_out, amount_out);

        assert_eq!(swap_info.max_amount_in, U256::from(1_005_000_000u64));
    }

    #[test]
    fn test_swap_info_preserves_addresses() {
        let token_in: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let token_out: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let amount_out = U256::from(100u64);

        let swap_info = SwapInfo::new(token_in, token_out, amount_out);

        assert_eq!(swap_info.token_in, token_in);
        assert_eq!(swap_info.token_out, token_out);
    }

    #[test]
    fn test_swap_slippage_bps_constant() {
        assert_eq!(SWAP_SLIPPAGE_BPS, 50);
    }

    #[test]
    fn test_bps_denominator_constant() {
        assert_eq!(BPS_DENOMINATOR, 10000);
    }

    // --- build_swap_calls ---

    #[test]
    fn test_build_swap_calls_produces_three_calls() {
        let token_in: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let token_out: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let recipient: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let amount = U256::from(1_000_000u64);

        let swap_info = SwapInfo::new(token_in, token_out, amount);
        let calls = build_swap_calls(&swap_info, recipient, amount, None).unwrap();

        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].to.to().unwrap(), &token_in);
        assert_eq!(calls[1].to.to().unwrap(), &DEX_ADDRESS);
        assert_eq!(calls[2].to.to().unwrap(), &token_out);
        assert!(calls.iter().all(|c| c.value == U256::ZERO));
    }

    #[test]
    fn test_build_swap_calls_with_memo() {
        let token_in = Address::repeat_byte(0x01);
        let token_out = Address::repeat_byte(0x02);
        let recipient = Address::repeat_byte(0x03);
        let amount = U256::from(500_000u64);
        let memo = Some([0xab; 32]);

        let swap_info = SwapInfo::new(token_in, token_out, amount);
        let calls = build_swap_calls(&swap_info, recipient, amount, memo).unwrap();

        assert_eq!(calls.len(), 3);
        assert!(!calls[2].input.is_empty());
    }

    // --- build_open_calls ---

    #[test]
    fn test_build_open_calls_produces_two_calls() {
        let currency = Address::repeat_byte(0x01);
        let escrow = Address::repeat_byte(0x02);
        let payee = Address::repeat_byte(0x03);
        let signer = Address::repeat_byte(0x04);
        let salt = alloy::primitives::B256::repeat_byte(0x05);

        let calls = build_open_calls(currency, escrow, 1_000_000, payee, salt, signer);

        assert_eq!(calls.len(), 2);
        // Call 1: approve on currency
        assert_eq!(calls[0].to.to().unwrap(), &currency);
        assert_eq!(calls[0].value, U256::ZERO);
        // Call 2: open on escrow contract
        assert_eq!(calls[1].to.to().unwrap(), &escrow);
        assert_eq!(calls[1].value, U256::ZERO);
    }

    #[test]
    fn test_build_open_calls_approve_data_starts_with_approve_selector() {
        let currency = Address::repeat_byte(0x01);
        let escrow = Address::repeat_byte(0x02);

        let calls = build_open_calls(
            currency,
            escrow,
            500_000,
            Address::ZERO,
            alloy::primitives::B256::ZERO,
            Address::ZERO,
        );

        // approve selector: 0x095ea7b3
        assert_eq!(&calls[0].input[..4], &[0x09, 0x5e, 0xa7, 0xb3]);
    }

    // --- calldata semantic correctness ---

    #[test]
    fn test_build_swap_calls_approve_calldata() {
        let token_in: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let token_out: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let recipient: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let amount = U256::from(1_000_000u64);

        let swap_info = SwapInfo::new(token_in, token_out, amount);
        let calls = build_swap_calls(&swap_info, recipient, amount, None).unwrap();

        let expected = encode_approve(DEX_ADDRESS, swap_info.max_amount_in);
        assert_eq!(calls[0].input, expected);
    }

    #[test]
    fn test_build_swap_calls_swap_calldata() {
        let token_in: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let token_out: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let recipient: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let amount = U256::from(1_000_000u64);

        let swap_info = SwapInfo::new(token_in, token_out, amount);
        let amount_out: u128 = swap_info.amount_out.try_into().unwrap();
        let max_amount_in: u128 = swap_info.max_amount_in.try_into().unwrap();
        let calls = build_swap_calls(&swap_info, recipient, amount, None).unwrap();

        let expected =
            encode_swap_exact_amount_out(token_in, token_out, amount_out, max_amount_in);
        assert_eq!(calls[1].input, expected);
    }

    #[test]
    fn test_build_swap_calls_transfer_calldata_no_memo() {
        let token_in: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let token_out: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let recipient: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let amount = U256::from(1_000_000u64);

        let swap_info = SwapInfo::new(token_in, token_out, amount);
        let calls = build_swap_calls(&swap_info, recipient, amount, None).unwrap();

        let expected = encode_transfer(recipient, amount, None);
        assert_eq!(calls[2].input, expected);
    }

    #[test]
    fn test_build_swap_calls_transfer_calldata_with_memo() {
        let token_in: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let token_out: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let recipient: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();
        let amount = U256::from(1_000_000u64);
        let memo = [0xab; 32];

        let swap_info = SwapInfo::new(token_in, token_out, amount);
        let calls = build_swap_calls(&swap_info, recipient, amount, Some(memo)).unwrap();

        let expected = encode_transfer(recipient, amount, Some(memo));
        assert_eq!(calls[2].input, expected);
    }

    #[test]
    fn test_build_swap_calls_amount_out_overflow() {
        let swap_info = SwapInfo {
            token_in: Address::repeat_byte(0x01),
            token_out: Address::repeat_byte(0x02),
            amount_out: U256::from(u128::MAX) + U256::from(1u64),
            max_amount_in: U256::from(100u64),
        };
        let recipient = Address::repeat_byte(0x03);

        let result = build_swap_calls(&swap_info, recipient, U256::from(100u64), None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MppError::InvalidAmount(_)));
    }

    #[test]
    fn test_build_swap_calls_max_amount_in_overflow() {
        let swap_info = SwapInfo {
            token_in: Address::repeat_byte(0x01),
            token_out: Address::repeat_byte(0x02),
            amount_out: U256::from(100u64),
            max_amount_in: U256::from(u128::MAX) + U256::from(1u64),
        };
        let recipient = Address::repeat_byte(0x03);

        let result = build_swap_calls(&swap_info, recipient, U256::from(100u64), None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MppError::InvalidAmount(_)));
    }

    #[test]
    fn test_build_open_calls_approve_calldata() {
        let currency = Address::repeat_byte(0x01);
        let escrow = Address::repeat_byte(0x02);
        let payee = Address::repeat_byte(0x03);
        let signer = Address::repeat_byte(0x04);
        let salt = alloy::primitives::B256::repeat_byte(0x05);
        let deposit: u128 = 1_000_000;

        let calls = build_open_calls(currency, escrow, deposit, payee, salt, signer);

        let expected = encode_approve(escrow, U256::from(deposit));
        assert_eq!(calls[0].input, expected);
    }

    #[test]
    fn test_swap_info_zero_amount() {
        let token_in = Address::repeat_byte(0x01);
        let token_out = Address::repeat_byte(0x02);

        let swap_info = SwapInfo::new(token_in, token_out, U256::ZERO);

        assert_eq!(swap_info.amount_out, U256::ZERO);
        assert_eq!(swap_info.max_amount_in, U256::ZERO);
    }
}
