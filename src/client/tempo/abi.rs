//! ABI encoding helpers for Tempo token operations.
//!
//! Provides encode functions for TIP-20 transfers.

use alloy::primitives::{address, Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolCall;

sol! {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferWithMemo(address to, uint256 amount, bytes32 memo) external returns (bool);
}

sol! {
    /// TIP-20 token interface for balance queries and approvals.
    #[sol(rpc)]
    interface ITIP20 {
        function balanceOf(address account) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

sol! {
    /// Stablecoin DEX interface for swap operations.
    #[sol(rpc)]
    interface IStablecoinDEX {
        function swapExactAmountOut(address tokenIn, address tokenOut, uint128 amountOut, uint128 maxAmountIn) external returns (uint128 amountIn);
        function quoteSwapExactAmountOut(address tokenIn, address tokenOut, uint128 amountOut) external view returns (uint128 amountIn);
    }
}

/// Stablecoin DEX precompile address on Tempo.
pub const DEX_ADDRESS: Address = address!("0xdec0000000000000000000000000000000000000");

/// Encode a `swapExactAmountOut` call for the Stablecoin DEX.
///
/// Swaps `token_in` for exactly `amount_out` of `token_out`, with a maximum
/// input amount of `max_amount_in` to protect against slippage.
pub fn encode_swap_exact_amount_out(
    token_in: Address,
    token_out: Address,
    amount_out: u128,
    max_amount_in: u128,
) -> Bytes {
    let call = IStablecoinDEX::swapExactAmountOutCall {
        tokenIn: token_in,
        tokenOut: token_out,
        amountOut: amount_out,
        maxAmountIn: max_amount_in,
    };
    Bytes::from(call.abi_encode())
}

/// Encode a token transfer call, optionally with memo.
pub fn encode_transfer(recipient: Address, amount: U256, memo: Option<[u8; 32]>) -> Bytes {
    if let Some(memo_bytes) = memo {
        let call = transferWithMemoCall {
            to: recipient,
            amount,
            memo: memo_bytes.into(),
        };
        Bytes::from(call.abi_encode())
    } else {
        let call = transferCall {
            to: recipient,
            amount,
        };
        Bytes::from(call.abi_encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_encoding() {
        let recipient: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
            .parse()
            .unwrap();
        let amount = U256::from(1_000_000u64);
        let encoded = encode_transfer(recipient, amount, None);
        assert_eq!(&encoded[..4], &[0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_transfer_with_memo_encoding() {
        let recipient: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
            .parse()
            .unwrap();
        let amount = U256::from(1_000_000u64);
        let memo = [0x12u8; 32];
        let encoded = encode_transfer(recipient, amount, Some(memo));
        assert_eq!(&encoded[..4], &[0x95, 0x77, 0x7d, 0x59]);
    }

    #[test]
    fn test_transfer_encodes_correct_args() {
        let recipient = Address::repeat_byte(0x42);
        let amount = U256::from(999_999u64);
        let encoded = encode_transfer(recipient, amount, None);
        let decoded = transferCall::abi_decode_raw(&encoded[4..]).unwrap();
        assert_eq!(decoded.to, recipient);
        assert_eq!(decoded.amount, amount);
    }

    #[test]
    fn test_transfer_with_memo_encodes_correct_args() {
        let recipient = Address::repeat_byte(0x42);
        let amount = U256::from(500_000u64);
        let memo = [0xAB; 32];
        let encoded = encode_transfer(recipient, amount, Some(memo));
        let decoded = transferWithMemoCall::abi_decode_raw(&encoded[4..]).unwrap();
        assert_eq!(decoded.to, recipient);
        assert_eq!(decoded.amount, amount);
        assert_eq!(decoded.memo, memo);
    }

    #[test]
    fn test_encode_transfer_zero_amount() {
        let recipient = Address::repeat_byte(0x42);
        let encoded = encode_transfer(recipient, U256::ZERO, None);
        let decoded = transferCall::abi_decode_raw(&encoded[4..]).unwrap();
        assert_eq!(decoded.amount, U256::ZERO);
    }
}
