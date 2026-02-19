//! ABI encoding helpers for Tempo token operations.
//!
//! Provides encode functions for TIP-20 transfers, approvals,
//! and DEX swap operations.

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol;
use alloy::sol_types::SolCall;

sol! {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferWithMemo(address to, uint256 amount, bytes32 memo) external returns (bool);
    function swapExactAmountOut(address tokenIn, address tokenOut, uint128 amountOut, uint128 maxAmountIn) external returns (uint128 amountIn);
}

sol! {
    /// TIP-20 token interface for balance queries and approvals.
    #[sol(rpc)]
    interface ITIP20 {
        function balanceOf(address account) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

/// StablecoinDEX contract address on Tempo networks.
pub const DEX_ADDRESS: Address = Address::new([
    0xde, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
]);

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

/// Encode a TIP-20 approve call.
pub fn encode_approve(spender: Address, amount: U256) -> Bytes {
    let call = ITIP20::approveCall { spender, amount };
    Bytes::from(call.abi_encode())
}

/// Encode a DEX swapExactAmountOut call.
///
/// Note: The DEX uses uint128 for amounts, not U256.
pub fn encode_swap_exact_amount_out(
    token_in: Address,
    token_out: Address,
    amount_out: u128,
    max_amount_in: u128,
) -> Bytes {
    let call = swapExactAmountOutCall {
        tokenIn: token_in,
        tokenOut: token_out,
        amountOut: amount_out,
        maxAmountIn: max_amount_in,
    };
    Bytes::from(call.abi_encode())
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
    fn test_approve_encoding() {
        let spender: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"
            .parse()
            .unwrap();
        let amount = U256::from(1_000_000u64);
        let encoded = encode_approve(spender, amount);
        assert_eq!(&encoded[..4], &[0x09, 0x5e, 0xa7, 0xb3]);
        assert_eq!(encoded.len(), 68);
    }

    #[test]
    fn test_swap_exact_amount_out_encoding() {
        let token_in: Address = "0x20c0000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let token_out: Address = "0x20c0000000000000000000000000000000000000"
            .parse()
            .unwrap();
        let encoded = encode_swap_exact_amount_out(token_in, token_out, 1_000_000, 1_005_000);
        assert_eq!(&encoded[..4], &[0xf0, 0x12, 0x2b, 0x75]);
        assert_eq!(encoded.len(), 132);
    }

    #[test]
    fn test_dex_address_constant() {
        assert_eq!(
            format!("{}", DEX_ADDRESS),
            "0xDEc0000000000000000000000000000000000000"
        );
    }
}
