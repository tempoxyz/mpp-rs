//! Swap types and slippage constants for Tempo payments.

use alloy::primitives::{Address, U256};

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
}
