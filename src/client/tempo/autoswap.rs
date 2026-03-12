//! Autoswap support for Tempo MPP payments.
//!
//! When a payment challenge requires a currency the client doesn't hold,
//! this module prepends a DEX swap call to the transaction so the user
//! automatically acquires the required token via the Tempo Stablecoin DEX.
//!
//! # How it works
//!
//! 1. Check the client's balance of the challenge currency
//! 2. If balance >= amount, no swap needed — proceed normally
//! 3. If balance < amount, compute the deficit and query the DEX for a quote
//! 4. Prepend a `swapExactAmountOut` call to the transaction's call list
//!    so the swap and transfer execute atomically in a single AA transaction
//!
//! # Example
//!
//! ```ignore
//! use mpp::client::TempoProvider;
//!
//! let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?
//!     .with_autoswap(AutoswapConfig {
//!         token_in: "0x20C000000000000000000000b9537d11c60E8b50".parse()?,
//!         slippage_bps: 100, // 1%
//!     });
//! ```

use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::sol_types::{SolCall, SolType};
use tempo_primitives::transaction::Call;

use super::abi::{self, IStablecoinDEX, ITIP20};
use crate::error::MppError;

/// Maximum allowed slippage in basis points (50% = 5000 bps).
const MAX_SLIPPAGE_BPS: u16 = 5_000;

/// Configuration for automatic token swaps.
#[derive(Debug, Clone)]
pub struct AutoswapConfig {
    /// The token to swap from (the token the user holds).
    pub token_in: Address,
    /// Slippage tolerance in basis points (e.g., 100 = 1%).
    /// Applied on top of the quoted `amountIn` to protect against price movement.
    pub slippage_bps: u16,
}

impl AutoswapConfig {
    /// Create a new autoswap config with the given input token and slippage.
    pub fn new(token_in: Address, slippage_bps: u16) -> Self {
        Self {
            token_in,
            slippage_bps,
        }
    }
}

/// Default slippage: 1% (100 basis points).
pub const DEFAULT_SLIPPAGE_BPS: u16 = 100;

/// Query the user's balance of `currency` and determine if a swap is needed.
///
/// Returns `Some(deficit)` if the user needs more tokens, `None` if balance is sufficient.
pub async fn check_balance_deficit<P: alloy::providers::Provider<tempo_alloy::TempoNetwork>>(
    provider: &P,
    owner: Address,
    currency: Address,
    amount: U256,
) -> Result<Option<U256>, MppError> {
    let balance_call = ITIP20::balanceOfCall { account: owner }.abi_encode();
    let result = provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(currency)
                .input(alloy::rpc::types::TransactionInput::new(Bytes::from(
                    balance_call,
                )))
                .into(),
        )
        .await
        .map_err(|e| MppError::Http(format!("failed to query balance: {e}")))?;

    let balance = <alloy::sol_types::sol_data::Uint<256>>::abi_decode(&result)
        .map_err(|e| MppError::Http(format!("failed to decode balance: {e}")))?;
    if balance >= amount {
        Ok(None)
    } else {
        Ok(Some(amount - balance))
    }
}

/// Quote the DEX for the `amountIn` required to receive `amount_out` of `token_out`.
pub async fn quote_swap<P: alloy::providers::Provider<tempo_alloy::TempoNetwork>>(
    provider: &P,
    token_in: Address,
    token_out: Address,
    amount_out: u128,
) -> Result<u128, MppError> {
    let quote_call = IStablecoinDEX::quoteSwapExactAmountOutCall {
        tokenIn: token_in,
        tokenOut: token_out,
        amountOut: amount_out,
    }
    .abi_encode();

    let result = provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(abi::DEX_ADDRESS)
                .input(alloy::rpc::types::TransactionInput::new(Bytes::from(
                    quote_call,
                )))
                .into(),
        )
        .await
        .map_err(|e| MppError::Http(format!("DEX quote failed: {e}")))?;

    let amount_in = <alloy::sol_types::sol_data::Uint<128>>::abi_decode(&result)
        .map_err(|e| MppError::Http(format!("failed to decode DEX quote: {e}")))?;
    Ok(amount_in)
}

/// Build the swap call to prepend to the transaction.
///
/// Applies slippage tolerance to the quoted `amount_in` to compute `max_amount_in`.
pub fn build_swap_call(
    token_in: Address,
    token_out: Address,
    amount_out: u128,
    quoted_amount_in: u128,
    slippage_bps: u16,
) -> Call {
    // max_amount_in = quoted_amount_in * (10000 + slippage_bps) / 10000
    let max_amount_in = quoted_amount_in.saturating_mul(10_000 + slippage_bps as u128) / 10_000;

    let swap_data =
        abi::encode_swap_exact_amount_out(token_in, token_out, amount_out, max_amount_in);

    Call {
        to: TxKind::Call(abi::DEX_ADDRESS),
        value: U256::ZERO,
        input: swap_data,
    }
}

/// Resolve autoswap: check balance, quote, and return the swap call if needed.
///
/// Returns `Ok(Some(call))` if a swap is needed, `Ok(None)` if balance is sufficient.
///
/// Validates that:
/// 1. The slippage tolerance is within bounds
/// 2. The user has sufficient `token_in` balance to cover `max_amount_in`
pub async fn resolve_autoswap<P: alloy::providers::Provider<tempo_alloy::TempoNetwork>>(
    provider: &P,
    owner: Address,
    currency: Address,
    amount: U256,
    config: &AutoswapConfig,
) -> Result<Option<Call>, MppError> {
    if config.slippage_bps > MAX_SLIPPAGE_BPS {
        return Err(MppError::InvalidConfig(format!(
            "autoswap slippage {}bps exceeds maximum {}bps",
            config.slippage_bps, MAX_SLIPPAGE_BPS
        )));
    }

    if config.token_in == currency {
        // Already holding the right token — no swap needed.
        return Ok(None);
    }

    let deficit = match check_balance_deficit(provider, owner, currency, amount).await? {
        Some(d) => d,
        None => return Ok(None),
    };

    // Convert deficit to u128 for the DEX call (TIP-20 tokens use u128 amounts).
    let deficit_u128: u128 = deficit
        .try_into()
        .map_err(|_| MppError::InvalidAmount(format!("deficit {} exceeds u128", deficit)))?;

    let quoted_amount_in = quote_swap(provider, config.token_in, currency, deficit_u128).await?;

    // Compute max_amount_in with slippage and verify the user can cover it.
    let max_amount_in =
        quoted_amount_in.saturating_mul(10_000 + config.slippage_bps as u128) / 10_000;
    let token_in_balance =
        check_balance_deficit(provider, owner, config.token_in, U256::from(max_amount_in)).await?;
    if token_in_balance.is_some() {
        return Err(MppError::from(
            crate::client::tempo::TempoClientError::InsufficientBalance {
                token: format!("{}", config.token_in),
                available: String::new(),
                required: format!("{}", max_amount_in),
            },
        ));
    }

    Ok(Some(build_swap_call(
        config.token_in,
        currency,
        deficit_u128,
        quoted_amount_in,
        config.slippage_bps,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_autoswap_config_new() {
        let token = address!("0x20C000000000000000000000b9537d11c60E8b50");
        let config = AutoswapConfig::new(token, 50);
        assert_eq!(config.token_in, token);
        assert_eq!(config.slippage_bps, 50);
    }

    #[test]
    fn test_build_swap_call_slippage() {
        let token_in = address!("0x20C000000000000000000000b9537d11c60E8b50");
        let token_out = address!("0x20c0000000000000000000000000000000000000");

        let call = build_swap_call(token_in, token_out, 1_000_000, 1_000_000, 100);

        // max_amount_in = 1_000_000 * 10100 / 10000 = 1_010_000
        assert_eq!(call.to, TxKind::Call(abi::DEX_ADDRESS));
        assert_eq!(call.value, U256::ZERO);

        // Verify the encoded call data decodes correctly.
        let decoded =
            IStablecoinDEX::swapExactAmountOutCall::abi_decode_raw(&call.input[4..]).unwrap();
        assert_eq!(decoded.tokenIn, token_in);
        assert_eq!(decoded.tokenOut, token_out);
        assert_eq!(decoded.amountOut, 1_000_000);
        assert_eq!(decoded.maxAmountIn, 1_010_000);
    }

    #[test]
    fn test_build_swap_call_zero_slippage() {
        let token_in = address!("0x20C000000000000000000000b9537d11c60E8b50");
        let token_out = address!("0x20c0000000000000000000000000000000000000");

        let call = build_swap_call(token_in, token_out, 500_000, 500_000, 0);
        let decoded =
            IStablecoinDEX::swapExactAmountOutCall::abi_decode_raw(&call.input[4..]).unwrap();
        assert_eq!(decoded.maxAmountIn, 500_000);
    }

    #[test]
    fn test_build_swap_call_high_slippage() {
        let token_in = address!("0x20C000000000000000000000b9537d11c60E8b50");
        let token_out = address!("0x20c0000000000000000000000000000000000000");

        // 5% slippage
        let call = build_swap_call(token_in, token_out, 1_000_000, 1_000_000, 500);
        let decoded =
            IStablecoinDEX::swapExactAmountOutCall::abi_decode_raw(&call.input[4..]).unwrap();
        assert_eq!(decoded.maxAmountIn, 1_050_000);
    }
}
