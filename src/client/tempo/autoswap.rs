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
//! 3. If balance < amount, query the DEX for an exact-output quote
//! 4. Prepend `approve` and `swapExactAmountOut` calls to the transaction
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
use alloy::sol_types::SolCall;
use tempo_alloy::contracts::precompiles::{
    IStablecoinDEX, ITIP20, STABLECOIN_DEX_ADDRESS as DEX_ADDRESS,
};
use tempo_primitives::transaction::Call;

use crate::error::{MppError, ResultExt};

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
    let tip20 = ITIP20::new(currency, provider);
    let balance = tip20
        .balanceOf(owner)
        .call()
        .await
        .mpp_http("failed to query balance")?;

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
    let dex = IStablecoinDEX::new(DEX_ADDRESS, provider);
    let amount_in = dex
        .quoteSwapExactAmountOut(token_in, token_out, amount_out)
        .call()
        .await
        .mpp_http("DEX quote failed")?;

    Ok(amount_in)
}

/// Build the approval required by the Stablecoin DEX.
pub fn build_approve_call(token_in: Address, max_amount_in: u128) -> Call {
    Call {
        to: TxKind::Call(token_in),
        value: U256::ZERO,
        input: Bytes::from(
            ITIP20::approveCall::new((DEX_ADDRESS, U256::from(max_amount_in))).abi_encode(),
        ),
    }
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

    let swap_data = Bytes::from(
        IStablecoinDEX::swapExactAmountOutCall {
            tokenIn: token_in,
            tokenOut: token_out,
            amountOut: amount_out,
            maxAmountIn: max_amount_in,
        }
        .abi_encode(),
    );

    Call {
        to: TxKind::Call(DEX_ADDRESS),
        value: U256::ZERO,
        input: swap_data,
    }
}

/// Resolve autoswap: check balance, quote, and return the approval + swap calls if needed.
///
/// Returns `Ok(Some(calls))` if a swap is needed, `Ok(None)` if balance is sufficient.
///
/// Validates that:
/// 1. The slippage tolerance is within bounds
/// 2. The user has sufficient `token_in` balance to cover `max_amount_in`
pub async fn resolve_autoswap_calls<P: alloy::providers::Provider<tempo_alloy::TempoNetwork>>(
    provider: &P,
    owner: Address,
    currency: Address,
    amount: U256,
    config: &AutoswapConfig,
) -> Result<Option<Vec<Call>>, MppError> {
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

    match check_balance_deficit(provider, owner, currency, amount).await? {
        Some(_) => {}
        None => return Ok(None),
    }

    // Match MPPx: acquire the full requested output amount when the target
    // balance is insufficient, leaving any pre-existing dust untouched.
    let amount_out: u128 = amount
        .try_into()
        .map_err(|_| MppError::InvalidAmount(format!("amount {amount} exceeds u128")))?;

    let quoted_amount_in = quote_swap(provider, config.token_in, currency, amount_out).await?;

    // Compute max_amount_in with slippage and verify the user can cover it.
    let max_amount_in =
        quoted_amount_in.saturating_mul(10_000 + config.slippage_bps as u128) / 10_000;
    let required = U256::from(max_amount_in);
    if let Some(deficit) = check_balance_deficit(provider, owner, config.token_in, required).await?
    {
        return Err(MppError::from(
            crate::client::tempo::TempoClientError::InsufficientBalance {
                token: config.token_in.to_string(),
                available: (required - deficit).to_string(),
                required: max_amount_in.to_string(),
            },
        ));
    }

    Ok(Some(vec![
        build_approve_call(config.token_in, max_amount_in),
        build_swap_call(
            config.token_in,
            currency,
            amount_out,
            quoted_amount_in,
            config.slippage_bps,
        ),
    ]))
}

/// Resolve the DEX swap call without its approval call.
///
/// This compatibility helper preserves the original API. Transaction builders
/// should use [`resolve_autoswap_calls`] so the DEX approval and swap execute
/// atomically in the correct order.
pub async fn resolve_autoswap<P: alloy::providers::Provider<tempo_alloy::TempoNetwork>>(
    provider: &P,
    owner: Address,
    currency: Address,
    amount: U256,
    config: &AutoswapConfig,
) -> Result<Option<Call>, MppError> {
    Ok(
        resolve_autoswap_calls(provider, owner, currency, amount, config)
            .await?
            .and_then(|mut calls| calls.pop()),
    )
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
        assert_eq!(call.to, TxKind::Call(DEX_ADDRESS));
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

    #[test]
    fn test_build_approve_call() {
        let token_in = address!("0x20c0000000000000000000000000000000000000");
        let call = build_approve_call(token_in, 5_050_500);

        assert_eq!(call.to, TxKind::Call(token_in));
        let decoded = ITIP20::approveCall::abi_decode_raw(&call.input[4..]).unwrap();
        assert_eq!(decoded.spender, DEX_ADDRESS);
        assert_eq!(decoded.amount, U256::from(5_050_500));
    }

    #[tokio::test]
    async fn test_resolve_autoswap_returns_approve_then_swap() {
        use alloy::{
            primitives::Bytes,
            providers::{mock::Asserter, ProviderBuilder},
        };

        let token_in = address!("0x20c0000000000000000000000000000000000000");
        let token_out = address!("0x20C000000000000000000000b9537d11c60E8b50");
        let asserter = Asserter::new();
        asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
            &U256::from(52_906),
        )));
        asserter.push_success(&Bytes::from(
            IStablecoinDEX::quoteSwapExactAmountOutCall::abi_encode_returns(&5_000_500u128),
        ));
        asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
            &U256::from(16_852_785),
        )));
        let provider = ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);

        let calls = resolve_autoswap_calls(
            &provider,
            Address::repeat_byte(0x11),
            token_out,
            U256::from(5_000_000),
            &AutoswapConfig::new(token_in, 100),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(calls.len(), 2);
        let approve = ITIP20::approveCall::abi_decode_raw(&calls[0].input[4..]).unwrap();
        assert_eq!(approve.spender, DEX_ADDRESS);
        assert_eq!(approve.amount, U256::from(5_050_505));
        let swap =
            IStablecoinDEX::swapExactAmountOutCall::abi_decode_raw(&calls[1].input[4..]).unwrap();
        assert_eq!(swap.amountOut, 5_000_000);
        assert_eq!(swap.maxAmountIn, 5_050_505);
    }

    #[tokio::test]
    async fn test_resolve_autoswap_reports_available_input_balance() {
        use alloy::{
            primitives::Bytes,
            providers::{mock::Asserter, ProviderBuilder},
        };

        let token_in = address!("0x20c0000000000000000000000000000000000000");
        let token_out = address!("0x20C000000000000000000000b9537d11c60E8b50");
        let asserter = Asserter::new();
        asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
            &U256::ZERO,
        )));
        asserter.push_success(&Bytes::from(
            IStablecoinDEX::quoteSwapExactAmountOutCall::abi_encode_returns(&5_000_000u128),
        ));
        asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
            &U256::from(3_000),
        )));
        let provider = ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);

        let err = resolve_autoswap_calls(
            &provider,
            Address::repeat_byte(0x11),
            token_out,
            U256::from(5_000_000),
            &AutoswapConfig::new(token_in, 100),
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!("Insufficient {token_in} balance: have 3000, need 5050000")
        );
    }
}
