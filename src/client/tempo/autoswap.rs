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
//! 3. Otherwise try each candidate input token in order: the configured
//!    [`AutoswapConfig::token_in`], then (unless [`AutoswapConfig::fallback`]
//!    is off) the default currencies pathUSD, USDC.e and OUSD, skipping
//!    duplicates and the challenge currency, as mppx does
//! 4. Take the first candidate the payer holds that has a DEX route within the
//!    spend limit, and prepend `approve` and `swapExactAmountOut` calls to the
//!    transaction so the swap and transfer execute atomically in a single AA
//!    transaction
//!
//! # Example
//!
//! ```ignore
//! use mpp::client::{AutoswapConfig, TempoProvider};
//!
//! // Swap from pathUSD, USDC.e or OUSD, in that order (mppx's `autoSwap: true`).
//! let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?
//!     .with_autoswap(AutoswapConfig::default());
//!
//! // Prefer USDC.e, then fall back to the defaults.
//! let provider = provider.with_autoswap(AutoswapConfig::new(usdc, 100));
//!
//! // Swap only from USDC.e (mppx's `autoSwap: { tokenIn: [usdc], fallback: false }`),
//! // with an explicit input-token budget.
//! let provider = provider.with_autoswap(
//!     AutoswapConfig::new(usdc, 100)
//!         .with_fallback(false)
//!         .with_max_amount_in(1_010_000),
//! );
//! ```

use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::sol_types::SolCall;
use tempo_alloy::contracts::precompiles::{
    IStablecoinDEX, ITIP20, STABLECOIN_DEX_ADDRESS as DEX_ADDRESS,
};
use tempo_alloy::primitives::transaction::Call;

use crate::error::{MppError, ResultExt};
use crate::protocol::methods::tempo::{OUSD, PATH_USD, USDC};

/// Maximum allowed slippage in basis points (50% = 5000 bps).
const MAX_SLIPPAGE_BPS: u16 = 5_000;

/// Default fallback currencies for autoswap, in priority order: pathUSD,
/// USDC.e, then OUSD, as mppx's `defaultCurrencies`.
pub const DEFAULT_AUTOSWAP_CURRENCIES: [&str; 3] = [PATH_USD, USDC, OUSD];

/// The [`DEFAULT_AUTOSWAP_CURRENCIES`] as addresses, in priority order.
pub fn default_autoswap_currencies() -> Vec<Address> {
    DEFAULT_AUTOSWAP_CURRENCIES
        .iter()
        .map(|token| {
            token
                .parse()
                .expect("default autoswap currency is a valid address")
        })
        .collect()
}

/// Whether `token` can pay Tempo transaction fees. OUSD cannot.
fn can_pay_fees(token: Address) -> bool {
    OUSD.parse::<Address>().is_ok_and(|ousd| ousd != token)
}

/// Configuration for automatic token swaps.
///
/// The swap tries [`token_in`](Self::token_in) first and then, while
/// [`fallback`](Self::fallback) is on (the default, as in mppx), the
/// [`DEFAULT_AUTOSWAP_CURRENCIES`]. [`AutoswapConfig::default()`] swaps from
/// the default currencies alone, like mppx's `autoSwap: true`.
#[derive(Debug, Clone)]
pub struct AutoswapConfig {
    /// The preferred token to swap from (the token the user holds).
    pub token_in: Address,
    /// Slippage tolerance in basis points (e.g., 100 = 1%).
    /// Applied on top of the quoted `amountIn` to protect against price movement.
    pub slippage_bps: u16,
    /// Maximum input-token units per swap. Defaults to the missing output amount
    /// plus slippage (1:1 token units). Set explicitly for non-parity pairs.
    pub max_amount_in: Option<u128>,
    /// Whether to also try the [`DEFAULT_AUTOSWAP_CURRENCIES`] after
    /// `token_in`. Set `false` to swap only from `token_in`, as mppx's
    /// `autoSwap.fallback: false`. Defaults to `true`.
    pub fallback: bool,
}

impl AutoswapConfig {
    /// Create a new autoswap config with the given input token and slippage.
    ///
    /// `token_in` is tried first, then the [`DEFAULT_AUTOSWAP_CURRENCIES`]
    /// (fallback is on, as in mppx). Call [`with_fallback(false)`](Self::with_fallback)
    /// to swap only from `token_in`.
    pub fn new(token_in: Address, slippage_bps: u16) -> Self {
        Self {
            token_in,
            slippage_bps,
            max_amount_in: None,
            fallback: true,
        }
    }

    /// Set whether the default currencies are tried after `token_in`.
    pub fn with_fallback(mut self, fallback: bool) -> Self {
        self.fallback = fallback;
        self
    }

    /// Set the maximum input-token units per swap.
    pub fn with_max_amount_in(mut self, max_amount_in: u128) -> Self {
        self.max_amount_in = Some(max_amount_in);
        self
    }

    /// The input tokens to try, in priority order: `token_in`, then the
    /// default currencies not already listed when fallback is on.
    pub fn candidates(&self) -> Vec<Address> {
        let mut candidates = vec![self.token_in];
        if self.fallback {
            for token in default_autoswap_currencies() {
                if !candidates.contains(&token) {
                    candidates.push(token);
                }
            }
        }
        candidates
    }

    /// The token to pay gas in when no other fee token is configured:
    /// `token_in`, unless it cannot pay fees (OUSD).
    pub fn fee_token(&self) -> Option<Address> {
        Some(self.token_in).filter(|token| can_pay_fees(*token))
    }

    /// The gas token for a transaction paying in `currency` after autoswap
    /// resolved `route`, or `None` to let `currency` pay its own gas.
    ///
    /// `token_in` is only a candidate the payer may not hold, so without a
    /// swap the charge currency pays gas when it can; `token_in` is used only
    /// when the currency cannot pay fees (OUSD). With a swap, the swap's input
    /// token pays gas, unless it is OUSD.
    pub fn fee_token_for(
        &self,
        route: Option<&AutoswapRoute>,
        currency: Address,
    ) -> Option<Address> {
        match route {
            Some(route) => route.fee_token(self),
            None if can_pay_fees(currency) => None,
            None => self.fee_token(),
        }
    }
}

impl Default for AutoswapConfig {
    /// Swap from the [`DEFAULT_AUTOSWAP_CURRENCIES`] (pathUSD, USDC.e, OUSD)
    /// with 1% slippage, like mppx's `autoSwap: true`.
    fn default() -> Self {
        Self::new(
            PATH_USD.parse().expect("pathUSD is a valid address"),
            DEFAULT_SLIPPAGE_BPS,
        )
    }
}

/// A resolved swap: the input token chosen and the calls to prepend.
#[derive(Debug, Clone)]
pub struct AutoswapRoute {
    /// The token the swap spends.
    pub token_in: Address,
    /// The DEX `approve` call followed by the `swapExactAmountOut` call.
    pub calls: Vec<Call>,
}

impl AutoswapRoute {
    /// The token to pay gas in for a transaction funded by this route: the
    /// swap's input token, or `config`'s fee token when that is OUSD, which
    /// cannot pay fees.
    pub fn fee_token(&self, config: &AutoswapConfig) -> Option<Address> {
        Some(self.token_in)
            .filter(|token| can_pay_fees(*token))
            .or_else(|| config.fee_token())
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
    let max_amount_in = (U256::from(quoted_amount_in)
        * U256::from(10_000u64 + u64::from(slippage_bps))
        / U256::from(10_000))
    .min(U256::from(u128::MAX))
    .to::<u128>();

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
/// [`resolve_autoswap_route`] also returns the input token it chose.
pub async fn resolve_autoswap_calls<P: alloy::providers::Provider<tempo_alloy::TempoNetwork>>(
    provider: &P,
    owner: Address,
    currency: Address,
    amount: U256,
    config: &AutoswapConfig,
) -> Result<Option<Vec<Call>>, MppError> {
    Ok(
        resolve_autoswap_route(provider, owner, currency, amount, config)
            .await?
            .map(|route| route.calls),
    )
}

/// Resolve autoswap: choose an input token and build its approval + swap calls.
///
/// Returns `Ok(None)` when `owner` already holds `amount` of `currency`, or
/// when `currency` is the only candidate. Otherwise tries each of
/// [`AutoswapConfig::candidates`] other than `currency`, in order, and uses
/// the first one `owner` holds whose DEX quote is non-zero, within the spend
/// limit, and covered by `owner`'s balance with slippage, as mppx does.
///
/// With a single candidate (fallback off, or every default already listed)
/// its own failure is returned, such as an insufficient balance of it; with
/// several, failing candidates are skipped and an insufficient-balance error
/// naming `currency` is returned when none works.
pub async fn resolve_autoswap_route<P: alloy::providers::Provider<tempo_alloy::TempoNetwork>>(
    provider: &P,
    owner: Address,
    currency: Address,
    amount: U256,
    config: &AutoswapConfig,
) -> Result<Option<AutoswapRoute>, MppError> {
    if config.slippage_bps > MAX_SLIPPAGE_BPS {
        return Err(MppError::InvalidConfig(format!(
            "autoswap slippage {}bps exceeds maximum {}bps",
            config.slippage_bps, MAX_SLIPPAGE_BPS
        )));
    }

    let candidates: Vec<Address> = config
        .candidates()
        .into_iter()
        .filter(|token| *token != currency)
        .collect();
    if candidates.is_empty() {
        // Already holding the right token — no swap needed.
        return Ok(None);
    }

    let deficit = match check_balance_deficit(provider, owner, currency, amount).await? {
        Some(deficit) => deficit,
        None => return Ok(None),
    };
    let amount_out: u128 = deficit
        .try_into()
        .map_err(|_| MppError::InvalidAmount(format!("deficit {deficit} exceeds u128")))?;

    let single = candidates.len() == 1;
    for token_in in candidates {
        match swap_from(
            provider, owner, token_in, currency, amount_out, config, single,
        )
        .await
        {
            Ok(Some(calls)) => return Ok(Some(AutoswapRoute { token_in, calls })),
            Ok(None) => continue,
            Err(error) if single => return Err(error),
            Err(_) => continue,
        }
    }

    Err(MppError::InsufficientBalance(Some(format!(
        "no balance in {currency} and no viable swap route from fallback currencies"
    ))))
}

/// Build the approval and swap from `token_in`, or `Ok(None)` to skip a
/// candidate `owner` holds none of when others remain (`single` is false).
async fn swap_from<P: alloy::providers::Provider<tempo_alloy::TempoNetwork>>(
    provider: &P,
    owner: Address,
    token_in: Address,
    currency: Address,
    amount_out: u128,
    config: &AutoswapConfig,
    single: bool,
) -> Result<Option<Vec<Call>>, MppError> {
    let balance = ITIP20::new(token_in, provider)
        .balanceOf(owner)
        .call()
        .await
        .mpp_http("failed to query balance")?;
    if balance.is_zero() && !single {
        return Ok(None);
    }

    let quoted_amount_in = quote_swap(provider, token_in, currency, amount_out).await?;

    // Compute max_amount_in with slippage and verify the user can cover it.
    let max_amount_in = bounded_swap_input(amount_out, quoted_amount_in, config)?;
    if balance < U256::from(max_amount_in) {
        return Err(MppError::from(
            crate::client::tempo::TempoClientError::InsufficientBalance {
                token: token_in.to_string(),
                available: balance.to_string(),
                required: max_amount_in.to_string(),
                funding_url: None,
            },
        ));
    }

    Ok(Some(vec![
        build_approve_call(token_in, max_amount_in),
        build_swap_call(token_in, currency, amount_out, max_amount_in, 0),
    ]))
}

/// Bound spending independently of the DEX quote, using wide arithmetic to avoid overflow.
fn bounded_swap_input(
    amount_out: u128,
    quoted: u128,
    config: &AutoswapConfig,
) -> Result<u128, MppError> {
    let with_slippage = |amount: u128| {
        U256::from(amount) * U256::from(10_000u64 + u64::from(config.slippage_bps))
            / U256::from(10_000)
    };
    let limit = config
        .max_amount_in
        .map(U256::from)
        .unwrap_or_else(|| with_slippage(amount_out));
    if quoted == 0 || U256::from(quoted) > limit {
        return Err(MppError::InvalidAmount(
            "autoswap quote exceeds spend limit or is zero".into(),
        ));
    }
    with_slippage(quoted)
        .min(limit)
        .try_into()
        .map_err(|_| MppError::InvalidAmount("autoswap maximum input exceeds u128".into()))
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
    fn test_independent_spend_limit() {
        for (quote, cap, expected) in [
            (100, None, Some(101)),
            (101, None, Some(101)),
            (102, None, None),
            (0, None, None),
            (500, Some(600), Some(505)),
            (500, Some(499), None),
        ] {
            let mut config = AutoswapConfig::new(Address::ZERO, 100);
            config.max_amount_in = cap;
            assert_eq!(bounded_swap_input(100, quote, &config).ok(), expected);
        }
        let config = AutoswapConfig::new(Address::ZERO, 100);
        assert!(bounded_swap_input(u128::MAX, u128::MAX, &config).is_err());
        let call = build_swap_call(Address::ZERO, Address::ZERO, 1, u128::MAX, 0);
        let decoded =
            IStablecoinDEX::swapExactAmountOutCall::abi_decode_raw(&call.input[4..]).unwrap();
        assert_eq!(decoded.maxAmountIn, u128::MAX);
    }

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
        asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
            &U256::from(16_852_785),
        )));
        asserter.push_success(&Bytes::from(
            IStablecoinDEX::quoteSwapExactAmountOutCall::abi_encode_returns(&4_947_094u128),
        ));
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
        assert_eq!(approve.amount, U256::from(4_996_564));
        let swap =
            IStablecoinDEX::swapExactAmountOutCall::abi_decode_raw(&calls[1].input[4..]).unwrap();
        assert_eq!(swap.amountOut, 4_947_094);
        assert_eq!(swap.maxAmountIn, 4_996_564);
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
        asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
            &U256::from(3_000),
        )));
        asserter.push_success(&Bytes::from(
            IStablecoinDEX::quoteSwapExactAmountOutCall::abi_encode_returns(&5_000_000u128),
        ));
        let provider = ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);

        let err = resolve_autoswap_calls(
            &provider,
            Address::repeat_byte(0x11),
            token_out,
            U256::from(5_000_000),
            &AutoswapConfig::new(token_in, 100).with_fallback(false),
        )
        .await
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            format!("Insufficient {token_in} balance: have 3000, need 5050000")
        );
    }

    fn mocked(responses: &[Bytes]) -> impl alloy::providers::Provider<tempo_alloy::TempoNetwork> {
        use alloy::providers::{mock::Asserter, ProviderBuilder};
        let asserter = Asserter::new();
        for response in responses {
            asserter.push_success(response);
        }
        ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter)
    }

    fn balance(amount: u64) -> Bytes {
        Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(&U256::from(
            amount,
        )))
    }

    fn quote(amount: u128) -> Bytes {
        Bytes::from(IStablecoinDEX::quoteSwapExactAmountOutCall::abi_encode_returns(&amount))
    }

    fn addr(token: &str) -> Address {
        token.parse().unwrap()
    }

    #[test]
    fn test_default_candidates_match_mppx() {
        assert_eq!(
            default_autoswap_currencies(),
            vec![addr(PATH_USD), addr(USDC), addr(OUSD)]
        );
        let config = AutoswapConfig::default();
        assert!(config.fallback);
        assert_eq!(config.slippage_bps, DEFAULT_SLIPPAGE_BPS);
        assert_eq!(config.candidates(), default_autoswap_currencies());

        // token_in first, then the defaults it doesn't repeat.
        let config = AutoswapConfig::new(addr(USDC), 100);
        assert!(config.fallback);
        assert_eq!(
            config.candidates(),
            vec![addr(USDC), addr(PATH_USD), addr(OUSD)]
        );
        let custom = Address::repeat_byte(0x11);
        assert_eq!(
            AutoswapConfig::new(custom, 100).candidates(),
            vec![custom, addr(PATH_USD), addr(USDC), addr(OUSD)]
        );
        // fallback: false makes token_in an allowlist.
        assert_eq!(
            AutoswapConfig::new(custom, 100)
                .with_fallback(false)
                .candidates(),
            vec![custom]
        );
    }

    #[test]
    fn test_ousd_never_pays_fees() {
        assert_eq!(AutoswapConfig::new(addr(OUSD), 100).fee_token(), None);
        assert_eq!(AutoswapConfig::default().fee_token(), Some(addr(PATH_USD)));
        let route = AutoswapRoute {
            token_in: addr(OUSD),
            calls: Vec::new(),
        };
        assert_eq!(
            route.fee_token(&AutoswapConfig::default()),
            Some(addr(PATH_USD))
        );
        assert_eq!(route.fee_token(&AutoswapConfig::new(addr(OUSD), 100)), None);
        let route = AutoswapRoute {
            token_in: addr(USDC),
            calls: Vec::new(),
        };
        assert_eq!(
            route.fee_token(&AutoswapConfig::default()),
            Some(addr(USDC))
        );
    }

    #[test]
    fn test_fee_token_without_a_swap_is_the_currency() {
        let config = AutoswapConfig::default();
        // No swap: a fee-capable currency pays its own gas, never the unheld token_in.
        assert_eq!(config.fee_token_for(None, addr(USDC)), None);
        // OUSD cannot pay fees, so token_in does.
        assert_eq!(config.fee_token_for(None, addr(OUSD)), Some(addr(PATH_USD)));
        let route = AutoswapRoute {
            token_in: addr(USDC),
            calls: Vec::new(),
        };
        assert_eq!(
            config.fee_token_for(Some(&route), addr(OUSD)),
            Some(addr(USDC))
        );
    }

    #[tokio::test]
    async fn test_falls_back_to_first_funded_default() {
        // Pay in USDC.e holding no pathUSD: pathUSD is skipped without a quote
        // and the swap comes from OUSD.
        let provider = mocked(&[balance(0), balance(0), balance(2_000_000), quote(1_000_000)]);
        let route = resolve_autoswap_route(
            &provider,
            Address::repeat_byte(0x11),
            addr(USDC),
            U256::from(1_000_000),
            &AutoswapConfig::default(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(route.token_in, addr(OUSD));
        assert_eq!(route.calls[0].to, TxKind::Call(addr(OUSD)));
        let swap =
            IStablecoinDEX::swapExactAmountOutCall::abi_decode_raw(&route.calls[1].input[4..])
                .unwrap();
        assert_eq!(swap.tokenIn, addr(OUSD));
        assert_eq!(swap.tokenOut, addr(USDC));
        assert_eq!(swap.maxAmountIn, 1_010_000);
    }

    #[tokio::test]
    async fn test_skips_candidate_that_cannot_cover_the_swap() {
        // token_in holds too little; the next candidate (pathUSD) covers it.
        let custom = Address::repeat_byte(0x22);
        let provider = mocked(&[
            balance(0),
            balance(10),
            quote(1_000_000),
            balance(5_000_000),
            quote(1_000_000),
        ]);
        let route = resolve_autoswap_route(
            &provider,
            Address::repeat_byte(0x11),
            addr(USDC),
            U256::from(1_000_000),
            &AutoswapConfig::new(custom, 100),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(route.token_in, addr(PATH_USD));
    }

    #[tokio::test]
    async fn test_no_viable_fallback_reports_the_currency() {
        let provider = mocked(&[balance(0), balance(0), balance(0)]);
        let err = resolve_autoswap_route(
            &provider,
            Address::repeat_byte(0x11),
            addr(USDC),
            U256::from(1_000_000),
            &AutoswapConfig::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Insufficient balance: no balance in {} and no viable swap route from fallback currencies.",
                addr(USDC)
            )
        );
    }

    #[tokio::test]
    async fn test_currency_as_only_candidate_needs_no_swap() {
        let provider = mocked(&[]);
        let route = resolve_autoswap_route(
            &provider,
            Address::repeat_byte(0x11),
            addr(USDC),
            U256::from(1_000_000),
            &AutoswapConfig::new(addr(USDC), 100).with_fallback(false),
        )
        .await
        .unwrap();
        assert!(route.is_none());
    }
}
