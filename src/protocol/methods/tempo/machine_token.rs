//! Canonical first-party machine-token settlement routes.
//!
//! A machine-token charge approves the canonical MACH swapper and calls
//! `swapTo` atomically. The merchant continues to receive the challenge
//! currency while the payer spends MACH, matching mppx's charge deployment.
//!
//! Sessions denominated in MACH are ordinary TIP-1034 channels whose token is
//! MACH. TIP-1095 applies MACH's recipient policy to the logical payer to payee
//! path and returns refunds to the payer, so they need no swapper route. The
//! machineUSD session route below remains for channels that already use it.

use alloy::primitives::{address, Address, Bytes, TxKind, U256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use alloy::sol_types::SolValue;
use tempo_alloy::contracts::precompiles::ITIP20;
use tempo_alloy::primitives::transaction::Call;
use tempo_alloy::rpc::TempoTransactionRequest;

use super::{transfers::Transfer, CHAIN_ID, MODERATO_CHAIN_ID};

alloy::sol! {
    interface IMachineTokenSwapper {
        function swapTo(
            address inputToken,
            uint256 amount,
            address targetToken,
            address recipient,
            bytes32 memo
        ) external;

        struct ChannelDescriptor {
            address payer;
            address payee;
            address operator;
            address token;
            bytes32 salt;
            address authorizedSigner;
            bytes32 expiringNonceHash;
        }

        function settleSession(
            ChannelDescriptor calldata descriptor,
            address recipient,
            address targetToken,
            bytes32 routeSalt
        ) external;
    }
}

/// Resolve the legacy machineUSD session token and swapper for a supported chain.
pub fn session_addresses(chain_id: u64) -> Option<(Address, Address)> {
    session_deployment(chain_id).map(|deployment| (deployment.token, deployment.swapper))
}

/// Bind a logical merchant settlement route into a TIP-1034 descriptor salt.
pub fn compute_session_salt(
    merchant: Address,
    target_token: Address,
    route_salt: alloy::primitives::B256,
) -> alloy::primitives::B256 {
    let typehash = alloy::primitives::keccak256(
        b"MachineUsdSessionRoute(address merchant,address targetToken,bytes32 routeSalt)",
    );
    alloy::primitives::keccak256((typehash, merchant, target_token, route_salt).abi_encode())
}

/// Encode a canonical machine-token session settlement call.
pub fn settle_session_call(
    chain_id: u64,
    descriptor: &super::session::ChannelDescriptor,
    route: &super::session::SettlementRoute,
) -> Result<Call, crate::error::MppError> {
    let (_, swapper) = session_addresses(chain_id).ok_or_else(|| {
        crate::error::MppError::InvalidConfig(format!(
            "machine tokens are not supported on chain ID {chain_id}"
        ))
    })?;
    let parse_address = |name: &str, value: &str| {
        value.parse::<Address>().map_err(|error| {
            crate::error::MppError::InvalidConfig(format!(
                "invalid session descriptor {name}: {error}"
            ))
        })
    };
    let parse_b256 = |name: &str, value: &str| {
        value.parse::<alloy::primitives::B256>().map_err(|error| {
            crate::error::MppError::InvalidConfig(format!(
                "invalid session descriptor {name}: {error}"
            ))
        })
    };
    if route.adapter.parse::<Address>().ok() != Some(swapper) {
        return Err(crate::error::MppError::InvalidConfig(
            "session settlement adapter is not canonical".into(),
        ));
    }
    let merchant = parse_address("settlement recipient", &route.recipient)?;
    let target_token = parse_address("settlement targetToken", &route.target_token)?;
    let route_salt = parse_b256("settlement routeSalt", &route.route_salt)?;
    let descriptor_salt = parse_b256("salt", &descriptor.salt)?;
    if descriptor_salt != compute_session_salt(merchant, target_token, route_salt) {
        return Err(crate::error::MppError::InvalidConfig(
            "session descriptor salt does not bind the settlement route".into(),
        ));
    }
    let descriptor = IMachineTokenSwapper::ChannelDescriptor {
        payer: parse_address("payer", &descriptor.payer)?,
        payee: parse_address("payee", &descriptor.payee)?,
        operator: parse_address("operator", &descriptor.operator)?,
        token: parse_address("token", &descriptor.token)?,
        salt: parse_b256("salt", &descriptor.salt)?,
        authorizedSigner: parse_address("authorizedSigner", &descriptor.authorized_signer)?,
        expiringNonceHash: parse_b256("expiringNonceHash", &descriptor.expiring_nonce_hash)?,
    };
    Ok(Call {
        to: TxKind::Call(swapper),
        value: U256::ZERO,
        input: Bytes::from(
            IMachineTokenSwapper::settleSessionCall {
                descriptor,
                recipient: merchant,
                targetToken: target_token,
                routeSalt: route_salt,
            }
            .abi_encode(),
        ),
    })
}

/// MACH, the canonical machine token on Tempo mainnet and Moderato.
pub const MACH: Address = address!("20c000000000000000000000f37de3740ADec032");
/// Canonical MACH swapper on Tempo mainnet.
pub const MACH_SWAPPER_MAINNET: Address = address!("F72E5107c32C655ffA7539a3C8e97B7C3cE16A3F");
/// Canonical MACH swapper on Tempo Moderato.
pub const MACH_SWAPPER_TESTNET: Address = address!("d05f8EdFBB54Da0d765C9fE9b2B3f7d2E3a8C466");

/// Tempo Wallet's MACH funding page, where a payer buys MACH on Tempo mainnet.
///
/// [`funding_url`] adds the payer's address and the amount to buy. MACH is
/// sold only on mainnet, so the link names chain ID 4217.
pub const MACH_FUNDING_URL: &str =
    "https://wallet.tempo.xyz/agent?action=fund&intent=mach&chainId=4217";

/// Decimals of MACH, which is worth 1 USD per whole token.
pub const MACH_DECIMALS: u8 = 6;

/// Builds the link where a payer buys MACH, or `None` on chains other than
/// Tempo mainnet, where MACH is not sold.
///
/// `address` is the payer, which the wallet requires to be signed in; pass it
/// only when known. `amount` is the MACH to buy in base units, rounded up to
/// whole cents since MACH is worth 1 USD; zero is left out.
///
/// ```
/// use mpp::protocol::methods::tempo::machine_token::{funding_url, MACH_FUNDING_URL};
///
/// assert_eq!(funding_url(4217, None, None).as_deref(), Some(MACH_FUNDING_URL));
/// assert_eq!(
///     funding_url(4217, None, Some(1_250_001)).unwrap(),
///     format!("{MACH_FUNDING_URL}&amount=1.26"),
/// );
/// assert!(funding_url(42431, None, None).is_none());
/// ```
pub fn funding_url(
    chain_id: u64,
    address: Option<Address>,
    amount: Option<u128>,
) -> Option<String> {
    if chain_id != CHAIN_ID {
        return None;
    }
    let mut url = MACH_FUNDING_URL.to_owned();
    if let Some(address) = address {
        url.push_str(&format!("&address={address}"));
    }
    if let Some(amount) = amount.filter(|amount| *amount > 0) {
        // 10^(6 - 2) base units per cent.
        let cents = amount.div_ceil(10_000);
        url.push_str(&format!("&amount={}.{:02}", cents / 100, cents % 100));
    }
    Some(url)
}

/// Formats MACH base units as a decimal amount with at least two places,
/// such as `0.25` or `1.000001`.
pub fn format_amount(amount: u128) -> String {
    let scale = 10u128.pow(u32::from(MACH_DECIMALS));
    let fraction = format!("{:06}", amount % scale);
    let fraction = fraction.trim_end_matches('0');
    format!("{}.{fraction:0<2}", amount / scale)
}

/// Returns the first MACH funding link (see [`funding_url`]) in `text`, such
/// as a problem's `detail`.
///
/// Only the parameters [`funding_url`] writes are kept: an `address` of 40 hex
/// digits, then an `amount` in dollars and cents. Anything else after the base
/// link ends it, so text around the link can't reshape it.
pub fn funding_url_in(text: &str) -> Option<&str> {
    fn take(rest: &str, prefix: &str, valid: impl Fn(&str) -> Option<usize>) -> usize {
        rest.strip_prefix(prefix)
            .and_then(valid)
            .map_or(0, |len| prefix.len() + len)
    }
    let start = text.find(MACH_FUNDING_URL)?;
    let mut end = start + MACH_FUNDING_URL.len();
    end += take(&text[end..], "&address=0x", |value| {
        let hex = value.bytes().take_while(u8::is_ascii_hexdigit).count();
        (hex == 40).then_some(40)
    });
    end += take(&text[end..], "&amount=", |value| {
        let whole = value.bytes().take_while(u8::is_ascii_digit).count();
        let cents = value[whole..].strip_prefix('.')?;
        (whole > 0
            && cents.len() >= 2
            && cents.as_bytes()[..2].iter().all(u8::is_ascii_digit)
            && !cents.as_bytes().get(2).is_some_and(u8::is_ascii_digit))
        .then_some(whole + 3)
    });
    Some(&text[start..end])
}

/// machineUSD on Tempo mainnet, used only by the legacy session route.
pub const MACHINE_TOKEN_MAINNET: Address = address!("20C0000000000000000000003793c39601711f19");
/// Canonical machineUSD swapper on Tempo mainnet.
pub const MACHINE_TOKEN_SWAPPER_MAINNET: Address =
    address!("C6D32f013E0fA3e83B63Dc680E99826761595732");
/// machineUSD on Tempo Moderato.
pub const MACHINE_TOKEN_TESTNET: Address = address!("20c000000000000000000000f85bbCa724044De0");
/// Canonical machineUSD swapper on Tempo Moderato.
pub const MACHINE_TOKEN_SWAPPER_TESTNET: Address =
    address!("07f1FE0467Ae01DE340024aa4b7DD9729b1c169b");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Deployment {
    token: Address,
    swapper: Address,
}

/// The exact canonical calls and settlement sender for a machine-token payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineTokenRoute {
    /// `approve` followed by `swapTo`.
    pub calls: [Call; 2],
    /// The swapper that emits the merchant-facing TIP-20 transfer.
    pub settlement_sender: Address,
    /// The single merchant transfer settled by the route.
    pub transfer: Transfer,
}

fn deployment(chain_id: u64) -> Option<Deployment> {
    match chain_id {
        CHAIN_ID => Some(Deployment {
            token: MACH,
            swapper: MACH_SWAPPER_MAINNET,
        }),
        MODERATO_CHAIN_ID => Some(Deployment {
            token: MACH,
            swapper: MACH_SWAPPER_TESTNET,
        }),
        _ => None,
    }
}

fn session_deployment(chain_id: u64) -> Option<Deployment> {
    match chain_id {
        CHAIN_ID => Some(Deployment {
            token: MACHINE_TOKEN_MAINNET,
            swapper: MACHINE_TOKEN_SWAPPER_MAINNET,
        }),
        MODERATO_CHAIN_ID => Some(Deployment {
            token: MACHINE_TOKEN_TESTNET,
            swapper: MACHINE_TOKEN_SWAPPER_TESTNET,
        }),
        _ => None,
    }
}

/// Returns the canonical machine token that funds charges on `chain_id`.
pub fn token(chain_id: u64) -> Option<Address> {
    deployment(chain_id).map(|deployment| deployment.token)
}

/// Returns whether a canonical machine-token route exists on `chain_id`.
pub fn is_supported(chain_id: u64) -> bool {
    deployment(chain_id).is_some()
}

/// Returns the trusted settlement sender for a supported chain.
pub fn settlement_sender(chain_id: u64) -> Option<Address> {
    deployment(chain_id).map(|deployment| deployment.swapper)
}

/// Build the canonical route for a compatible charge.
///
/// The route intentionally supports exactly one memo-bearing transfer. Split
/// payments and unbound transfers fall back to ordinary funding behavior.
pub fn route(
    chain_id: u64,
    currency: Address,
    transfers: &[Transfer],
) -> Option<MachineTokenRoute> {
    let deployment = deployment(chain_id)?;
    let transfer = match transfers {
        [transfer] if transfer.memo.is_some() => transfer.clone(),
        _ => return None,
    };
    let memo = transfer.memo?;
    let approve = Call {
        to: TxKind::Call(deployment.token),
        value: U256::ZERO,
        input: Bytes::from(
            ITIP20::approveCall {
                spender: deployment.swapper,
                amount: transfer.amount,
            }
            .abi_encode(),
        ),
    };
    let swap = Call {
        to: TxKind::Call(deployment.swapper),
        value: U256::ZERO,
        input: Bytes::from(
            IMachineTokenSwapper::swapToCall {
                inputToken: deployment.token,
                amount: transfer.amount,
                targetToken: currency,
                recipient: transfer.recipient,
                memo: memo.into(),
            }
            .abi_encode(),
        ),
    };

    Some(MachineTokenRoute {
        calls: [approve, swap],
        settlement_sender: deployment.swapper,
        transfer,
    })
}

/// Match only the exact canonical route for a charge.
pub fn match_route(
    calls: &[Call],
    chain_id: u64,
    currency: Address,
    transfers: &[Transfer],
) -> Option<MachineTokenRoute> {
    let transfer = match transfers {
        [transfer] => transfer.clone(),
        _ => return None,
    };
    let swap = calls.get(1)?;
    let decoded = IMachineTokenSwapper::swapToCall::abi_decode_raw(swap.input.get(4..)?).ok()?;
    let mut transfer_with_memo = transfer;
    if transfer_with_memo.memo.is_none() {
        transfer_with_memo.memo = Some(decoded.memo.0);
    }
    let expected = route(chain_id, currency, &[transfer_with_memo])?;
    if calls == expected.calls.as_slice() {
        Some(expected)
    } else {
        None
    }
}

/// Prefer machine-token funding when the payer has sufficient balance and the
/// complete route simulates successfully. Any failure falls back to the
/// client's existing funding behavior.
pub async fn find_route<P: Provider<tempo_alloy::TempoNetwork>>(
    provider: &P,
    account: Address,
    chain_id: u64,
    currency: Address,
    transfers: &[Transfer],
) -> Option<MachineTokenRoute> {
    let route = route(chain_id, currency, transfers)?;
    let token = match route.calls[0].to {
        TxKind::Call(token) => token,
        TxKind::Create => return None,
    };
    let mut request = TempoTransactionRequest {
        calls: route.calls.to_vec(),
        ..Default::default()
    };
    request.inner.from = Some(account);
    request.inner.chain_id = Some(chain_id);
    // Both reads gate the same decision, so issue them together.
    let token = ITIP20::new(token, provider);
    let balance = token.balanceOf(account);
    let (balance, simulation) = tokio::join!(balance.call(), provider.call(request));
    (balance.ok()? >= route.transfer.amount && simulation.is_ok()).then_some(route)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::sol_types::SolCall;

    fn transfer() -> Transfer {
        Transfer {
            amount: U256::from(1_000_000),
            recipient: Address::repeat_byte(0x22),
            memo: Some([0xab; 32]),
        }
    }

    #[test]
    fn funding_url_links_mainnet_only() {
        let payer = Address::repeat_byte(0x11);
        assert_eq!(
            funding_url(CHAIN_ID, None, None).as_deref(),
            Some(MACH_FUNDING_URL)
        );
        assert_eq!(
            funding_url(CHAIN_ID, Some(payer), Some(750_000)).unwrap(),
            format!("{MACH_FUNDING_URL}&address={payer}&amount=0.75")
        );
        assert_eq!(
            funding_url(CHAIN_ID, None, Some(1)).unwrap(),
            format!("{MACH_FUNDING_URL}&amount=0.01")
        );
        assert_eq!(
            funding_url(CHAIN_ID, None, Some(12_000_000)).unwrap(),
            format!("{MACH_FUNDING_URL}&amount=12.00")
        );
        assert_eq!(
            funding_url(CHAIN_ID, None, Some(0)).as_deref(),
            Some(MACH_FUNDING_URL)
        );
        assert!(funding_url(MODERATO_CHAIN_ID, Some(payer), Some(1)).is_none());
    }

    #[test]
    fn formats_amounts_and_finds_links() {
        assert_eq!(format_amount(0), "0.00");
        assert_eq!(format_amount(250_000), "0.25");
        assert_eq!(format_amount(1_000_001), "1.000001");
        assert_eq!(format_amount(12_000_000), "12.00");

        let url = funding_url(CHAIN_ID, Some(Address::repeat_byte(0x11)), Some(1)).unwrap();
        assert_eq!(
            funding_url_in(&format!("short; buy MACH at {url}.")),
            Some(url.as_str())
        );
        assert_eq!(
            funding_url_in(&format!("(buy MACH: {url}) more")),
            Some(url.as_str())
        );
        assert_eq!(funding_url_in("no link here"), None);
        // Text that isn't a parameter the link builder writes ends the link.
        assert_eq!(
            funding_url_in(&format!("{MACH_FUNDING_URL}&address=evil&amount=1.00")),
            Some(MACH_FUNDING_URL)
        );
        assert_eq!(
            funding_url_in(&format!("{url}&redirect=https://example.com")),
            Some(url.as_str())
        );
    }

    #[test]
    fn builds_and_matches_exact_canonical_route() {
        let currency = Address::repeat_byte(0x33);
        let route = route(MODERATO_CHAIN_ID, currency, &[transfer()]).unwrap();

        assert_eq!(route.calls[0].to, TxKind::Call(MACH));
        assert_eq!(route.calls[1].to, TxKind::Call(MACH_SWAPPER_TESTNET));
        assert_eq!(
            match_route(&route.calls, MODERATO_CHAIN_ID, currency, &[transfer()]),
            Some(route.clone())
        );

        let approve = ITIP20::approveCall::abi_decode_raw(&route.calls[0].input[4..]).unwrap();
        assert_eq!(approve.spender, MACH_SWAPPER_TESTNET);
        assert_eq!(approve.amount, U256::from(1_000_000));
        let swap =
            IMachineTokenSwapper::swapToCall::abi_decode_raw(&route.calls[1].input[4..]).unwrap();
        assert_eq!(swap.inputToken, MACH);
        assert_eq!(token(CHAIN_ID), Some(MACH));
        assert_eq!(settlement_sender(CHAIN_ID), Some(MACH_SWAPPER_MAINNET));
        assert_eq!(
            session_addresses(CHAIN_ID),
            Some((MACHINE_TOKEN_MAINNET, MACHINE_TOKEN_SWAPPER_MAINNET))
        );
        assert_eq!(swap.targetToken, currency);
        assert_eq!(swap.recipient, Address::repeat_byte(0x22));
    }

    #[test]
    fn rejects_mutated_and_incompatible_routes() {
        let currency = Address::repeat_byte(0x33);
        let canonical = route(MODERATO_CHAIN_ID, currency, &[transfer()]).unwrap();
        let mut mutated = canonical.calls.to_vec();
        mutated[0].value = U256::from(1);

        assert!(match_route(&mutated, MODERATO_CHAIN_ID, currency, &[transfer()]).is_none());
        assert!(route(1, currency, &[transfer()]).is_none());
        assert!(route(MODERATO_CHAIN_ID, currency, &[]).is_none());
        let mut without_memo = transfer();
        without_memo.memo = None;
        assert!(route(MODERATO_CHAIN_ID, currency, &[without_memo]).is_none());
        assert!(route(MODERATO_CHAIN_ID, currency, &[transfer(), transfer()]).is_none());
    }

    #[test]
    fn encodes_session_settlement_with_the_full_bound_descriptor() {
        let descriptor = super::super::session::ChannelDescriptor {
            payer: Address::repeat_byte(0x11).to_string(),
            payee: MACHINE_TOKEN_SWAPPER_TESTNET.to_string(),
            operator: Address::repeat_byte(0x22).to_string(),
            token: MACHINE_TOKEN_TESTNET.to_string(),
            salt: alloy::primitives::B256::repeat_byte(0x33).to_string(),
            authorized_signer: Address::repeat_byte(0x44).to_string(),
            expiring_nonce_hash: alloy::primitives::B256::repeat_byte(0x55).to_string(),
        };
        let route = super::super::session::SettlementRoute {
            adapter: MACHINE_TOKEN_SWAPPER_TESTNET.to_string(),
            recipient: Address::repeat_byte(0x22).to_string(),
            target_token: Address::repeat_byte(0x66).to_string(),
            route_salt: alloy::primitives::B256::repeat_byte(0x77).to_string(),
        };
        let expected_salt = compute_session_salt(
            Address::repeat_byte(0x22),
            Address::repeat_byte(0x66),
            alloy::primitives::B256::repeat_byte(0x77),
        );
        let descriptor = super::super::session::ChannelDescriptor {
            salt: expected_salt.to_string(),
            ..descriptor
        };
        let call = settle_session_call(MODERATO_CHAIN_ID, &descriptor, &route).unwrap();

        assert_eq!(call.to, TxKind::Call(MACHINE_TOKEN_SWAPPER_TESTNET));
        let decoded = IMachineTokenSwapper::settleSessionCall::abi_decode(&call.input).unwrap();
        assert_eq!(decoded.descriptor.payee, MACHINE_TOKEN_SWAPPER_TESTNET);
        assert_eq!(decoded.descriptor.operator, Address::repeat_byte(0x22));
        assert_eq!(decoded.descriptor.token, MACHINE_TOKEN_TESTNET);
        assert_eq!(decoded.recipient, Address::repeat_byte(0x22));
        assert_eq!(decoded.targetToken, Address::repeat_byte(0x66));
    }

    #[test]
    fn rejects_session_settlement_on_an_unsupported_chain() {
        let descriptor = super::super::session::ChannelDescriptor {
            payer: Address::ZERO.to_string(),
            payee: Address::ZERO.to_string(),
            operator: Address::ZERO.to_string(),
            token: Address::ZERO.to_string(),
            salt: alloy::primitives::B256::ZERO.to_string(),
            authorized_signer: Address::ZERO.to_string(),
            expiring_nonce_hash: alloy::primitives::B256::ZERO.to_string(),
        };
        let route = super::super::session::SettlementRoute {
            adapter: Address::ZERO.to_string(),
            recipient: Address::ZERO.to_string(),
            target_token: Address::ZERO.to_string(),
            route_salt: alloy::primitives::B256::ZERO.to_string(),
        };
        assert!(settle_session_call(1, &descriptor, &route).is_err());
    }

    #[tokio::test]
    async fn finds_a_funded_route_after_successful_simulation() {
        use alloy::providers::{mock::Asserter, ProviderBuilder};

        let asserter = Asserter::new();
        asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
            &U256::from(1_000_000),
        )));
        asserter.push_success(&Bytes::new());
        let provider = ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);

        let found = find_route(
            &provider,
            Address::repeat_byte(0x11),
            MODERATO_CHAIN_ID,
            Address::repeat_byte(0x33),
            &[transfer()],
        )
        .await;

        assert!(found.is_some());
    }

    #[tokio::test]
    async fn falls_back_when_machine_token_balance_is_insufficient() {
        use alloy::providers::{mock::Asserter, ProviderBuilder};

        let asserter = Asserter::new();
        asserter.push_success(&Bytes::from(ITIP20::balanceOfCall::abi_encode_returns(
            &U256::from(999_999),
        )));
        let provider = ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(asserter);

        let found = find_route(
            &provider,
            Address::repeat_byte(0x11),
            MODERATO_CHAIN_ID,
            Address::repeat_byte(0x33),
            &[transfer()],
        )
        .await;

        assert!(found.is_none());
    }
}
