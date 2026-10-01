//! Amount parsing.
//!
//! - `ChargeRequest::parse_amount` and `SessionRequest::parse_amount` agree.
//! - `parse_units` never panics, returns a canonical base-unit integer
//!   (`0|[1-9][0-9]*`), and one more decimal multiplies the result by ten.
//! - With `--features tempo`: the `u128` and `U256` parsers agree, and `get_transfers` conserves the amount: the transfers sum to
//!   the total, none is zero, and the primary recipient comes first.
//! - With `--features strict-amounts`: every parser rejects anything but
//!   `0|[1-9][0-9]*`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::{parse_units, ChargeRequest, SessionRequest};

fuzz_target!(|input: (&str, u8, Vec<(&str, [u8; 20])>)| {
    let (amount, decimals, splits) = input;

    let charge = ChargeRequest {
        amount: amount.to_owned(),
        ..Default::default()
    };
    let session = SessionRequest {
        amount: amount.to_owned(),
        ..Default::default()
    };
    let parsed = charge.parse_amount().ok();
    assert_eq!(parsed, session.parse_amount().ok());

    let digits = !amount.is_empty() && amount.bytes().all(|b| b.is_ascii_digit());
    if cfg!(feature = "strict-amounts") {
        assert!(
            parsed.is_none() || is_canonical(amount),
            "u128 accepts {amount:?}"
        );
    }

    let decimals = decimals.min(u8::MAX - 1);
    if let Ok(units) = parse_units(amount, decimals) {
        assert!(is_canonical(&units), "{units:?}");
        if decimals == 0 && digits {
            assert_eq!(units.parse::<u128>().ok(), parsed);
        }
        let scaled = parse_units(amount, decimals + 1).expect("one more decimal still fits");
        let expected = if units == "0" {
            units
        } else {
            format!("{units}0")
        };
        assert_eq!(scaled, expected);
    }

    #[cfg(feature = "tempo")]
    tempo::check(&charge, parsed, &splits);
    #[cfg(not(feature = "tempo"))]
    let _ = splits;
});

/// The amount grammar of the charge intent: `0|[1-9][0-9]*`.
fn is_canonical(amount: &str) -> bool {
    !amount.is_empty()
        && amount.bytes().all(|b| b.is_ascii_digit())
        && (amount == "0" || !amount.starts_with('0'))
}

#[cfg(feature = "tempo")]
mod tempo {
    use super::is_canonical;
    use mpp::protocol::methods::tempo::{get_transfers, transfers::MAX_SPLITS, Split};
    use mpp::{Address, ChargeRequest, U256};

    pub fn check(charge: &ChargeRequest, parsed: Option<u128>, splits: &[(&str, [u8; 20])]) {
        let wide = charge.parse_amount_u256().ok();
        match wide {
            Some(wide) if wide <= U256::from(u128::MAX) => {
                assert_eq!(parsed.map(U256::from), Some(wide));
            }
            _ => assert_eq!(parsed, None),
        }
        if cfg!(feature = "strict-amounts") {
            let amount = &charge.amount;
            assert!(
                wide.is_none() || is_canonical(amount),
                "U256 accepts {amount:?}"
            );
        }

        let Some(total) = wide else { return };
        let recipient = Address::repeat_byte(0x11);
        let memo = Some([0x22; 32]);
        let splits: Vec<Split> = splits
            .iter()
            .map(|(amount, recipient)| Split {
                amount: (*amount).to_owned(),
                memo: None,
                recipient: Address::from(*recipient).to_string(),
            })
            .collect();
        let splits = (!splits.is_empty()).then_some(splits.as_slice());

        let Ok(transfers) = get_transfers(total, recipient, memo, splits) else {
            return;
        };
        assert!(transfers.len() <= 1 + MAX_SPLITS);
        assert_eq!(transfers.len(), 1 + splits.map_or(0, <[Split]>::len));
        assert_eq!(
            (transfers[0].recipient, transfers[0].memo),
            (recipient, memo)
        );
        let sum = transfers
            .iter()
            .try_fold(U256::ZERO, |sum, transfer| sum.checked_add(transfer.amount));
        assert_eq!(sum, Some(total));
        // A zero total is a valid charge (proof flow); it cannot be split.
        assert!(transfers.iter().all(|t| !t.amount.is_zero()) || total.is_zero());
    }
}
