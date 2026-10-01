//! `Accept-Payment` parsing, serialization and ranking.
//!
//! - `parse` never panics; accepted entries are well-formed (`[a-z0-9-]+` or
//!   `*` tokens, `0 <= q <= 1`, indices in header order).
//! - `parse(serialize(entries))` gives the same entries.
//! - `rank` returns offers without duplicates, drops offers that match
//!   nothing or whose best match is `q=0`, and orders the rest by `q`
//!   descending, then by offer order. The best match is the most specific
//!   preference, then the highest `q`, then the first declared. Checked
//!   against a direct transcription of that rule.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::accept_payment::{parse, rank, select, serialize, Entry, HasMethodIntent};

#[derive(Debug, PartialEq)]
struct Offer {
    id: usize,
    method: String,
    intent: String,
}

impl HasMethodIntent for Offer {
    fn method(&self) -> &str {
        &self.method
    }
    fn intent(&self) -> &str {
        &self.intent
    }
}

fuzz_target!(|header: &str| {
    let Ok(entries) = parse(header) else { return };
    assert!(!entries.is_empty());
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.index, index);
        assert!((0.0..=1.0).contains(&entry.q));
        assert!(
            is_token(&entry.method) && is_token(&entry.intent),
            "{entry:?}"
        );
    }

    // The serializer writes three decimals. `parse` also accepts exponent
    // forms such as `q=1e-5` (which mppx and RFC 9110 reject); those do not
    // survive and would flip to an opt-out, so they are left out here.
    if entries.iter().all(|entry| is_qvalue(entry.q)) {
        assert_eq!(parse(&serialize(&entries)).unwrap(), entries);
    }

    // Offers: everything the header names, plus offers it does not name.
    let mut offers = Vec::new();
    for (method, intent) in entries
        .iter()
        .map(|entry| (entry.method.as_str(), entry.intent.as_str()))
        .chain([
            ("tempo", "charge"),
            ("tempo", "session"),
            ("stripe", "charge"),
        ])
    {
        let id = offers.len();
        offers.push(Offer {
            id,
            method: method.replace('*', "other"),
            intent: intent.replace('*', "other"),
        });
    }

    let ranked: Vec<usize> = rank(&offers, &entries)
        .iter()
        .map(|offer| offer.id)
        .collect();
    assert_eq!(ranked, reference_rank(&offers, &entries));
    assert_eq!(
        select(&offers, &entries).map(|offer| offer.id),
        ranked.first().copied()
    );
});

fn is_token(token: &str) -> bool {
    token == "*"
        || (!token.is_empty()
            && token
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

fn is_qvalue(q: f32) -> bool {
    (q * 1000.0).round() / 1000.0 == q
}

fn reference_rank(offers: &[Offer], entries: &[Entry]) -> Vec<usize> {
    let mut scored: Vec<(usize, f32)> = offers
        .iter()
        .filter_map(|offer| {
            let best = entries
                .iter()
                .filter(|entry| {
                    (entry.method == "*" || entry.method == offer.method)
                        && (entry.intent == "*" || entry.intent == offer.intent)
                })
                .max_by(|a, b| {
                    let specificity =
                        |e: &Entry| usize::from(e.method != "*") + usize::from(e.intent != "*");
                    specificity(a)
                        .cmp(&specificity(b))
                        .then(a.q.partial_cmp(&b.q).expect("q is never NaN"))
                        .then(b.index.cmp(&a.index))
                })?;
            (best.q > 0.0).then_some((offer.id, best.q))
        })
        .collect();
    // Stable, so ties keep offer order.
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).expect("q is never NaN"));
    scored.into_iter().map(|(id, _)| id).collect()
}
