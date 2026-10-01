//! `Accept-Payment` request header parsing, serialization, and ranking.
//!
//! Clients send `Accept-Payment: tempo/charge, stripe/charge;q=0.5` to
//! advertise which payment methods they support and in what priority.
//! Servers use [`rank`] to reorder offered challenges by client preference.
//!
//! The format mirrors HTTP content-negotiation headers (`Accept`,
//! `Accept-Language`) with wildcard and quality-value support.
//!
//! # Header syntax
//!
//! ```text
//! Accept-Payment: <method>/<intent>[;q=<qvalue>], ...
//! ```
//!
//! - `method` and `intent` are lowercase `[a-z0-9-]+` or `*` (wildcard);
//!   `method` may also contain `:` and `_`.
//! - `q` is an HTTP qvalue: `0` or `1`, optionally followed by `.` and up to
//!   3 decimal places (`0.0..=1.0`). The parameter name is case-insensitive.
//! - Omitted `q` defaults to `1.0`.
//! - `q=0` means explicit opt-out.
//!
//! # Examples
//!
//! ```
//! use mpp::protocol::core::accept_payment::{parse, serialize, rank, Entry, HasMethodIntent};
//!
//! let entries = parse("tempo/charge, stripe/charge;q=0.5").unwrap();
//! assert_eq!(entries.len(), 2);
//! assert_eq!(entries[0].q, 1.0);
//! assert_eq!(entries[1].q, 0.5);
//!
//! let header = serialize(&entries);
//! assert_eq!(header, "tempo/charge, stripe/charge;q=0.5");
//!
//! // Rank server offers by client preferences
//! struct Offer { method: String, intent: String }
//! impl HasMethodIntent for Offer {
//!     fn method(&self) -> &str { &self.method }
//!     fn intent(&self) -> &str { &self.intent }
//! }
//!
//! let offers = vec![
//!     Offer { method: "stripe".into(), intent: "charge".into() },
//!     Offer { method: "tempo".into(), intent: "charge".into() },
//! ];
//! let ranked = rank(&offers, &entries);
//! assert_eq!(ranked[0].method(), "tempo");  // q=1.0 beats q=0.5
//! ```

use crate::error::MppError;

/// HTTP header name.
pub const ACCEPT_PAYMENT_HEADER: &str = "Accept-Payment";

/// A parsed entry from the `Accept-Payment` header.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// Method name or `"*"` for wildcard.
    pub method: String,
    /// Intent name or `"*"` for wildcard.
    pub intent: String,
    /// Quality value `0.0..=1.0`. Default `1.0`.
    pub q: f32,
    /// Position in the header (used for tie-breaking).
    pub index: usize,
}

/// Trait for types that expose a method/intent pair (used by [`rank`]).
pub trait HasMethodIntent {
    fn method(&self) -> &str;
    fn intent(&self) -> &str;
}

impl<T: HasMethodIntent> HasMethodIntent for &T {
    fn method(&self) -> &str {
        (*self).method()
    }
    fn intent(&self) -> &str {
        (*self).intent()
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse an `Accept-Payment` header value into entries.
///
/// # Errors
///
/// Returns [`MppError::BadRequest`] if the header is empty or contains
/// malformed entries.
pub fn parse(header: &str) -> Result<Vec<Entry>, MppError> {
    let parts: Vec<&str> = header
        .split(',')
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        return Err(MppError::bad_request("Accept-Payment header is empty"));
    }
    parts
        .iter()
        .enumerate()
        .map(|(i, part)| parse_entry(part, i))
        .collect()
}

fn parse_entry(part: &str, index: usize) -> Result<Entry, MppError> {
    // Split on ';' to separate "method/intent" from params
    let (token, params_str) = match part.find(';') {
        Some(pos) => (part[..pos].trim(), Some(part[pos + 1..].trim())),
        None => (part.trim(), None),
    };

    // Split token on '/'
    let slash = token
        .find('/')
        .ok_or_else(|| MppError::bad_request(format!("invalid Accept-Payment entry: {part}")))?;
    let method = &token[..slash];
    let intent = &token[slash + 1..];

    if method.is_empty() || intent.is_empty() {
        return Err(MppError::bad_request(format!(
            "invalid Accept-Payment entry: {part}"
        )));
    }

    validate_token(method, true, part)?;
    validate_token(intent, false, part)?;

    let q = match params_str {
        Some(ps) => parse_q_param(ps, part)?,
        None => 1.0,
    };

    Ok(Entry {
        method: method.to_string(),
        intent: intent.to_string(),
        q,
        index,
    })
}

/// Validate that a token is `[a-z0-9-]+` or `*`. Method tokens may also
/// contain `:` and `_`, which the method name grammar allows.
fn validate_token(token: &str, is_method: bool, entry: &str) -> Result<(), MppError> {
    if token == "*" {
        return Ok(());
    }
    if token.chars().all(|c| {
        c.is_ascii_lowercase()
            || c.is_ascii_digit()
            || c == '-'
            || (is_method && matches!(c, ':' | '_'))
    }) {
        Ok(())
    } else {
        Err(MppError::bad_request(format!(
            "invalid token in Accept-Payment entry: {entry}"
        )))
    }
}

/// Parse `q=<value>` from params string.
/// Last `q` wins (matches mppx behavior). Spaces around `=` are tolerated.
/// The parameter name is case-insensitive, other parameters are ignored.
fn parse_q_param(params: &str, entry: &str) -> Result<f32, MppError> {
    let mut q = 1.0;
    for param in params.split(';') {
        let param = param.trim();
        if param.is_empty() {
            continue;
        }
        // Split on '=' tolerating spaces: "q = 0.5" → name="q", value="0.5"
        let (name, value) = param
            .split_once('=')
            .map(|(name, value)| (name.trim(), value.trim()))
            .filter(|(name, value)| {
                is_param_name(name) && !value.is_empty() && !value.contains(char::is_whitespace)
            })
            .ok_or_else(|| {
                MppError::bad_request(format!(
                    "invalid parameter in Accept-Payment entry: {entry}"
                ))
            })?;
        if name.eq_ignore_ascii_case("q") {
            q = parse_q_value(value, entry)?;
        }
    }
    Ok(q)
}

fn is_param_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Parse an RFC 9110 `qvalue`: `0` or `1`, optionally followed by `.` and up
/// to three digits (only zeros after `1`).
fn parse_q_value(val: &str, entry: &str) -> Result<f32, MppError> {
    let (int, frac) = val.split_once('.').unwrap_or((val, ""));
    let valid = frac.len() <= 3
        && match int {
            "0" => frac.bytes().all(|b| b.is_ascii_digit()),
            "1" => frac.bytes().all(|b| b == b'0'),
            _ => false,
        };
    if !valid {
        return Err(MppError::bad_request(format!(
            "invalid q-value in: {entry}"
        )));
    }
    if int == "1" {
        return Ok(1.0);
    }
    let thousandths = (0..3).fold(0u16, |acc, i| {
        acc * 10 + u16::from(frac.as_bytes().get(i).map_or(0, |b| b - b'0'))
    });
    Ok(f32::from(thousandths) / 1000.0)
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serialize entries into an `Accept-Payment` header value.
pub fn serialize(entries: &[Entry]) -> String {
    entries
        .iter()
        .map(|e| {
            let value = format!("{}/{}", e.method, e.intent);
            if (e.q - 1.0).abs() < f32::EPSILON {
                value
            } else {
                format!("{};q={}", value, format_q(e.q))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_q(q: f32) -> String {
    let s = format!("{:.3}", q);
    let s = s.trim_end_matches('0');
    let s = s.trim_end_matches('.');
    s.to_string()
}

/// Build an `Accept-Payment` header value from a list of supported
/// `(method, intent)` pairs. All entries get `q=1.0`.
pub fn from_methods(methods: &[(&str, &str)]) -> String {
    let entries: Vec<Entry> = methods
        .iter()
        .enumerate()
        .map(|(i, (m, intent))| Entry {
            method: m.to_string(),
            intent: intent.to_string(),
            q: 1.0,
            index: i,
        })
        .collect();
    serialize(&entries)
}

impl HasMethodIntent for super::PaymentChallenge {
    fn method(&self) -> &str {
        self.method.as_str()
    }
    fn intent(&self) -> &str {
        self.intent.as_str()
    }
}

// ---------------------------------------------------------------------------
// Ranking
// ---------------------------------------------------------------------------

/// Rank server-offered payment methods by client preferences.
///
/// Returns references to the offers, sorted by best match. Offers matched
/// only by `q=0` preferences (explicit opt-out) are excluded.
///
/// The algorithm matches `mppx`'s `AcceptPayment.rank()`:
/// 1. For each offer, find the best-matching preference (highest specificity,
///    then highest q, then earliest declaration index).
/// 2. Exclude offers where the best match has `q=0`.
/// 3. Sort remaining by `(q DESC, offer_index ASC)`.
pub fn rank<'a, T: HasMethodIntent>(offers: &'a [T], preferences: &[Entry]) -> Vec<&'a T> {
    let mut scored: Vec<(usize, f32, &T)> = offers
        .iter()
        .enumerate()
        .filter_map(|(offer_idx, offer)| {
            let best = best_match(offer, preferences)?;
            if best.q <= 0.0 {
                None
            } else {
                Some((offer_idx, best.q, offer))
            }
        })
        .collect();

    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
    });

    scored.into_iter().map(|(_, _, offer)| offer).collect()
}

/// Select the best challenge from a list, given client preferences.
///
/// Returns `None` if no offer matches or all matches are `q=0`.
pub fn select<'a, T: HasMethodIntent>(offers: &'a [T], preferences: &[Entry]) -> Option<&'a T> {
    rank(offers, preferences).into_iter().next()
}

#[derive(Debug)]
struct Match {
    q: f32,
    specificity: u8,
    index: usize,
}

fn best_match<T: HasMethodIntent>(offer: &T, preferences: &[Entry]) -> Option<Match> {
    let mut best: Option<Match> = None;

    for pref in preferences {
        if !matches_entry(offer, pref) {
            continue;
        }
        let candidate = Match {
            q: pref.q,
            specificity: specificity(pref),
            index: pref.index,
        };
        let dominated = match &best {
            None => true,
            Some(b) => {
                candidate.specificity > b.specificity
                    || (candidate.specificity == b.specificity && candidate.q > b.q)
                    || (candidate.specificity == b.specificity
                        && (candidate.q - b.q).abs() < f32::EPSILON
                        && candidate.index < b.index)
            }
        };
        if dominated {
            best = Some(candidate);
        }
    }

    best
}

/// Specificity score: exact=2, partial-wildcard=1, full-wildcard=0.
fn specificity(entry: &Entry) -> u8 {
    let m = u8::from(entry.method != "*");
    let i = u8::from(entry.intent != "*");
    m + i
}

fn matches_entry<T: HasMethodIntent>(offer: &T, pref: &Entry) -> bool {
    (pref.method == "*" || pref.method == offer.method())
        && (pref.intent == "*" || pref.intent == offer.intent())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::MethodName;

    struct Offer {
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
    fn offer(m: &str, i: &str) -> Offer {
        Offer {
            method: m.into(),
            intent: i.into(),
        }
    }

    #[test]
    fn parse_valid_entries() {
        // Single, multiple, wildcards, boundary q-values
        let e = parse("tempo/charge").unwrap();
        assert_eq!(
            (
                e[0].method.as_str(),
                e[0].intent.as_str(),
                e[0].q,
                e[0].index
            ),
            ("tempo", "charge", 1.0, 0)
        );

        let e = parse("tempo/charge, stripe/charge;q=0.5").unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].q, e[1].q), (1.0, 0.5));

        let e = parse("tempo/*, */session;q=0").unwrap();
        assert_eq!(
            (e[0].intent.as_str(), e[1].method.as_str(), e[1].q),
            ("*", "*", 0.0)
        );

        let e = parse("a/b;q=0, c/d;q=1, e/f;q=0.001").unwrap();
        assert_eq!((e[0].q, e[1].q, e[2].q), (0.0, 1.0, 0.001));
    }

    #[test]
    fn parse_rejects_invalid() {
        assert!(parse("").is_err()); // empty
        assert!(parse("   ").is_err()); // whitespace
        assert!(parse("tempo").is_err()); // no slash
        assert!(parse("Tempo/charge").is_err()); // uppercase
        assert!(parse("tempo/charge;q=1.5").is_err()); // q > 1
        assert!(parse("tempo/charge;q=-0.1").is_err()); // q < 0
        assert!(parse("tempo/charge;q=0.1234").is_err()); // >3 decimals
    }

    #[test]
    fn parse_rejects_non_http_qvalues() {
        for q in [
            ".5", "1e-1", "+0.5", "0.5f", "01", "1.001", "inf", "NaN", "",
        ] {
            assert!(parse(&format!("tempo/charge;q={q}")).is_err(), "q={q}");
        }
        for (q, expected) in [("0.", 0.0), ("1.", 1.0), ("1.000", 1.0), ("0.25", 0.25)] {
            let e = parse(&format!("tempo/charge;q={q}")).unwrap();
            assert_eq!(e[0].q, expected, "q={q}");
        }
    }

    #[test]
    fn parse_q_name_is_case_insensitive() {
        let prefs = parse("tempo/charge;Q=0, stripe/charge").unwrap();
        assert_eq!(prefs[0].q, 0.0);

        let offers = vec![offer("tempo", "charge"), offer("stripe", "charge")];
        let ranked = rank(&offers, &prefs);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].method(), "stripe");
    }

    #[test]
    fn parse_rejects_parameter_without_value() {
        assert!(parse("tempo/charge;q").is_err());
        assert!(parse("tempo/charge;q=").is_err());
        assert!(parse("tempo/charge;=0.5").is_err());
        // Unknown well-formed parameters are ignored.
        assert_eq!(parse("tempo/charge;foo=bar;q=0.5").unwrap()[0].q, 0.5);
    }

    #[test]
    fn parse_accepts_method_name_grammar() {
        let e = parse("eip155:8453_usdc/charge;q=0.5").unwrap();
        assert_eq!(e[0].method, "eip155:8453_usdc");
        assert!(MethodName::new(e[0].method.as_str()).is_valid());

        // The intent token grammar has neither.
        assert!(parse("tempo/char:ge").is_err());
        assert!(parse("tempo/char_ge").is_err());
    }

    #[test]
    fn parse_duplicate_q_last_wins() {
        let e = parse("tempo/charge;q=0.5;q=0.8").unwrap();
        assert_eq!(e[0].q, 0.8);
    }

    #[test]
    fn parse_spaces_around_equals() {
        let e = parse("tempo/charge;q = 0.5").unwrap();
        assert_eq!(e[0].q, 0.5);

        let e = parse("tempo/charge;q= 0.5").unwrap();
        assert_eq!(e[0].q, 0.5);

        let e = parse("tempo/charge; q=0.5").unwrap();
        assert_eq!(e[0].q, 0.5);
    }

    #[test]
    fn serialize_and_round_trip() {
        // q=1 omitted, q<1 included, trailing zeros stripped
        let header = "tempo/charge, stripe/charge;q=0.5, */session;q=0";
        let entries = parse(header).unwrap();
        assert_eq!(serialize(&entries), header);

        assert_eq!(
            from_methods(&[("tempo", "charge"), ("stripe", "charge")]),
            "tempo/charge, stripe/charge"
        );

        // Trailing zeros: 0.1 not 0.100
        let e = vec![Entry {
            method: "a".into(),
            intent: "b".into(),
            q: 0.1,
            index: 0,
        }];
        assert!(serialize(&e).contains("q=0.1") && !serialize(&e).contains("q=0.100"));
    }

    #[test]
    fn rank_by_q_and_excludes_q0() {
        let offers = vec![offer("stripe", "charge"), offer("tempo", "charge")];
        let ranked = rank(
            &offers,
            &parse("tempo/charge, stripe/charge;q=0.5").unwrap(),
        );
        assert_eq!(
            (ranked[0].method(), ranked[1].method()),
            ("tempo", "stripe")
        );

        // q=0 excluded
        let offers = vec![offer("tempo", "charge"), offer("stripe", "charge")];
        let ranked = rank(&offers, &parse("tempo/charge;q=0, stripe/charge").unwrap());
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].method(), "stripe");
    }

    #[test]
    fn rank_specificity_and_wildcards() {
        // Exact match (specificity=2) beats wildcard even with lower q
        let offers = vec![offer("stripe", "charge"), offer("tempo", "charge")];
        let ranked = rank(
            &offers,
            &parse("*/charge;q=0.3, stripe/charge;q=0.8").unwrap(),
        );
        assert_eq!(
            (ranked[0].method(), ranked[1].method()),
            ("stripe", "tempo")
        );

        // tempo/* at q=1 but tempo/charge;q=0 — specificity wins, charge excluded
        let offers = vec![offer("tempo", "charge"), offer("tempo", "session")];
        let ranked = rank(&offers, &parse("tempo/*;q=1, tempo/charge;q=0").unwrap());
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].intent(), "session");
    }

    #[test]
    fn rank_preserves_offer_order_and_handles_edge_cases() {
        // Tie → preserve original offer order
        let offers = vec![offer("a", "charge"), offer("b", "charge")];
        let ranked = rank(&offers, &parse("*/charge").unwrap());
        assert_eq!((ranked[0].method(), ranked[1].method()), ("a", "b"));

        // No match → empty
        assert!(rank(
            &[offer("lightning", "charge")],
            &parse("tempo/charge").unwrap()
        )
        .is_empty());

        // Empty preferences → empty
        assert!(rank(&[offer("tempo", "charge")], &[]).is_empty());
    }

    #[test]
    fn select_best_and_none() {
        let offers = vec![offer("stripe", "charge"), offer("tempo", "charge")];
        assert_eq!(
            select(
                &offers,
                &parse("tempo/charge, stripe/charge;q=0.5").unwrap()
            )
            .unwrap()
            .method(),
            "tempo"
        );
        assert!(select(
            &[offer("tempo", "charge")],
            &parse("tempo/charge;q=0").unwrap()
        )
        .is_none());
    }

    #[test]
    fn declaration_index_tiebreak() {
        let offers = vec![offer("a", "charge")];
        let prefs = vec![
            Entry {
                method: "*".into(),
                intent: "charge".into(),
                q: 0.5,
                index: 0,
            },
            Entry {
                method: "*".into(),
                intent: "charge".into(),
                q: 0.5,
                index: 1,
            },
        ];
        assert_eq!(rank(&offers, &prefs).len(), 1);
    }
}
