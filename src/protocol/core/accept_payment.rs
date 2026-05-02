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
//! - `method` and `intent` are lowercase `[a-z0-9-]+` or `*` (wildcard).
//! - `q` is a float in `0.0..=1.0` with up to 3 decimal places.
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

    validate_token(method, part)?;
    validate_token(intent, part)?;

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

/// Validate that a token is `[a-z0-9-]+` or `*`.
fn validate_token(token: &str, entry: &str) -> Result<(), MppError> {
    if token == "*" {
        return Ok(());
    }
    if token
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        Ok(())
    } else {
        Err(MppError::bad_request(format!(
            "invalid token in Accept-Payment entry: {entry}"
        )))
    }
}

/// Parse `q=<value>` from params string.
/// Last `q` wins (matches mppx behavior). Spaces around `=` are tolerated.
fn parse_q_param(params: &str, entry: &str) -> Result<f32, MppError> {
    let mut q = 1.0;
    for param in params.split(';') {
        let param = param.trim();
        // Split on '=' tolerating spaces: "q = 0.5" → name="q", value="0.5"
        if let Some(eq_pos) = param.find('=') {
            let name = param[..eq_pos].trim();
            let value = param[eq_pos + 1..].trim();
            if name == "q" {
                q = parse_q_value(value, entry)?;
            }
        }
    }
    Ok(q)
}

fn parse_q_value(val: &str, entry: &str) -> Result<f32, MppError> {
    let q: f32 = val
        .parse()
        .map_err(|_| MppError::bad_request(format!("invalid q-value in: {entry}")))?;
    if !(0.0..=1.0).contains(&q) {
        return Err(MppError::bad_request(format!(
            "q-value out of range in: {entry}"
        )));
    }
    // Validate max 3 decimal places
    if let Some(dot) = val.find('.') {
        if val[dot + 1..].len() > 3 {
            return Err(MppError::bad_request(format!(
                "q-value has more than 3 decimal places in: {entry}"
            )));
        }
    }
    Ok(q)
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
