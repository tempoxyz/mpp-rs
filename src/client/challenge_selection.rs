use crate::error::MppError;
use crate::protocol::core::accept_payment::{self, Entry};
use crate::protocol::core::PaymentChallenge;

#[derive(Debug, Clone)]
pub(crate) enum ChallengeSelectionError {
    Expired(Box<PaymentChallenge>),
    NoSupportedChallenge(String),
}

pub(crate) fn expired_payment_error(challenge: &PaymentChallenge) -> MppError {
    MppError::PaymentExpired(challenge.expires.clone())
}

pub(crate) fn select_supported_challenge<'a>(
    challenges: &'a [PaymentChallenge],
    ranking_accept: Option<&str>,
    mut supports: impl FnMut(&PaymentChallenge) -> bool,
    mut select: impl FnMut(&[&'a PaymentChallenge]) -> Option<&'a PaymentChallenge>,
) -> Result<&'a PaymentChallenge, ChallengeSelectionError> {
    let ranking_preferences = ranking_accept.and_then(|header| accept_payment::parse(header).ok());
    let supported: Vec<_> = challenges
        .iter()
        .filter(|challenge| supports(challenge))
        .collect();
    let payable: Vec<_> = supported
        .iter()
        .copied()
        .filter(|challenge| !challenge.is_expired())
        .collect();

    let payable = rank_challenges(&payable, ranking_preferences.as_deref());
    if !payable.is_empty() {
        return select(&payable).ok_or_else(|| {
            ChallengeSelectionError::NoSupportedChallenge(no_method_found(challenges))
        });
    }

    let supported = rank_challenges(&supported, ranking_preferences.as_deref());
    if let Some(challenge) = select(&supported) {
        return Err(ChallengeSelectionError::Expired(Box::new(
            challenge.clone(),
        )));
    }

    Err(ChallengeSelectionError::NoSupportedChallenge(
        no_method_found(challenges),
    ))
}

/// The start of mppx's error for a `402` with no payable challenge:
/// `No method found for challenges: tempo.charge, stripe.charge`. Callers
/// that know the client's methods append `. Available: ...` with
/// [`with_available_methods`].
fn no_method_found(challenges: &[PaymentChallenge]) -> String {
    let offered: Vec<_> = challenges
        .iter()
        .map(|challenge| format!("{}.{}", challenge.method, challenge.intent))
        .collect();
    format!("No method found for challenges: {}", offered.join(", "))
}

/// Complete a [`ChallengeSelectionError::NoSupportedChallenge`] message with
/// the methods the client can pay, as mppx does (`Available: tempo.charge`).
///
/// `accept_payment` is the provider's `Accept-Payment` header, which lists
/// its `method/intent` pairs.
pub(crate) fn with_available_methods(message: String, accept_payment: Option<&str>) -> String {
    let available: Vec<String> = accept_payment
        .and_then(|header| accept_payment::parse(header).ok())
        .unwrap_or_default()
        .into_iter()
        .map(|entry| format!("{}.{}", entry.method, entry.intent))
        .collect();
    format!("{message}. Available: {}", available.join(", "))
}

fn rank_challenges<'a>(
    challenges: &[&'a PaymentChallenge],
    preferences: Option<&[Entry]>,
) -> Vec<&'a PaymentChallenge> {
    match preferences {
        Some(preferences) => accept_payment::rank(challenges, preferences)
            .into_iter()
            .copied()
            .collect(),
        None => challenges.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::Base64UrlJson;

    fn challenge_with_expires(expires: Option<&str>) -> PaymentChallenge {
        let challenge = PaymentChallenge::new(
            "challenge-123",
            "api.example.com",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
        );

        match expires {
            Some(expires) => challenge.with_expires(expires),
            None => challenge,
        }
    }

    #[test]
    fn select_supported_challenge_fails_closed_for_malformed_expiry() {
        let challenges = vec![challenge_with_expires(Some("not-a-date"))];

        let err = select_supported_challenge(
            &challenges,
            None,
            |challenge| challenge.method.as_str() == "tempo",
            |candidates| candidates.first().copied(),
        )
        .unwrap_err();

        assert!(matches!(err, ChallengeSelectionError::Expired(_)));
    }

    #[test]
    fn select_supported_challenge_rejects_past_expiry() {
        let challenges = vec![challenge_with_expires(Some("2020-01-01T00:00:00Z"))];

        let err = select_supported_challenge(
            &challenges,
            None,
            |challenge| challenge.method.as_str() == "tempo",
            |candidates| candidates.first().copied(),
        )
        .unwrap_err();

        assert!(matches!(err, ChallengeSelectionError::Expired(_)));
    }

    #[test]
    fn provider_selects_between_equivalent_supported_challenges() {
        let challenges = vec![
            challenge_with_expires(None),
            PaymentChallenge::new(
                "challenge-preferred",
                "api.example.com",
                "tempo",
                "charge",
                Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap(),
            ),
        ];

        let selected = select_supported_challenge(
            &challenges,
            None,
            |_| true,
            |candidates| candidates.get(1).copied(),
        )
        .unwrap();

        assert_eq!(selected.id, "challenge-preferred");
    }

    /// The message matches mppx's `Fetch.ts` error for an unpayable `402`.
    #[test]
    fn unsupported_challenges_report_mppx_message() {
        let challenges = vec![
            PaymentChallenge::new(
                "a",
                "api.example.com",
                "stripe",
                "charge",
                Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
            ),
            PaymentChallenge::new(
                "b",
                "api.example.com",
                "tempo",
                "session",
                Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
            ),
        ];
        let err = select_supported_challenge(
            &challenges,
            None,
            |_| false,
            |candidates| candidates.first().copied(),
        )
        .unwrap_err();
        let ChallengeSelectionError::NoSupportedChallenge(message) = err else {
            panic!("expected NoSupportedChallenge");
        };
        assert_eq!(
            with_available_methods(message, Some("tempo/charge, stripe/charge")),
            "No method found for challenges: stripe.charge, tempo.session. Available: tempo.charge, stripe.charge"
        );
    }
}
