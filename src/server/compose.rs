//! Multi-method challenge composition and credential dispatch.
//!
//! Combines challenges from multiple [`Mpp`](super::Mpp) instances into a
//! single ranked list, optionally reordered by the client's `Accept-Payment`
//! header preferences. Also dispatches incoming credentials to the correct
//! verifier by matching `method`/`intent`.
//!
//! # Example
//!
//! ```ignore
//! use mpp::server::{compose, compose_verify_with_expected_requests};
//! use mpp::format_www_authenticate_many;
//!
//! let mut challenges = tempo_mpp.charge("0.10")?;
//! challenges.push(stripe_mpp.stripe_charge("0.10")?);
//!
//! // Challenge path: rank and format multiple WWW-Authenticate headers
//! let ranked = compose(
//!     challenges,
//!     req.headers().get("Accept-Payment").and_then(|h| h.to_str().ok()),
//! );
//! let headers = format_www_authenticate_many(&ranked)?;
//!
//! // Credential path: dispatch to the correct verifier, which checks the
//! // credential against the request this route charges with that method
//! let tempo_expected = tempo_mpp.expected_charge_request("0.10", Default::default())?;
//! let stripe_expected = stripe_mpp.stripe_expected_charge_request("0.10", Default::default())?;
//! let receipt = compose_verify_with_expected_requests(
//!     &[(&tempo_mpp, &tempo_expected), (&stripe_mpp, &stripe_expected)],
//!     &credential,
//! )
//! .await?;
//! ```

use std::future::Future;
use std::pin::Pin;

use crate::protocol::core::accept_payment;
use crate::protocol::core::{PaymentChallenge, PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::VerificationError;

/// Rank pre-generated challenges by client `Accept-Payment` preferences.
///
/// Returns challenges reordered by the client's declared preferences.
/// Challenges matched only by `q=0` (explicit opt-out) are excluded.
///
/// If `accept_payment` is `None` or fails to parse, the original order
/// is preserved (matching `mppx`'s fallback behavior).
///
/// The returned list is ready to pass to
/// [`format_www_authenticate_many()`](crate::protocol::core::format_www_authenticate_many).
pub fn compose(
    challenges: Vec<PaymentChallenge>,
    accept_payment: Option<&str>,
) -> Vec<PaymentChallenge> {
    let preferences = accept_payment
        .and_then(|header| accept_payment::parse(header).ok())
        .unwrap_or_default();

    if preferences.is_empty() {
        return challenges;
    }

    let ranked_refs = accept_payment::rank(&challenges, &preferences);

    // If ranking yields nothing (e.g. all offers q=0), fall back to original order
    if ranked_refs.is_empty() {
        return challenges;
    }

    // Map ranked references back to owned values by position.
    // Build an index from pointer identity to original vec index.
    let ranked_indices: Vec<usize> = ranked_refs
        .iter()
        .map(|r| {
            challenges
                .iter()
                .position(|c| std::ptr::eq(c, *r))
                .expect("ranked ref must point into challenges slice")
        })
        .collect();

    // Consume the original vec and pick by index
    let mut slots: Vec<Option<PaymentChallenge>> = challenges.into_iter().map(Some).collect();
    ranked_indices
        .into_iter()
        .map(|i| slots[i].take().expect("each index used exactly once"))
        .collect()
}

/// Object-safe trait for type-erased charge verification.
///
/// This enables multi-method credential dispatch: multiple `Mpp` instances
/// with different `ChargeMethod` types can be collected as `&dyn ChargeVerifier`
/// and used with [`compose_verify_with_expected_requests()`].
///
/// Automatically implemented for all [`Mpp<M, S>`](super::Mpp) where
/// `M: ChargeMethod`.
pub trait ChargeVerifier: Send + Sync {
    /// Payment method name (e.g., `"tempo"`, `"stripe"`).
    fn method_name(&self) -> &str;

    /// Verify a payment credential without checking it against a route.
    fn verify_credential<'a>(
        &'a self,
        credential: &'a PaymentCredential,
    ) -> Pin<Box<dyn Future<Output = Result<Receipt, VerificationError>> + Send + 'a>>;

    /// Verify a payment credential against the request the route charges.
    ///
    /// The default rejects every credential, so a custom verifier that does
    /// not compare the request cannot pass for a route-bound one.
    fn verify_credential_with_expected_request<'a>(
        &'a self,
        credential: &'a PaymentCredential,
        expected: &'a ChargeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Receipt, VerificationError>> + Send + 'a>> {
        let _ = (credential, expected);
        Box::pin(std::future::ready(Err(VerificationError::new(
            "expected request verification is not implemented for this ChargeVerifier",
        ))))
    }
}

impl<M, S> ChargeVerifier for super::Mpp<M, S>
where
    M: crate::protocol::traits::ChargeMethod,
    S: Send + Sync,
{
    fn method_name(&self) -> &str {
        self.method_name()
    }

    fn verify_credential<'a>(
        &'a self,
        credential: &'a PaymentCredential,
    ) -> Pin<Box<dyn Future<Output = Result<Receipt, VerificationError>> + Send + 'a>> {
        Box::pin(self.broadcast_credential(credential))
    }

    fn verify_credential_with_expected_request<'a>(
        &'a self,
        credential: &'a PaymentCredential,
        expected: &'a ChargeRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Receipt, VerificationError>> + Send + 'a>> {
        Box::pin(self.broadcast_credential_with_expected_request(credential, expected))
    }
}

/// Dispatch a charge credential to the matching verifier by method name.
///
/// Non-charge intents are rejected immediately. If no verifier matches
/// the credential's method, falls back to the first verifier (which
/// will reject via HMAC mismatch).
#[deprecated(
    since = "0.15.0",
    note = "accepts a credential paid for any route of the matching handler, whatever its price; use `compose_verify_with_expected_requests`"
)]
pub async fn compose_verify(
    verifiers: &[&dyn ChargeVerifier],
    credential: &PaymentCredential,
) -> Result<Receipt, VerificationError> {
    select_verifier(verifiers, credential, |verifier| verifier.method_name())?
        .verify_credential(credential)
        .await
}

/// Dispatch a charge credential to the matching verifier by method name and
/// verify it against the request this route charges with that method.
///
/// Each entry pairs a verifier with its expected request (for example from
/// [`Mpp::expected_charge_request()`](super::Mpp::expected_charge_request)).
/// A credential whose challenge was issued for another amount, currency or
/// recipient is rejected, so a payment for a cheaper route cannot be replayed
/// here. Dispatch follows the same rules as [`compose_verify()`].
pub async fn compose_verify_with_expected_requests(
    routes: &[(&dyn ChargeVerifier, &ChargeRequest)],
    credential: &PaymentCredential,
) -> Result<Receipt, VerificationError> {
    let (verifier, expected) =
        select_verifier(routes, credential, |(verifier, _)| verifier.method_name())?;
    verifier
        .verify_credential_with_expected_request(credential, expected)
        .await
}

/// Pick the entry whose method matches the charge credential, else the first.
fn select_verifier<'a, T>(
    verifiers: &'a [T],
    credential: &PaymentCredential,
    method_name: impl Fn(&T) -> &str,
) -> Result<&'a T, VerificationError> {
    if verifiers.is_empty() {
        return Err(VerificationError::new("No verifiers configured"));
    }

    let cred_method = credential.challenge.method.as_str();
    let cred_intent = credential.challenge.intent.as_str();

    if cred_intent != "charge" {
        return Err(VerificationError::with_code(
            format!("compose_verify only supports charge credentials, got intent '{cred_intent}'"),
            crate::protocol::traits::ErrorCode::InvalidCredential,
        ));
    }

    Ok(verifiers
        .iter()
        .find(|v| method_name(v) == cred_method)
        .unwrap_or(&verifiers[0]))
}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;
    use crate::protocol::core::types::Base64UrlJson;
    use crate::protocol::core::{ChallengeEcho, PaymentPayload};
    use crate::protocol::intents::ChargeRequest;
    use std::future::Future;

    fn challenge(method: &str, intent: &str) -> PaymentChallenge {
        PaymentChallenge {
            id: format!("id-{method}-{intent}"),
            realm: "test".into(),
            method: method.into(),
            intent: intent.into(),
            request: Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
            header: None,
        }
    }

    #[test]
    fn no_header_preserves_order() {
        let challenges = vec![challenge("stripe", "charge"), challenge("tempo", "charge")];
        let result = compose(challenges, None);
        assert_eq!(result[0].method.as_str(), "stripe");
        assert_eq!(result[1].method.as_str(), "tempo");
    }

    #[test]
    fn ranks_by_client_preference() {
        let challenges = vec![challenge("stripe", "charge"), challenge("tempo", "charge")];
        let result = compose(challenges, Some("tempo/charge, stripe/charge;q=0.5"));
        assert_eq!(result[0].method.as_str(), "tempo");
        assert_eq!(result[1].method.as_str(), "stripe");
    }

    #[test]
    fn excludes_q_zero_offers() {
        let challenges = vec![challenge("tempo", "charge"), challenge("stripe", "charge")];
        let result = compose(challenges, Some("tempo/charge;q=0, stripe/charge"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].method.as_str(), "stripe");
    }

    #[test]
    fn all_q_zero_falls_back_to_original_order() {
        let challenges = vec![challenge("tempo", "charge"), challenge("stripe", "charge")];
        let result = compose(challenges, Some("tempo/charge;q=0, stripe/charge;q=0"));
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].method.as_str(), "tempo");
    }

    #[test]
    fn parse_error_preserves_original_order() {
        let challenges = vec![challenge("stripe", "charge"), challenge("tempo", "charge")];
        let result = compose(challenges, Some(";;;invalid;;;"));
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].method.as_str(), "stripe");
    }

    // ── compose_verify tests ──────────────────────────────────────────

    #[derive(Clone)]
    struct MockMethod(&'static str);

    #[allow(clippy::manual_async_fn)]
    impl crate::protocol::traits::ChargeMethod for MockMethod {
        fn method(&self) -> &str {
            self.0
        }
        fn verify(
            &self,
            _credential: &PaymentCredential,
            _request: &ChargeRequest,
        ) -> impl Future<Output = Result<Receipt, VerificationError>> + Send {
            let name = self.0;
            async move { Ok(Receipt::success(name, format!("{name}_ref"))) }
        }
    }

    fn test_credential(method: &str, secret: &str) -> PaymentCredential {
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "1000",
            "currency": "USD"
        }))
        .unwrap();
        let request_raw = request.raw();
        let expires = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let id = crate::protocol::core::compute_challenge_id(
            secret,
            "test.example.com",
            method,
            "charge",
            request_raw,
            Some(&expires),
            None,
            None,
        );
        let echo = ChallengeEcho {
            id,
            realm: "test.example.com".into(),
            method: method.into(),
            intent: "charge".into(),
            request: Base64UrlJson::from_raw(request_raw),
            expires: Some(expires),
            description: None,
            digest: None,
            opaque: None,
            header: None,
        };
        PaymentCredential::new(echo, PaymentPayload::hash("0x123"))
    }

    #[tokio::test]
    async fn verify_dispatches_to_matching_method() {
        let mpp_a = super::super::Mpp::new(MockMethod("alpha"), "test.example.com", "secret");
        let mpp_b = super::super::Mpp::new(MockMethod("beta"), "test.example.com", "secret");
        let verifiers: Vec<&dyn ChargeVerifier> = vec![&mpp_a, &mpp_b];

        let cred = test_credential("beta", "secret");
        let receipt = compose_verify(&verifiers, &cred).await.unwrap();
        assert_eq!(receipt.method.as_str(), "beta");
    }

    #[tokio::test]
    async fn verify_falls_back_to_first_on_no_match() {
        let mpp = super::super::Mpp::new(MockMethod("alpha"), "test.example.com", "secret");
        let verifiers: Vec<&dyn ChargeVerifier> = vec![&mpp];

        // Credential for "unknown" method — falls back to first verifier.
        // Use a different secret so the HMAC check fails.
        let cred = test_credential("unknown", "wrong-secret");
        let result = compose_verify(&verifiers, &cred).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verify_empty_verifiers_returns_error() {
        let cred = test_credential("tempo", "secret");
        let result = compose_verify(&[], &cred).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("No verifiers"));
    }

    #[tokio::test]
    async fn verify_rejects_non_charge_intent() {
        let mpp = super::super::Mpp::new(MockMethod("tempo"), "test.example.com", "secret");
        let verifiers: Vec<&dyn ChargeVerifier> = vec![&mpp];

        // Build a credential with intent="session"
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "1000",
            "currency": "USD"
        }))
        .unwrap();
        let expires = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let id = crate::protocol::core::compute_challenge_id(
            "secret",
            "test.example.com",
            "tempo",
            "session",
            request.raw(),
            Some(&expires),
            None,
            None,
        );
        let echo = ChallengeEcho {
            id,
            realm: "test.example.com".into(),
            method: "tempo".into(),
            intent: "session".into(),
            request: Base64UrlJson::from_raw(request.raw()),
            expires: Some(expires),
            description: None,
            digest: None,
            opaque: None,
            header: None,
        };
        let cred = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));

        let result = compose_verify(&verifiers, &cred).await;
        let err = result.unwrap_err();
        assert!(err.message.contains("only supports charge"));
    }

    fn expected(amount: &str) -> ChargeRequest {
        ChargeRequest {
            amount: amount.into(),
            currency: "USD".into(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn verify_with_expected_requests_rejects_other_routes_credential() {
        let mpp = super::super::Mpp::new(MockMethod("alpha"), "test.example.com", "secret");
        // Issued by this handler for a route that charges 1000.
        let cred = test_credential("alpha", "secret");

        let expensive = expected("100000");
        let err = compose_verify_with_expected_requests(&[(&mpp, &expensive)], &cred)
            .await
            .unwrap_err();
        assert!(err.message.contains("Amount mismatch"), "{}", err.message);

        let route = expected("1000");
        let receipt = compose_verify_with_expected_requests(&[(&mpp, &route)], &cred)
            .await
            .unwrap();
        assert_eq!(receipt.method.as_str(), "alpha");

        // The deprecated dispatcher has no expectation to compare against.
        let verifiers: Vec<&dyn ChargeVerifier> = vec![&mpp];
        assert!(compose_verify(&verifiers, &cred).await.is_ok());
    }

    #[tokio::test]
    async fn verify_with_expected_requests_uses_matching_verifiers_expectation() {
        let mpp_a = super::super::Mpp::new(MockMethod("alpha"), "test.example.com", "secret");
        let mpp_b = super::super::Mpp::new(MockMethod("beta"), "test.example.com", "secret");
        let (alpha_expected, beta_expected) = (expected("5"), expected("1000"));
        let cred = test_credential("beta", "secret");

        let receipt = compose_verify_with_expected_requests(
            &[(&mpp_a, &alpha_expected), (&mpp_b, &beta_expected)],
            &cred,
        )
        .await
        .unwrap();
        assert_eq!(receipt.method.as_str(), "beta");

        let result = compose_verify_with_expected_requests(
            &[(&mpp_a, &beta_expected), (&mpp_b, &alpha_expected)],
            &cred,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn verify_with_expected_requests_rejects_verifier_without_comparison() {
        struct Unbound;
        impl ChargeVerifier for Unbound {
            fn method_name(&self) -> &str {
                "alpha"
            }
            fn verify_credential<'a>(
                &'a self,
                _credential: &'a PaymentCredential,
            ) -> Pin<Box<dyn Future<Output = Result<Receipt, VerificationError>> + Send + 'a>>
            {
                Box::pin(async { Ok(Receipt::success("alpha", "alpha_ref")) })
            }
        }

        let cred = test_credential("alpha", "secret");
        let route = expected("1000");
        let result = compose_verify_with_expected_requests(&[(&Unbound, &route)], &cred).await;
        assert!(result.is_err());
    }

    #[test]
    fn empty_challenges_returns_empty() {
        let result = compose(vec![], None);
        assert!(result.is_empty());

        let result = compose(vec![], Some("tempo/charge"));
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn verify_same_method_picks_first() {
        let mpp_a = super::super::Mpp::new(MockMethod("tempo"), "test.example.com", "secret");
        let mpp_b = super::super::Mpp::new(MockMethod("tempo"), "test.example.com", "secret");
        let verifiers: Vec<&dyn ChargeVerifier> = vec![&mpp_a, &mpp_b];

        let cred = test_credential("tempo", "secret");
        let receipt = compose_verify(&verifiers, &cred).await.unwrap();
        // Both are "tempo" — first one wins, both return same receipt
        assert_eq!(receipt.method.as_str(), "tempo");
    }
}
