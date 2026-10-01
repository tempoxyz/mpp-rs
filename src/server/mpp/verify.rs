//! Charge credential verification.

use super::Mpp;
use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::{ChargeMethod, ChargeValidation, VerificationError};
use crate::server::events::PaymentSuccessContext;

impl<M, S> Mpp<M, S>
where
    M: ChargeMethod,
{
    /// Reject unless the credential's echoed `opaque` equals the configured one.
    pub(super) fn verify_opaque(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<(), VerificationError> {
        let configured_opaque = self.config.opaque.as_ref().map(|o| o.raw());
        let echoed_opaque = credential.challenge.opaque.as_ref().map(|o| o.raw());
        if echoed_opaque != configured_opaque {
            return Err(VerificationError::with_code(
                "credential opaque data does not match this route's requirements",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }
        Ok(())
    }

    /// Tier-2 pinned field verification.
    ///
    /// After the HMAC check (Tier 1) confirms the echoed challenge was issued
    /// by this server, this check compares economically-significant fields
    /// from the credential against the server's current configuration to
    /// prevent cross-route credential replay attacks.
    fn verify_pinned_fields(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<(), VerificationError> {
        // Challenge-level fields: method, intent, realm
        if credential.challenge.method.as_str() != self.method.method() {
            return Err(VerificationError::with_code(
                format!(
                    "credential method '{}' does not match this route's requirements (expected '{}')",
                    credential.challenge.method, self.method.method()
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if !credential.challenge.intent.is_charge() {
            return Err(VerificationError::with_code(
                format!(
                    "credential intent '{}' does not match this route's requirements (expected 'charge')",
                    credential.challenge.intent
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if credential.challenge.realm != self.config.realm {
            return Err(VerificationError::with_code(
                format!(
                    "credential realm '{}' does not match this route's requirements (expected '{}')",
                    credential.challenge.realm, self.config.realm
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        self.verify_opaque(credential)?;

        // Request-level core fields: currency, recipient
        if !self.config.currencies.is_empty() && !self.offers_currency(&request.currency) {
            return Err(VerificationError::with_code(
                format!(
                    "credential currency '{}' does not match this route's requirements",
                    request.currency
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if let Some(ref expected_recipient) = self.config.recipient {
            if request.recipient.as_deref() != Some(expected_recipient.as_str()) {
                return Err(VerificationError::with_code(
                    "credential recipient does not match this route's requirements",
                    crate::protocol::traits::ErrorCode::InvalidChallenge,
                ));
            }
        }

        // Request-level method fields: chainId (fail-closed when expected but missing)
        if let Some(expected_chain_id) = self.config.chain_id {
            let actual_chain_id = request
                .method_details
                .as_ref()
                .and_then(|md| md.get("chainId"))
                .and_then(|v| match v {
                    serde_json::Value::Number(n) => Some(n.to_string()),
                    serde_json::Value::String(s) => Some(s.clone()),
                    _ => None,
                });

            if actual_chain_id.as_deref() != Some(&*expected_chain_id.to_string()) {
                return Err(VerificationError::with_code(
                    format!(
                        "credential chainId {:?} does not match this route's requirements (expected '{}')",
                        actual_chain_id, expected_chain_id
                    ),
                    crate::protocol::traits::ErrorCode::InvalidChallenge,
                ));
            }
        }

        Ok(())
    }

    /// Verify the challenge HMAC and reject expired challenges.
    ///
    /// Shared validation used by both charge and session verification paths.
    pub(super) fn verify_hmac_and_expiry(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<(), VerificationError> {
        let expected_id = crate::protocol::core::compute_challenge_id_with_header(
            &self.config.secret_key,
            &self.config.realm,
            credential.challenge.method.as_str(),
            credential.challenge.intent.as_str(),
            credential.challenge.request.raw(),
            credential.challenge.expires.as_deref(),
            credential.challenge.digest.as_deref(),
            credential.challenge.opaque.as_ref().map(|o| o.raw()),
            credential.challenge.header.as_deref(),
        );

        if !crate::protocol::core::constant_time_eq(&credential.challenge.id, &expected_id) {
            return Err(VerificationError::with_code(
                "Challenge ID mismatch - not issued by this server",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        let expires = credential.challenge.expires.as_deref().ok_or_else(|| {
            VerificationError::with_code(
                "Challenge missing required expires field",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            )
        })?;

        let expires_at =
            time::OffsetDateTime::parse(expires, &time::format_description::well_known::Rfc3339)
                .map_err(|_| {
                    VerificationError::invalid_challenge("Invalid expires timestamp in challenge")
                })?;

        if expires_at <= time::OffsetDateTime::now_utc() {
            return Err(VerificationError::expired(format!(
                "Challenge expired at {}",
                expires
            )));
        }

        Ok(())
    }

    fn decode_credential_request(
        credential: &PaymentCredential,
    ) -> std::result::Result<ChargeRequest, VerificationError> {
        credential.challenge.request.decode().map_err(|e| {
            VerificationError::invalid_challenge(format!("Failed to decode request: {e}"))
        })
    }

    /// Validate a payment credential without consuming or broadcasting it.
    ///
    /// Not bound to a route: see [`Self::broadcast_credential`].
    pub async fn validate_credential(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.validate(credential, &request).await
    }

    /// Validate a credential against the actual request body without accepting payment.
    ///
    /// Not bound to a route: see [`Self::broadcast_credential`].
    pub async fn validate_credential_with_body(
        &self,
        credential: &PaymentCredential,
        body: &[u8],
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.validate_with_body(credential, &request, Some(body))
            .await
    }

    /// Validate a credential against expected route values without accepting payment.
    pub async fn validate_credential_with_expected_request(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.verify_expected_request_matches(credential, &request, expected)?;
        self.validate(credential, &request).await
    }

    /// Validate a credential against expected route values and body bytes.
    pub async fn validate_credential_with_expected_request_and_body(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
        body: &[u8],
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.verify_expected_request_matches(credential, &request, expected)?;
        self.validate_with_body(credential, &request, Some(body))
            .await
    }

    /// Re-validate and accept a payment credential.
    ///
    /// Not bound to a route: this accepts any unexpired charge challenge this
    /// handler issued, whatever its amount. A handler that serves routes with
    /// different prices must compare the credential with the route's request,
    /// using [`Self::broadcast_credential_with_expected_request`] or
    /// [`Self::verify_charge`]. Otherwise a credential paid for the cheapest
    /// route unlocks every other one.
    pub async fn broadcast_credential(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<Receipt, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.broadcast(credential, &request).await
    }

    /// Re-validate and accept a credential bound to the actual request body.
    ///
    /// Not bound to a route: see [`Self::broadcast_credential`].
    pub async fn broadcast_credential_with_body(
        &self,
        credential: &PaymentCredential,
        body: &[u8],
    ) -> std::result::Result<Receipt, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.broadcast_with_body(credential, &request, Some(body))
            .await
    }

    /// Re-validate and accept a credential matching expected route values.
    pub async fn broadcast_credential_with_expected_request(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.verify_expected_request_matches(credential, &request, expected)?;
        self.broadcast(credential, &request).await
    }

    /// Re-validate and accept a credential matching expected route values and body bytes.
    pub async fn broadcast_credential_with_expected_request_and_body(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
        body: &[u8],
    ) -> std::result::Result<Receipt, VerificationError> {
        let request = Self::decode_credential_request(credential)?;
        self.verify_expected_request_matches(credential, &request, expected)?;
        self.broadcast_with_body(credential, &request, Some(body))
            .await
    }

    /// Accept a credential for a route that charges `amount` with
    /// [`charge()`](Self::charge).
    ///
    /// Rejects a credential whose challenge was issued for another amount,
    /// currency or recipient, so a payment for a cheaper route cannot be
    /// replayed here. `amount` is in dollars, as for `charge()`.
    #[cfg(feature = "tempo")]
    pub async fn verify_charge(
        &self,
        credential: &PaymentCredential,
        amount: &str,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.verify_charge_with_options(credential, amount, crate::server::ChargeOptions::default())
            .await
    }

    /// Accept a credential for a route that charges `amount` with
    /// [`charge_with_options()`](Self::charge_with_options).
    ///
    /// Pass the options the route issues its challenges with. See
    /// [`verify_charge()`](Self::verify_charge).
    #[cfg(feature = "tempo")]
    pub async fn verify_charge_with_options(
        &self,
        credential: &PaymentCredential,
        amount: &str,
        options: crate::server::ChargeOptions<'_>,
    ) -> std::result::Result<Receipt, VerificationError> {
        let expected = self.expected_charge_request(amount, options).map_err(|e| {
            VerificationError::new(format!("Failed to build expected charge request: {e}"))
        })?;
        self.broadcast_credential_with_expected_request(credential, &expected)
            .await
    }

    /// Backwards-compatible alias for [`Self::broadcast_credential`].
    #[deprecated(
        since = "0.15.0",
        note = "accepts a credential paid for any route of this handler, whatever its price; use `verify_charge` (Tempo), `stripe_verify_charge` (Stripe) or `verify_credential_with_expected_request`. `broadcast_credential` keeps the unbound behavior"
    )]
    pub async fn verify_credential(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast_credential(credential).await
    }

    /// Backwards-compatible alias for [`Self::broadcast_credential_with_body`].
    #[deprecated(
        since = "0.15.0",
        note = "accepts a credential paid for any route of this handler, whatever its price; use `verify_credential_with_expected_request_and_body`. `broadcast_credential_with_body` keeps the unbound behavior"
    )]
    pub async fn verify_credential_with_body(
        &self,
        credential: &PaymentCredential,
        body: &[u8],
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast_credential_with_body(credential, body).await
    }

    /// Backwards-compatible alias for [`Self::broadcast_credential_with_expected_request`].
    pub async fn verify_credential_with_expected_request(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast_credential_with_expected_request(credential, expected)
            .await
    }

    /// Backwards-compatible alias for
    /// [`Self::broadcast_credential_with_expected_request_and_body`].
    pub async fn verify_credential_with_expected_request_and_body(
        &self,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
        body: &[u8],
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast_credential_with_expected_request_and_body(credential, expected, body)
            .await
    }

    fn verify_expected_request_matches(
        &self,
        _credential: &PaymentCredential,
        request: &ChargeRequest,
        expected: &ChargeRequest,
    ) -> std::result::Result<(), VerificationError> {
        if request.amount != expected.amount {
            return Err(VerificationError::with_code(
                format!(
                    "Amount mismatch: credential has {} but endpoint expects {}",
                    request.amount, expected.amount
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        // A route built from this handler's bound currencies accepts any of
        // them, since each was offered as an equivalent challenge.
        if request.currency != expected.currency
            && !(self.offers_currency(&expected.currency)
                && self.offers_currency(&request.currency))
        {
            return Err(VerificationError::with_code(
                format!(
                    "Currency mismatch: credential has {} but endpoint expects {}",
                    request.currency, expected.currency
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if request.recipient != expected.recipient {
            return Err(VerificationError::with_code(
                "Recipient mismatch: credential was issued for a different recipient",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if request.mppx_scope != expected.mppx_scope {
            return Err(VerificationError::with_code(
                "Framework scope mismatch: credential was issued for a different route",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if request.external_id != expected.external_id {
            return Err(VerificationError::with_code(
                "External ID mismatch: credential was issued for a different order",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        #[cfg(feature = "tempo")]
        if _credential.challenge.method.as_str() == crate::protocol::methods::tempo::METHOD_NAME {
            let req_transfers =
                crate::protocol::methods::tempo::transfers::get_request_transfers(request)
                    .map_err(|e| {
                        VerificationError::with_code(
                            format!("Invalid Tempo request in credential: {e}"),
                            crate::protocol::traits::ErrorCode::InvalidCredential,
                        )
                    })?;
            let expected_transfers =
                crate::protocol::methods::tempo::transfers::get_request_transfers(expected)
                    .map_err(|e| {
                        VerificationError::with_code(
                            format!("Invalid expected Tempo request: {e}"),
                            crate::protocol::traits::ErrorCode::Internal,
                        )
                    })?;

            let mut unmatched = req_transfers;
            let same_transfers = unmatched.len() == expected_transfers.len()
                && expected_transfers.into_iter().all(|expected| {
                    unmatched
                        .iter()
                        .position(|actual| *actual == expected)
                        .map(|index| unmatched.swap_remove(index))
                        .is_some()
                });
            if !same_transfers {
                return Err(VerificationError::with_code(
                    "Tempo transfer routing mismatch: credential was issued with different memo or splits",
                    crate::protocol::traits::ErrorCode::InvalidChallenge,
                ));
            }
        }

        Ok(())
    }

    /// Validate a charge credential with an explicit request without accepting payment.
    pub async fn validate(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        self.validate_with_body(credential, request, None).await
    }

    async fn validate_with_body(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
        body: Option<&[u8]>,
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        self.verify_hmac_and_expiry(credential)?;
        self.verify_body_digest(credential, body)?;
        self.verify_pinned_fields(credential, request)?;
        self.method.validate(credential, request).await
    }

    async fn validate_before_broadcast(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<(), VerificationError> {
        if self.method.supports_validation() {
            self.method.validate(credential, request).await?;
        }
        Ok(())
    }

    /// Re-validate and perform the terminal payment operation.
    pub async fn broadcast(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast_with_body(credential, request, None).await
    }

    async fn broadcast_with_body(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
        body: Option<&[u8]>,
    ) -> std::result::Result<Receipt, VerificationError> {
        // Tier 1: HMAC provenance + expiry
        self.verify_hmac_and_expiry(credential)?;
        self.verify_body_digest(credential, body)?;
        // Tier 2: Pinned field safety net
        self.verify_pinned_fields(credential, request)?;
        self.validate_before_broadcast(credential, request).await?;
        let receipt = self.method.broadcast(credential, request).await?;
        self.events
            .emit_payment_success(PaymentSuccessContext {
                credential: credential.clone(),
                receipt: receipt.clone(),
                request: serde_json::to_value(request).unwrap_or(serde_json::Value::Null),
                method: credential.challenge.method.as_str().to_string(),
                intent: credential.challenge.intent.as_str().to_string(),
                management_response: false,
            })
            .await;
        Ok(receipt)
    }

    /// Backwards-compatible alias for [`Self::broadcast`].
    pub async fn verify(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.broadcast(credential, request).await
    }

    fn verify_body_digest(
        &self,
        credential: &PaymentCredential,
        body: Option<&[u8]>,
    ) -> std::result::Result<(), VerificationError> {
        match (credential.challenge.digest.as_deref(), body) {
            (Some(_), None) => Err(VerificationError::with_code(
                "body digest present but request body was not provided",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            )),
            (None, Some(_)) => Err(VerificationError::with_code(
                "missing body digest",
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            )),
            (Some(digest), Some(body)) if !crate::body_digest::verify(digest, body) => {
                Err(VerificationError::with_code(
                    "body digest mismatch",
                    crate::protocol::traits::ErrorCode::InvalidChallenge,
                ))
            }
            _ => Ok(()),
        }
    }

    /// Whether `currency` is one of this handler's bound currencies.
    fn offers_currency(&self, currency: &str) -> bool {
        self.config
            .currencies
            .iter()
            .any(|offered| offered == currency)
    }
}

#[cfg(feature = "stripe")]
impl<S> Mpp<crate::protocol::methods::stripe::method::ChargeMethod, S> {
    /// Accept a credential for a route that charges `amount` with
    /// [`stripe_charge()`](Self::stripe_charge).
    ///
    /// Rejects a credential whose challenge was issued for another amount or
    /// currency, so a payment for a cheaper route cannot be replayed here.
    pub async fn stripe_verify_charge(
        &self,
        credential: &PaymentCredential,
        amount: &str,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.stripe_verify_charge_with_options(
            credential,
            amount,
            crate::server::StripeChargeOptions::default(),
        )
        .await
    }

    /// Accept a credential for a route that charges `amount` with
    /// [`stripe_charge_with_options()`](Self::stripe_charge_with_options).
    ///
    /// Pass the options the route issues its challenges with. See
    /// [`stripe_verify_charge()`](Self::stripe_verify_charge).
    pub async fn stripe_verify_charge_with_options(
        &self,
        credential: &PaymentCredential,
        amount: &str,
        options: crate::server::StripeChargeOptions<'_>,
    ) -> std::result::Result<Receipt, VerificationError> {
        let expected = self
            .stripe_expected_charge_request(amount, options)
            .map_err(|e| {
                VerificationError::new(format!("Failed to build expected charge request: {e}"))
            })?;
        self.broadcast_credential_with_expected_request(credential, &expected)
            .await
    }
}
