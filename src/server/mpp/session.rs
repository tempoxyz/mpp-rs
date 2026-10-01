//! Session challenge issuance and verification.

use super::Mpp;
#[cfg(feature = "tempo")]
use crate::protocol::core::{Base64UrlJson, PaymentChallenge};
use crate::protocol::core::{PaymentCredential, Receipt};
use crate::protocol::traits::{ChargeMethod, VerificationError};
use crate::server::events::PaymentSuccessContext;

/// Result of session verification, including optional management response.
#[derive(Debug)]
pub struct SessionVerifyResult {
    /// The payment receipt.
    pub receipt: Receipt,
    /// Optional management response body (for channel open/close/topUp).
    /// When `Some`, the caller should return this as the response body
    /// instead of proceeding with normal request handling.
    pub management_response: Option<serde_json::Value>,
}

impl<M, S> Mpp<M, S>
where
    M: ChargeMethod,
    S: crate::protocol::traits::SessionMethod,
{
    /// Generate a session challenge.
    #[cfg(feature = "tempo")]
    pub fn session_challenge(
        &self,
        amount: &str,
        currency: &str,
        recipient: &str,
    ) -> crate::error::Result<PaymentChallenge> {
        use crate::protocol::intents::SessionRequest;
        use time::{Duration, OffsetDateTime};

        let request = SessionRequest {
            amount: amount.to_string(),
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            ..Default::default()
        };
        let encoded = Base64UrlJson::from_typed(&request)?;

        let expires = {
            let expiry_time = OffsetDateTime::now_utc()
                + Duration::minutes(
                    crate::protocol::methods::tempo::DEFAULT_EXPIRES_MINUTES as i64,
                );
            expiry_time
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| {
                    crate::error::MppError::InvalidConfig(format!("failed to format expires: {e}"))
                })?
        };

        let id = crate::protocol::methods::tempo::generate_challenge_id(
            &self.secret_key,
            &self.realm,
            "tempo",
            "session",
            encoded.raw(),
            Some(&expires),
            None,
            None,
        );

        Ok(self.apply_pinned_opaque(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: "tempo".into(),
            intent: "session".into(),
            request: encoded,
            expires: Some(expires),
            description: None,
            digest: None,
            opaque: None,
            header: None,
        }))
    }

    /// Generate a session challenge with method details populated from the session method.
    ///
    /// When a session method is configured (e.g., Tempo's `SessionMethod`), this
    /// automatically populates `methodDetails` with fields like `escrowContract`,
    /// `chainId`, and `minVoucherDelta`. Additional options like `suggestedDeposit`,
    /// `feePayer`, `description`, and `expires` can be set via [`SessionChallengeOptions`](crate::server::SessionChallengeOptions).
    ///
    /// `feePayer` and the machine-token settlement route are only advertised
    /// when the session method reports that it supports them (see
    /// [`SessionMethod::supports_fee_payer`](crate::protocol::traits::SessionMethod::supports_fee_payer)
    /// and
    /// [`SessionMethod::supports_machine_tokens`](crate::protocol::traits::SessionMethod::supports_machine_tokens)).
    /// Tempo's `SessionMethod` supports neither.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let challenge = mpp.session_challenge_with_details(
    ///     "1000",
    ///     "0x20c0...",
    ///     "0x742d...",
    ///     SessionChallengeOptions {
    ///         unit_type: Some("second"),
    ///         suggested_deposit: Some("60000"),
    ///         ..Default::default()
    ///     },
    /// )?;
    /// ```
    #[cfg(feature = "tempo")]
    pub fn session_challenge_with_details(
        &self,
        amount: &str,
        currency: &str,
        recipient: &str,
        options: crate::server::SessionChallengeOptions<'_>,
    ) -> crate::error::Result<PaymentChallenge> {
        use crate::protocol::intents::SessionRequest;
        use time::{Duration, OffsetDateTime};

        let session = self.session_method.as_ref();

        let mut method_details = session.and_then(|s| s.challenge_method_details());

        // Fee sponsorship and machine tokens are configured on the handler for
        // charges; only advertise them when the session method can honour them.
        let sponsors_fees = session.is_some_and(|s| s.supports_fee_payer());
        let settles_machine_tokens = session.is_some_and(|s| s.supports_machine_tokens());

        if (options.fee_payer || self.fee_payer) && sponsors_fees {
            let details = method_details.get_or_insert_with(|| serde_json::json!({}));
            if let Some(obj) = details.as_object_mut() {
                obj.insert("feePayer".to_string(), serde_json::json!(true));
            }
        }

        if self.machine_token_enabled && settles_machine_tokens {
            let chain_id = self
                .chain_id
                .unwrap_or(crate::protocol::methods::tempo::CHAIN_ID);
            let (_, adapter) =
                crate::protocol::methods::tempo::machine_token::session_addresses(chain_id)
                    .ok_or_else(|| {
                        crate::error::MppError::InvalidConfig(format!(
                            "machine tokens are not supported on chain ID {chain_id}"
                        ))
                    })?;
            let details = method_details.get_or_insert_with(|| serde_json::json!({}));
            if let Some(obj) = details.as_object_mut() {
                obj.insert("machineTokenEnabled".to_string(), serde_json::json!(true));
                obj.insert("settlementAdapter".to_string(), serde_json::json!(adapter));
                obj.insert(
                    "settlementRecipient".to_string(),
                    serde_json::json!(recipient),
                );
                obj.insert("settlementToken".to_string(), serde_json::json!(currency));
            }
        }

        let request = SessionRequest {
            amount: amount.to_string(),
            unit_type: options.unit_type.map(|s| s.to_string()),
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            suggested_deposit: options.suggested_deposit.map(|s| s.to_string()),
            method_details,
            ..Default::default()
        };
        let encoded = Base64UrlJson::from_typed(&request)?;

        let default_expires;
        let expires = match options.expires {
            Some(e) => Some(e),
            None => {
                let expiry_time = OffsetDateTime::now_utc()
                    + Duration::minutes(
                        crate::protocol::methods::tempo::DEFAULT_EXPIRES_MINUTES as i64,
                    );
                default_expires = expiry_time
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|e| {
                        crate::error::MppError::InvalidConfig(format!(
                            "failed to format expires: {e}"
                        ))
                    })?;
                Some(default_expires.as_str())
            }
        };

        let id = crate::protocol::methods::tempo::generate_challenge_id(
            &self.secret_key,
            &self.realm,
            "tempo",
            "session",
            encoded.raw(),
            expires,
            None,
            None,
        );

        Ok(self.apply_pinned_opaque(PaymentChallenge {
            id,
            realm: self.realm.clone(),
            method: "tempo".into(),
            intent: "session".into(),
            request: encoded,
            expires: expires.map(|s| s.to_string()),
            description: options.description.map(|s| s.to_string()),
            digest: None,
            opaque: None,
            header: None,
        }))
    }

    /// Verify a session credential.
    pub async fn verify_session(
        &self,
        credential: &PaymentCredential,
    ) -> std::result::Result<SessionVerifyResult, crate::protocol::traits::VerificationError> {
        let session = self.session_method.as_ref().ok_or_else(|| {
            crate::protocol::traits::VerificationError::new("No session method configured")
        })?;

        self.verify_hmac_and_expiry(credential)?;
        self.verify_opaque(credential)?;

        let request: crate::protocol::intents::SessionRequest =
            credential.challenge.request.decode().map_err(|e| {
                crate::protocol::traits::VerificationError::invalid_challenge(format!(
                    "Failed to decode session request: {}",
                    e
                ))
            })?;

        // Channels opened in any accepted currency keep verifying, including
        // channels opened before OUSD became the preferred default.
        if !self.currencies.is_empty()
            && !self
                .currencies
                .iter()
                .any(|bound| request.currency.eq_ignore_ascii_case(bound))
        {
            return Err(VerificationError::with_code(
                format!(
                    "Currency mismatch: credential has {} but server expects {}",
                    request.currency,
                    self.currencies.join(" or ")
                ),
                crate::protocol::traits::ErrorCode::InvalidChallenge,
            ));
        }

        if let Some(bound) = &self.recipient {
            let echoed = request.recipient.as_deref().unwrap_or("");
            if !echoed.eq_ignore_ascii_case(bound) {
                return Err(VerificationError::with_code(
                    format!(
                        "Recipient mismatch: credential has {} but server expects {}",
                        echoed, bound
                    ),
                    crate::protocol::traits::ErrorCode::InvalidChallenge,
                ));
            }
        }

        let receipt = session.verify_session(credential, &request).await?;

        // Call respond hook — management actions (open, topUp, close) may
        // return a response body that short-circuits normal request handling.
        let management_response = session.respond(credential, &receipt);
        let has_management_response = management_response.is_some();

        self.events
            .emit_payment_success(PaymentSuccessContext {
                credential: credential.clone(),
                receipt: receipt.clone(),
                request: serde_json::to_value(&request).unwrap_or(serde_json::Value::Null),
                method: credential.challenge.method.as_str().to_string(),
                intent: credential.challenge.intent.as_str().to_string(),
                management_response: has_management_response,
            })
            .await;

        Ok(SessionVerifyResult {
            receipt,
            management_response,
        })
    }
}
