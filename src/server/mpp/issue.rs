//! Charge challenge issuance.

use super::Mpp;
use crate::error::Result;
#[cfg(feature = "stripe")]
use crate::protocol::core::Base64UrlJson;
use crate::protocol::core::PaymentChallenge;
use crate::protocol::intents::ChargeRequest;
use crate::protocol::traits::ChargeMethod;

/// Validate the `supportedModes` a charge challenge advertises.
///
/// The verifier rejects credentials whose mode is not listed, so an empty or
/// misspelled list would make the challenge unpayable.
#[cfg(feature = "tempo")]
fn validate_charge_modes(modes: &[&str]) -> Result<()> {
    if modes.is_empty() || modes.iter().any(|mode| !matches!(*mode, "pull" | "push")) {
        return Err(crate::error::MppError::InvalidConfig(
            "supported_modes must be a non-empty list of \"pull\" and/or \"push\"".into(),
        ));
    }
    Ok(())
}

impl<M, S> Mpp<M, S>
where
    M: ChargeMethod,
{
    /// Stamp configured `opaque` and credential `header` onto an issued
    /// challenge and recompute its HMAC id. No-op when neither is configured.
    #[cfg(any(feature = "tempo", feature = "stripe"))]
    pub(super) fn apply_pinned_opaque(&self, mut challenge: PaymentChallenge) -> PaymentChallenge {
        if self.config.opaque.is_none() && self.config.credential_header.is_none() {
            return challenge;
        }
        if let Some(opaque) = &self.config.opaque {
            challenge.opaque = Some(opaque.clone());
        }
        challenge.header = self.config.credential_header.clone();
        challenge.id = crate::protocol::core::compute_challenge_id_with_header(
            &self.config.secret_key,
            &challenge.realm,
            challenge.method.as_str(),
            challenge.intent.as_str(),
            challenge.request.raw(),
            challenge.expires.as_deref(),
            challenge.digest.as_deref(),
            challenge.opaque.as_ref().map(|o| o.raw()),
            challenge.header.as_deref(),
        );
        challenge
    }

    #[cfg(feature = "tempo")]
    fn require_bound_config(&self) -> Result<(&str, &str)> {
        let currency = self.currency().ok_or_else(|| {
            crate::error::MppError::InvalidConfig(
                "currency not configured — use Mpp::create() or set currency".into(),
            )
        })?;
        let recipient = self.config.recipient.as_deref().ok_or_else(|| {
            crate::error::MppError::InvalidConfig(
                "recipient not configured — use Mpp::create() or set recipient".into(),
            )
        })?;
        Ok((currency, recipient))
    }

    /// Generate one charge challenge per accepted currency, in order.
    ///
    /// Servers created with [`Mpp::create()`] on Tempo mainnet or Moderato
    /// accept OUSD first by default (see [`tempo()`](crate::server::tempo)). Return
    /// every challenge in the 402 response (for example with
    /// [`format_www_authenticate_many()`](crate::protocol::core::format_www_authenticate_many))
    /// so clients can pay with any accepted currency. A credential for any of
    /// these challenges verifies against this handler.
    ///
    /// `amount` is in dollars (e.g., `"0.10"` for 10 cents), converted using
    /// the configured decimals (default: 6). Even a single accepted currency
    /// returns a one-element vector.
    ///
    /// Requires currency and recipient to be bound (via [`Mpp::create()`]).
    #[cfg(feature = "tempo")]
    pub fn charge(&self, amount: &str) -> Result<Vec<PaymentChallenge>> {
        self.charge_with_options(amount, crate::server::ChargeOptions::default())
    }

    /// Generate one body-bound charge challenge per accepted currency.
    ///
    /// See [`charge()`](Self::charge).
    #[cfg(feature = "tempo")]
    pub fn charge_with_body(&self, amount: &str, body: &[u8]) -> Result<Vec<PaymentChallenge>> {
        self.charge_with_options_and_body(amount, crate::server::ChargeOptions::default(), body)
    }

    /// Generate one charge challenge per accepted currency with additional options.
    ///
    /// See [`charge()`](Self::charge).
    #[cfg(feature = "tempo")]
    pub fn charge_with_options(
        &self,
        amount: &str,
        options: crate::server::ChargeOptions<'_>,
    ) -> Result<Vec<PaymentChallenge>> {
        self.require_bound_config()?;
        self.config
            .currencies
            .iter()
            .map(|currency| self.charge_for_currency(amount, currency, &options))
            .collect()
    }

    /// Generate one body-bound charge challenge per accepted currency.
    ///
    /// See [`charge()`](Self::charge).
    #[cfg(feature = "tempo")]
    pub fn charge_with_options_and_body(
        &self,
        amount: &str,
        options: crate::server::ChargeOptions<'_>,
        body: &[u8],
    ) -> Result<Vec<PaymentChallenge>> {
        Ok(self
            .charge_with_options(amount, options)?
            .into_iter()
            .map(|challenge| self.with_body_digest(challenge, body))
            .collect())
    }

    /// Generate a charge challenge for one bound currency.
    #[cfg(feature = "tempo")]
    fn charge_for_currency(
        &self,
        amount: &str,
        currency: &str,
        options: &crate::server::ChargeOptions<'_>,
    ) -> Result<PaymentChallenge> {
        let (_, recipient) = self.require_bound_config()?;
        let base_units = crate::server::parse_dollar_amount(amount, self.config.decimals)?;
        let mut request = ChargeRequest {
            amount: base_units,
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            description: options.description.map(|s| s.to_string()),
            external_id: options.external_id.map(|s| s.to_string()),
            mppx_scope: options.mppx_scope.cloned(),
            ..Default::default()
        };
        {
            let mut details = serde_json::Map::new();
            if options.fee_payer || self.config.fee_payer {
                details.insert("feePayer".into(), serde_json::json!(true));
            }
            if self.config.machine_token_enabled {
                details.insert("machineTokenEnabled".into(), serde_json::json!(true));
            }
            if let Some(chain_id) = self.config.chain_id {
                details.insert("chainId".into(), serde_json::json!(chain_id));
            }
            if let Some(supported_modes) = options.supported_modes {
                validate_charge_modes(supported_modes)?;
                details.insert("supportedModes".into(), serde_json::json!(supported_modes));
            }
            if !details.is_empty() {
                request.method_details = Some(serde_json::Value::Object(details));
            }
        }
        let challenge = crate::protocol::methods::tempo::charge_challenge_with_options(
            &self.config.secret_key,
            &self.config.realm,
            &request,
            options.expires,
            options.description,
        )?;
        Ok(self.apply_pinned_opaque(challenge))
    }

    /// Generate a charge challenge with explicit parameters (base units).
    ///
    /// Use this when you want to specify amount, currency, and recipient
    /// per-call instead of using bound defaults. Amount is in base units
    /// (e.g., `"1000000"` for 1 pathUSD).
    #[cfg(feature = "tempo")]
    pub fn charge_challenge(
        &self,
        amount: &str,
        currency: &str,
        recipient: &str,
    ) -> Result<PaymentChallenge> {
        let request = ChargeRequest {
            amount: amount.to_string(),
            currency: currency.to_string(),
            recipient: Some(recipient.to_string()),
            ..Default::default()
        };
        self.charge_challenge_with_options(&request, None, None)
    }

    /// Generate a charge challenge with full options (base units).
    #[cfg(feature = "tempo")]
    pub fn charge_challenge_with_options(
        &self,
        request: &ChargeRequest,
        expires: Option<&str>,
        description: Option<&str>,
    ) -> Result<PaymentChallenge> {
        // Verification fails closed on a missing `chainId` when one is pinned,
        // so a caller-built request must carry it like `charge()` requests do.
        let mut request = request.clone();
        if let Some(chain_id) = self.config.chain_id {
            let details = request
                .method_details
                .get_or_insert_with(|| serde_json::json!({}));
            if let Some(details) = details.as_object_mut() {
                details
                    .entry("chainId")
                    .or_insert_with(|| serde_json::json!(chain_id));
            }
        }
        let challenge = crate::protocol::methods::tempo::charge_challenge_with_options(
            &self.config.secret_key,
            &self.config.realm,
            &request,
            expires,
            description,
        )?;
        Ok(self.apply_pinned_opaque(challenge))
    }

    /// The charge request [`charge_with_options()`](Self::charge_with_options)
    /// issues for `amount` and `options`: what a route with that price expects
    /// a credential to have paid.
    ///
    /// Pass it to the `*_with_expected_request` verification methods, for
    /// example to validate without accepting payment or to verify a
    /// body-bound challenge. It names the first accepted currency; credentials
    /// for the other accepted currencies match it too.
    #[cfg(feature = "tempo")]
    pub fn expected_charge_request(
        &self,
        amount: &str,
        options: crate::server::ChargeOptions<'_>,
    ) -> Result<ChargeRequest> {
        let (currency, _) = self.require_bound_config()?;
        self.charge_for_currency(amount, currency, &options)?
            .request
            .decode()
    }

    #[cfg(any(feature = "tempo", feature = "stripe"))]
    fn with_body_digest(&self, mut challenge: PaymentChallenge, body: &[u8]) -> PaymentChallenge {
        let digest = crate::body_digest::compute(body);
        challenge.id = crate::protocol::core::compute_challenge_id_with_header(
            &self.config.secret_key,
            &challenge.realm,
            challenge.method.as_str(),
            challenge.intent.as_str(),
            challenge.request.raw(),
            challenge.expires.as_deref(),
            Some(&digest),
            challenge.opaque.as_ref().map(|o| o.raw()),
            challenge.header.as_deref(),
        );
        challenge.digest = Some(digest);
        challenge
    }
}

// ==================== Stripe charge helpers ====================

#[cfg(feature = "stripe")]
impl<S> Mpp<crate::protocol::methods::stripe::method::ChargeMethod, S> {
    /// Generate a Stripe charge challenge for a dollar amount.
    ///
    /// Creates a `method=stripe`, `intent=charge` challenge with HMAC-bound ID.
    pub fn stripe_charge(&self, amount: &str) -> Result<PaymentChallenge> {
        self.stripe_charge_with_options(amount, crate::server::StripeChargeOptions::default())
    }

    /// Generate a Stripe charge challenge and bind it to the actual request body bytes.
    pub fn stripe_charge_with_body(&self, amount: &str, body: &[u8]) -> Result<PaymentChallenge> {
        self.stripe_charge_with_options_and_body(
            amount,
            crate::server::StripeChargeOptions::default(),
            body,
        )
    }

    /// Generate a Stripe charge challenge with additional options.
    ///
    /// Accepts [`StripeChargeOptions`](crate::server::StripeChargeOptions) for description,
    /// external ID, expiration, and metadata.
    pub fn stripe_charge_with_options(
        &self,
        amount: &str,
        options: crate::server::StripeChargeOptions<'_>,
    ) -> Result<PaymentChallenge> {
        use time::{Duration, OffsetDateTime};

        use crate::protocol::methods::stripe::StripeMethodDetails;

        let base_units = crate::server::parse_dollar_amount(amount, self.config.decimals)?;
        let currency = self.currency().unwrap_or("usd");

        let details = StripeMethodDetails {
            network_id: self.method.network_id().to_string(),
            payment_method_types: self.method.payment_method_types().to_vec(),
            metadata: options.metadata.cloned(),
        };

        let request = ChargeRequest {
            amount: base_units,
            currency: currency.to_string(),
            description: options.description.map(|s| s.to_string()),
            external_id: options.external_id.map(|s| s.to_string()),
            method_details: Some(serde_json::to_value(&details).map_err(|e| {
                crate::error::MppError::InvalidConfig(format!(
                    "failed to serialize methodDetails: {e}"
                ))
            })?),
            mppx_scope: options.mppx_scope.cloned(),
            ..Default::default()
        };

        let encoded_request = Base64UrlJson::from_typed(&request)?;

        let expires = if let Some(exp) = options.expires {
            exp.to_string()
        } else {
            let expiry_time = OffsetDateTime::now_utc() + Duration::minutes(5);
            expiry_time
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| {
                    crate::error::MppError::InvalidConfig(format!("failed to format expires: {e}"))
                })?
        };

        let id = crate::protocol::core::compute_challenge_id(
            &self.config.secret_key,
            &self.config.realm,
            crate::protocol::methods::stripe::METHOD_NAME,
            crate::protocol::methods::stripe::INTENT_CHARGE,
            encoded_request.raw(),
            Some(&expires),
            None,
            None,
        );

        Ok(self.apply_pinned_opaque(PaymentChallenge {
            id,
            realm: self.config.realm.clone(),
            method: crate::protocol::methods::stripe::METHOD_NAME.into(),
            intent: crate::protocol::methods::stripe::INTENT_CHARGE.into(),
            request: encoded_request,
            expires: Some(expires),
            description: options.description.map(|s| s.to_string()),
            digest: None,
            opaque: None,
            header: None,
        }))
    }

    /// Generate a Stripe charge challenge with options and bind it to the actual request body bytes.
    pub fn stripe_charge_with_options_and_body(
        &self,
        amount: &str,
        options: crate::server::StripeChargeOptions<'_>,
        body: &[u8],
    ) -> Result<PaymentChallenge> {
        let challenge = self.stripe_charge_with_options(amount, options)?;
        Ok(self.with_body_digest(challenge, body))
    }

    /// The charge request
    /// [`stripe_charge_with_options()`](Self::stripe_charge_with_options)
    /// issues for `amount` and `options`: what a route with that price expects
    /// a credential to have paid.
    ///
    /// Pass it to the `*_with_expected_request` verification methods, for
    /// example to validate without accepting payment or to verify a
    /// body-bound challenge.
    pub fn stripe_expected_charge_request(
        &self,
        amount: &str,
        options: crate::server::StripeChargeOptions<'_>,
    ) -> Result<ChargeRequest> {
        self.stripe_charge_with_options(amount, options)?
            .request
            .decode()
    }
}
