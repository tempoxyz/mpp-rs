//! Extension trait for reqwest RequestBuilder.
//!
//! Provides `.send_with_payment()` method for opt-in per-request payment handling.

use reqwest::header::WWW_AUTHENTICATE;
use reqwest::{RequestBuilder, Response, StatusCode};

use super::error::HttpError;
use super::provider::PaymentProvider;
use crate::protocol::core::{format_authorization, parse_www_authenticate, AUTHORIZATION_HEADER};

/// Extension trait for `reqwest::RequestBuilder` with payment support.
///
/// This trait adds a `.send_with_payment()` method that automatically handles
/// HTTP 402 responses by executing a payment and retrying the request.
///
/// # Examples
///
/// ```ignore
/// use mpp::client::{Fetch, TempoProvider};
/// use reqwest::Client;
///
/// let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
/// let client = Client::new();
///
/// let resp = client
///     .get("https://api.example.com/paid")
///     .send_with_payment(&provider)
///     .await?;
/// ```
pub trait PaymentExt {
    /// Send the request, automatically handling 402 Payment Required responses.
    ///
    /// If the initial request returns 402:
    /// 1. Parse the challenge from the `WWW-Authenticate` header
    /// 2. Call `provider.pay()` to execute the payment
    /// 3. Retry the request with the credential in the `Authorization` header
    ///
    /// # Errors
    ///
    /// Returns `HttpError` if:
    /// - The request cannot be cloned (required for retry)
    /// - The 402 response is missing the `WWW-Authenticate` header
    /// - The challenge cannot be parsed
    /// - The payment fails
    /// - The retry request fails
    fn send_with_payment<P: PaymentProvider>(
        self,
        provider: &P,
    ) -> impl std::future::Future<Output = Result<Response, HttpError>> + Send;
}

impl PaymentExt for RequestBuilder {
    async fn send_with_payment<P: PaymentProvider>(
        self,
        provider: &P,
    ) -> Result<Response, HttpError> {
        let retry_builder = self.try_clone().ok_or(HttpError::CloneFailed)?;

        let resp = self.send().await?;

        if resp.status() != StatusCode::PAYMENT_REQUIRED {
            return Ok(resp);
        }

        let www_auth = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .ok_or(HttpError::MissingChallenge)?
            .to_str()
            .map_err(|e| HttpError::InvalidChallenge(e.to_string()))?;

        let challenge = parse_www_authenticate(www_auth)
            .map_err(|e| HttpError::InvalidChallenge(e.to_string()))?;

        let credential = provider.pay(&challenge).await?;

        let auth_header = format_authorization(&credential)
            .map_err(|e| HttpError::InvalidCredential(e.to_string()))?;

        let retry_resp = retry_builder
            .header(AUTHORIZATION_HEADER, auth_header)
            .send()
            .await?;

        Ok(retry_resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_payment_ext_trait_exists() {
        fn assert_payment_ext<T: PaymentExt>() {}
        assert_payment_ext::<RequestBuilder>();
    }
}
