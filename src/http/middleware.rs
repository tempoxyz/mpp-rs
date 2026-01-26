//! reqwest-middleware integration for automatic 402 handling.
//!
//! Provides `PaymentMiddleware` for use with `reqwest_middleware::ClientBuilder`.

use anyhow::Context;
use async_trait::async_trait;
use reqwest::header::WWW_AUTHENTICATE;
use reqwest::{Request, Response, StatusCode};
use reqwest_middleware::{Middleware, Next};

use super::provider::PaymentProvider;
use crate::protocol::core::{format_authorization, parse_www_authenticate, AUTHORIZATION_HEADER};

/// Middleware that automatically handles 402 Payment Required responses.
///
/// When a request returns 402, the middleware:
/// 1. Parses the challenge from the `WWW-Authenticate` header
/// 2. Calls the provider to execute the payment
/// 3. Retries the request with the credential in the `Authorization` header
///
/// # Examples
///
/// ```ignore
/// use mpay::http::{PaymentMiddleware, TempoProvider};
/// use reqwest_middleware::ClientBuilder;
///
/// let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz");
///
/// let client = ClientBuilder::new(reqwest::Client::new())
///     .with(PaymentMiddleware::new(provider))
///     .build();
///
/// // All requests through this client automatically handle 402
/// let resp = client.get("https://api.example.com/paid").send().await?;
/// ```
pub struct PaymentMiddleware<P> {
    provider: P,
}

impl<P> PaymentMiddleware<P> {
    /// Create a new payment middleware with the given provider.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

#[async_trait]
impl<P> Middleware for PaymentMiddleware<P>
where
    P: PaymentProvider + 'static,
{
    async fn handle(
        &self,
        req: Request,
        extensions: &mut http_types::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let retry_req = req.try_clone();
        let resp = next.clone().run(req, extensions).await?;

        if resp.status() != StatusCode::PAYMENT_REQUIRED {
            return Ok(resp);
        }

        let retry_req = retry_req
            .context("request could not be cloned for payment retry")
            .map_err(reqwest_middleware::Error::Middleware)?;

        let www_auth = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .context("402 response missing WWW-Authenticate header")
            .map_err(reqwest_middleware::Error::Middleware)?
            .to_str()
            .context("invalid WWW-Authenticate header")
            .map_err(reqwest_middleware::Error::Middleware)?;

        let challenge = parse_www_authenticate(www_auth)
            .context("invalid challenge")
            .map_err(reqwest_middleware::Error::Middleware)?;

        let credential = self
            .provider
            .pay(&challenge)
            .await
            .context("payment failed")
            .map_err(reqwest_middleware::Error::Middleware)?;

        let auth_header = format_authorization(&credential)
            .context("failed to format credential")
            .map_err(reqwest_middleware::Error::Middleware)?;

        let mut retry_req = retry_req;
        retry_req.headers_mut().insert(
            AUTHORIZATION_HEADER,
            auth_header
                .parse()
                .context("invalid authorization header")
                .map_err(reqwest_middleware::Error::Middleware)?,
        );

        next.run(retry_req, extensions).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockProvider;

    impl PaymentProvider for MockProvider {
        async fn pay(
            &self,
            _challenge: &crate::protocol::core::PaymentChallenge,
        ) -> Result<crate::protocol::core::PaymentCredential, crate::error::MppError> {
            unimplemented!("mock provider")
        }
    }

    #[test]
    fn test_middleware_new() {
        let _middleware = PaymentMiddleware::new(MockProvider);
    }
}
