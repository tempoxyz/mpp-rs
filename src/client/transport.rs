//! Client-side transport abstraction.
//!
//! Abstracts how challenges are received and credentials are sent
//! across different transport protocols (HTTP, WebSocket, MCP, etc.).
//!
//! This matches the mppx `Transport` interface from `mppx/client`.
//!
//! # Built-in transports
//!
//! - [`http()`]: HTTP transport (Authorization/WWW-Authenticate headers)
//!
//! # Custom transports
//!
//! Implement [`Transport`] for custom protocols:
//!
//! ```ignore
//! use mpp::client::transport::{Transport};
//! use mpp::protocol::core::PaymentChallenge;
//!
//! struct MyTransport;
//!
//! impl Transport for MyTransport {
//!     type Request = MyRequest;
//!     type Response = MyResponse;
//!
//!     fn name(&self) -> &str { "custom" }
//!     // ...
//! }
//! ```

use crate::error::MppError;
use crate::protocol::core::PaymentChallenge;

/// Client-side transport trait.
///
/// Abstracts how the client detects payment-required responses, extracts
/// challenges, and attaches credentials to requests.
pub trait Transport: Send + Sync {
    /// The outgoing request type.
    type Request;
    /// The incoming response type.
    type Response;

    /// Transport name for identification (e.g., "http", "ws", "mcp").
    fn name(&self) -> &str;

    /// Check if a response indicates payment is required.
    fn is_payment_required(&self, response: &Self::Response) -> bool;

    /// Extract the payment challenge from a payment-required response.
    fn get_challenge(&self, response: &Self::Response) -> Result<PaymentChallenge, MppError>;

    /// Attach a credential string to a request.
    ///
    /// When `challenge` is provided, the credential is placed in the HTTP field
    /// selected by that challenge (`Authorization` by default, or
    /// `Payment-Authorization` when advertised).
    fn set_credential(
        &self,
        request: Self::Request,
        credential: &str,
        challenge: Option<&PaymentChallenge>,
    ) -> Self::Request;
}

/// Reqwest HTTP transport for client-side payment handling.
///
/// - Detects payment required via 402 status
/// - Selects the first valid Payment challenge across repeated or combined headers
/// - Sends credentials via `Authorization` header
///
/// This is the default transport, matching mppx's `Transport.http()`.
pub struct HttpTransport;

/// Create an HTTP transport instance.
pub fn http() -> HttpTransport {
    HttpTransport
}

impl Transport for HttpTransport {
    type Request = reqwest::RequestBuilder;
    type Response = reqwest::Response;

    fn name(&self) -> &str {
        "http"
    }

    fn is_payment_required(&self, response: &Self::Response) -> bool {
        response.status() == reqwest::StatusCode::PAYMENT_REQUIRED
    }

    fn get_challenge(&self, response: &Self::Response) -> Result<PaymentChallenge, MppError> {
        let headers = response
            .headers()
            .get_all(reqwest::header::WWW_AUTHENTICATE);
        if headers.iter().next().is_none() {
            return Err(MppError::MissingHeader("WWW-Authenticate".to_string()));
        }
        crate::protocol::core::parse_www_authenticate_all_bytes(
            headers.iter().map(|header| header.as_bytes()),
        )
        .into_iter()
        .find_map(Result::ok)
        .ok_or_else(|| MppError::MalformedCredential(Some("no valid Payment challenge".into())))
    }

    fn set_credential(
        &self,
        request: Self::Request,
        credential: &str,
        challenge: Option<&PaymentChallenge>,
    ) -> Self::Request {
        let header = challenge
            .map(PaymentChallenge::credential_header)
            .unwrap_or("Authorization");
        request.header(header, credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_transport_name() {
        let transport = http();
        assert_eq!(transport.name(), "http");
    }
    #[test]
    fn test_http_transport_selects_first_valid_payment_offer() {
        let first =
            r#"Payment id="first", realm="api", method="tempo", intent="charge", request="e30""#;
        let second = first.replace("first", "second");
        for values in [
            vec![first.to_string()],
            vec![format!("{first}, {second}")],
            vec![first.to_string(), second.clone()],
            vec!["Bearer realm=api".into(), first.to_string()],
            vec![format!("Payment id=broken, {first}")],
        ] {
            let mut response = axum::http::Response::builder().status(402);
            for value in values {
                response = response.header("WWW-Authenticate", value);
            }
            let response = reqwest::Response::from(response.body("").unwrap());
            assert_eq!(http().get_challenge(&response).unwrap().id, "first");
        }
    }

    #[test]
    fn test_http_transport_decodes_latin1_field_values() {
        let response = axum::http::Response::builder()
            .status(402)
            .header(
                "WWW-Authenticate",
                axum::http::HeaderValue::from_bytes(
                    b"Payment id=\"latin1\", realm=\"caf\xe9\", method=\"tempo\", intent=\"charge\", request=\"e30\"",
                )
                .unwrap(),
            )
            .body("")
            .unwrap();
        let challenge = http()
            .get_challenge(&reqwest::Response::from(response))
            .unwrap();
        assert_eq!(challenge.realm, "caf\u{e9}");
    }

    #[test]
    fn test_http_transport_rejects_missing_or_invalid_offers() {
        for value in [None, Some("Bearer realm=api"), Some("Payment id=broken")] {
            let mut response = axum::http::Response::builder().status(402);
            if let Some(value) = value {
                response = response.header("WWW-Authenticate", value);
            }
            let response = reqwest::Response::from(response.body("").unwrap());
            assert!(http().get_challenge(&response).is_err());
        }
    }
}
