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
    fn set_credential(&self, request: Self::Request, credential: &str) -> Self::Request;
}

/// Reqwest HTTP transport for client-side payment handling.
///
/// - Detects payment required via 402 status
/// - Extracts challenges from `WWW-Authenticate` header
/// - Sends credentials via `Authorization` header
///
/// This is the default transport, matching mppx's `Transport.http()`.
#[cfg(feature = "client")]
pub struct HttpTransport;

/// Create an HTTP transport instance.
#[cfg(feature = "client")]
pub fn http() -> HttpTransport {
    HttpTransport
}

#[cfg(feature = "client")]
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
        let header = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .ok_or_else(|| MppError::MissingHeader("WWW-Authenticate".to_string()))?;

        let header_str = header.to_str().map_err(|e| {
            MppError::MalformedCredential(Some(format!("invalid WWW-Authenticate header: {e}")))
        })?;

        crate::protocol::core::parse_www_authenticate(header_str)
    }

    fn set_credential(&self, request: Self::Request, credential: &str) -> Self::Request {
        request.header(reqwest::header::AUTHORIZATION, credential)
    }
}

#[cfg(all(test, feature = "client"))]
mod tests {
    use super::*;

    #[test]
    fn test_http_transport_name() {
        let transport = http();
        assert_eq!(transport.name(), "http");
    }
}
