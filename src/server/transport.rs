//! Server-side transport abstraction.
//!
//! Abstracts how challenges are issued and credentials are received
//! across different transport protocols (HTTP, WebSocket, MCP, etc.).
//!
//! This matches the mppx `Transport` interface from `mppx/server`.
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
//! use mpp::server::transport::{Transport, ChallengeContext};
//! use mpp::protocol::core::{PaymentChallenge, PaymentCredential, Receipt};
//!
//! struct MyTransport;
//!
//! impl Transport for MyTransport {
//!     type Input = MyRequest;
//!     type ChallengeOutput = MyResponse;
//!     type ReceiptOutput = MyResponse;
//!
//!     fn name(&self) -> &str { "custom" }
//!     // ...
//! }
//! ```

use crate::error::MppError;
use crate::protocol::core::{PaymentChallenge, PaymentCredential, Receipt};

/// Context passed to [`Transport::respond_challenge`].
pub struct ChallengeContext<'a, I> {
    /// The payment challenge to send to the client.
    pub challenge: &'a PaymentChallenge,
    /// The original transport input (e.g., HTTP request).
    pub input: &'a I,
    /// Optional error message for the client.
    pub error: Option<&'a str>,
}

/// Context passed to [`Transport::respond_receipt`].
pub struct ReceiptContext<'a, R> {
    /// The challenge ID this receipt corresponds to.
    pub challenge_id: &'a str,
    /// The payment receipt.
    pub receipt: &'a Receipt,
    /// The application response to attach the receipt to.
    pub response: R,
}

/// Server-side transport trait.
///
/// Abstracts how the server extracts credentials from incoming requests,
/// issues payment challenges, and attaches receipts to responses.
pub trait Transport: Send + Sync {
    /// The incoming request/message type (e.g., `http::Request<Body>`).
    type Input;
    /// The response type for payment challenges (e.g., `http::Response<Body>`).
    type ChallengeOutput;
    /// The response type after attaching a receipt.
    type ReceiptOutput;

    /// Transport name for identification (e.g., "http", "ws", "mcp").
    fn name(&self) -> &str;

    /// Extract a payment credential from the transport input.
    ///
    /// Returns `Ok(Some(credential))` if a valid credential is present,
    /// `Ok(None)` if no credential was provided (trigger challenge),
    /// or `Err` if the credential is malformed.
    fn get_credential(&self, input: &Self::Input) -> Result<Option<PaymentCredential>, MppError>;

    /// Create a transport response for a payment challenge.
    fn respond_challenge(&self, ctx: ChallengeContext<'_, Self::Input>) -> Self::ChallengeOutput;

    /// Attach a receipt to a successful response.
    fn respond_receipt(&self, ctx: ReceiptContext<'_, Self::ReceiptOutput>) -> Self::ReceiptOutput;
}

/// HTTP transport for server-side payment handling.
///
/// - Reads credentials from the `Authorization` header
/// - Issues challenges via `WWW-Authenticate` header with 402 status
/// - Attaches receipts via `Payment-Receipt` header
///
/// This is the default transport, matching mppx's `Transport.http()`.
pub struct HttpTransport;

/// Create an HTTP transport instance.
pub fn http() -> HttpTransport {
    HttpTransport
}

impl Transport for HttpTransport {
    type Input = http_types::Request<()>;
    type ChallengeOutput = http_types::Response<String>;
    type ReceiptOutput = http_types::Response<String>;

    fn name(&self) -> &str {
        "http"
    }

    fn get_credential(&self, input: &Self::Input) -> Result<Option<PaymentCredential>, MppError> {
        let header = match input.headers().get(http_types::header::AUTHORIZATION) {
            Some(v) => v,
            None => return Ok(None),
        };

        let header_str = header
            .to_str()
            .map_err(|e| MppError::MalformedCredential(Some(format!("invalid header: {e}"))))?;

        let payment = crate::protocol::core::extract_payment_scheme(header_str);
        let payment = match payment {
            Some(p) => p,
            None => return Ok(None),
        };

        // extract_payment_scheme returns the full "Payment ..." fragment
        let credential = crate::protocol::core::parse_authorization(payment).map_err(|e| {
            MppError::MalformedCredential(Some(format!("failed to parse credential: {e}")))
        })?;

        Ok(Some(credential))
    }

    fn respond_challenge(&self, ctx: ChallengeContext<'_, Self::Input>) -> Self::ChallengeOutput {
        let www_auth = crate::protocol::core::format_www_authenticate(ctx.challenge)
            .unwrap_or_else(|_| "Payment".to_string());

        let body = match ctx.error {
            Some(msg) => serde_json::json!({ "error": msg }).to_string(),
            None => serde_json::json!({ "error": "Payment Required" }).to_string(),
        };

        let mut resp = http_types::Response::builder()
            .status(http_types::StatusCode::PAYMENT_REQUIRED)
            .header(http_types::header::WWW_AUTHENTICATE, &www_auth)
            .header(http_types::header::CONTENT_TYPE, "application/json")
            .body(body)
            .expect("response builder cannot fail");

        // Add Cache-Control: no-store to prevent caching of challenges
        resp.headers_mut().insert(
            http_types::header::CACHE_CONTROL,
            http_types::HeaderValue::from_static("no-store"),
        );

        resp
    }

    fn respond_receipt(&self, ctx: ReceiptContext<'_, Self::ReceiptOutput>) -> Self::ReceiptOutput {
        let receipt_header =
            crate::protocol::core::format_receipt(ctx.receipt).unwrap_or_else(|_| String::new());

        let mut resp = ctx.response;
        if let Ok(value) = http_types::HeaderValue::from_str(&receipt_header) {
            resp.headers_mut()
                .insert(crate::protocol::core::PAYMENT_RECEIPT_HEADER, value);
        }
        resp
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
    fn test_http_get_credential_none() {
        let transport = http();
        let req = http_types::Request::builder()
            .uri("/test")
            .body(())
            .unwrap();
        let result = transport.get_credential(&req).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_http_get_credential_non_payment_auth() {
        let transport = http();
        let req = http_types::Request::builder()
            .uri("/test")
            .header("Authorization", "Bearer some-token")
            .body(())
            .unwrap();
        let result = transport.get_credential(&req).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_http_get_credential_valid_payment() {
        let transport = http();

        // Build a valid Payment authorization header
        let challenge = PaymentChallenge::new(
            "test-id",
            "test.example.com",
            "tempo",
            "charge",
            crate::protocol::core::Base64UrlJson::from_value(
                &serde_json::json!({"amount": "1000"}),
            )
            .unwrap(),
        );
        let credential = crate::protocol::core::PaymentCredential::new(
            challenge.to_echo(),
            crate::protocol::core::PaymentPayload::hash("0xdeadbeef"),
        );
        let auth_header = crate::protocol::core::format_authorization(&credential).unwrap();

        let req = http_types::Request::builder()
            .uri("/test")
            .header("Authorization", &auth_header)
            .body(())
            .unwrap();

        let result = transport.get_credential(&req).unwrap();
        assert!(result.is_some(), "should parse valid Payment credential");
        let parsed = result.unwrap();
        assert_eq!(parsed.challenge.id, "test-id");
    }

    #[test]
    fn test_http_respond_challenge() {
        let transport = http();
        let challenge = PaymentChallenge::new(
            "test-id",
            "test.example.com",
            "tempo",
            "charge",
            crate::protocol::core::Base64UrlJson::from_value(
                &serde_json::json!({"amount": "1000"}),
            )
            .unwrap(),
        );
        let req = http_types::Request::builder()
            .uri("/test")
            .body(())
            .unwrap();

        let resp = transport.respond_challenge(ChallengeContext {
            challenge: &challenge,
            input: &req,
            error: None,
        });

        assert_eq!(resp.status(), http_types::StatusCode::PAYMENT_REQUIRED);
        assert!(resp
            .headers()
            .get(http_types::header::WWW_AUTHENTICATE)
            .is_some());
        assert!(resp.body().contains("Payment Required"));
    }

    #[test]
    fn test_http_respond_challenge_with_error() {
        let transport = http();
        let challenge = PaymentChallenge::new(
            "test-id",
            "test.example.com",
            "tempo",
            "charge",
            crate::protocol::core::Base64UrlJson::from_value(
                &serde_json::json!({"amount": "1000"}),
            )
            .unwrap(),
        );
        let req = http_types::Request::builder()
            .uri("/test")
            .body(())
            .unwrap();

        let resp = transport.respond_challenge(ChallengeContext {
            challenge: &challenge,
            input: &req,
            error: Some("Verification failed"),
        });

        assert_eq!(resp.status(), http_types::StatusCode::PAYMENT_REQUIRED);
        assert!(resp.body().contains("Verification failed"));
    }

    #[test]
    fn test_http_respond_receipt() {
        let transport = http();
        let receipt = Receipt::success("tempo", "0xabc123");

        let resp = http_types::Response::builder()
            .status(http_types::StatusCode::OK)
            .body("ok".to_string())
            .unwrap();

        let resp = transport.respond_receipt(ReceiptContext {
            challenge_id: "ch-1",
            receipt: &receipt,
            response: resp,
        });

        assert_eq!(resp.status(), http_types::StatusCode::OK);
        assert!(resp
            .headers()
            .get(crate::protocol::core::PAYMENT_RECEIPT_HEADER)
            .is_some());
    }
}
