//! Paid API proxy that gates upstream services behind the 402 protocol.
//!
//! Provides routing/config/discovery plus header-stripping helpers. HTTP
//! forwarding is left to the consumer.

pub mod headers;
pub mod service;
pub mod services;

pub use headers::{
    is_request_header_stripped, is_response_header_stripped, scrub_request_headers,
    scrub_response_headers,
};
pub use service::{
    apply_proxy_request_headers, generate_openapi, Endpoint, PaidEndpoint, ProxyConfig, Route,
    Service, ServiceBuilder,
};
