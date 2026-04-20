//! Paid API proxy that gates upstream services behind the 402 protocol.
//!
//! Routes incoming requests to upstream APIs (OpenAI, Anthropic, etc.),
//! requires payment for configured endpoints, and provides service discovery.
//!
//! This module provides the routing/config/discovery layer only — actual HTTP
//! proxying is left to the consumer (e.g., via `reqwest` or `hyper`).

pub mod service;
pub mod services;

pub use service::{
    generate_openapi, Endpoint, PaidEndpoint, ProxyConfig, Route, Service, ServiceBuilder,
};
