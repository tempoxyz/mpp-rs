//! Payment protocol implementations for Web Payment Auth (IETF draft-ietf-httpauth-payment).
//!
//! This module provides a layered architecture for the Web Payment Auth protocol:
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                        Application Layer                         │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │
//! ┌────────────────────────────▼────────────────────────────────────┐
//! │                     Methods Layer (feature-gated)                │
//! │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
//! │  │  tempo  │  │  base   │  │  evm    │  │ stripe  │            │
//! │  │(88153)  │  │(84532)  │  │(shared) │  │(no evm) │            │
//! │  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │
//! ┌────────────────────────────▼────────────────────────────────────┐
//! │                      Intents Layer (always available)            │
//! │  ChargeRequest (string fields - no blockchain types)            │
//! └────────────────────────────┬────────────────────────────────────┘
//!                              │
//! ┌────────────────────────────▼────────────────────────────────────┐
//! │                       Core Layer (always available)              │
//! │  PaymentChallenge, PaymentCredential, PaymentReceipt            │
//! │  MethodName, IntentName, Base64UrlJson (newtypes)              │
//! │  Header parsing/formatting (no regex)                           │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Module Structure
//!
//! - [`core`]: Core protocol types with zero heavy dependencies (always available)
//! - [`intents`]: Intent-specific request types (always available)
//! - [`methods`]: Method-specific implementations (feature-gated)
//!
//! # Examples
//!
//! ## Parse a challenge (core layer only)
//!
//! ```
//! use mpay::protocol::core::*;
//! use mpay::protocol::intents::ChargeRequest;
//!
//! let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QifQ""#;
//! let challenge = parse_www_authenticate(header).unwrap();
//! if challenge.intent.is_charge() {
//!     let req: ChargeRequest = challenge.request.decode().unwrap();
//!     println!("Amount: {}", req.amount);
//! }
//! ```
//!
//! ## EVM-specific accessors (with "evm" feature)
//!
//! ```
//! use mpay::protocol::core::parse_www_authenticate;
//! use mpay::protocol::intents::ChargeRequest;
//! use mpay::protocol::methods::tempo::TempoChargeExt;
//! use mpay::evm::U256;
//!
//! let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiIweDEyMyIsInJlY2lwaWVudCI6IjB4NDU2In0""#;
//! let challenge = parse_www_authenticate(header).unwrap();
//! let req: ChargeRequest = challenge.request.decode().unwrap();
//! let amount: U256 = req.amount_u256().unwrap();
//! ```
//!
//! ## Tempo-specific accessors (with "tempo" feature)
//!
//! ```
//! use mpay::protocol::core::parse_www_authenticate;
//! use mpay::protocol::intents::ChargeRequest;
//! use mpay::protocol::methods::tempo::TempoChargeExt;
//!
//! let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QifQ""#;
//! let challenge = parse_www_authenticate(header).unwrap();
//! let req: ChargeRequest = challenge.request.decode().unwrap();
//! let nonce_key = req.nonce_key();
//! ```

pub mod core;
pub mod intents;
pub mod methods;
