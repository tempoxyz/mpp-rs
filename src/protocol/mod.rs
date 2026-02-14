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
//! │  │(42431)  │  │(84532)  │  │(shared) │  │(no evm) │            │
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
//! │  PaymentChallenge, PaymentCredential, Receipt                   │
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
//! use mpp::protocol::core::*;
//! use mpp::protocol::intents::ChargeRequest;
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
#![cfg_attr(feature = "tempo", doc = "```")]
#![cfg_attr(not(feature = "tempo"), doc = "```ignore")]
//! use mpp::protocol::core::parse_www_authenticate;
//! use mpp::protocol::intents::ChargeRequest;
//! use mpp::protocol::methods::tempo::TempoChargeExt;
//! use mpp::evm::U256;
//!
//! let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiIweDEyMyIsInJlY2lwaWVudCI6IjB4NDU2In0""#;
//! let challenge = parse_www_authenticate(header).unwrap();
//! let req: ChargeRequest = challenge.request.decode().unwrap();
//! let amount: U256 = req.amount_u256().unwrap();
//! ```
//!
//! ## Tempo-specific accessors (with "tempo" feature)
//!
#![cfg_attr(feature = "tempo", doc = "```")]
#![cfg_attr(not(feature = "tempo"), doc = "```ignore")]
//! use mpp::protocol::core::parse_www_authenticate;
//! use mpp::protocol::intents::ChargeRequest;
//! use mpp::protocol::methods::tempo::TempoChargeExt;
//!
//! let header = r#"Payment id="abc", realm="api", method="tempo", intent="charge", request="eyJhbW91bnQiOiIxMDAwIiwiY3VycmVuY3kiOiJVU0QifQ""#;
//! let challenge = parse_www_authenticate(header).unwrap();
//! let req: ChargeRequest = challenge.request.decode().unwrap();
//! assert!(!req.fee_payer());
//! ```

pub mod core;
pub mod intents;

#[cfg(any(feature = "server", feature = "tempo"))]
pub mod methods;

#[cfg(feature = "server")]
pub mod traits;
