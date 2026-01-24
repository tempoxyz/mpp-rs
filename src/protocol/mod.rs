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
//! │  ChargeRequest, AuthorizeRequest, SubscriptionRequest           │
//! │  (All string fields - no blockchain types)                      │
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
//! ```ignore
//! use mpp_rs::protocol::core::*;
//! use mpp_rs::protocol::intents::ChargeRequest;
//!
//! let challenge = parse_www_authenticate(header)?;
//! if challenge.intent.is_charge() {
//!     let req: ChargeRequest = challenge.request.decode()?;
//!     println!("Amount: {}", req.amount);
//! }
//! ```
//!
//! ## EVM-specific accessors (with "evm" feature)
//!
//! ```ignore
//! use mpp_rs::protocol::intents::ChargeRequest;
//! use mpp_rs::protocol::methods::evm::{EvmChargeExt, Address, U256};
//!
//! let req: ChargeRequest = challenge.request.decode()?;
//! let amount: U256 = req.amount_u256()?;
//! let recipient: Address = req.recipient_address()?;
//! ```
//!
//! ## Tempo-specific accessors (with "tempo" feature)
//!
//! ```ignore
//! use mpp_rs::protocol::intents::ChargeRequest;
//! use mpp_rs::protocol::methods::tempo::TempoChargeExt;
//!
//! let req: ChargeRequest = challenge.request.decode()?;
//! let nonce_key = req.nonce_key();
//! let fee_token = req.fee_token();
//! ```

pub mod core;
pub mod intents;
pub mod methods;
