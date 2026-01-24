//! Shared EVM types and helpers for Web Payment Auth methods.
//!
//! This module provides the shared foundation for all EVM-based payment methods
//! (Tempo, Base, Ethereum, Polygon, etc.). It requires the `evm` feature.
//!
//! # Types
//!
//! - [`EvmMethodDetails`]: Method-specific details (chain_id, fee_payer)
//! - [`EvmChargeExt`]: Extension trait for ChargeRequest with typed accessors
//!
//! # Helpers
//!
//! - [`parse_address`]: Parse an Ethereum address from string
//! - [`parse_amount`]: Parse a U256 amount from string
//!
//! # Re-exports
//!
//! For convenience, this module re-exports `Address` and `U256` from alloy:
//!
//! ```ignore
//! use mpp_rs::protocol::methods::evm::{Address, U256};
//! ```
//!
//! # Examples
//!
//! ```ignore
//! use mpp_rs::protocol::intents::ChargeRequest;
//! use mpp_rs::protocol::methods::evm::{EvmChargeExt, Address, U256};
//!
//! let req: ChargeRequest = challenge.request.decode()?;
//! let amount: U256 = req.amount_u256()?;
//! let recipient: Address = req.recipient_address()?;
//! let chain_id = req.chain_id();
//! ```

pub mod charge;
pub mod helpers;
pub mod types;

// Re-export alloy primitives for convenience
pub use alloy::primitives::{Address, U256};

// Re-export module types
pub use charge::EvmChargeExt;
pub use helpers::{parse_address, parse_amount};
pub use types::EvmMethodDetails;
