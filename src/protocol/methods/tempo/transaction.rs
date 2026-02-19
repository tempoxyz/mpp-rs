//! Tempo transaction types for building and submitting transactions.
//!
//! This module re-exports transaction types from `tempo-alloy` and `tempo-primitives`
//! for building Tempo transactions (type 0x76).
//!
//! # Transaction Types
//!
//! - [`TempoTransactionRequest`]: Builder for Tempo transactions (from tempo-alloy)
//! - [`TempoTransaction`]: Full Tempo transaction with RLP encoding (from tempo-primitives)
//!
//! # Transaction Flow
//!
//! 1. **Client** builds a TempoTransaction (type 0x76), signs it, and returns
//!    it as a `transaction` credential
//! 2. **Server** submits via `tempo_sendTransaction` (direct or via fee payer)
//!
//! When `fee_payer` is `true`, the server forwards the signed transaction to
//! a fee payer service which adds its signature before broadcasting.
//!
//! # Examples
//!
//! Using the tempo-alloy transaction request builder:
//!
//! ```ignore
//! use mpp::protocol::methods::tempo::transaction::TempoTransactionRequest;
//! use alloy::primitives::{Address, U256};
//!
//! let request = TempoTransactionRequest::default()
//!     .with_nonce_key(U256::from(42u64))
//!     .with_fee_token(fee_token_address);
//!
//! // Build a TempoTransaction (0x76)
//! let tx = request.build_aa()?;
//! ```

/// Re-export TempoTransactionRequest from tempo-alloy.
///
/// This is the main builder type for Tempo transactions, wrapping alloy's
/// `TransactionRequest` with Tempo-specific fields:
/// - `fee_token`: Optional TIP-20 token for gas payment
/// - `nonce_key`: 2D nonce key for parallel transaction sessions
/// - `calls`: Optional multi-call support
/// - `tempo_authorization_list`: Tempo-specific authorization list
pub use tempo_alloy::rpc::TempoTransactionRequest;

/// Re-export TempoTransaction from tempo-primitives.
///
/// This is the full Tempo transaction type (0x76) with:
/// - RLP encoding/decoding
/// - 2D nonce system (nonce_key)
/// - Fee payer signature support
/// - Multi-call support
/// - TIP-20 fee token support
pub use tempo_primitives::TempoTransaction;

/// Re-export transaction primitives from tempo-primitives.
pub use tempo_primitives::transaction::{Call, SignatureType, TEMPO_TX_TYPE_ID};

/// JSON-RPC method name for Tempo transactions.
pub const TEMPO_SEND_TRANSACTION_METHOD: &str = "tempo_sendTransaction";
