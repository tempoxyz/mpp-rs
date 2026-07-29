//! Payment method implementations for Web Payment Auth.
//!
//! This module provides method-specific types and helpers.
//!
//! # Available Methods
//!
//! - [`evm`]: Generic EVM charge via EIP-3009 authorization (requires `evm` feature)
//! - [`tempo`]: Tempo blockchain (requires `tempo` feature)
//! - [`stripe`]: Stripe payments via SPTs (requires `stripe` feature)
//!
//! # Architecture
//!
//! ```text
//! methods/
//! ├── evm/        # Generic EVM (ERC-20 EIP-3009 TransferWithAuthorization)
//! │   ├── types.rs          # EvmMethodDetails, AuthorizationPayload
//! │   └── authorization.rs  # EIP-712 signing/recovery, challenge nonce
//! ├── tempo/      # Tempo-specific (chain_id=42431, TIP-20, 2D nonces)
//! │   ├── types.rs    # TempoMethodDetails
//! │   └── charge.rs   # TempoChargeExt trait
//! └── stripe/     # Stripe SPT-based payments
//!     ├── types.rs    # StripeChargeRequest, StripeCredentialPayload
//!     └── method.rs   # ChargeMethod impl
//! ```
//!
//! Shared EVM utilities (Address, U256, parsing) are in the top-level `evm` module.

#[cfg(feature = "evm")]
pub mod evm;

#[cfg(feature = "tempo")]
pub mod tempo;

#[cfg(feature = "stripe")]
pub mod stripe;
