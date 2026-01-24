//! Payment method implementations for Web Payment Auth.
//!
//! This module provides method-specific types and helpers. Each method is
//! feature-gated to minimize dependencies.
//!
//! # Available Methods
//!
//! - [`evm`]: Shared EVM types (requires `evm` feature)
//! - [`tempo`]: Tempo blockchain (requires `tempo` feature, implies `evm`)
//! - [`stripe`]: Stripe payments (requires `stripe` feature, no EVM deps)
//!
//! # Architecture
//!
//! ```text
//! methods/
//! ├── evm/        # Shared EVM foundation (alloy types)
//! │   ├── types.rs    # EvmMethodDetails
//! │   ├── helpers.rs  # parse_address, parse_amount
//! │   └── charge.rs   # EvmChargeExt trait
//! │
//! ├── tempo/      # Tempo-specific (chain_id=88153, TIP-20, 2D nonces)
//! │   ├── types.rs    # TempoMethodDetails
//! │   └── charge.rs   # TempoChargeExt trait
//! │
//! └── stripe/     # Non-EVM method (no blockchain deps)
//!     ├── types.rs    # StripeMethodDetails
//!     └── charge.rs   # StripeChargePayload
//! ```

#[cfg(feature = "evm")]
pub mod evm;

#[cfg(feature = "tempo")]
pub mod tempo;

#[cfg(feature = "stripe")]
pub mod stripe;
