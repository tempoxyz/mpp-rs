//! Payment method implementations for Web Payment Auth.
//!
//! This module provides method-specific types and helpers.
//!
//! # Available Methods
//!
//! - [`tempo`]: Tempo blockchain (requires `tempo` feature)
//!
//! # Architecture
//!
//! ```text
//! methods/
//! └── tempo/      # Tempo-specific (chain_id=42431, TIP-20, 2D nonces)
//!     ├── types.rs    # TempoMethodDetails
//!     └── charge.rs   # TempoChargeExt trait
//! ```
//!
//! Shared EVM utilities (Address, U256, parsing) are in the top-level `evm` module.

#[cfg(feature = "tempo")]
pub mod tempo;
