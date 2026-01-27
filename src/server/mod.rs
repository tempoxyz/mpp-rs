//! Server-side payment verification.
//!
//! This module provides the server-side API for verifying payment credentials.
//!
//! # Exports
//!
//! - [`ChargeMethod`]: Trait for verifying charge intent payments
//! - [`VerificationError`]: Error type for verification failures
//! - [`ErrorCode`]: Error codes for programmatic handling
//! - [`tempo`]: Tempo-specific verification (feature-gated)
//!
//! # Example
//!
//! ```ignore
//! use mpay::server::{ChargeMethod, tempo};
//!
//! let method = tempo::ChargeMethod::new(provider);
//! let receipt = method.verify(&credential, &request).await?;
//! ```

pub use crate::protocol::traits::{ChargeMethod, ErrorCode, VerificationError};

/// Tempo-specific server verification.
#[cfg(feature = "tempo")]
pub mod tempo {
    pub use crate::protocol::methods::tempo::{
        ChargeMethod, TempoChargeExt, TempoMethodDetails, CHAIN_ID, METHOD_NAME,
    };
}
