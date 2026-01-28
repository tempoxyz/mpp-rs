//! Server-side payment verification.
//!
//! This module provides the server-side API for verifying payment credentials.
//!
//! # Exports
//!
//! - [`ChargeMethod`]: Trait for verifying charge intent payments
//! - [`VerificationError`]: Error type for verification failures
//! - [`ErrorCode`]: Error codes for programmatic handling
//! - [`TempoChargeMethod`]: Tempo blockchain verification (requires `tempo`)
//!
//! # Example
//!
//! ```ignore
//! use mpay::server::{ChargeMethod, TempoChargeMethod};
//!
//! let method = TempoChargeMethod::new(provider);
//! let receipt = method.verify(&credential, &request).await?;
//! ```

pub use crate::protocol::traits::{ChargeMethod, ErrorCode, VerificationError};

#[cfg(feature = "tempo")]
pub use crate::protocol::methods::tempo::ChargeMethod as TempoChargeMethod;

#[cfg(feature = "tempo")]
pub use crate::protocol::methods::tempo::{
    TempoChargeExt, TempoMethodDetails, CHAIN_ID, METHOD_NAME,
};
