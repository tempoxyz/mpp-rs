//! Server-side payment verification.
//!
//! # Simple API
//!
//! ```ignore
//! use mpp::server::{Mpp, tempo, TempoConfig};
//!
//! let mpp = Mpp::create(tempo(TempoConfig {
//!     recipient: "0xabc...123",
//! }))?;
//!
//! // Charge $0.10 — everything else has smart defaults
//! let challenge = mpp.charge("0.10")?;
//! ```
//!
//! # Advanced API
//!
//! ```ignore
//! use mpp::server::{Mpp, tempo_provider, TempoChargeMethod};
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
//! let method = TempoChargeMethod::new(provider);
//! let payment = Mpp::new(method, "api.example.com", "my-server-secret");
//!
//! let challenge = payment.charge_challenge("1000000", "0x...", "0x...")?;
//! let receipt = payment.verify(&credential, &request).await?;
//! ```

mod amount;
mod mpp;
pub mod sse;

#[cfg(feature = "tower")]
pub mod middleware;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "tempo")]
mod tempo;

#[cfg(feature = "stripe")]
mod stripe;

pub use crate::protocol::traits::{ChargeMethod, ErrorCode, SessionMethod, VerificationError};
pub use amount::{parse_dollar_amount, AmountError};
pub use mpp::{Mpp, SessionVerifyResult};

// Re-export tempo types at server level for backward compatibility
#[cfg(feature = "tempo")]
pub use tempo::{
    tempo, tempo_provider, SessionChannelStore, SessionMethodConfig, TempoBuilder, TempoChargeExt,
    TempoChargeMethod, TempoConfig, TempoMethodDetails, TempoProvider, TempoSessionMethod,
    CHAIN_ID, METHOD_NAME,
};

// Re-export stripe types at server level for backward compatibility
#[cfg(feature = "stripe")]
pub use stripe::{
    stripe, StripeBuilder, StripeChargeMethod, StripeChargeOptions, StripeConfig,
    StripeCredentialPayload, StripeMethodDetails,
};

// ==================== Shared Types ====================

/// Options for [`Mpp::session_challenge_with_details()`].
#[derive(Debug, Default)]
pub struct SessionChallengeOptions<'a> {
    /// Unit type label (e.g., "token", "byte", "request"). Optional.
    pub unit_type: Option<&'a str>,
    /// Suggested deposit amount in base units.
    pub suggested_deposit: Option<&'a str>,
    /// Enable fee sponsorship.
    pub fee_payer: bool,
    /// Human-readable description.
    pub description: Option<&'a str>,
    /// Custom expiration (ISO 8601). Default: none.
    pub expires: Option<&'a str>,
}

/// Options for [`Mpp::charge_with_options()`].
#[derive(Debug, Default)]
pub struct ChargeOptions<'a> {
    /// Human-readable description.
    pub description: Option<&'a str>,
    /// Merchant reference ID.
    pub external_id: Option<&'a str>,
    /// Custom expiration (ISO 8601). Default: now + 5 minutes.
    pub expires: Option<&'a str>,
    /// Enable fee sponsorship.
    pub fee_payer: bool,
}
