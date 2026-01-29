//! Server-side payment verification.
//!
//! This module provides the server-side API for verifying payment credentials.
//!
//! # Exports
//!
//! - [`Mpay`]: Payment handler that binds method, realm, and secret_key
//! - [`ChargeMethod`]: Trait for verifying charge intent payments
//! - [`VerificationError`]: Error type for verification failures
//! - [`ErrorCode`]: Error codes for programmatic handling
//! - [`TempoChargeMethod`]: Tempo blockchain verification (requires `tempo`)
//!
//! # Example
//!
//! ```ignore
//! use mpay::server::{Mpay, tempo_provider, TempoChargeMethod};
//!
//! let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
//! let method = TempoChargeMethod::new(provider);
//!
//! // Create payment handler with bound secret_key
//! let payment = Mpay::new(method, "api.example.com", "my-server-secret");
//!
//! // Generate challenge (secretKey already bound)
//! let challenge = payment.charge_challenge("1000000", "0x...", "0x...")?;
//!
//! // Verify credential
//! let receipt = payment.verify(&credential, &request).await?;
//! ```

mod mpay;

pub use crate::protocol::traits::{ChargeMethod, ErrorCode, VerificationError};
pub use mpay::Mpay;

#[cfg(feature = "tempo")]
pub use crate::protocol::methods::tempo::ChargeMethod as TempoChargeMethod;

#[cfg(feature = "tempo")]
pub use crate::protocol::methods::tempo::{
    TempoChargeExt, TempoMethodDetails, CHAIN_ID, METHOD_NAME,
};

/// Create a Tempo-compatible provider for server-side verification.
///
/// This provider uses `TempoNetwork` which properly handles Tempo's
/// custom transaction type (0x76) and receipt format.
///
/// # Example
///
/// ```ignore
/// use mpay::server::{tempo_provider, TempoChargeMethod};
///
/// let provider = tempo_provider("https://rpc.moderato.tempo.xyz")?;
/// let method = TempoChargeMethod::new(provider);
/// ```
///
/// # Errors
///
/// Returns an error if the RPC URL is invalid.
#[cfg(feature = "tempo")]
pub fn tempo_provider(rpc_url: &str) -> crate::error::Result<TempoProvider> {
    use alloy::providers::ProviderBuilder;
    use tempo_alloy::TempoNetwork;

    let url = rpc_url
        .parse()
        .map_err(|e| crate::error::MppError::InvalidConfig(format!("invalid RPC URL: {}", e)))?;
    Ok(ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(url))
}

/// Type alias for the Tempo provider returned by [`tempo_provider`].
#[cfg(feature = "tempo")]
pub type TempoProvider = alloy::providers::fillers::FillProvider<
    alloy::providers::fillers::JoinFill<
        alloy::providers::Identity,
        alloy::providers::fillers::JoinFill<
            alloy::providers::fillers::NonceFiller,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::ChainIdFiller,
            >,
        >,
    >,
    alloy::providers::RootProvider<tempo_alloy::TempoNetwork>,
    tempo_alloy::TempoNetwork,
>;
