//! Client-side payment providers.
//!
//! This module provides the client-side API for creating payment credentials.
//!
//! # Exports
//!
//! - [`PaymentProvider`]: Trait for payment providers
//! - [`Fetch`]: Extension trait for reqwest with `.send_with_payment()` method
//! - [`TempoProvider`]: Tempo blockchain provider (requires `tempo`)
//!
//! # Example
//!
//! ```ignore
//! use mpp::client::{Fetch, TempoProvider};
//!
//! let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz")?;
//! let resp = client.get(url).header("Accept-Payment", "tempo/charge")
//!     .send_with_payment(&provider).await?;
//! ```

#[cfg(feature = "client")]
mod accept_payment_policy;
#[cfg(feature = "client")]
pub(crate) mod challenge_selection;
mod error;
mod events;
mod provider;
pub mod transport;

#[cfg(feature = "ws")]
pub mod ws;

#[cfg(feature = "tempo")]
pub mod tempo;

#[cfg(feature = "client")]
mod charge_client;
#[cfg(feature = "client")]
pub mod directory;
#[cfg(feature = "client")]
mod fetch;
#[cfg(feature = "client")]
mod flow;
#[cfg(feature = "forward-proxy")]
mod forward_proxy;

#[cfg(feature = "middleware")]
mod middleware;

pub use error::HttpError;
pub use flow::{send_with_exchange, Exchange, FlowError};
pub use provider::{
    ManagementFuture, ManagementTransport, MultiProvider, PaymentContext, PaymentEventFuture,
    PaymentProvider, PendingPayment,
};

/// Default number of payment challenge retries after the initial 402 response.
#[cfg(any(feature = "client", feature = "middleware"))]
pub const DEFAULT_MAX_PAYMENT_RETRIES: usize = 3;

#[cfg(feature = "client")]
pub use accept_payment_policy::AcceptPaymentPolicy;

#[cfg(feature = "client")]
pub use events::{
    ChallengeReceivedContext, ClientEvent, ClientEventKind, ClientEventSubscription, ClientEvents,
    CredentialCreatedContext, DepositContext, PaymentFailedContext, PaymentFailureReason,
    PaymentResponseContext, PaymentUpdateContext,
};

#[cfg(feature = "client")]
pub use fetch::PaymentExt as Fetch;

#[cfg(feature = "client")]
pub use charge_client::ChargeClient;

#[cfg(feature = "forward-proxy")]
pub use forward_proxy::ForwardProxy;

#[cfg(feature = "middleware")]
pub use middleware::PaymentMiddleware;

// Re-export Tempo types at client level for convenience
#[cfg(feature = "tempo")]
pub use tempo::session::{channel_ops, TempoSessionProvider};
#[cfg(feature = "tempo")]
pub use tempo::{AutoswapConfig, TempoAccountsProvider, TempoClientError, TempoProvider};
#[cfg(feature = "tempo")]
pub use tempo_alloy::TempoNetwork;

// Re-export Stripe types at client level for convenience
#[cfg(feature = "stripe")]
pub mod stripe;
#[cfg(feature = "stripe")]
pub use stripe::StripeProvider;

pub(crate) fn payment_credential_header_name(
    challenge: &crate::protocol::core::PaymentChallenge,
) -> reqwest::header::HeaderName {
    reqwest::header::HeaderName::from_bytes(challenge.credential_header().as_bytes())
        .unwrap_or(reqwest::header::AUTHORIZATION)
}
