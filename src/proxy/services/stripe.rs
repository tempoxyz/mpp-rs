use crate::proxy::service::{Service, ServiceBuilder};
use base64::Engine;

/// Create a Stripe service configuration.
///
/// Injects `Authorization: Basic` header (API key as username) for upstream authentication.
///
/// # Example
///
/// ```
/// use mpp::proxy::service::{Endpoint, ServiceBuilder};
/// use mpp::proxy::services::stripe;
///
/// let svc = stripe::service("sk_test_123", |r| {
///     r.route("POST /v1/charges", Endpoint::Paid(mpp::proxy::service::PaidEndpoint {
///         intent: "charge".into(),
///         amount: "1".into(),
///         unit_type: None,
///         description: None,
///     }))
///     .route("GET /v1/customers/:id", Endpoint::Free)
/// });
///
/// assert_eq!(svc.id, "stripe");
/// ```
pub fn service(api_key: &str, configure: impl FnOnce(ServiceBuilder) -> ServiceBuilder) -> Service {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{api_key}:"));
    configure(
        Service::new("stripe", "https://api.stripe.com")
            .header("Authorization", format!("Basic {encoded}")),
    )
    .build()
}
