use crate::proxy::service::{Service, ServiceBuilder};

/// Create an OpenAI service configuration.
///
/// Injects `Authorization: Bearer` header for upstream authentication.
///
/// # Example
///
/// ```
/// use mpp::proxy::service::{Endpoint, PaidEndpoint, ServiceBuilder};
/// use mpp::proxy::services::openai;
///
/// let svc = openai::service("sk-...", |r| {
///     r.route("POST /v1/chat/completions", Endpoint::Paid(PaidEndpoint {
///         intent: "charge".into(),
///         amount: "0.05".into(),
///         unit_type: None,
///         description: Some("Chat completion".into()),
///     }))
///     .route("GET /v1/models", Endpoint::Free)
/// });
///
/// assert_eq!(svc.id, "openai");
/// ```
pub fn service(api_key: &str, configure: impl FnOnce(ServiceBuilder) -> ServiceBuilder) -> Service {
    configure(Service::new("openai", "https://api.openai.com").bearer(api_key)).build()
}
