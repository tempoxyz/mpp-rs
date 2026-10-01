use crate::proxy::service::{Service, ServiceBuilder};

/// Create an Anthropic service configuration.
///
/// Injects the `x-api-key` header for upstream authentication.
///
/// # Example
///
/// ```
/// use mpp::proxy::service::{Endpoint, PaidEndpoint, ServiceBuilder};
/// use mpp::proxy::services::anthropic;
///
/// let svc = anthropic::service("sk-ant-...", |r| {
///     r.route(
///         "POST /v1/messages",
///         Endpoint::Paid(
///             PaidEndpoint::new("tempo", "charge", "30000")
///                 .with_decimals(6)
///                 .with_description("Message"),
///         ),
///     )
/// });
///
/// assert_eq!(svc.id, "anthropic");
/// assert_eq!(svc.headers.get("x-api-key").unwrap(), "sk-ant-...");
/// ```
pub fn service(api_key: &str, configure: impl FnOnce(ServiceBuilder) -> ServiceBuilder) -> Service {
    configure(Service::new("anthropic", "https://api.anthropic.com").header("x-api-key", api_key))
        .build()
}
