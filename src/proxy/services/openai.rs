use crate::proxy::service::{Service, ServiceBuilder};

/// Create an OpenAI service configuration.
///
/// Injects `Authorization: Bearer` header for upstream authentication and
/// strips caller-supplied `OpenAI-Organization` and `OpenAI-Project` headers,
/// which select the organization and project a request is billed to. Set
/// them with [`ServiceBuilder::header`] to pin one.
///
/// # Example
///
/// ```
/// use mpp::proxy::service::{Endpoint, PaidEndpoint, ServiceBuilder};
/// use mpp::proxy::services::openai;
///
/// let svc = openai::service("sk-...", |r| {
///     r.route(
///         "POST /v1/chat/completions",
///         Endpoint::Paid(
///             PaidEndpoint::new("tempo", "charge", "50000")
///                 .with_decimals(6)
///                 .with_description("Chat completion"),
///         ),
///     )
///     .route("GET /v1/models", Endpoint::Free)
/// });
///
/// assert_eq!(svc.id, "openai");
/// ```
pub fn service(api_key: &str, configure: impl FnOnce(ServiceBuilder) -> ServiceBuilder) -> Service {
    configure(
        Service::new("openai", "https://api.openai.com")
            .bearer(api_key)
            .strip_request_header("OpenAI-Organization")
            .strip_request_header("OpenAI-Project"),
    )
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_service_strips_caller_supplied_tenant_headers() {
        let svc = service("sk-abc", |r| r);

        let mut headers = vec![
            ("Content-Type".into(), "application/json".into()),
            ("OpenAI-Organization".into(), "org-evil".into()),
            ("openai-project".into(), "proj_evil".into()),
        ];
        svc.apply_request_headers(&mut headers);

        let names: Vec<String> = headers.iter().map(|(n, _)| n.to_lowercase()).collect();
        assert_eq!(names, ["content-type", "authorization"]);
    }
}
