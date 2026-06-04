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
///         amount: "100".into(),
///         decimals: Some(2),
///         currency: None,
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
            .header("Authorization", format!("Basic {encoded}"))
            .strip_request_header("Stripe-Account"),
    )
    .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stripe_service_strips_caller_supplied_stripe_account() {
        let svc = service("sk_test_abc", |r| r);

        let mut headers = vec![
            (
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
            ("Stripe-Account".into(), "acct_evil".into()),
        ];
        svc.apply_request_headers(&mut headers);

        let names: Vec<String> = headers.iter().map(|(n, _)| n.to_lowercase()).collect();
        assert!(
            !names.contains(&"stripe-account".to_string()),
            "Stripe-Account must be stripped, got: {names:?}"
        );
        let auth = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            .expect("Authorization must be injected");
        assert!(
            auth.1.starts_with("Basic "),
            "expected Basic auth, got: {}",
            auth.1
        );
    }

    #[test]
    fn test_stripe_account_strip_is_case_insensitive() {
        let svc = service("sk_test_abc", |r| r);
        let mut headers = vec![("stripe-account".into(), "acct_evil".into())];
        svc.apply_request_headers(&mut headers);
        assert!(headers
            .iter()
            .all(|(n, _)| !n.eq_ignore_ascii_case("stripe-account")));
    }

    #[test]
    fn test_apply_proxy_request_headers_pipeline() {
        use crate::proxy::service::apply_proxy_request_headers;

        let svc = service("sk_test_abc", |r| r);
        let mut headers = vec![
            ("Authorization".into(), "Payment evil".into()),
            ("Stripe-Account".into(), "acct_evil".into()),
            ("Connection".into(), "keep-alive".into()),
            ("X-Forwarded-For".into(), "1.2.3.4".into()),
            ("Cookie".into(), "sid=abc".into()),
            (
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ),
        ];

        apply_proxy_request_headers(&svc, &mut headers);

        let names: Vec<String> = headers.iter().map(|(n, _)| n.to_lowercase()).collect();
        for forbidden in ["stripe-account", "connection", "x-forwarded-for", "cookie"] {
            assert!(
                !names.contains(&forbidden.to_string()),
                "{forbidden} must be stripped, got: {names:?}"
            );
        }
        assert!(names.contains(&"content-type".to_string()));
        let auth = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            .expect("injected Authorization must survive");
        assert!(
            auth.1.starts_with("Basic "),
            "caller's Payment Authorization must be replaced with injected Basic, got: {}",
            auth.1
        );
    }
}
