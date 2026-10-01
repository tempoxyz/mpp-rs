use crate::protocol::core::PaymentCredential;
use crate::proxy::headers::scrub_request_headers;
use serde_json::{json, Value};

/// Canonical proxy→upstream request-header pipeline: generic scrub, then
/// per-service strip/inject. Reversing the order would drop the injected
/// `Authorization`.
pub fn apply_proxy_request_headers(service: &Service, headers: &mut Vec<(String, String)>) {
    scrub_request_headers(headers);
    service.apply_request_headers(headers);
}

/// A proxied upstream service with route definitions.
#[derive(Debug, Clone)]
pub struct Service {
    /// Unique identifier used as the URL prefix (e.g., `"openai"` → `/{id}/...`).
    pub id: String,
    /// Base URL of the upstream service.
    pub base_url: String,
    /// Route definitions.
    pub routes: Vec<Route>,
    /// Headers to inject on upstream requests, in the order they are sent.
    pub headers: Vec<(String, String)>,
    /// Caller-supplied request headers to drop before forwarding (vendor-specific
    /// strips on top of [`crate::proxy::headers::scrub_request_headers`]).
    pub strip_request_headers: Vec<String>,
    /// Human-readable title.
    pub title: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
}

/// A route definition mapping a pattern to payment requirements.
#[derive(Debug, Clone)]
pub struct Route {
    /// HTTP method (e.g., "POST", "GET"). None means any method.
    pub method: Option<String>,
    /// URL path pattern (e.g., "/v1/chat/completions").
    pub path: String,
    /// The original pattern string (e.g., "POST /v1/chat/completions").
    pub pattern: String,
    /// Endpoint configuration.
    pub endpoint: Endpoint,
}

/// Endpoint payment configuration.
#[derive(Debug, Clone)]
pub enum Endpoint {
    /// Free passthrough — no payment required.
    Free,
    /// Payment required with these parameters.
    Paid(PaidEndpoint),
}

/// Payment parameters for a paid endpoint.
#[derive(Debug, Clone)]
pub struct PaidEndpoint {
    /// Payment intent (e.g., "charge", "session").
    pub intent: String,
    /// Amount in atomic units (e.g., "50000").
    pub amount: String,
    /// Number of decimal places for human-readable conversion (e.g., 6 means
    /// 50000 atomic units = 0.05).
    pub decimals: Option<u8>,
    /// Currency identifier (e.g., a contract address).
    pub currency: Option<String>,
    /// Unit type for session payments (e.g., "token", "request").
    pub unit_type: Option<String>,
    /// Description.
    pub description: Option<String>,
}

impl Service {
    /// Start building a new service.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(id: impl Into<String>, base_url: impl Into<String>) -> ServiceBuilder {
        ServiceBuilder {
            id: id.into(),
            base_url: base_url.into(),
            routes: Vec::new(),
            headers: Vec::new(),
            strip_request_headers: Vec::new(),
            title: None,
            description: None,
        }
    }

    /// Drop `strip_request_headers`, then upsert `headers`. Prefer
    /// [`apply_proxy_request_headers`] which composes this with the generic scrub.
    pub fn apply_request_headers(&self, headers: &mut Vec<(String, String)>) {
        headers.retain(|(name, _)| {
            !self
                .strip_request_headers
                .iter()
                .any(|s| s.eq_ignore_ascii_case(name))
        });
        for (name, value) in &self.headers {
            headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
            headers.push((name.clone(), value.clone()));
        }
    }
}

/// Builder for constructing a [`Service`].
#[derive(Debug)]
pub struct ServiceBuilder {
    id: String,
    base_url: String,
    routes: Vec<Route>,
    headers: Vec<(String, String)>,
    strip_request_headers: Vec<String>,
    title: Option<String>,
    description: Option<String>,
}

impl ServiceBuilder {
    /// Inject an `Authorization: Bearer {token}` header on upstream requests.
    pub fn bearer(self, token: impl Into<String>) -> Self {
        self.header("Authorization", format!("Bearer {}", token.into()))
    }

    /// Inject a custom header on upstream requests.
    ///
    /// Headers are injected in the order they are added. Adding a name again,
    /// in any letter case, replaces the earlier value.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(&name));
        self.headers.push((name, value.into()));
        self
    }

    /// Mark a caller-supplied request header to drop before forwarding (e.g. `Stripe-Account`).
    pub fn strip_request_header(mut self, name: impl Into<String>) -> Self {
        self.strip_request_headers.push(name.into());
        self
    }

    /// Set a human-readable title for the service.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set a human-readable description for the service.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add a route. `pattern` is `"METHOD /path"` or just `"/path"`.
    ///
    /// Routes are matched in the order they are added; see
    /// [`ProxyConfig::match_route`].
    pub fn route(mut self, pattern: &str, endpoint: Endpoint) -> Self {
        let (method, path) = parse_route_pattern(pattern);
        self.routes.push(Route {
            method,
            path,
            pattern: pattern.to_string(),
            endpoint,
        });
        self
    }

    /// Consume the builder and produce a [`Service`].
    pub fn build(self) -> Service {
        Service {
            id: self.id,
            base_url: self.base_url,
            routes: self.routes,
            headers: self.headers,
            strip_request_headers: self.strip_request_headers,
            title: self.title,
            description: self.description,
        }
    }
}

// ---------------------------------------------------------------------------
// Route pattern parsing & matching
// ---------------------------------------------------------------------------

const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// Parse a route pattern like `"POST /v1/chat/completions"` into (method, path).
fn parse_route_pattern(pattern: &str) -> (Option<String>, String) {
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    if tokens.len() >= 2 && HTTP_METHODS.contains(&tokens[0].to_uppercase().as_str()) {
        (Some(tokens[0].to_uppercase()), tokens[1..].join(" "))
    } else {
        (None, pattern.trim().to_string())
    }
}

/// Check if a URL path matches a route pattern path.
///
/// Supports `:param` segments as wildcards (e.g., `/v1/customers/:id` matches
/// `/v1/customers/cus_123`). A `:param` never matches a segment that a URL
/// parser would rewrite into a different path once the request is forwarded:
/// dot segments (`.`, `..`, also spelled with `%2e`) and segments containing a
/// backslash.
fn path_matches(pattern: &str, path: &str) -> bool {
    let pat_segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if pat_segments.len() != path_segments.len() {
        return false;
    }

    pat_segments
        .iter()
        .zip(path_segments.iter())
        .all(|(pat, seg)| {
            if pat.starts_with(':') {
                !is_dot_segment(seg) && !seg.contains('\\')
            } else {
                *pat == *seg
            }
        })
}

/// Whether `segment` is `.` or `..`, with `%2e` accepted for either dot.
fn is_dot_segment(segment: &str) -> bool {
    let mut rest = segment.as_bytes();
    let mut dots = 0;
    while !rest.is_empty() {
        rest = match rest {
            [b'.', tail @ ..] | [b'%', b'2', b'e' | b'E', tail @ ..] => tail,
            _ => return false,
        };
        dots += 1;
    }
    matches!(dots, 1 | 2)
}

// ---------------------------------------------------------------------------
// ProxyConfig
// ---------------------------------------------------------------------------

/// Proxy configuration holding services and optional base path.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Base path prefix to strip (e.g., "/api/proxy").
    pub base_path: Option<String>,
    /// Services to proxy.
    pub services: Vec<Service>,
    /// Human-readable title for llms.txt / discovery.
    pub title: Option<String>,
    /// Human-readable description for llms.txt / discovery.
    pub description: Option<String>,
}

/// Result of parsing a request path into service + upstream path.
#[derive(Debug, Clone)]
pub struct ParsedRoute<'a> {
    pub service: &'a Service,
    pub route: &'a Route,
    pub upstream_path: String,
}

impl ProxyConfig {
    /// Strip the base path from a request path and return the remainder.
    ///
    /// Returns `None` if the path is not the base path or below it.
    pub fn strip_base<'a>(&self, path: &'a str) -> Option<&'a str> {
        match &self.base_path {
            None => Some(path),
            Some(base) => {
                let rest = path.strip_prefix(base.trim_end_matches('/'))?;
                (rest.is_empty() || rest.starts_with('/')).then_some(rest)
            }
        }
    }

    /// Match a request to a service and route.
    ///
    /// The `path` should be the full request path (base path will be stripped).
    /// Returns the matched service, route, and the upstream path portion.
    ///
    /// Routes are tried in registration order and the first match wins, so a
    /// pattern shadows any later route it also matches. Register specific
    /// routes before broader `:param` or any-method ones.
    pub fn match_route<'a>(&'a self, method: &str, path: &str) -> Option<ParsedRoute<'a>> {
        let stripped = self.strip_base(path)?;
        let (service_id, upstream_path) = parse_path(stripped)?;

        let service = self.services.iter().find(|s| s.id == service_id)?;

        let route = match_route(&service.routes, method, &upstream_path)?;

        Some(ParsedRoute {
            service,
            route,
            upstream_path,
        })
    }

    /// Match a session credential POST to its paid route for local verification.
    ///
    /// Session lifecycle operations and SSE voucher updates POST to the protected
    /// URL even when its upstream route uses another method. Callers must verify
    /// the credential and handle this request locally; it must never be forwarded
    /// to the upstream service.
    pub fn match_session_credential_route<'a>(
        &'a self,
        method: &str,
        path: &str,
        credential: &PaymentCredential,
    ) -> Option<ParsedRoute<'a>> {
        if !method.eq_ignore_ascii_case("POST") || !credential.challenge.intent.is_session() {
            return None;
        }

        match credential.payload.get("action")?.as_str()? {
            "open" | "topUp" | "voucher" | "close" => {}
            _ => return None,
        }

        let stripped = self.strip_base(path)?;
        let (service_id, upstream_path) = parse_path(stripped)?;
        let service = self
            .services
            .iter()
            .find(|service| service.id == service_id)?;
        let route = service.routes.iter().find(|route| {
            matches!(
                &route.endpoint,
                Endpoint::Paid(endpoint) if endpoint.intent.eq_ignore_ascii_case("session")
            ) && path_matches(&route.path, &upstream_path)
        })?;

        Some(ParsedRoute {
            service,
            route,
            upstream_path,
        })
    }

    /// Handle discovery requests (`GET /services`, `GET /services/{id}`, `GET /llms.txt`).
    ///
    /// Returns `Some(value)` if the request is a discovery request, where `value` is
    /// a JSON payload or `None` for llms.txt (use [`to_llms_txt`] instead).
    pub fn handle_discovery(&self, method: &str, path: &str) -> Option<DiscoveryResponse> {
        if !method.eq_ignore_ascii_case("GET") {
            return None;
        }

        let stripped = self.strip_base(path)?;

        if stripped == "/openapi.json" || stripped == "/openapi.json/" {
            return Some(DiscoveryResponse::Json(generate_openapi(self)));
        }

        if stripped == "/llms.txt" {
            let open_api_path = match &self.base_path {
                Some(base) => format!("{}/openapi.json", base.trim_end_matches('/')),
                None => "/openapi.json".to_string(),
            };
            let options = LlmsTxtOptions {
                title: self.title.as_deref(),
                description: self.description.as_deref(),
                open_api_path: Some(&open_api_path),
            };
            return Some(DiscoveryResponse::LlmsTxt(to_llms_txt_with(
                &self.services,
                Some(&options),
            )));
        }

        if stripped == "/services" || stripped == "/services/" {
            return Some(DiscoveryResponse::Json(serialize_services(&self.services)));
        }

        // /services/{id}
        let rest = stripped
            .strip_prefix("/services/")
            .map(|s| s.trim_end_matches('/'));
        if let Some(id) = rest {
            if !id.is_empty() && !id.contains('/') {
                if let Some(service) = self.services.iter().find(|s| s.id == id) {
                    return Some(DiscoveryResponse::Json(serialize_service(service)));
                }
            }
        }

        None
    }
}

/// Response from a discovery endpoint.
#[derive(Debug, Clone)]
pub enum DiscoveryResponse {
    /// JSON payload (for `/services` and `/services/{id}`).
    Json(Value),
    /// Plain-text llms.txt content.
    LlmsTxt(String),
}

// ---------------------------------------------------------------------------
// Path parsing helpers
// ---------------------------------------------------------------------------

/// Parse a stripped path into `(service_id, upstream_path)`.
///
/// E.g., `"/openai/v1/chat/completions"` → `("openai", "/v1/chat/completions")`.
fn parse_path(path: &str) -> Option<(String, String)> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let service_id = segments.first()?;
    let upstream = format!("/{}", segments[1..].join("/"));
    Some((service_id.to_string(), upstream))
}

/// Match a request against routes by method + path.
fn match_route<'a>(routes: &'a [Route], method: &str, path: &str) -> Option<&'a Route> {
    routes.iter().find(|r| {
        if let Some(ref m) = r.method {
            if !m.eq_ignore_ascii_case(method) {
                return false;
            }
        }
        path_matches(&r.path, path)
    })
}

// ---------------------------------------------------------------------------
// Serialization / Discovery
// ---------------------------------------------------------------------------

/// Serialize a single service for discovery responses.
pub fn serialize_service(s: &Service) -> Value {
    json!({
        "id": s.id,
        "title": s.title,
        "description": s.description,
        "baseUrl": s.base_url,
        "routes": s.routes.iter().map(|r| {
            json!({
                "method": r.method,
                "path": r.path,
                "pattern": r.pattern,
                "payment": serialize_payment(&r.endpoint),
            })
        }).collect::<Vec<_>>(),
    })
}

/// Serialize all services for the `/services` discovery endpoint.
pub fn serialize_services(services: &[Service]) -> Value {
    Value::Array(services.iter().map(serialize_service).collect())
}

fn serialize_payment(endpoint: &Endpoint) -> Value {
    match endpoint {
        Endpoint::Free => Value::Null,
        Endpoint::Paid(p) => {
            let mut m = serde_json::Map::new();
            m.insert("intent".to_string(), json!(p.intent));
            m.insert("amount".to_string(), json!(p.amount));
            if let Some(decimals) = p.decimals {
                m.insert("decimals".to_string(), json!(decimals));
            }
            if let Some(ref currency) = p.currency {
                m.insert("currency".to_string(), json!(currency));
            }
            if let Some(ref ut) = p.unit_type {
                m.insert("unitType".to_string(), json!(ut));
            }
            if let Some(ref desc) = p.description {
                m.insert("description".to_string(), json!(desc));
            }
            Value::Object(m)
        }
    }
}

/// Options for customizing llms.txt output.
pub struct LlmsTxtOptions<'a> {
    /// Override the default title.
    pub title: Option<&'a str>,
    /// Override the default description.
    pub description: Option<&'a str>,
    /// Path to the OpenAPI discovery document (default: "/openapi.json").
    pub open_api_path: Option<&'a str>,
}

/// Generate llms.txt content for LLM-friendly service discovery.
pub fn to_llms_txt(services: &[Service]) -> String {
    to_llms_txt_with(services, None)
}

/// Generate llms.txt content with optional title/description overrides.
pub fn to_llms_txt_with(services: &[Service], options: Option<&LlmsTxtOptions<'_>>) -> String {
    let title = options.and_then(|o| o.title).unwrap_or("API Proxy");
    let description = options
        .and_then(|o| o.description)
        .unwrap_or("Paid API proxy powered by [Machine Payments Protocol](https://mpp.tempo.xyz).");
    let open_api_path = options
        .and_then(|o| o.open_api_path)
        .unwrap_or("/openapi.json");

    let mut lines = vec![
        format!("# {title}"),
        String::new(),
        format!("> {description}"),
        String::new(),
    ];

    if !services.is_empty() {
        lines.push("## Services".to_string());
        lines.push(String::new());
        for s in services {
            let label = s.title.as_deref().unwrap_or(&s.id);
            match &s.description {
                Some(desc) => lines.push(format!("- {label}: {desc}")),
                None => lines.push(format!("- {label}")),
            }
        }
        lines.push(String::new());
    }

    lines.push(format!("[OpenAPI discovery]({open_api_path})"));

    lines.join("\n")
}

/// Generate an OpenAPI 3.1.0 discovery document from the proxy configuration.
///
/// Paths include the configured `base_path`, and `:param` route segments are
/// written as `{param}` path templates with matching `parameters`.
pub fn generate_openapi(config: &ProxyConfig) -> Value {
    let title = config.title.as_deref().unwrap_or("API Proxy");
    let base_path = config
        .base_path
        .as_deref()
        .map_or("", |base| base.trim_end_matches('/'));

    let mut paths = serde_json::Map::new();
    for service in &config.services {
        for route in &service.routes {
            let (path, parameters) = openapi_path(&route.path);
            let path_key = format!("{base_path}/{}{path}", service.id);
            let method_key = route.method.as_deref().unwrap_or("GET").to_lowercase();

            let mut operation = serde_json::Map::new();
            if !parameters.is_empty() {
                operation.insert("parameters".to_string(), Value::Array(parameters));
            }

            let mut responses = serde_json::Map::new();
            if let Endpoint::Paid(p) = &route.endpoint {
                responses.insert(
                    "402".to_string(),
                    json!({ "description": "Payment Required" }),
                );

                let mut offer = serde_json::Map::new();
                offer.insert("intent".to_string(), json!(p.intent));
                offer.insert("amount".to_string(), json!(p.amount));
                if let Some(decimals) = p.decimals {
                    offer.insert("decimals".to_string(), json!(decimals));
                }
                if let Some(ref currency) = p.currency {
                    offer.insert("currency".to_string(), json!(currency));
                }
                if let Some(ref ut) = p.unit_type {
                    offer.insert("unitType".to_string(), json!(ut));
                }
                if let Some(ref desc) = p.description {
                    offer.insert("description".to_string(), json!(desc));
                }
                operation.insert("x-payment-info".to_string(), json!({ "offers": [offer] }));
            }
            responses.insert(
                "200".to_string(),
                json!({ "description": "Successful response" }),
            );
            operation.insert("responses".to_string(), Value::Object(responses));

            let path_entry = paths.entry(&path_key).or_insert_with(|| json!({}));
            path_entry[&method_key] = Value::Object(operation);
        }
    }

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": "1.0.0",
        },
        "paths": Value::Object(paths),
    })
}

/// Rewrite `:param` route segments as OpenAPI `{param}` templates and return
/// the path parameter objects they require.
fn openapi_path(route_path: &str) -> (String, Vec<Value>) {
    let mut parameters = Vec::new();
    let path = route_path
        .split('/')
        .map(|segment| match segment.strip_prefix(':') {
            Some(name) if !name.is_empty() => {
                parameters.push(json!({
                    "name": name,
                    "in": "path",
                    "required": true,
                    "schema": { "type": "string" },
                }));
                format!("{{{name}}}")
            }
            _ => segment.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/");
    (path, parameters)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> Service {
        Service::new("openai", "https://api.openai.com")
            .bearer("sk-test")
            .route(
                "POST /v1/chat/completions",
                Endpoint::Paid(PaidEndpoint {
                    intent: "charge".into(),
                    amount: "50000".into(),
                    decimals: Some(6),
                    currency: Some("0x20c0000000000000000000000000000000000001".into()),
                    unit_type: None,
                    description: Some("Chat completion".into()),
                }),
            )
            .route("GET /v1/models", Endpoint::Free)
            .build()
    }

    fn test_config() -> ProxyConfig {
        ProxyConfig {
            base_path: None,
            services: vec![test_service()],
            title: None,
            description: None,
        }
    }

    #[test]
    fn test_parse_route_pattern() {
        let (method, path) = parse_route_pattern("POST /v1/chat/completions");
        assert_eq!(method.as_deref(), Some("POST"));
        assert_eq!(path, "/v1/chat/completions");

        let (method, path) = parse_route_pattern("/v1/models");
        assert!(method.is_none());
        assert_eq!(path, "/v1/models");
    }

    #[test]
    fn test_path_matches() {
        assert!(path_matches("/v1/chat/completions", "/v1/chat/completions"));
        assert!(!path_matches("/v1/chat/completions", "/v1/models"));
        assert!(path_matches("/v1/customers/:id", "/v1/customers/cus_123"));
        assert!(!path_matches(
            "/v1/customers/:id",
            "/v1/customers/cus_123/charges"
        ));
    }

    #[test]
    fn test_service_builder() {
        let svc = test_service();
        assert_eq!(svc.id, "openai");
        assert_eq!(svc.base_url, "https://api.openai.com");
        assert_eq!(svc.routes.len(), 2);
        assert_eq!(
            svc.headers,
            [("Authorization".to_string(), "Bearer sk-test".to_string())]
        );
    }

    #[test]
    fn test_service_builder_custom_header() {
        let svc = Service::new("anthropic", "https://api.anthropic.com")
            .header("x-api-key", "sk-ant-test")
            .route("POST /v1/messages", Endpoint::Free)
            .build();
        assert_eq!(
            svc.headers,
            [("x-api-key".to_string(), "sk-ant-test".to_string())]
        );
    }

    #[test]
    fn test_request_headers_are_injected_in_insertion_order() {
        let names: Vec<String> = (0..16).map(|i| format!("x-injected-{i}")).collect();
        let mut builder = Service::new("api", "https://api.example.com").bearer("first");
        for name in &names {
            builder = builder.header(name, "value");
        }
        // Same header in another letter case: the last value wins.
        let svc = builder.header("authorization", "Basic last").build();

        let mut headers = vec![("Authorization".to_string(), "Payment caller".to_string())];
        svc.apply_request_headers(&mut headers);

        let mut expected: Vec<(String, String)> = names
            .into_iter()
            .map(|name| (name, "value".to_string()))
            .collect();
        expected.push(("authorization".to_string(), "Basic last".to_string()));
        assert_eq!(headers, expected);
    }

    #[test]
    fn test_match_route() {
        let config = test_config();

        let m = config.match_route("POST", "/openai/v1/chat/completions");
        assert!(m.is_some());
        let m = m.unwrap();
        assert_eq!(m.service.id, "openai");
        assert_eq!(m.route.pattern, "POST /v1/chat/completions");
        assert_eq!(m.upstream_path, "/v1/chat/completions");
    }

    #[test]
    fn test_match_route_with_base_path() {
        let config = ProxyConfig {
            base_path: Some("/api/proxy".to_string()),
            services: vec![test_service()],
            title: None,
            description: None,
        };

        let m = config.match_route("POST", "/api/proxy/openai/v1/chat/completions");
        assert!(m.is_some());

        let m = config.match_route("POST", "/openai/v1/chat/completions");
        assert!(m.is_none());
    }

    #[test]
    fn test_match_route_not_found() {
        let config = test_config();

        assert!(config.match_route("POST", "/openai/v1/unknown").is_none());
        assert!(config.match_route("GET", "/unknown/v1/models").is_none());
        assert!(config.match_route("DELETE", "/openai/v1/models").is_none());
    }

    #[test]
    fn test_match_route_rejects_method_mismatch_for_paid_route() {
        let svc = Service::new("api", "https://api.example.com")
            .route(
                "GET /v1/stream",
                Endpoint::Paid(PaidEndpoint {
                    intent: "charge".into(),
                    amount: "0.05".into(),
                    decimals: None,
                    currency: None,
                    unit_type: None,
                    description: None,
                }),
            )
            .build();

        let config = ProxyConfig {
            base_path: None,
            services: vec![svc],
            title: None,
            description: None,
        };

        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            assert!(
                config.match_route(method, "/api/v1/stream").is_none(),
                "{method} must not match a GET-only paid route"
            );
        }

        assert!(config.match_route("GET", "/api/v1/stream").is_some());
    }

    #[test]
    fn test_match_route_rejects_method_mismatch_for_free_route() {
        let config = test_config();

        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            assert!(
                config.match_route(method, "/openai/v1/models").is_none(),
                "{method} must not match a GET-only free route"
            );
        }
    }

    #[test]
    fn test_session_credential_posts_use_local_only_route_matcher() {
        use crate::protocol::core::{
            Base64UrlJson, ChallengeEcho, IntentName, MethodName, PaymentCredential,
        };

        let service = Service::new("api", "https://api.example.com")
            .route(
                "GET /v1/stream",
                Endpoint::Paid(PaidEndpoint {
                    intent: "session".into(),
                    amount: "1000".into(),
                    decimals: None,
                    currency: None,
                    unit_type: Some("token".into()),
                    description: None,
                }),
            )
            .build();
        let config = ProxyConfig {
            base_path: None,
            services: vec![service],
            title: None,
            description: None,
        };
        let challenge = ChallengeEcho {
            id: "challenge".into(),
            realm: "test".into(),
            method: MethodName::new("tempo"),
            intent: IntentName::new("session"),
            request: Base64UrlJson::default(),
            expires: None,
            description: None,
            digest: None,
            opaque: None,
            header: None,
        };

        assert!(config.match_route("POST", "/api/v1/stream").is_none());
        for action in ["open", "topUp", "voucher", "close"] {
            let credential =
                PaymentCredential::new(challenge.clone(), serde_json::json!({ "action": action }));
            assert!(config
                .match_session_credential_route("POST", "/api/v1/stream", &credential)
                .is_some());
            assert!(config
                .match_session_credential_route("GET", "/api/v1/stream", &credential)
                .is_none());
        }

        let invalid =
            PaymentCredential::new(challenge, serde_json::json!({ "action": "arbitraryPost" }));
        assert!(config
            .match_session_credential_route("POST", "/api/v1/stream", &invalid)
            .is_none());
    }

    #[test]
    fn test_discovery_services() {
        let config = test_config();

        let resp = config.handle_discovery("GET", "/services");
        assert!(resp.is_some());
        if let Some(DiscoveryResponse::Json(v)) = resp {
            let arr = v.as_array().unwrap();
            assert_eq!(arr.len(), 1);
            assert_eq!(arr[0]["id"], "openai");
        }
    }

    #[test]
    fn test_discovery_single_service() {
        let config = test_config();

        let resp = config.handle_discovery("GET", "/services/openai");
        assert!(resp.is_some());
        if let Some(DiscoveryResponse::Json(v)) = resp {
            assert_eq!(v["id"], "openai");
        }

        assert!(config
            .handle_discovery("GET", "/services/unknown")
            .is_none());
    }

    #[test]
    fn test_discovery_llms_txt() {
        let config = test_config();

        let resp = config.handle_discovery("GET", "/llms.txt");
        assert!(resp.is_some());
        if let Some(DiscoveryResponse::LlmsTxt(txt)) = resp {
            assert!(txt.contains("# API Proxy"));
            assert!(txt.contains("- openai"));
            assert!(txt.contains("[OpenAPI discovery](/openapi.json)"));
        }
    }

    #[test]
    fn test_discovery_not_get() {
        let config = test_config();

        assert!(config.handle_discovery("POST", "/services").is_none());
    }

    #[test]
    fn test_serialize_service() {
        let svc = test_service();
        let v = serialize_service(&svc);
        assert_eq!(v["id"], "openai");
        assert!(v["title"].is_null());
        assert!(v["description"].is_null());
        let routes = v["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0]["pattern"], "POST /v1/chat/completions");
        assert!(routes[0]["payment"].is_object());
        assert_eq!(routes[0]["payment"]["intent"], "charge");
        assert_eq!(routes[0]["payment"]["amount"], "50000");
        assert_eq!(routes[0]["payment"]["decimals"], 6);
        assert_eq!(
            routes[0]["payment"]["currency"],
            "0x20c0000000000000000000000000000000000001"
        );
        assert_eq!(routes[1]["pattern"], "GET /v1/models");
        assert!(routes[1]["payment"].is_null());
    }

    #[test]
    fn test_llms_txt_with_services() {
        let services = vec![test_service()];
        let txt = to_llms_txt(&services);
        assert!(txt.contains("# API Proxy"));
        assert!(txt.contains("## Services"));
        assert!(txt.contains("- openai"));
        assert!(txt.contains("[OpenAPI discovery](/openapi.json)"));
        // No per-route details (matches mppx toLlmsTxt)
        assert!(!txt.contains("charge"));
        assert!(!txt.contains("50000"));
    }

    #[test]
    fn test_param_route_matching() {
        let svc = Service::new("stripe", "https://api.stripe.com")
            .bearer("sk-test")
            .route("GET /v1/customers/:id", Endpoint::Free)
            .build();

        let config = ProxyConfig {
            base_path: None,
            services: vec![svc],
            title: None,
            description: None,
        };

        let m = config.match_route("GET", "/stripe/v1/customers/cus_123");
        assert!(m.is_some());
        assert_eq!(m.unwrap().upstream_path, "/v1/customers/cus_123");
    }

    #[test]
    fn test_match_route_first_registered_wins() {
        let svc = Service::new("stripe", "https://api.stripe.com")
            .route("GET /v1/customers/search", Endpoint::Free)
            .route("GET /v1/customers/:id", Endpoint::Free)
            .route("GET /v1/customers/me", Endpoint::Free)
            .build();
        let config = ProxyConfig {
            base_path: None,
            services: vec![svc],
            title: None,
            description: None,
        };

        let pattern = |path| {
            config
                .match_route("GET", path)
                .unwrap()
                .route
                .pattern
                .as_str()
        };
        assert_eq!(
            pattern("/stripe/v1/customers/search"),
            "GET /v1/customers/search"
        );
        assert_eq!(pattern("/stripe/v1/customers/me"), "GET /v1/customers/:id");
    }

    #[test]
    fn test_param_route_rejects_dot_segments() {
        let svc = Service::new("stripe", "https://api.stripe.com")
            .route("GET /v1/customers/:id", Endpoint::Free)
            .build();
        let config = ProxyConfig {
            base_path: None,
            services: vec![svc],
            title: None,
            description: None,
        };

        for id in [
            "..",
            ".",
            "%2e%2e",
            "%2E%2E",
            ".%2e",
            "%2e.",
            "%2e",
            "..\\admin",
        ] {
            let path = format!("/stripe/v1/customers/{id}");
            assert!(
                config.match_route("GET", &path).is_none(),
                "{path} must not match a :param route"
            );
        }

        for id in ["...", "cus_1.2", ".well-known", "%2e%2e%2e"] {
            let path = format!("/stripe/v1/customers/{id}");
            assert!(config.match_route("GET", &path).is_some(), "{path}");
        }
    }

    #[test]
    fn test_base_path_requires_segment_boundary() {
        let config = ProxyConfig {
            base_path: Some("/api".to_string()),
            services: vec![test_service()],
            title: None,
            description: None,
        };

        assert_eq!(
            config.strip_base("/api/openai/v1/models"),
            Some("/openai/v1/models")
        );
        assert_eq!(config.strip_base("/api"), Some(""));
        assert_eq!(config.strip_base("/apiopenai/v1/models"), None);
        assert!(config.match_route("GET", "/apiopenai/v1/models").is_none());
    }

    #[test]
    fn test_discovery_with_base_path() {
        let config = ProxyConfig {
            base_path: Some("/api/proxy".to_string()),
            services: vec![test_service()],
            title: None,
            description: None,
        };

        assert!(config
            .handle_discovery("GET", "/api/proxy/services")
            .is_some());
        assert!(config.handle_discovery("GET", "/services").is_none());
    }

    #[test]
    fn test_service_builder_title_description() {
        let svc = Service::new("test", "https://example.com")
            .title("Test Service")
            .description("A test service")
            .build();
        assert_eq!(svc.title.as_deref(), Some("Test Service"));
        assert_eq!(svc.description.as_deref(), Some("A test service"));

        let v = serialize_service(&svc);
        assert_eq!(v["title"], "Test Service");
        assert_eq!(v["description"], "A test service");
    }

    #[test]
    fn test_to_llms_txt_with_custom_title_description() {
        let svc = Service::new("openai", "https://api.openai.com")
            .title("OpenAI")
            .description("Chat completions and embeddings.")
            .route("GET /v1/models", Endpoint::Free)
            .build();
        let options = LlmsTxtOptions {
            title: Some("My AI Gateway"),
            description: Some("A paid proxy for LLM and AI services."),
            open_api_path: None,
        };
        let txt = to_llms_txt_with(std::slice::from_ref(&svc), Some(&options));
        assert!(txt.contains("# My AI Gateway"));
        assert!(txt.contains("> A paid proxy for LLM and AI services."));
        assert!(!txt.contains("# API Proxy"));
        // title fallback: service title used over id
        assert!(txt.contains("- OpenAI: Chat completions and embeddings."));
        // default openapi link
        assert!(txt.contains("[OpenAPI discovery](/openapi.json)"));
    }

    #[test]
    fn test_to_llms_txt_defaults() {
        let txt = to_llms_txt(&[]);
        assert!(txt.contains("# API Proxy"));
        assert!(txt.contains("[OpenAPI discovery](/openapi.json)"));
        assert!(!txt.contains("## Services"));

        // custom openapi path
        let options = LlmsTxtOptions {
            title: None,
            description: None,
            open_api_path: Some("/api/proxy/openapi.json"),
        };
        let txt = to_llms_txt_with(&[], Some(&options));
        assert!(txt.contains("[OpenAPI discovery](/api/proxy/openapi.json)"));
    }

    #[test]
    fn test_discovery_llms_txt_custom_title() {
        let config = ProxyConfig {
            base_path: None,
            services: vec![test_service()],
            title: Some("My Gateway".to_string()),
            description: Some("Custom description.".to_string()),
        };
        let resp = config.handle_discovery("GET", "/llms.txt");
        if let Some(DiscoveryResponse::LlmsTxt(txt)) = resp {
            assert!(txt.contains("# My Gateway"));
            assert!(txt.contains("> Custom description."));
        } else {
            panic!("expected LlmsTxt");
        }
    }

    #[test]
    fn test_generate_openapi() {
        let config = test_config();
        let doc = generate_openapi(&config);

        assert_eq!(doc["openapi"], "3.1.0");
        assert_eq!(doc["info"]["title"], "API Proxy");
        assert_eq!(doc["info"]["version"], "1.0.0");

        let paths = doc["paths"].as_object().unwrap();
        assert_eq!(paths.len(), 2);

        // Paid route
        let paid = &paths["/openai/v1/chat/completions"]["post"];
        assert!(paid["responses"]["402"].is_object());
        assert!(paid["responses"]["200"].is_object());
        assert!(paid["parameters"].is_null());
        assert_eq!(
            paid["x-payment-info"],
            json!({
                "offers": [{
                    "intent": "charge",
                    "amount": "50000",
                    "decimals": 6,
                    "currency": "0x20c0000000000000000000000000000000000001",
                    "description": "Chat completion",
                }],
            })
        );

        // Free route
        let free = &paths["/openai/v1/models"]["get"];
        assert!(free["responses"]["200"].is_object());
        assert!(free["responses"]["402"].is_null());
        assert!(free["x-payment-info"].is_null());

        // Empty config
        let empty = ProxyConfig {
            base_path: None,
            services: vec![],
            title: Some("Custom".to_string()),
            description: None,
        };
        let doc = generate_openapi(&empty);
        assert_eq!(doc["info"]["title"], "Custom");
        assert!(doc["paths"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_generate_openapi_base_path_and_path_params() {
        let svc = Service::new("stripe", "https://api.stripe.com")
            .route(
                "GET /v1/customers/:id/charges/:charge",
                Endpoint::Paid(PaidEndpoint {
                    intent: "charge".into(),
                    amount: "100".into(),
                    decimals: None,
                    currency: None,
                    unit_type: None,
                    description: None,
                }),
            )
            .route("GET /v1/customers/:id", Endpoint::Free)
            .build();
        let config = ProxyConfig {
            base_path: Some("/api/proxy/".to_string()),
            services: vec![svc],
            title: None,
            description: None,
        };
        let doc = generate_openapi(&config);
        let paths = doc["paths"].as_object().unwrap();
        assert_eq!(
            paths.keys().collect::<Vec<_>>(),
            [
                "/api/proxy/stripe/v1/customers/{id}/charges/{charge}",
                "/api/proxy/stripe/v1/customers/{id}",
            ]
        );

        let path_param = |name: &str| json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string" } });
        assert_eq!(
            paths["/api/proxy/stripe/v1/customers/{id}/charges/{charge}"]["get"]["parameters"],
            json!([path_param("id"), path_param("charge")])
        );
        assert_eq!(
            paths["/api/proxy/stripe/v1/customers/{id}"]["get"]["parameters"],
            json!([path_param("id")])
        );
    }

    #[test]
    fn test_discovery_openapi_json() {
        let config = test_config();

        let resp = config.handle_discovery("GET", "/openapi.json");
        assert!(resp.is_some());
        if let Some(DiscoveryResponse::Json(v)) = resp {
            assert_eq!(v["openapi"], "3.1.0");
            assert!(v["paths"]
                .as_object()
                .unwrap()
                .contains_key("/openai/v1/chat/completions"));
        } else {
            panic!("expected Json");
        }

        // trailing slash
        assert!(config.handle_discovery("GET", "/openapi.json/").is_some());

        // POST should not match
        assert!(config.handle_discovery("POST", "/openapi.json").is_none());
    }
}
