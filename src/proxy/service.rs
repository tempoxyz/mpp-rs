use serde_json::{json, Value};
use std::collections::HashMap;

/// A proxied upstream service with route definitions.
#[derive(Debug, Clone)]
pub struct Service {
    /// Unique identifier used as the URL prefix (e.g., `"openai"` → `/{id}/...`).
    pub id: String,
    /// Base URL of the upstream service.
    pub base_url: String,
    /// Route definitions.
    pub routes: Vec<Route>,
    /// Headers to inject on upstream requests.
    pub headers: HashMap<String, String>,
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
            headers: HashMap::new(),
            title: None,
            description: None,
        }
    }
}

/// Builder for constructing a [`Service`].
#[derive(Debug)]
pub struct ServiceBuilder {
    id: String,
    base_url: String,
    routes: Vec<Route>,
    headers: HashMap<String, String>,
    title: Option<String>,
    description: Option<String>,
}

impl ServiceBuilder {
    /// Inject an `Authorization: Bearer {token}` header on upstream requests.
    pub fn bearer(mut self, token: impl Into<String>) -> Self {
        self.headers.insert(
            "Authorization".to_string(),
            format!("Bearer {}", token.into()),
        );
        self
    }

    /// Inject a custom header on upstream requests.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
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
/// `/v1/customers/cus_123`).
fn path_matches(pattern: &str, path: &str) -> bool {
    let pat_segments: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let path_segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if pat_segments.len() != path_segments.len() {
        return false;
    }

    pat_segments
        .iter()
        .zip(path_segments.iter())
        .all(|(pat, seg)| pat.starts_with(':') || *pat == *seg)
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
    /// Returns `None` if the path doesn't start with the base path.
    pub fn strip_base<'a>(&self, path: &'a str) -> Option<&'a str> {
        match &self.base_path {
            None => Some(path),
            Some(base) => {
                let base = base.trim_end_matches('/');
                path.strip_prefix(base)
            }
        }
    }

    /// Match a request to a service and route.
    ///
    /// The `path` should be the full request path (base path will be stripped).
    /// Returns the matched service, route, and the upstream path portion.
    pub fn match_route<'a>(&'a self, method: &str, path: &str) -> Option<ParsedRoute<'a>> {
        let stripped = self.strip_base(path)?;
        let (service_id, upstream_path) = parse_path(stripped)?;

        let service = self.services.iter().find(|s| s.id == service_id)?;

        let route = match match_route(&service.routes, method, &upstream_path) {
            Some(r) => r,
            None => {
                // Fallback: for POST requests, try path-only matching
                // (management POSTs like session close may target a route
                // registered for a different HTTP method).
                if method.eq_ignore_ascii_case("POST") {
                    match_route_path_only_paid(&service.routes, &upstream_path)?
                } else {
                    return None;
                }
            }
        };

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

/// Match a request against routes by path only (ignoring method), excluding Free routes.
///
/// This prevents a POST to a free GET endpoint from bypassing payment requirements
/// via the method-mismatch fallback path.
fn match_route_path_only_paid<'a>(routes: &'a [Route], path: &str) -> Option<&'a Route> {
    routes
        .iter()
        .find(|r| matches!(r.endpoint, Endpoint::Paid(_)) && path_matches(&r.path, path))
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
pub fn generate_openapi(config: &ProxyConfig) -> Value {
    let title = config.title.as_deref().unwrap_or("API Proxy");

    let mut paths = serde_json::Map::new();
    for service in &config.services {
        for route in &service.routes {
            let path_key = format!("/{}{}", service.id, route.path);
            let method_key = route.method.as_deref().unwrap_or("GET").to_lowercase();

            let mut responses = serde_json::Map::new();
            if let Endpoint::Paid(p) = &route.endpoint {
                responses.insert(
                    "402".to_string(),
                    json!({ "description": "Payment Required" }),
                );

                let mut operation = serde_json::Map::new();
                operation.insert("intent".to_string(), json!(p.intent));
                operation.insert("amount".to_string(), json!(p.amount));
                if let Some(decimals) = p.decimals {
                    operation.insert("decimals".to_string(), json!(decimals));
                }
                if let Some(ref currency) = p.currency {
                    operation.insert("currency".to_string(), json!(currency));
                }
                if let Some(ref ut) = p.unit_type {
                    operation.insert("unitType".to_string(), json!(ut));
                }
                if let Some(ref desc) = p.description {
                    operation.insert("description".to_string(), json!(desc));
                }

                responses.insert(
                    "200".to_string(),
                    json!({ "description": "Successful response" }),
                );

                let path_entry = paths.entry(&path_key).or_insert_with(|| json!({}));
                path_entry[&method_key] = json!({
                    "responses": Value::Object(responses),
                    "x-payment-info": Value::Object(operation),
                });
            } else {
                responses.insert(
                    "200".to_string(),
                    json!({ "description": "Successful response" }),
                );

                let path_entry = paths.entry(&path_key).or_insert_with(|| json!({}));
                path_entry[&method_key] = json!({
                    "responses": Value::Object(responses),
                });
            }
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
            svc.headers.get("Authorization"),
            Some(&"Bearer sk-test".to_string())
        );
    }

    #[test]
    fn test_service_builder_custom_header() {
        let svc = Service::new("anthropic", "https://api.anthropic.com")
            .header("x-api-key", "sk-ant-test")
            .route("POST /v1/messages", Endpoint::Free)
            .build();
        assert_eq!(
            svc.headers.get("x-api-key"),
            Some(&"sk-ant-test".to_string())
        );
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
    fn test_match_route_method_fallback_skips_free() {
        let config = test_config();

        // POST to a free GET route should NOT match via fallback
        // (prevents bypassing payment on free routes)
        let m = config.match_route("POST", "/openai/v1/models");
        assert!(m.is_none());
    }

    #[test]
    fn test_match_route_method_fallback_matches_paid() {
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

        // POST to a paid GET route should match via fallback
        let m = config.match_route("POST", "/api/v1/stream");
        assert!(m.is_some());
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
        assert_eq!(paid["x-payment-info"]["intent"], "charge");
        assert_eq!(paid["x-payment-info"]["amount"], "50000");
        assert_eq!(paid["x-payment-info"]["decimals"], 6);
        assert_eq!(
            paid["x-payment-info"]["currency"],
            "0x20c0000000000000000000000000000000000001"
        );
        assert_eq!(paid["x-payment-info"]["description"], "Chat completion");

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
