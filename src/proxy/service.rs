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
    /// Amount in human-readable units (e.g., "0.05").
    pub amount: String,
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

        if stripped == "/llms.txt" {
            return Some(DiscoveryResponse::LlmsTxt(to_llms_txt(&self.services)));
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

/// Generate llms.txt content for LLM-friendly service discovery.
pub fn to_llms_txt(services: &[Service]) -> String {
    let mut lines = vec![
        "# API Proxy".to_string(),
        String::new(),
        "> Paid API proxy powered by [Machine Payments Protocol](https://mpp.tempo.xyz)."
            .to_string(),
        String::new(),
        "For machine-readable service data, use `GET /services` (JSON).".to_string(),
        String::new(),
    ];

    if services.is_empty() {
        return lines.join("\n");
    }

    lines.push("## Services".to_string());
    lines.push(String::new());
    for s in services {
        let free = s
            .routes
            .iter()
            .filter(|r| matches!(r.endpoint, Endpoint::Free))
            .count();
        let paid = s.routes.len() - free;
        let mut parts = Vec::new();
        if paid > 0 {
            parts.push(format!("{paid} paid"));
        }
        if free > 0 {
            parts.push(format!("{free} free"));
        }
        lines.push(format!(
            "- [{}]({}): {}",
            s.id,
            s.base_url,
            parts.join(", ")
        ));
    }

    for s in services {
        lines.push(String::new());
        lines.push(format!("## {}", s.id));
        lines.push(String::new());
        for route in &s.routes {
            match &route.endpoint {
                Endpoint::Free => {
                    lines.push(format!("- `{}`: Free", route.pattern));
                }
                Endpoint::Paid(p) => {
                    let mut parts = vec![p.intent.clone()];
                    let unit = format!("{} units", p.amount);
                    if let Some(ref ut) = p.unit_type {
                        parts.push(format!("{unit} per {ut}"));
                    } else {
                        parts.push(unit);
                    }
                    if let Some(ref desc) = p.description {
                        parts.push(format!("\"{desc}\""));
                    }
                    lines.push(format!("- `{}`: {}", route.pattern, parts.join(" — ")));
                }
            }
        }
    }

    lines.join("\n")
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
                    amount: "0.05".into(),
                    unit_type: None,
                    description: Some("Chat completion".into()),
                }),
            )
            .route("GET /v1/models", Endpoint::Free)
            .build()
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
        let config = ProxyConfig {
            base_path: None,
            services: vec![test_service()],
        };

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
        };

        let m = config.match_route("POST", "/api/proxy/openai/v1/chat/completions");
        assert!(m.is_some());

        let m = config.match_route("POST", "/openai/v1/chat/completions");
        assert!(m.is_none());
    }

    #[test]
    fn test_match_route_not_found() {
        let config = ProxyConfig {
            base_path: None,
            services: vec![test_service()],
        };

        assert!(config.match_route("POST", "/openai/v1/unknown").is_none());
        assert!(config.match_route("GET", "/unknown/v1/models").is_none());
        assert!(config.match_route("DELETE", "/openai/v1/models").is_none());
    }

    #[test]
    fn test_match_route_method_fallback_skips_free() {
        let config = ProxyConfig {
            base_path: None,
            services: vec![test_service()],
        };

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
                    unit_type: None,
                    description: None,
                }),
            )
            .build();

        let config = ProxyConfig {
            base_path: None,
            services: vec![svc],
        };

        // POST to a paid GET route should match via fallback
        let m = config.match_route("POST", "/api/v1/stream");
        assert!(m.is_some());
    }

    #[test]
    fn test_discovery_services() {
        let config = ProxyConfig {
            base_path: None,
            services: vec![test_service()],
        };

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
        let config = ProxyConfig {
            base_path: None,
            services: vec![test_service()],
        };

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
        let config = ProxyConfig {
            base_path: None,
            services: vec![test_service()],
        };

        let resp = config.handle_discovery("GET", "/llms.txt");
        assert!(resp.is_some());
        if let Some(DiscoveryResponse::LlmsTxt(txt)) = resp {
            assert!(txt.contains("# API Proxy"));
            assert!(txt.contains("openai"));
            assert!(txt.contains("1 paid"));
            assert!(txt.contains("1 free"));
            assert!(txt.contains("Chat completion"));
        }
    }

    #[test]
    fn test_discovery_not_get() {
        let config = ProxyConfig {
            base_path: None,
            services: vec![test_service()],
        };

        assert!(config.handle_discovery("POST", "/services").is_none());
    }

    #[test]
    fn test_serialize_service() {
        let svc = test_service();
        let v = serialize_service(&svc);
        assert_eq!(v["id"], "openai");
        let routes = v["routes"].as_array().unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0]["pattern"], "POST /v1/chat/completions");
        assert!(routes[0]["payment"].is_object());
        assert_eq!(routes[0]["payment"]["intent"], "charge");
        assert_eq!(routes[1]["pattern"], "GET /v1/models");
        assert!(routes[1]["payment"].is_null());
    }

    #[test]
    fn test_llms_txt_empty() {
        let txt = to_llms_txt(&[]);
        assert!(txt.contains("# API Proxy"));
        assert!(!txt.contains("## Services"));
    }

    #[test]
    fn test_llms_txt_with_services() {
        let services = vec![test_service()];
        let txt = to_llms_txt(&services);
        assert!(txt.contains("## Services"));
        assert!(txt.contains("- [openai](https://api.openai.com): 1 paid, 1 free"));
        assert!(txt.contains("## openai"));
        assert!(txt.contains("`POST /v1/chat/completions`: charge"));
        assert!(txt.contains("`GET /v1/models`: Free"));
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
        };

        assert!(config
            .handle_discovery("GET", "/api/proxy/services")
            .is_some());
        assert!(config.handle_discovery("GET", "/services").is_none());
    }
}
