//! Gates `Accept-Payment` header injection on outgoing requests.
//!
//! Without a gate, a global payment middleware advertises supported
//! payment methods on every cross-origin request, which can break CORS
//! preflight and leak wallet capabilities.
//!
//! Defaults to [`AcceptPaymentPolicy::Always`] for backwards compatibility.

use reqwest::Url;

/// Policy controlling when the `Accept-Payment` header is injected.
#[derive(Clone, Debug, Default)]
pub enum AcceptPaymentPolicy {
    /// Always inject (default).
    #[default]
    Always,
    /// Inject only when the request URL origin matches `same_origin`
    /// (`scheme://host[:port]`).
    SameOrigin { same_origin: String },
    /// Never inject.
    Never,
    /// Inject only when the request URL matches one of the patterns.
    /// Supports exact origins (`https://app.example.com`) and `*.example.com` wildcards.
    Origins(Vec<String>),
}

impl AcceptPaymentPolicy {
    /// Returns `true` if header injection is permitted for `url`.
    pub fn allows(&self, url: &Url) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::SameOrigin { same_origin } => match Url::parse(same_origin) {
                Ok(parsed) => url.origin() == parsed.origin(),
                Err(_) => false,
            },
            Self::Origins(patterns) => patterns.iter().any(|p| matches_origin(url, p)),
        }
    }
}

/// Match `url` against a pattern.
///
/// - `*.example.com` (bare hostname, no scheme) → wildcard subdomain match;
///   also matches the bare domain.
/// - `scheme://host[:port]` → exact `Url::origin()` equality.
///
/// Anything else (host-only without scheme, scheme-prefixed wildcards) is rejected.
fn matches_origin(url: &Url, pattern: &str) -> bool {
    if let Some(suffix_no_dot) = pattern.strip_prefix("*.") {
        let url_host = match url.host_str() {
            Some(h) => h.to_ascii_lowercase(),
            None => return false,
        };
        let suffix = suffix_no_dot.to_ascii_lowercase();
        return url_host == suffix || url_host.ends_with(&format!(".{suffix}"));
    }

    match Url::parse(pattern) {
        Ok(pattern_url) => url.origin() == pattern_url.origin(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn always_allows_any_url() {
        let p = AcceptPaymentPolicy::Always;
        assert!(p.allows(&url("https://example.com/api")));
        assert!(p.allows(&url("http://localhost:8080/")));
        assert!(p.allows(&url("https://cross-origin.example.com/")));
    }

    #[test]
    fn never_blocks_any_url() {
        let p = AcceptPaymentPolicy::Never;
        assert!(!p.allows(&url("https://example.com/api")));
        assert!(!p.allows(&url("http://localhost:8080/")));
    }

    #[test]
    fn default_is_always() {
        let p = AcceptPaymentPolicy::default();
        assert!(p.allows(&url("https://example.com/")));
    }

    #[test]
    fn same_origin_matches_exact_origin() {
        let p = AcceptPaymentPolicy::SameOrigin {
            same_origin: "https://app.example.com".to_string(),
        };
        assert!(p.allows(&url("https://app.example.com/api")));
        assert!(p.allows(&url("https://app.example.com/")));
        assert!(!p.allows(&url("https://other.example.com/api")));
        assert!(!p.allows(&url("http://app.example.com/api"))); // different scheme
    }

    #[test]
    fn same_origin_respects_port() {
        let p = AcceptPaymentPolicy::SameOrigin {
            same_origin: "http://localhost:3000".to_string(),
        };
        assert!(p.allows(&url("http://localhost:3000/api")));
        assert!(!p.allows(&url("http://localhost:3001/api")));
        assert!(!p.allows(&url("http://localhost/api")));
    }

    #[test]
    fn origins_exact_match() {
        let p = AcceptPaymentPolicy::Origins(vec!["https://app.example.com".to_string()]);
        assert!(p.allows(&url("https://app.example.com/api")));
        assert!(!p.allows(&url("https://other.com/api")));
    }

    #[test]
    fn origins_wildcard_subdomain() {
        let p = AcceptPaymentPolicy::Origins(vec!["*.example.com".to_string()]);
        assert!(p.allows(&url("https://api.example.com/")));
        assert!(p.allows(&url("https://x.y.example.com/")));
        assert!(p.allows(&url("https://example.com/"))); // bare domain matches
        assert!(!p.allows(&url("https://example.org/")));
        assert!(!p.allows(&url("https://maliciousexample.com/"))); // suffix-attack guard
    }

    #[test]
    fn origins_rejects_host_only_pattern() {
        // Patterns without a scheme are rejected (must be wildcard or full origin).
        let p = AcceptPaymentPolicy::Origins(vec!["api.example.com".to_string()]);
        assert!(!p.allows(&url("https://api.example.com/")));
    }

    #[test]
    fn origins_multiple_patterns() {
        let p = AcceptPaymentPolicy::Origins(vec![
            "https://app.example.com".to_string(),
            "*.trusted.io".to_string(),
        ]);
        assert!(p.allows(&url("https://app.example.com/")));
        assert!(p.allows(&url("https://api.trusted.io/")));
        assert!(p.allows(&url("https://deep.x.trusted.io/")));
        assert!(!p.allows(&url("https://untrusted.com/")));
    }

    #[test]
    fn origins_wildcard_case_insensitive() {
        let p = AcceptPaymentPolicy::Origins(vec!["*.Example.COM".to_string()]);
        assert!(p.allows(&url("https://API.example.com/")));
    }

    #[test]
    fn exact_origin_normalizes_default_port() {
        // WHATWG URL.origin omits default ports (443 for https).
        let p = AcceptPaymentPolicy::Origins(vec!["https://example.com:443".to_string()]);
        assert!(p.allows(&url("https://example.com/")));
    }
}
