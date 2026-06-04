//! Header stripping for proxied requests and responses.

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
];

const PAYMENT_HEADERS: &[&str] = &[
    "authorization",
    "accept-payment",
    "payment-receipt",
    "payment-required",
    "payment-response",
    "payment-signature",
    "www-authenticate",
];

fn eq_ascii_lower(name: &str, lower: &str) -> bool {
    name.len() == lower.len()
        && name
            .bytes()
            .zip(lower.bytes())
            .all(|(a, b)| a.to_ascii_lowercase() == b)
}

/// Returns true if `name` is always stripped from a proxy→upstream request.
/// `Connection`-nominated headers are handled by [`scrub_request_headers`].
pub fn is_request_header_stripped(name: &str) -> bool {
    if HOP_BY_HOP.iter().any(|h| eq_ascii_lower(name, h)) {
        return true;
    }
    if PAYMENT_HEADERS.iter().any(|h| eq_ascii_lower(name, h)) {
        return true;
    }
    if eq_ascii_lower(name, "host")
        || eq_ascii_lower(name, "cookie")
        || eq_ascii_lower(name, "accept-encoding")
        || eq_ascii_lower(name, "content-length")
    {
        return true;
    }
    name.len() >= "x-forwarded-".len()
        && name.as_bytes()[.."x-forwarded-".len()].eq_ignore_ascii_case(b"x-forwarded-")
}

/// Returns true if `name` is always stripped from an upstream→client response.
/// `Connection`-nominated headers are handled by [`scrub_response_headers`].
pub fn is_response_header_stripped(name: &str) -> bool {
    if HOP_BY_HOP.iter().any(|h| eq_ascii_lower(name, h)) {
        return true;
    }
    eq_ascii_lower(name, "set-cookie")
        || eq_ascii_lower(name, "content-encoding")
        || eq_ascii_lower(name, "content-length")
}

/// Lowercased header names nominated as hop-by-hop by any `Connection` header.
fn connection_nominated(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| eq_ascii_lower(name, "connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

pub fn scrub_request_headers(headers: &mut Vec<(String, String)>) {
    let nominated = connection_nominated(headers);
    headers.retain(|(name, _)| {
        !is_request_header_stripped(name) && !nominated.iter().any(|t| name.eq_ignore_ascii_case(t))
    });
}

pub fn scrub_response_headers(headers: &mut Vec<(String, String)>) {
    let nominated = connection_nominated(headers);
    headers.retain(|(name, _)| {
        !is_response_header_stripped(name)
            && !nominated.iter().any(|t| name.eq_ignore_ascii_case(t))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(h: &[(String, String)]) -> Vec<String> {
        h.iter().map(|(n, _)| n.to_lowercase()).collect()
    }

    #[test]
    fn test_scrub_response_drops_set_cookie() {
        let mut headers = vec![
            ("Content-Type".into(), "application/json".into()),
            (
                "Set-Cookie".into(),
                "session=evil; Domain=.example.com".into(),
            ),
            ("Content-Encoding".into(), "gzip".into()),
            ("Content-Length".into(), "42".into()),
            ("X-Request-Id".into(), "req_abc".into()),
        ];

        scrub_response_headers(&mut headers);

        let names = names(&headers);
        assert!(!names.contains(&"set-cookie".to_string()));
        assert!(!names.contains(&"content-encoding".to_string()));
        assert!(!names.contains(&"content-length".to_string()));
        assert!(names.contains(&"content-type".to_string()));
        assert!(names.contains(&"x-request-id".to_string()));
    }

    #[test]
    fn test_scrub_response_drops_all_set_cookie_values() {
        let mut headers = vec![
            ("Set-Cookie".into(), "a=1".into()),
            ("set-cookie".into(), "b=2".into()),
            ("SET-COOKIE".into(), "c=3".into()),
            ("Content-Type".into(), "text/html".into()),
        ];

        scrub_response_headers(&mut headers);

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Content-Type");
    }

    #[test]
    fn test_scrub_request_drops_bare_x_forwarded() {
        assert!(is_request_header_stripped("X-Forwarded-"));
        assert!(is_request_header_stripped("x-forwarded-"));
    }

    #[test]
    fn test_scrub_request_drops_hop_by_hop_payment_cookie() {
        let mut headers = vec![
            ("Connection".into(), "keep-alive".into()),
            ("Transfer-Encoding".into(), "chunked".into()),
            ("Proxy-Authorization".into(), "Basic xxx".into()),
            ("Authorization".into(), "Payment …".into()),
            ("Accept-Payment".into(), "tempo/charge".into()),
            ("Payment-Receipt".into(), "…".into()),
            ("WWW-Authenticate".into(), "…".into()),
            ("Cookie".into(), "sid=abc".into()),
            ("Accept-Encoding".into(), "gzip".into()),
            ("Content-Length".into(), "13".into()),
            ("X-Forwarded-For".into(), "1.2.3.4".into()),
            ("x-forwarded-proto".into(), "https".into()),
            ("Content-Type".into(), "application/json".into()),
            ("User-Agent".into(), "mpp-rs/test".into()),
        ];

        scrub_request_headers(&mut headers);

        let names = names(&headers);
        assert_eq!(
            names,
            vec!["content-type".to_string(), "user-agent".to_string()]
        );
    }

    #[test]
    fn test_scrub_request_drops_host() {
        assert!(is_request_header_stripped("Host"));

        let mut headers = vec![
            ("Host".into(), "proxy.example.com".into()),
            ("Content-Type".into(), "application/json".into()),
        ];
        scrub_request_headers(&mut headers);

        assert_eq!(names(&headers), vec!["content-type".to_string()]);
    }

    #[test]
    fn test_scrub_request_drops_connection_nominated() {
        let mut headers = vec![
            ("Connection".into(), "close, X-Debug".into()),
            ("X-Debug".into(), "1".into()),
            ("Content-Type".into(), "application/json".into()),
        ];
        scrub_request_headers(&mut headers);

        assert_eq!(names(&headers), vec!["content-type".to_string()]);
    }

    #[test]
    fn test_scrub_request_drops_multiple_connection_nominated_case_insensitive() {
        let mut headers = vec![
            ("Connection".into(), " keep-alive, X-Debug ,, ".into()),
            ("connection".into(), "x-trace".into()),
            ("x-debug".into(), "1".into()),
            ("X-Trace".into(), "2".into()),
            ("Content-Type".into(), "application/json".into()),
        ];
        scrub_request_headers(&mut headers);

        assert_eq!(names(&headers), vec!["content-type".to_string()]);
    }

    #[test]
    fn test_scrub_response_drops_hop_by_hop_and_nominated() {
        let mut headers = vec![
            ("Connection".into(), "X-Custom".into()),
            ("Keep-Alive".into(), "timeout=5".into()),
            ("X-Custom".into(), "secret".into()),
            ("Content-Type".into(), "text/html".into()),
        ];
        scrub_response_headers(&mut headers);

        assert_eq!(names(&headers), vec!["content-type".to_string()]);
    }
}
