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
    "payment-authorization",
    "payment-receipt",
    "payment-required",
    "payment-response",
    "payment-session",
    "payment-session-snapshot",
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
/// `Connection`-nominated headers, and `Authorization` and
/// `WWW-Authenticate` values carrying the Payment scheme, are handled by
/// [`scrub_response_headers`].
pub fn is_response_header_stripped(name: &str) -> bool {
    if HOP_BY_HOP.iter().any(|h| eq_ascii_lower(name, h)) {
        return true;
    }
    // An upstream must not forge payment protocol headers to the client.
    if PAYMENT_HEADERS
        .iter()
        .any(|h| *h != "authorization" && *h != "www-authenticate" && eq_ascii_lower(name, h))
    {
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
    // Drop Payment credentials and challenges while preserving other schemes.
    headers.retain_mut(|(name, value)| {
        if eq_ascii_lower(name, "authorization") {
            return !is_payment_authorization(value)
                && crate::protocol::core::extract_payment_scheme(value).is_none();
        }
        if eq_ascii_lower(name, "www-authenticate") {
            *value = remove_payment_challenges(value);
            // Drop the whole value if the client's own parser still finds a
            // Payment challenge in what is left, so a value split differently
            // by the two parsers cannot smuggle a challenge through.
            return !value.is_empty()
                && crate::protocol::core::parse_www_authenticate_all([value.as_str()]).is_empty();
        }
        true
    });
    // A client that joins repeated field lines into one value (as Fetch
    // `Headers.get` does) must not find a Payment challenge there either, such
    // as one hidden by a quote that opens on one line and closes on the next.
    let joined = headers
        .iter()
        .filter(|(name, _)| eq_ascii_lower(name, "www-authenticate"))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if !crate::protocol::core::parse_www_authenticate_all([joined.as_str()]).is_empty() {
        headers.retain(|(name, _)| !eq_ascii_lower(name, "www-authenticate"));
    }
}

/// Whether an `Authorization` value uses the Payment scheme.
fn is_payment_authorization(value: &str) -> bool {
    let value = value.trim_start();
    value.len() >= "payment".len()
        && value.as_bytes()[.."payment".len()].eq_ignore_ascii_case(b"payment")
        && value["payment".len()..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Remove Payment challenges from a `WWW-Authenticate` value, keeping the
/// other challenges in order. Commas inside quoted strings do not split.
fn remove_payment_challenges(value: &str) -> String {
    let bytes = value.as_bytes();
    // Start offset of each challenge, and whether it is a Payment challenge.
    let mut starts: Vec<(usize, bool)> = Vec::new();
    let mut in_quotes = false;
    let mut escaped = false;
    // Last non-whitespace byte before the current position.
    let mut previous: Option<u8> = None;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_quotes {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_quotes = false;
            }
            previous = Some(byte);
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_quotes = true;
            previous = Some(byte);
            index += 1;
            continue;
        }
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        // A challenge starts at the beginning or after a comma with a token
        // that is not followed by `=` (which would make it an auth-param).
        if previous.is_none() || previous == Some(b',') {
            let mut end = index;
            while end < bytes.len() && is_tchar(bytes[end]) {
                end += 1;
            }
            let delimited =
                end == bytes.len() || bytes[end].is_ascii_whitespace() || bytes[end] == b',';
            if end > index && delimited {
                let mut next = end;
                while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                    next += 1;
                }
                if bytes.get(next) != Some(&b'=') {
                    starts.push((index, value[index..end].eq_ignore_ascii_case("payment")));
                    previous = Some(bytes[end - 1]);
                    index = end;
                    continue;
                }
            }
        }
        previous = Some(byte);
        index += 1;
    }
    // A value that ends inside a quoted-string is malformed, and joined with
    // the next field line it could hide a challenge: drop it.
    if in_quotes {
        return String::new();
    }

    starts
        .iter()
        .enumerate()
        .filter(|(_, (_, is_payment))| !is_payment)
        .map(|(position, (start, _))| {
            let end = starts
                .get(position + 1)
                .map_or(value.len(), |(next, _)| *next);
            let challenge = value[*start..end].trim_end();
            challenge.strip_suffix(',').unwrap_or(challenge).trim()
        })
        .filter(|challenge| !challenge.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_response_drops_payment_hidden_by_parser_mismatch() {
        let mut headers = vec![
            (
                "WWW-Authenticate".into(),
                r#"Basic abc"def, Payment id="x", realm="r", method="tempo", intent="charge", request="e30""#.into(),
            ),
            ("WWW-Authenticate".into(), r#"Basic realm=a"b, Payment id="x", realm="r", method="tempo", intent="charge", request="e30""#.into()),
            ("WWW-Authenticate".into(), r#"Basic realm="kept""#.into()),
            ("Authorization".into(), "Bearer x, Payment abc".into()),
            ("Authorization".into(), "Bearer kept".into()),
        ];
        scrub_response_headers(&mut headers);
        assert_eq!(
            headers,
            vec![
                (
                    "WWW-Authenticate".to_string(),
                    r#"Basic realm="kept""#.to_string()
                ),
                ("Authorization".to_string(), "Bearer kept".to_string()),
            ]
        );
    }

    #[test]
    fn test_scrub_response_drops_payment_hidden_across_field_lines() {
        let mut headers = vec![
            ("WWW-Authenticate".into(), r#"Basic realm="a"#.into()),
            (
                "WWW-Authenticate".into(),
                r#"Basic p=", Payment id=x, realm=r, method=tempo, intent=charge, request=e30, Basic r=""#.into(),
            ),
            ("WWW-Authenticate".into(), r#"Basic realm="kept""#.into()),
        ];
        scrub_response_headers(&mut headers);
        let joined = headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("www-authenticate"))
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            crate::protocol::core::parse_www_authenticate_all([joined.as_str()]).is_empty(),
            "forged challenge survived: {headers:?}"
        );
    }

    /// Comma-separated fragments that never start a challenge must be scanned
    /// in linear time: this value took quadratic work before.
    #[test]
    fn test_scrub_response_handles_many_fragments_in_linear_time() {
        let value = format!("Basic {}", "a/,".repeat(200_000));
        let mut headers = vec![("WWW-Authenticate".to_string(), value.clone())];
        let started = std::time::Instant::now();
        scrub_response_headers(&mut headers);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(headers.len(), 1);
    }

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
    fn test_scrub_response_drops_upstream_payment_headers() {
        let mut headers: Vec<(String, String)> = [
            ("Accept-Payment", "evm/charge"),
            ("Authorization", "Payment credential"),
            ("Payment-Authorization", "Payment credential"),
            ("Payment-Receipt", "forged receipt"),
            ("Payment-Required", "forged challenge"),
            ("Payment-Response", "forged response"),
            ("Payment-Session", "forged session"),
            ("Payment-Session-Snapshot", "forged snapshot"),
            ("Payment-Signature", "forged signature"),
            ("WWW-Authenticate", "Payment id=\"forged\""),
            ("Content-Type", "application/json"),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect();

        scrub_response_headers(&mut headers);

        assert_eq!(names(&headers), vec!["content-type".to_string()]);
    }

    #[test]
    fn test_scrub_response_preserves_non_payment_challenges() {
        let mut headers = vec![(
            "WWW-Authenticate".into(),
            r#"Basic realm="example, inc", Payment id="forged", realm="api.example", Bearer realm="api""#.into(),
        )];

        scrub_response_headers(&mut headers);

        assert_eq!(
            headers,
            vec![(
                "WWW-Authenticate".to_string(),
                r#"Basic realm="example, inc", Bearer realm="api""#.to_string()
            )]
        );
    }

    #[test]
    fn test_scrub_response_preserves_parameterless_challenges() {
        for value in [
            "Negotiate",
            r#"Payment id="forged", Negotiate"#,
            r#"Negotiate, Payment id="forged""#,
        ] {
            let mut headers = vec![("WWW-Authenticate".into(), value.into())];
            scrub_response_headers(&mut headers);
            assert_eq!(headers[0].1, "Negotiate", "{value}");
        }
    }

    #[test]
    fn test_scrub_response_preserves_non_payment_authorization() {
        let mut headers = vec![
            ("Authorization".into(), "Bearer refreshed-token".into()),
            ("Authorization".into(), "  payment credential".into()),
            ("Authorization".into(), "PaymentX token".into()),
        ];

        scrub_response_headers(&mut headers);

        assert_eq!(
            headers
                .iter()
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            vec!["Bearer refreshed-token", "PaymentX token"]
        );
    }

    #[test]
    fn test_scrub_request_drops_payment_session_headers() {
        assert!(is_request_header_stripped("Payment-Session"));
        assert!(is_request_header_stripped("payment-session-snapshot"));
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
            ("Payment-Authorization".into(), "Payment …".into()),
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
            (
                "Connection".into(),
                format!("{}keep-alive, X-Debug ,, ", ' '),
            ),
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
