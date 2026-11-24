//! Tempo ID attestation issuer and its client.

use http_types::Request;

use super::*;
use crate::identity::ext::attestation::{verify, AttestationClaims, SigningKey, VerifyOptions};
use crate::identity::ext::tempo_id::constants::ATTEST_PATH;
use crate::identity::ext::tempo_id::issuer::{
    create as create_issuer, IssuerConfig, TempoIdIssuer, MAX_BODY,
};

const AUDIENCE: &str = "https://api.example";

/// The URL the attestation issuer runs at; access tokens name it as their audience.
const ATTEST_URL: &str = "https://attest.example";

fn attestation_key() -> SigningKey {
    SigningKey::from_bytes(&[5u8; 32])
}

fn config(tempo: &Issuer, url: &str) -> IssuerConfig {
    IssuerConfig::new(
        url,
        attestation_key(),
        CLIENT_ID,
        Arc::new(MemoryStore::new()),
    )
    .issuer(tempo.url.clone())
}

/// An access token for user_1 issued for the attestation issuer at `url`.
fn token_for(tempo: &Issuer, url: &str) -> String {
    let mut claims = access_claims(tempo);
    claims["aud"] = json!(url);
    access_token(&claims)
}

fn id_token(tempo: &Issuer, verified: bool) -> String {
    sign(
        json!({ "alg": "RS256", "kid": "key-1" }),
        json!({
            "iss": tempo.url, "aud": CLIENT_ID, "sub": "user_1",
            "exp": now() + 600, "email": "Ada@Example.com", "email_verified": verified,
        }),
    )
}

fn post(path: &str, headers: &[(&str, String)], body: &str) -> Request<Vec<u8>> {
    let mut request = Request::builder().method(Method::POST).uri(path);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    request.body(body.as_bytes().to_vec()).unwrap()
}

fn body(audience: &str, attestation_type: &str) -> String {
    json!({ "audience": audience, "type": attestation_type }).to_string()
}

async fn exchange(
    issuer: &TempoIdIssuer,
    headers: &[(&str, String)],
    body: &str,
) -> (StatusCode, HeaderMap, Value) {
    let response = issuer
        .handle(&post(ATTEST_PATH, headers, body))
        .await
        .unwrap();
    let json = serde_json::from_slice(response.body()).unwrap_or(Value::Null);
    (response.status(), response.headers().clone(), json)
}

async fn verified(
    issuer: &TempoIdIssuer,
    token: &str,
    attestation_type: &str,
) -> AttestationClaims {
    let options = VerifyOptions {
        issuer: issuer.issuer().to_owned(),
        audience: AUDIENCE.to_owned(),
        attestation_type: attestation_type.to_owned(),
        clock_tolerance: None,
        max_age: None,
        now: None,
    };
    verify(token, &options, issuer.attestation_issuer())
        .await
        .unwrap()
}

#[tokio::test]
async fn exchanges_an_access_token_for_attestations() {
    let tempo = issuer().await;
    let issuer = create_issuer(config(&tempo, ATTEST_URL)).unwrap();
    let auth = (
        "authorization",
        format!("Bearer {}", token_for(&tempo, ATTEST_URL)),
    );

    let (status, headers, json) = exchange(
        &issuer,
        std::slice::from_ref(&auth),
        &body(AUDIENCE, "tempo-id"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{json}");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["access-control-allow-origin"], "*");
    let token = json["attestation"].as_str().unwrap();
    let claims = verified(&issuer, token, "tempo-id").await;
    assert_eq!(claims.sub, "user_1");
    assert_eq!(claims.uid(), Some("user_1"));
    assert_eq!(claims.extra["azp"], CLIENT_ID);
    let expires = time::OffsetDateTime::parse(
        json["expires_at"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert_eq!(expires.unix_timestamp() as u64, claims.exp);
    assert!(json["expires_at"].as_str().unwrap().ends_with(".000Z"));

    // email needs an ID token naming an address Tempo ID verified.
    let (status, _, json) = exchange(
        &issuer,
        std::slice::from_ref(&auth),
        &body(AUDIENCE, "email"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        json["error"],
        "Send an ID token naming an email address Tempo ID verified."
    );
    let unverified = [auth.clone(), (ID_TOKEN_HEADER, id_token(&tempo, false))];
    let (status, _, _) = exchange(&issuer, &unverified, &body(AUDIENCE, "email")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let with_id = [auth, (ID_TOKEN_HEADER, id_token(&tempo, true))];
    let (status, _, json) = exchange(&issuer, &with_id, &body(AUDIENCE, "email")).await;
    assert_eq!(status, StatusCode::OK);
    let claims = verified(&issuer, json["attestation"].as_str().unwrap(), "email").await;
    assert_eq!(claims.sub, "ada@example.com");
    assert_eq!(claims.uid(), Some("user_1"));
}

#[tokio::test]
async fn refuses_bad_requests_and_tokens() {
    let tempo = issuer().await;
    let issuer =
        create_issuer(config(&tempo, ATTEST_URL).allow(|user| user.user_id != "blocked")).unwrap();
    let auth = (
        "authorization",
        format!("Bearer {}", token_for(&tempo, ATTEST_URL)),
    );
    type Case<'a> = (Vec<(&'a str, String)>, String, StatusCode, &'a str);
    let cases: Vec<Case> = vec![
        (
            vec![auth.clone()],
            "{".into(),
            StatusCode::BAD_REQUEST,
            "The body must be JSON of at most 4096 bytes.",
        ),
        (
            vec![auth.clone()],
            format!("{{\"pad\":\"{}\"}}", "a".repeat(MAX_BODY)),
            StatusCode::BAD_REQUEST,
            "The body must be JSON of at most 4096 bytes.",
        ),
        (
            vec![auth.clone()],
            body("http://api.example", "tempo-id"),
            StatusCode::BAD_REQUEST,
            "audience must be an https origin.",
        ),
        (
            vec![auth.clone()],
            body(AUDIENCE, "github"),
            StatusCode::BAD_REQUEST,
            "type must be one of tempo-id, email.",
        ),
        (
            vec![],
            body(AUDIENCE, "tempo-id"),
            StatusCode::UNAUTHORIZED,
            "Sign in with Tempo ID.",
        ),
        // A token issued for another API cannot be exchanged here.
        (
            vec![(
                "authorization",
                format!("Bearer {}", access_token(&access_claims(&tempo))),
            )],
            body(AUDIENCE, "tempo-id"),
            StatusCode::UNAUTHORIZED,
            "",
        ),
    ];
    for (headers, request_body, status, reason) in cases {
        let (got, response_headers, json) = exchange(&issuer, &headers, &request_body).await;
        assert_eq!(got, status, "{json}");
        if !reason.is_empty() {
            assert_eq!(json["error"], reason);
        }
        if status == StatusCode::UNAUTHORIZED {
            assert!(response_headers.contains_key("www-authenticate"));
        }
    }

    let mut blocked = access_claims(&tempo);
    blocked["aud"] = json!(ATTEST_URL);
    blocked["sub"] = json!("blocked");
    let headers = [(
        "authorization",
        format!("Bearer {}", access_token(&blocked)),
    )];
    let (status, _, _) = exchange(&issuer, &headers, &body(AUDIENCE, "tempo-id")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn answers_its_routes_only() {
    let tempo = issuer().await;
    let issuer = create_issuer(config(&tempo, "https://attest.example/tenant/")).unwrap();
    let request = |method: Method, path: &str| {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Vec::<u8>::new())
            .unwrap()
    };
    let preflight = issuer
        .handle(&request(Method::OPTIONS, "/tenant/tempo-id/attest"))
        .await
        .unwrap();
    assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        preflight.headers()["access-control-allow-headers"],
        "authorization, content-type, dpop, tempo-id-token"
    );
    let get = issuer
        .handle(&request(Method::GET, "/tenant/tempo-id/attest"))
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(get.headers()["allow"], "POST");
    let jwks = issuer
        .handle(&request(Method::GET, "/tenant/.well-known/jwks.json"))
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(jwks.body()).unwrap();
    assert_eq!(json, issuer.jwks());
    assert!(issuer
        .handle(&request(Method::POST, "/tempo-id/attest"))
        .await
        .is_none());
    assert!(issuer
        .handle(&request(Method::GET, "/tenant/other"))
        .await
        .is_none());
}

#[tokio::test]
async fn create_checks_its_config() {
    let tempo = issuer().await;
    assert!(create_issuer(config(&tempo, "http://attest.example")).is_err());
    assert!(create_issuer(config(&tempo, "https://attest.example?x=1")).is_err());
    assert!(create_issuer(config(&tempo, ATTEST_URL).types(["github"])).is_err());
    assert!(create_issuer(config(&tempo, ATTEST_URL).ttl(0)).is_err());
    let no_app = IssuerConfig::new(
        ATTEST_URL,
        attestation_key(),
        "",
        Arc::new(MemoryStore::new()),
    );
    assert!(create_issuer(no_app).is_err());
    let only_id = create_issuer(config(&tempo, ATTEST_URL).types(["tempo-id"])).unwrap();
    let auth = [(
        "authorization",
        format!("Bearer {}", token_for(&tempo, ATTEST_URL)),
    )];
    let (status, _, json) = exchange(&only_id, &auth, &body(AUDIENCE, "email")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["error"], "type must be one of tempo-id.");
}

#[tokio::test]
async fn create_checks_urls_and_audiences() {
    let tempo = issuer().await;
    // Tempo ID's keys decide whom the issuer signs for: never over plaintext off this host.
    assert!(create_issuer(config(&tempo, ATTEST_URL).issuer("http://id.example")).is_err());
    assert!(create_issuer(config(&tempo, ATTEST_URL).issuer("https://id.example")).is_ok());
    for bad in [
        "https://user:secret@attest.example",
        "https://attest.example/tenant ",
        "https://attest.example/tenant\\",
    ] {
        assert!(create_issuer(config(&tempo, bad)).is_err(), "{bad}");
    }
    assert!(create_issuer(config(&tempo, "https://Attest.Example/tenant/")).is_err());
    let canonical = create_issuer(config(&tempo, "https://attest.example/tenant/")).unwrap();
    assert_eq!(canonical.issuer(), "https://attest.example/tenant");
    // An injected client may use a proxy, so plaintext key discovery refuses one.
    assert!(tempo.url.starts_with("http://"));
    assert!(create_issuer(config(&tempo, ATTEST_URL).http_client(reqwest::Client::new())).is_err());
    // However the plaintext origin is spelled.
    for loose in [
        "http:localhost:8080",
        "HTTP://localhost:8080",
        "http:/localhost:8080",
    ] {
        assert!(
            create_issuer(
                config(&tempo, ATTEST_URL)
                    .issuer(loose)
                    .http_client(reqwest::Client::new())
            )
            .is_err(),
            "{loose}"
        );
    }
    assert!(create_issuer(
        config(&tempo, ATTEST_URL)
            .issuer("https://id.example")
            .http_client(reqwest::Client::new())
    )
    .is_ok());
    assert!(create_issuer(config(&tempo, ATTEST_URL).audiences(["http://api.example"])).is_err());

    let limited =
        create_issuer(config(&tempo, ATTEST_URL).audiences([format!("{AUDIENCE}/any/path")]))
            .unwrap();
    let auth = [(
        "authorization",
        format!("Bearer {}", token_for(&tempo, ATTEST_URL)),
    )];
    let (status, _, json) = exchange(&limited, &auth, &body(AUDIENCE, "tempo-id")).await;
    assert_eq!(status, StatusCode::OK, "{json}");
    let (status, _, json) =
        exchange(&limited, &auth, &body("https://other.example", "tempo-id")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        json["error"],
        "This issuer does not sign attestations for that audience."
    );
}

#[cfg(feature = "client")]
mod client {
    use super::super::dpop::{bound_token, dpop_key, proof_for};
    use super::*;
    use crate::identity::client::{ProveContext, Prover, ResponseParts, RetryContext};
    use crate::identity::ext::tempo_id::client::{attest, attestations, AttestConfig};

    /// Serves `issuer` over HTTP on localhost, returning its URL.
    async fn serve(make: impl FnOnce(&str) -> TempoIdIssuer) -> (String, Arc<TempoIdIssuer>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let issuer = Arc::new(make(&url));
        let shared = issuer.clone();
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let issuer = shared.clone();
            async move {
                let (parts, body) = request.into_parts();
                let bytes = axum::body::to_bytes(body, MAX_BODY + 1)
                    .await
                    .unwrap_or_default();
                let request = Request::from_parts(parts, bytes.to_vec());
                let response = issuer.handle(&request).await.unwrap_or_else(|| {
                    let mut response = http_types::Response::new(Vec::new());
                    *response.status_mut() = StatusCode::NOT_FOUND;
                    response
                });
                let (parts, body) = response.into_parts();
                axum::response::Response::from_parts(parts, axum::body::Body::from(body))
            }
        });
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, issuer)
    }

    fn context() -> ProveContext {
        ProveContext {
            created: 0,
            nonce: "n".into(),
            challenge: None,
        }
    }

    fn token_as(tempo: &Issuer, url: &str, user: &str) -> String {
        let mut claims = access_claims(tempo);
        claims["aud"] = json!(url);
        claims["sub"] = json!(user);
        access_token(&claims)
    }

    #[tokio::test]
    async fn attest_exchanges_bearer_and_dpop_tokens() {
        let tempo = issuer().await;
        let (url, issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;

        let token = token_for(&tempo, &url);
        let bearer = AttestConfig::new(&url, move || {
            let token = token.clone();
            async move { Ok(token) }
        })
        .unwrap();
        let attested = attest(&bearer, AUDIENCE, "tempo-id")
            .await
            .unwrap()
            .unwrap();
        let claims = verified(&issuer, &attested.attestation, "tempo-id").await;
        assert_eq!(claims.uid(), Some("user_1"));
        let expires = attested
            .expires_at
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        assert_eq!(expires.as_secs(), claims.exp);
        // email without an ID token is refused: no attestation, no error.
        assert_eq!(attest(&bearer, AUDIENCE, "email").await.unwrap(), None);
        // Other failures are errors carrying the issuer's reason.
        let error = attest(&bearer, "http://api.example", "tempo-id")
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "audience must be an https origin.");

        let key = dpop_key();
        let bound = bound_token(&tempo, &key);
        let mut claims = decode_claims(&bound);
        claims["aud"] = json!(url);
        let bound = access_token(&claims);
        let dpop = AttestConfig::new(&url, move || {
            let token = bound.clone();
            async move { Ok(token) }
        })
        .unwrap()
        .dpop(key.clone());
        assert!(attest(&dpop, AUDIENCE, "tempo-id").await.unwrap().is_some());
        // A proof is accepted once.
        let token = access_token(&claims);
        let proof = proof_for(
            &key,
            &token,
            reqwest::Method::POST,
            &format!("{url}{ATTEST_PATH}"),
        );
        let headers = [("authorization", format!("DPoP {token}")), ("dpop", proof)];
        let (status, _, _) = exchange(&issuer, &headers, &body(AUDIENCE, "tempo-id")).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, json) = exchange(&issuer, &headers, &body(AUDIENCE, "tempo-id")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
        // A proof for another URL is refused.
        let proof = proof_for(
            &key,
            &token,
            reqwest::Method::POST,
            "https://evil.example/tempo-id/attest",
        );
        let headers = [("authorization", format!("DPoP {token}")), ("dpop", proof)];
        let (status, _, _) = exchange(&issuer, &headers, &body(AUDIENCE, "tempo-id")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        assert!(
            AttestConfig::new("http://attest.example", || async { Ok(String::new()) }).is_err()
        );
    }

    fn decode_claims(token: &str) -> Value {
        Value::Object(
            crate::identity::ext::tempo_id::jwt::decode(token)
                .unwrap()
                .claims,
        )
    }

    #[tokio::test]
    async fn attestations_are_kept_per_signed_in_user() {
        let tempo = issuer().await;
        let (url, issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let current = Arc::new(std::sync::Mutex::new(token_as(&tempo, &url, "user_1")));
        let source = current.clone();
        let attest_config = AttestConfig::new(&url, move || {
            let token = source.lock().unwrap().clone();
            async move { Ok(token) }
        })
        .unwrap();
        let prover = attestations(
            attest_config,
            [AUDIENCE],
            Some(["tempo-id"]),
            Vec::<String>::new(),
        )
        .unwrap();

        // The server asks for a Tempo ID attestation from this issuer.
        let request = reqwest::Request::new(
            reqwest::Method::GET,
            format!("{AUDIENCE}/paid").parse().unwrap(),
        );
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "identity-attestation-required",
            format!("tempo-id;issuer=\"{url}\"").parse().unwrap(),
        );
        let response = ResponseParts {
            status: reqwest::StatusCode::UNAUTHORIZED,
            headers,
            url: request.url().clone(),
        };
        let retry = prover
            .retry(&response, RetryContext { request: &request })
            .await
            .unwrap();
        let first = retry["identity-attestation"].to_str().unwrap().to_owned();
        assert_eq!(
            verified(&issuer, &first, "tempo-id").await.uid(),
            Some("user_1")
        );

        // The cached attestation is presented on the next request.
        let mut next = reqwest::Request::new(
            reqwest::Method::GET,
            format!("{AUDIENCE}/paid").parse().unwrap(),
        );
        prover.prove(&mut next, &context()).await.unwrap();
        assert_eq!(next.headers()["identity-attestation"], first.as_str());

        // Another user signs in: the first user's attestation is neither
        // presented nor kept on a request in flight.
        *current.lock().unwrap() = token_as(&tempo, &url, "user_2");
        let mut in_flight = reqwest::Request::new(
            reqwest::Method::GET,
            format!("{AUDIENCE}/paid").parse().unwrap(),
        );
        in_flight.headers_mut().insert(
            "identity-attestation",
            format!("{first}, other.token.here").parse().unwrap(),
        );
        prover.prove(&mut in_flight, &context()).await.unwrap();
        assert_eq!(
            in_flight.headers()["identity-attestation"],
            "other.token.here"
        );

        let retry = prover
            .retry(&response, RetryContext { request: &request })
            .await
            .unwrap();
        let second = retry["identity-attestation"].to_str().unwrap().to_owned();
        assert_eq!(
            verified(&issuer, &second, "tempo-id").await.uid(),
            Some("user_2")
        );
    }

    #[tokio::test]
    async fn overlapping_lookups_keep_the_users_cache() {
        let tempo = issuer().await;
        let (url, _issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let token = token_as(&tempo, &url, "user_1");
        // The first two access token reads wait for their gate, so two
        // lookups overlap and the earlier one finishes first.
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let gates = Arc::new([tokio::sync::Notify::new(), tokio::sync::Notify::new()]);
        let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
        let attest_config = {
            let (calls, gates) = (calls.clone(), gates.clone());
            AttestConfig::new(&url, move || {
                let (token, calls, gates, entered) =
                    (token.clone(), calls.clone(), gates.clone(), entered.clone());
                async move {
                    let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = entered.send(call);
                    if let Some(gate) = gates.get(call) {
                        gate.notified().await;
                    }
                    Ok(token)
                }
            })
            .unwrap()
        };
        let prover = attestations(
            attest_config,
            [AUDIENCE],
            Some(["tempo-id"]),
            Vec::<String>::new(),
        )
        .unwrap();
        let get = || {
            reqwest::Request::new(
                reqwest::Method::GET,
                format!("{AUDIENCE}/paid").parse().unwrap(),
            )
        };
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "identity-attestation-required",
            format!("tempo-id;issuer=\"{url}\"").parse().unwrap(),
        );
        let response = ResponseParts {
            status: reqwest::StatusCode::UNAUTHORIZED,
            headers,
            url: get().url().clone(),
        };

        // A retry starts a lookup, then a request starts another before it ends.
        let retry = tokio::spawn({
            let prover = prover.clone();
            async move {
                let request = get();
                prover
                    .retry(&response, RetryContext { request: &request })
                    .await
            }
        });
        assert_eq!(entries.recv().await, Some(0));
        let request = tokio::spawn({
            let prover = prover.clone();
            async move {
                let mut request = get();
                prover.prove(&mut request, &context()).await.unwrap();
            }
        });
        assert_eq!(entries.recv().await, Some(1));

        // The earlier lookup ends first and acquires an attestation.
        gates[0].notify_one();
        let attested = retry.await.unwrap().unwrap()["identity-attestation"]
            .to_str()
            .unwrap()
            .to_owned();
        gates[1].notify_one();
        request.await.unwrap();

        // The attestation stays cached for later requests.
        let mut next = get();
        prover.prove(&mut next, &context()).await.unwrap();
        assert_eq!(next.headers()["identity-attestation"], attested.as_str());
    }

    #[tokio::test]
    async fn restores_only_the_signed_in_users_attestations() {
        let tempo = issuer().await;
        let (url, issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let sign_for = |uid: &str, app: &str| {
            let mut claims = serde_json::Map::new();
            claims.insert("azp".into(), json!(app));
            issuer
                .attestation_issuer()
                .sign(
                    crate::identity::ext::attestation::SignParameters::new(
                        AUDIENCE, "tempo-id", uid,
                    )
                    .uid(uid)
                    .claims(claims),
                )
                .unwrap()
        };
        let (mine, theirs, other_app) = (
            sign_for("user_1", CLIENT_ID),
            sign_for("user_2", CLIENT_ID),
            sign_for("user_1", "app_other"),
        );
        let token = token_as(&tempo, &url, "user_1");
        let attest_config = AttestConfig::new(&url, move || {
            let token = token.clone();
            async move { Ok(token) }
        })
        .unwrap();
        let prover = attestations(
            attest_config,
            [AUDIENCE],
            None::<[&str; 0]>,
            [&theirs, &other_app, &mine],
        )
        .unwrap();
        let mut request = reqwest::Request::new(
            reqwest::Method::GET,
            format!("{AUDIENCE}/paid").parse().unwrap(),
        );
        prover.prove(&mut request, &context()).await.unwrap();
        assert_eq!(request.headers()["identity-attestation"], mine.as_str());

        // While the access token cannot be read, nothing is presented.
        let failing = AttestConfig::new(&url, || async {
            Err(crate::identity::client::ProverError::new("signed out"))
        })
        .unwrap();
        let prover = attestations(failing, [AUDIENCE], None::<[&str; 0]>, [&mine]).unwrap();
        let mut request = reqwest::Request::new(
            reqwest::Method::GET,
            format!("{AUDIENCE}/paid").parse().unwrap(),
        );
        prover.prove(&mut request, &context()).await.unwrap();
        assert!(!request.headers().contains_key("identity-attestation"));
    }

    /// Serves fixed answers on localhost: `answer` gets the server's URL and
    /// returns the status and body of every response.
    async fn serve_fixed(answer: impl FnOnce(&str) -> (u16, String)) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (status, body) = answer(&url);
        let app = axum::Router::new().fallback(move || {
            let body = body.clone();
            async move {
                axum::response::Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap()
            }
        });
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        url
    }

    fn bearer(url: &str) -> AttestConfig {
        AttestConfig::new(url, || async { Ok("token".to_owned()) }).unwrap()
    }

    /// An attestation the issuer at `url` signs, with `edit` applied to its parameters.
    fn signed_at(
        url: &str,
        edit: impl FnOnce(
            crate::identity::ext::attestation::SignParameters,
        ) -> crate::identity::ext::attestation::SignParameters,
    ) -> (String, String) {
        let issuer =
            crate::identity::ext::attestation::AttestationIssuer::new(url, attestation_key())
                .unwrap();
        let token = issuer
            .sign(edit(
                crate::identity::ext::attestation::SignParameters::new(
                    AUDIENCE, "tempo-id", "user_1",
                )
                .uid("user_1"),
            ))
            .unwrap();
        let exp = crate::identity::ext::attestation::decode(&token)
            .unwrap()
            .claims["exp"]
            .as_i64()
            .unwrap();
        let expires_at = time::OffsetDateTime::from_unix_timestamp(exp)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        (token, expires_at)
    }

    #[tokio::test]
    async fn attest_checks_the_issuers_answer() {
        let answer = |token: &str, expires_at: &str| {
            json!({ "attestation": token, "expires_at": expires_at }).to_string()
        };
        // A matching attestation is returned, and its Debug output leaves it out.
        let url = serve_fixed(|url| {
            let (token, expires_at) = signed_at(url, |p| p);
            (200, answer(&token, &expires_at))
        })
        .await;
        let attested = attest(&bearer(&url), AUDIENCE, "tempo-id")
            .await
            .unwrap()
            .unwrap();
        assert!(!format!("{attested:?}").contains(&attested.attestation));
        assert!(format!("{attested:?}").contains("[redacted]"));

        let mismatched = [serve_fixed(|url| {
            let (token, expires_at) = signed_at(url, |p| p);
            (200, answer(&token, &expires_at))
        })
        .await];
        // Asked for email or another audience, it does not match.
        assert_eq!(
            attest(&bearer(&mismatched[0]), AUDIENCE, "email")
                .await
                .unwrap_err()
                .to_string(),
            "The issuer returned an attestation that does not match the request."
        );
        assert!(
            attest(&bearer(&mismatched[0]), "https://other.example", "tempo-id")
                .await
                .is_err()
        );
        // Another issuer's attestation, or another expiry, does not match.
        let other_issuer = serve_fixed(|_| {
            let (token, expires_at) = signed_at("https://other-issuer.example", |p| p);
            (200, answer(&token, &expires_at))
        })
        .await;
        assert!(attest(&bearer(&other_issuer), AUDIENCE, "tempo-id")
            .await
            .is_err());
        let other_expiry = serve_fixed(|url| {
            let (token, _) = signed_at(url, |p| p);
            (200, answer(&token, "2030-01-01T00:00:00.000Z"))
        })
        .await;
        assert!(attest(&bearer(&other_expiry), AUDIENCE, "tempo-id")
            .await
            .is_err());
        // An iss with a trailing slash is not this issuer: verifiers compare it exactly.
        let slashed = serve_fixed(|url| {
            let (token, expires_at) = signed_at(url, |p| p);
            let mut claims = crate::identity::ext::attestation::decode(&token)
                .unwrap()
                .claims;
            claims.insert("iss".into(), json!(format!("{url}/")));
            let token =
                crate::identity::ext::attestation::sign(&claims, &attestation_key(), "k").unwrap();
            (200, answer(&token, &expires_at))
        })
        .await;
        assert_eq!(
            attest(&bearer(&slashed), AUDIENCE, "tempo-id")
                .await
                .unwrap_err()
                .to_string(),
            "The issuer returned an attestation that does not match the request."
        );
        // A fraction past the signed second is dropped: the expiry is the signed exp.
        let fraction = serve_fixed(|url| {
            let (token, _) = signed_at(url, |p| p);
            let exp = crate::identity::ext::attestation::decode(&token)
                .unwrap()
                .claims["exp"]
                .as_i64()
                .unwrap();
            let late = (time::OffsetDateTime::from_unix_timestamp(exp).unwrap()
                + time::Duration::milliseconds(999))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
            assert!(late.contains(".999"), "{late}");
            (200, answer(&token, &late))
        })
        .await;
        let attested = attest(&bearer(&fraction), AUDIENCE, "tempo-id")
            .await
            .unwrap()
            .unwrap();
        let exp = crate::identity::ext::attestation::decode(&attested.attestation)
            .unwrap()
            .claims["exp"]
            .as_u64()
            .unwrap();
        assert_eq!(
            attested.expires_at,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(exp)
        );
        // Empty or undecodable attestations are malformed.
        for token in ["", "not-a-token"] {
            let url = serve_fixed(|_| (200, answer(token, "2030-01-01T00:00:00.000Z"))).await;
            assert_eq!(
                attest(&bearer(&url), AUDIENCE, "tempo-id")
                    .await
                    .unwrap_err()
                    .to_string(),
                "The issuer returned a malformed attestation."
            );
        }
        // A body over the limit is never parsed; a refusal's is never read.
        let huge = json!({ "error": "x".repeat(40_000) }).to_string();
        let url = serve_fixed(|_| (500, huge.clone())).await;
        assert_eq!(
            attest(&bearer(&url), AUDIENCE, "tempo-id")
                .await
                .unwrap_err()
                .to_string(),
            "The issuer answered 500."
        );
        let url = serve_fixed(|_| (200, huge.clone())).await;
        assert!(attest(&bearer(&url), AUDIENCE, "tempo-id").await.is_err());
        let url = serve_fixed(|_| (403, huge)).await;
        assert_eq!(
            attest(&bearer(&url), AUDIENCE, "tempo-id").await.unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn attest_config_checks_the_issuer_and_skips_proxies_on_localhost() {
        for bad in [
            "https://user:secret@attest.example",
            "https://attest.example/tenant/ ",
            "https://attest.example/tenant\\",
        ] {
            assert!(
                AttestConfig::new(bad, || async { Ok(String::new()) }).is_err(),
                "{bad}"
            );
        }
        assert!(
            AttestConfig::new("https://Attest.Example/tenant/", || async {
                Ok(String::new())
            })
            .is_err()
        );
        let canonical = AttestConfig::new("https://attest.example/tenant/", || async {
            Ok(String::new())
        })
        .unwrap();
        assert_eq!(canonical.issuer(), "https://attest.example/tenant");

        // A localhost exchange never goes through a proxy, even one the builder sets.
        let tempo = issuer().await;
        let (url, _issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let token = token_for(&tempo, &url);
        let proxied = AttestConfig::new(&url, move || {
            let token = token.clone();
            async move { Ok(token) }
        })
        .unwrap()
        .http_client_builder(
            reqwest::Client::builder().proxy(reqwest::Proxy::all("http://127.0.0.1:9").unwrap()),
        )
        .unwrap();
        assert!(attest(&proxied, AUDIENCE, "tempo-id")
            .await
            .unwrap()
            .is_some());
    }

    fn required_response(url: &str) -> ResponseParts {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "identity-attestation-required",
            format!("tempo-id;issuer=\"{url}\"").parse().unwrap(),
        );
        ResponseParts {
            status: reqwest::StatusCode::UNAUTHORIZED,
            headers,
            url: format!("{AUDIENCE}/paid").parse().unwrap(),
        }
    }

    fn paid() -> reqwest::Request {
        reqwest::Request::new(
            reqwest::Method::GET,
            format!("{AUDIENCE}/paid").parse().unwrap(),
        )
    }

    #[tokio::test]
    async fn attestations_are_kept_per_app() {
        let tempo = issuer().await;
        let (url, issuer) =
            serve(|url| create_issuer(config(&tempo, url).client_id("app_other")).unwrap()).await;
        let current = Arc::new(std::sync::Mutex::new(token_for(&tempo, &url)));
        let source = current.clone();
        let attest_config = AttestConfig::new(&url, move || {
            let token = source.lock().unwrap().clone();
            async move { Ok(token) }
        })
        .unwrap();
        let prover = attestations(
            attest_config,
            [AUDIENCE],
            Some(["tempo-id"]),
            Vec::<String>::new(),
        )
        .unwrap();
        let response = required_response(&url);
        let request = paid();
        let retry = prover
            .retry(&response, RetryContext { request: &request })
            .await
            .unwrap();
        let first = retry["identity-attestation"].to_str().unwrap().to_owned();
        assert_eq!(decode_claims_of(&first)["azp"], CLIENT_ID);

        // The same user under another app: the first app's attestation is not presented.
        let mut claims = access_claims(&tempo);
        claims["aud"] = json!(url);
        claims["client_id"] = json!("app_other");
        *current.lock().unwrap() = access_token(&claims);
        let mut next = paid();
        prover.prove(&mut next, &context()).await.unwrap();
        assert!(!next.headers().contains_key("identity-attestation"));
        let retry = prover
            .retry(&response, RetryContext { request: &request })
            .await
            .unwrap();
        let second = retry["identity-attestation"].to_str().unwrap().to_owned();
        assert_eq!(decode_claims_of(&second)["azp"], "app_other");
        assert_eq!(
            verified(&issuer, &second, "tempo-id").await.uid(),
            Some("user_1")
        );
    }

    fn decode_claims_of(token: &str) -> Value {
        Value::Object(
            crate::identity::ext::attestation::decode(token)
                .unwrap()
                .claims,
        )
    }

    #[tokio::test]
    async fn prepare_refuses_to_pay_after_the_user_changed() {
        use crate::identity::client::PrepareContext;
        let tempo = issuer().await;
        let (url, _issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let current = Arc::new(std::sync::Mutex::new(token_as(&tempo, &url, "user_1")));
        let source = current.clone();
        let attest_config = AttestConfig::new(&url, move || {
            let token = source.lock().unwrap().clone();
            async move { Ok(token) }
        })
        .unwrap();
        let prover = attestations(
            attest_config,
            [AUDIENCE],
            Some(["tempo-id"]),
            Vec::<String>::new(),
        )
        .unwrap();
        let context_for = |requirements: Vec<crate::identity::Requirement>| PrepareContext {
            challenge: crate::protocol::core::PaymentChallenge::new(
                "id",
                "realm",
                "tempo",
                "charge",
                crate::protocol::core::Base64UrlJson::from_value(&json!({})).unwrap(),
            ),
            requirements,
        };
        let required = || {
            context_for(vec![
                crate::identity::Requirement::new("tempo-id").with_issuer(url.clone())
            ])
        };
        let parts = ResponseParts {
            status: reqwest::StatusCode::PAYMENT_REQUIRED,
            headers: reqwest::header::HeaderMap::new(),
            url: format!("{AUDIENCE}/paid").parse().unwrap(),
        };
        let mut request = paid();
        prover.prove(&mut request, &context()).await.unwrap();
        // The same user: the payment goes ahead.
        assert!(prover.prepare(&parts, &required()).await.is_ok());

        // Another user signed in after the request was sent: refuse before paying.
        *current.lock().unwrap() = token_as(&tempo, &url, "user_2");
        let error = prover.prepare(&parts, &required()).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "The signed-in Tempo ID user changed: send the request again."
        );
        // The prover now presents for the new user, so the next 402 pays.
        assert!(prover.prepare(&parts, &required()).await.is_ok());

        // A 402 that needs none of these attestations is not refused.
        *current.lock().unwrap() = token_as(&tempo, &url, "user_3");
        assert!(prover
            .prepare(&parts, &context_for(Vec::new()))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn a_superseded_lookup_presents_for_the_newer_user() {
        let tempo = issuer().await;
        let (url, issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let mut claims = serde_json::Map::new();
        claims.insert("azp".into(), json!(CLIENT_ID));
        let previous = issuer
            .attestation_issuer()
            .sign(
                crate::identity::ext::attestation::SignParameters::new(
                    AUDIENCE, "tempo-id", "user_1",
                )
                .uid("user_1")
                .claims(claims),
            )
            .unwrap();
        // The first access token read (user_1) waits for its gate; the second (user_2) does not.
        let tokens = [
            token_as(&tempo, &url, "user_1"),
            token_as(&tempo, &url, "user_2"),
        ];
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());
        let (entered, mut entries) = tokio::sync::mpsc::unbounded_channel();
        let attest_config = {
            let (calls, gate) = (calls.clone(), gate.clone());
            AttestConfig::new(&url, move || {
                let (tokens, calls, gate, entered) =
                    (tokens.clone(), calls.clone(), gate.clone(), entered.clone());
                async move {
                    let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = entered.send(call);
                    if call == 0 {
                        gate.notified().await;
                    }
                    Ok(tokens[call.min(1)].clone())
                }
            })
            .unwrap()
        };
        let prover = attestations(
            attest_config,
            [AUDIENCE],
            Some(["tempo-id"]),
            Vec::<String>::new(),
        )
        .unwrap();

        // A request carrying user_1's attestation starts a lookup that reads user_1's token...
        let slow = tokio::spawn({
            let (prover, previous) = (prover.clone(), previous.clone());
            async move {
                let mut request = paid();
                request
                    .headers_mut()
                    .insert("identity-attestation", previous.parse().unwrap());
                prover.prove(&mut request, &context()).await.unwrap();
                request
            }
        });
        assert_eq!(entries.recv().await, Some(0));
        // ...while a newer lookup finds user_2 signed in and ends first.
        let mut newer = paid();
        prover.prove(&mut newer, &context()).await.unwrap();
        gate.notify_one();
        let request = slow.await.unwrap();
        assert!(!request.headers().contains_key("identity-attestation"));
    }

    /// A request carrying a Payment Credential, as a paid attempt does.
    fn paid_attempt() -> reqwest::Request {
        let mut request = paid();
        request
            .headers_mut()
            .insert("authorization", "Payment e30".parse().unwrap());
        request
    }

    /// An attestation for user `uid` of the app `CLIENT_ID` that `issuer` signs.
    fn attestation_for(issuer: &TempoIdIssuer, uid: &str) -> String {
        let mut claims = serde_json::Map::new();
        claims.insert("azp".into(), json!(CLIENT_ID));
        issuer
            .attestation_issuer()
            .sign(
                crate::identity::ext::attestation::SignParameters::new(AUDIENCE, "tempo-id", uid)
                    .uid(uid)
                    .claims(claims),
            )
            .unwrap()
    }

    /// An access token source answering each read from `answer`, by call
    /// index; reads whose index is in `gated` wait for `gate` and report
    /// their index on `entered` first.
    fn scripted(
        url: &str,
        answer: impl Fn(usize) -> Result<String, crate::identity::client::ProverError>
            + Send
            + Sync
            + 'static,
        gated: &'static [usize],
    ) -> (
        AttestConfig,
        Arc<tokio::sync::Notify>,
        tokio::sync::mpsc::UnboundedReceiver<usize>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());
        let (entered, entries) = tokio::sync::mpsc::unbounded_channel();
        let answer = Arc::new(answer);
        let config = {
            let (calls, gate) = (calls.clone(), gate.clone());
            AttestConfig::new(url, move || {
                let (calls, gate, entered, answer) =
                    (calls.clone(), gate.clone(), entered.clone(), answer.clone());
                async move {
                    let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = entered.send(call);
                    if gated.contains(&call) {
                        gate.notified().await;
                    }
                    answer(call)
                }
            })
            .unwrap()
        };
        (config, gate, entries, calls)
    }

    #[tokio::test]
    async fn a_paid_attempt_is_refused_rather_than_sent_without_its_attestations() {
        let tempo = issuer().await;
        let (url, issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let first = attestation_for(&issuer, "user_1");
        let current = Arc::new(std::sync::Mutex::new(Some(token_as(
            &tempo, &url, "user_1",
        ))));
        let source = current.clone();
        let attest_config =
            AttestConfig::new(&url, move || {
                let token = source.lock().unwrap().clone();
                async move {
                    token.ok_or_else(|| crate::identity::client::ProverError::new("signed out"))
                }
            })
            .unwrap();
        let prover = attestations(attest_config, [AUDIENCE], Some(["tempo-id"]), [&first]).unwrap();
        let carrying = || {
            let mut request = paid_attempt();
            request
                .headers_mut()
                .insert("identity-attestation", first.parse().unwrap());
            request
        };
        // The same user: the paid attempt keeps its attestation.
        let mut request = carrying();
        prover.prove(&mut request, &context()).await.unwrap();
        assert_eq!(request.headers()["identity-attestation"], first.as_str());

        // Another user signed in after the attestation was added.
        *current.lock().unwrap() = Some(token_as(&tempo, &url, "user_2"));
        let mut request = carrying();
        let error = prover.prove(&mut request, &context()).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "The signed-in Tempo ID user changed: send the request again."
        );

        // The access token cannot be read.
        *current.lock().unwrap() = None;
        let mut request = carrying();
        let error = prover.prove(&mut request, &context()).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "The Tempo ID access token could not be read: send the request again."
        );

        // An unpaid attempt still only drops them.
        let mut request = paid();
        request
            .headers_mut()
            .insert("identity-attestation", first.parse().unwrap());
        prover.prove(&mut request, &context()).await.unwrap();
        assert!(!request.headers().contains_key("identity-attestation"));
    }

    #[tokio::test]
    async fn retry_reads_the_token_only_when_it_can_answer_and_never_switches_users() {
        let tempo = issuer().await;
        let (url, issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let first = attestation_for(&issuer, "user_1");
        let token = token_as(&tempo, &url, "user_2");
        let (attest_config, _gate, _entries, calls) =
            scripted(&url, move |_| Ok(token.clone()), &[]);
        let prover = attestations(
            attest_config,
            [AUDIENCE],
            Some(["tempo-id"]),
            Vec::<String>::new(),
        )
        .unwrap();
        let request = paid();
        // A 500, or a 401 that asks for no attestation, never reads the token.
        for (status, headers) in [
            (
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                required_response(&url).headers,
            ),
            (
                reqwest::StatusCode::UNAUTHORIZED,
                reqwest::header::HeaderMap::new(),
            ),
        ] {
            let response = ResponseParts {
                status,
                headers,
                url: request.url().clone(),
            };
            assert!(prover
                .retry(&response, RetryContext { request: &request })
                .await
                .is_none());
        }
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);

        // A request proved for user_1 is not resent under user_2.
        let mut carrying = paid();
        carrying
            .headers_mut()
            .insert("identity-attestation", first.parse().unwrap());
        let response = required_response(&url);
        assert!(prover
            .retry(&response, RetryContext { request: &carrying })
            .await
            .is_none());
        // One that carried none of them is answered for the signed-in user.
        let retry = prover
            .retry(&response, RetryContext { request: &request })
            .await
            .unwrap();
        let second = retry["identity-attestation"].to_str().unwrap().to_owned();
        assert_eq!(
            verified(&issuer, &second, "tempo-id").await.uid(),
            Some("user_2")
        );
    }

    #[tokio::test]
    async fn a_lookup_confirming_the_user_supersedes_an_older_one() {
        let tempo = issuer().await;
        let (url, issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let mine = attestation_for(&issuer, "user_1");
        let tokens = [
            token_as(&tempo, &url, "user_1"),
            token_as(&tempo, &url, "user_2"),
        ];
        // Read 1 (user_2) waits; every other read names user_1.
        let (attest_config, gate, mut entries, _calls) = scripted(
            &url,
            move |call| Ok(tokens[usize::from(call == 1)].clone()),
            &[1],
        );
        let prover = attestations(attest_config, [AUDIENCE], Some(["tempo-id"]), [&mine]).unwrap();
        let mut request = paid();
        prover.prove(&mut request, &context()).await.unwrap();
        assert_eq!(entries.recv().await, Some(0));
        assert_eq!(request.headers()["identity-attestation"], mine.as_str());

        // A slow lookup reads user_2's token while a newer one confirms user_1.
        let slow = tokio::spawn({
            let prover = prover.clone();
            async move {
                let mut request = paid();
                prover.prove(&mut request, &context()).await.unwrap();
            }
        });
        assert_eq!(entries.recv().await, Some(1));
        let mut newer = paid();
        prover.prove(&mut newer, &context()).await.unwrap();
        assert_eq!(newer.headers()["identity-attestation"], mine.as_str());
        gate.notify_one();
        slow.await.unwrap();

        // The slow lookup did not replace user_1's cache.
        let mut next = paid();
        prover.prove(&mut next, &context()).await.unwrap();
        assert_eq!(next.headers()["identity-attestation"], mine.as_str());
    }

    #[tokio::test]
    async fn an_older_lookup_presents_nothing_after_a_newer_read_failed() {
        let tempo = issuer().await;
        let (url, issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let mine = attestation_for(&issuer, "user_1");
        let token = token_as(&tempo, &url, "user_1");
        // Read 1 waits; read 2 fails, as after a sign-out.
        let (attest_config, gate, mut entries, _calls) = scripted(
            &url,
            move |call| {
                if call == 2 {
                    Err(crate::identity::client::ProverError::new("signed out"))
                } else {
                    Ok(token.clone())
                }
            },
            &[1],
        );
        let prover = attestations(attest_config, [AUDIENCE], Some(["tempo-id"]), [&mine]).unwrap();
        let mut request = paid();
        prover.prove(&mut request, &context()).await.unwrap();
        assert_eq!(entries.recv().await, Some(0));
        assert_eq!(request.headers()["identity-attestation"], mine.as_str());

        let slow = tokio::spawn({
            let prover = prover.clone();
            async move {
                let mut request = paid();
                prover.prove(&mut request, &context()).await.unwrap();
                request
            }
        });
        assert_eq!(entries.recv().await, Some(1));
        let mut newer = paid();
        prover.prove(&mut newer, &context()).await.unwrap();
        assert!(!newer.headers().contains_key("identity-attestation"));
        gate.notify_one();
        let request = slow.await.unwrap();
        assert!(!request.headers().contains_key("identity-attestation"));
    }

    #[tokio::test]
    async fn prepare_refuses_after_a_switch_when_the_previous_user_held_one_for_the_origin() {
        use crate::identity::client::PrepareContext;
        let tempo = issuer().await;
        let (url, issuer) = serve(|url| create_issuer(config(&tempo, url)).unwrap()).await;
        let mine = attestation_for(&issuer, "user_1");
        let current = Arc::new(std::sync::Mutex::new(token_as(&tempo, &url, "user_1")));
        let source = current.clone();
        let attest_config = AttestConfig::new(&url, move || {
            let token = source.lock().unwrap().clone();
            async move { Ok(token) }
        })
        .unwrap();
        let prover = attestations(attest_config, [AUDIENCE], Some(["tempo-id"]), [&mine]).unwrap();
        let mut request = paid();
        prover.prove(&mut request, &context()).await.unwrap();
        assert_eq!(request.headers()["identity-attestation"], mine.as_str());
        // A route that asks only with Identity-Attestation-Required lists nothing in its 402.
        let context = PrepareContext {
            challenge: crate::protocol::core::PaymentChallenge::new(
                "id",
                "realm",
                "tempo",
                "charge",
                crate::protocol::core::Base64UrlJson::from_value(&json!({})).unwrap(),
            ),
            requirements: Vec::new(),
        };
        let parts = |origin: &str| ResponseParts {
            status: reqwest::StatusCode::PAYMENT_REQUIRED,
            headers: reqwest::header::HeaderMap::new(),
            url: format!("{origin}/paid").parse().unwrap(),
        };
        assert!(prover.prepare(&parts(AUDIENCE), &context).await.is_ok());
        *current.lock().unwrap() = token_as(&tempo, &url, "user_2");
        let error = prover
            .prepare(&parts(AUDIENCE), &context)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "The signed-in Tempo ID user changed: send the request again."
        );
        // An origin the previous user held nothing for is not refused.
        *current.lock().unwrap() = token_as(&tempo, &url, "user_3");
        assert!(prover
            .prepare(&parts("https://other.example"), &context)
            .await
            .is_ok());
    }
}
