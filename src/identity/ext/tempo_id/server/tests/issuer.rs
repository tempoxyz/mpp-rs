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
        let sign_for = |uid: &str| {
            issuer
                .attestation_issuer()
                .sign(
                    crate::identity::ext::attestation::SignParameters::new(
                        AUDIENCE, "tempo-id", uid,
                    )
                    .uid(uid),
                )
                .unwrap()
        };
        let (mine, theirs) = (sign_for("user_1"), sign_for("user_2"));
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
            [&theirs, &mine],
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
}
