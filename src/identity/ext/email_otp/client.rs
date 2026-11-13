//! Client helpers that verify an email address with a one-time code.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::{ATTESTATION_TYPE, CODE_ATTEMPTS, OTP_PATH, VERIFY_PATH};
use crate::identity::ext::attestation::IdentityError;
use crate::identity::ext::attestation::{is_issuer, AttestationProver, AttestationRequest};

/// A code request an issuer accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeRequest {
    /// ID that [`verify_code`] exchanges, with the code, for an attestation.
    pub id: String,
    /// When the code expires.
    pub expires_at: OffsetDateTime,
}

/// An attestation an issuer signed for a verified code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCode {
    /// The attestation, a compact JWS.
    pub attestation: String,
    /// When the attestation expires.
    pub expires_at: OffsetDateTime,
}

/// What the code callback of an [`EmailOtpProver`] is asked for.
#[derive(Debug, Clone)]
pub struct CodeContext {
    /// The address the code was sent to.
    pub email: String,
    /// The issuer that sent it.
    pub issuer: String,
    /// The origin the attestation will be bound to.
    pub audience: String,
    /// The code request's ID.
    pub id: String,
    /// When the code expires.
    pub expires_at: OffsetDateTime,
    /// Which attempt this is, from 1 to [`CODE_ATTEMPTS`].
    pub attempt: u32,
    /// Why the previous code was rejected, on later attempts.
    pub error: Option<String>,
}

type CodeFuture = Pin<Box<dyn Future<Output = Option<String>> + Send>>;
type CodeCallback = dyn Fn(CodeContext) -> CodeFuture + Send + Sync;

/// Asks `issuer` to email a one-time code to `email` for `audience`.
///
/// `client` must not follow redirects: one would re-post the address to
/// wherever the issuer redirects. [`EmailOtpProver`] builds such a client.
pub async fn send_code(
    client: &reqwest::Client,
    issuer: &str,
    email: &str,
    audience: &str,
) -> Result<CodeRequest, IdentityError> {
    let body = post(
        client,
        issuer,
        OTP_PATH,
        serde_json::json!({ "audience": audience, "email": email }),
    )
    .await?;
    match (
        body.get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty()),
        date(body.get("expires_at")),
    ) {
        (Some(id), Some(expires_at)) => Ok(CodeRequest {
            id: id.to_string(),
            expires_at,
        }),
        _ => Err(IdentityError::email_otp(
            "The issuer returned a malformed code request.",
            None,
        )),
    }
}

/// Exchanges an emailed one-time code for an email attestation.
///
/// `client` must not follow redirects, as for [`send_code`].
pub async fn verify_code(
    client: &reqwest::Client,
    issuer: &str,
    id: &str,
    code: &str,
) -> Result<VerifiedCode, IdentityError> {
    let body = post(
        client,
        issuer,
        VERIFY_PATH,
        serde_json::json!({ "code": code, "id": id }),
    )
    .await?;
    match (
        body.get("attestation")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty()),
        date(body.get("expires_at")),
    ) {
        (Some(attestation), Some(expires_at)) => Ok(VerifiedCode {
            attestation: attestation.to_string(),
            expires_at,
        }),
        _ => Err(IdentityError::email_otp(
            "The issuer returned a malformed attestation.",
            None,
        )),
    }
}

/// Builds an [`AttestationProver`] that verifies an email address when a
/// server asks for one, as mppx's `EmailOtp.Client.prover`.
///
/// When a server answers with
/// `Identity-Attestation-Required: email;issuer="…"`, the prover asks the
/// issuer to email a code to the address, gets the code from the `code`
/// callback, exchanges it for an attestation bound to the server's origin and
/// sends the request again with it. Later requests to that origin reuse it
/// until it expires. A route that accepts any of several issuers lists them
/// as alternatives: the prover asks the first trusted one, and the next only
/// if that one fails or the callback declines (returns `None`). A rejected
/// code is asked for again, up to [`CODE_ATTEMPTS`] times.
///
/// Trust is set by two lists together:
/// - `scope`: the origins that may ask for and receive the attestation. It
///   is always bound to the request's own origin, never one a server names.
/// - `issuers`: the issuers the email address may be sent to. A server only
///   names the issuer it wants; an untrusted one could relay a code and
///   obtain an attestation for another server.
///
/// ```no_run
/// # fn run() -> Result<(), mpp::identity::ext::attestation::IdentityError> {
/// use mpp::identity::ext::email_otp::EmailOtpProver;
///
/// let prover = EmailOtpProver::new(
///     "me@example.com",
///     ["https://issuer.example"],
///     ["https://api.example"],
///     |ctx| async move {
///         eprintln!("Enter the code sent to {} (attempt {}):", ctx.email, ctx.attempt);
///         let mut code = String::new();
///         std::io::stdin().read_line(&mut code).ok()?;
///         Some(code)
///     },
/// )
/// .build()?;
/// # Ok(())
/// # }
/// ```
pub struct EmailOtpProver {
    email: String,
    issuers: Vec<String>,
    scope: Vec<String>,
    code: Arc<CodeCallback>,
    client: Option<reqwest::ClientBuilder>,
    attestations: Vec<String>,
}

impl std::fmt::Debug for EmailOtpProver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailOtpProver")
            .field("issuers", &self.issuers)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl EmailOtpProver {
    /// Configures a prover for `email` that trusts `issuers` and presents
    /// attestations only to the `scope` origins. `code` returns the code the
    /// issuer emailed, or `None` to decline.
    pub fn new<I, S, F, Fut>(
        email: impl Into<String>,
        issuers: impl IntoIterator<Item = I>,
        scope: impl IntoIterator<Item = S>,
        code: F,
    ) -> Self
    where
        I: AsRef<str>,
        S: AsRef<str>,
        F: Fn(CodeContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<String>> + Send + 'static,
    {
        Self {
            email: email.into(),
            issuers: issuers
                .into_iter()
                .map(|i| i.as_ref().to_string())
                .collect(),
            scope: scope.into_iter().map(|s| s.as_ref().to_string()).collect(),
            code: Arc::new(move |context| -> CodeFuture { Box::pin(code(context)) }),
            client: None,
            attestations: Vec::new(),
        }
    }

    /// Builds the client that sends issuer requests from `builder`, such as
    /// for a proxy or TLS settings. Redirects are turned off whatever it
    /// sets, so the address and code never follow a redirect to another
    /// origin, and each request still times out.
    pub fn with_http_client_builder(mut self, builder: reqwest::ClientBuilder) -> Self {
        self.client = Some(builder);
        self
    }

    /// Presents attestations obtained beforehand until they expire.
    pub fn with_attestations<T: AsRef<str>>(
        mut self,
        attestations: impl IntoIterator<Item = T>,
    ) -> Self {
        self.attestations
            .extend(attestations.into_iter().map(|t| t.as_ref().to_string()));
        self
    }

    /// Builds the prover. Fails when `issuers` or `scope` is empty, an issuer
    /// is not `https` (or `http` on localhost), a scope entry is not an
    /// origin, or a pre-obtained attestation is malformed.
    pub fn build(self) -> Result<AttestationProver, IdentityError> {
        if self.issuers.is_empty() {
            return Err(IdentityError::InvalidConfig(
                "An email OTP prover must list its trusted issuers.".into(),
            ));
        }
        if self.scope.is_empty() {
            return Err(IdentityError::InvalidConfig(
                "An email OTP prover must list the origins in its scope.".into(),
            ));
        }
        if let Some(issuer) = self.issuers.iter().find(|issuer| !is_issuer(issuer)) {
            return Err(IdentityError::InvalidConfig(format!(
                "issuer {issuer:?} must be an https URL (http only on localhost)"
            )));
        }
        let client = self
            .client
            .unwrap_or_default()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(IdentityError::Request)?;
        let email = self.email;
        let code = self.code;
        AttestationProver::new(&self.scope, &self.issuers)?
            .with_types([ATTESTATION_TYPE])
            .with_acquire(move |request| {
                acquire(client.clone(), email.clone(), code.clone(), request)
            })
            .with_attestations(&self.attestations)
    }
}

/// Sends a code, prompts for it and verifies it, asking again after a
/// rejected code.
async fn acquire(
    client: reqwest::Client,
    email: String,
    code: Arc<CodeCallback>,
    request: AttestationRequest,
) -> Result<Option<String>, IdentityError> {
    if email.is_empty() {
        return Ok(None);
    }
    let sent = send_code(&client, &request.issuer, &email, &request.audience).await?;
    let mut error: Option<IdentityError> = None;
    for attempt in 1..=CODE_ATTEMPTS {
        let context = CodeContext {
            email: email.clone(),
            issuer: request.issuer.clone(),
            audience: request.audience.clone(),
            id: sent.id.clone(),
            expires_at: sent.expires_at,
            attempt,
            error: error.as_ref().map(ToString::to_string),
        };
        let Some(entered) = code(context).await else {
            return Ok(None);
        };
        match verify_code(&client, &request.issuer, &sent.id, entered.trim()).await {
            Ok(verified) => return Ok(Some(verified.attestation)),
            // Only a rejected code is worth another try; other failures end the attempt.
            Err(
                rejected @ IdentityError::EmailOtp {
                    status: Some(400), ..
                },
            ) => {
                error = Some(rejected);
            }
            Err(other) => return Err(other),
        }
    }
    Err(error.unwrap_or_else(|| IdentityError::email_otp("The code was rejected.", Some(400))))
}

/// Longest an issuer request may take, from sending it to reading its body.
const ISSUER_TIMEOUT: Duration = Duration::from_secs(10);

#[cfg(test)]
fn no_redirect_client() -> Result<reqwest::Client, IdentityError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(IdentityError::Request)
}

/// Parses an issuer timestamp, or returns `None` when it is not RFC 3339.
fn date(value: Option<&Value>) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value?.as_str()?, &Rfc3339).ok()
}

async fn post(
    client: &reqwest::Client,
    issuer: &str,
    path: &str,
    body: Value,
) -> Result<Value, IdentityError> {
    // The address and code never go over plain HTTP, except to localhost.
    if !is_issuer(issuer) {
        return Err(IdentityError::email_otp(
            "The issuer must be an https URL (http only on localhost).",
            None,
        ));
    }
    let response = client
        .post(format!("{}{path}", issuer.trim_end_matches('/')))
        .json(&body)
        // Bounded so a stalled issuer cannot hang the request, and every
        // retry waiting on the same acquisition, forever. The code callback
        // itself stays unbounded: a person may be typing the code.
        .timeout(ISSUER_TIMEOUT)
        .send()
        .await
        .map_err(IdentityError::Request)?;
    // A client that followed a redirect has already sent the body on; at
    // least never trust the answer of another origin.
    let issuer_origin = reqwest::Url::parse(issuer).map(|url| url.origin());
    if issuer_origin.as_ref().ok() != Some(&response.url().origin()) {
        return Err(IdentityError::email_otp(
            "The issuer redirected to another origin.",
            None,
        ));
    }
    let status = response.status();
    let json: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let message = json
            .get("error")
            .and_then(Value::as_str)
            .map(String::from)
            .unwrap_or_else(|| format!("The issuer answered {}.", status.as_u16()));
        return Err(IdentityError::email_otp(message, Some(status.as_u16())));
    }
    Ok(json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ext::attestation::sign;
    use crate::identity::ext::attestation::token::tests::{signing_key, KID};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// A fake issuer: code `123456` is accepted, anything else is a 400.
    async fn issuer(otp_requests: Arc<Mutex<Vec<Value>>>) -> String {
        use axum::routing::post;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let issuer = base.clone();
        let app = axum::Router::new()
            .route(
                "/email/otp",
                post(move |axum::Json(body): axum::Json<Value>| {
                    let requests = otp_requests.clone();
                    async move {
                        requests.lock().unwrap().push(body);
                        axum::Json(serde_json::json!({
                            "id": "otp_1", "expires_at": "2030-01-01T00:00:00.000Z"
                        }))
                    }
                }),
            )
            .route(
                "/email/verify",
                post(move |axum::Json(body): axum::Json<Value>| {
                    let issuer = issuer.clone();
                    async move {
                        if body["code"] != "123456" || body["id"] != "otp_1" {
                            return (
                                axum::http::StatusCode::BAD_REQUEST,
                                axum::Json(serde_json::json!({ "error": "Invalid code." })),
                            );
                        }
                        let now = crate::identity::ext::attestation::now();
                        let attestation = sign(
                            &serde_json::json!({
                                "iss": issuer, "aud": "https://api.example", "sub": "me@example.com",
                                "type": "email", "iat": now, "exp": now + 900, "jti": "att_1",
                            }),
                            &signing_key(),
                            KID,
                        )
                        .unwrap();
                        (
                            axum::http::StatusCode::OK,
                            axum::Json(serde_json::json!({
                                "attestation": attestation, "expires_at": "2030-01-01T00:15:00Z"
                            })),
                        )
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        base
    }

    #[tokio::test]
    async fn acquires_after_a_rejected_code() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let issuer = issuer(requests.clone()).await;
        let attempts = Arc::new(AtomicU32::new(0));
        let seen = attempts.clone();
        let code: Arc<CodeCallback> = Arc::new(move |context: CodeContext| -> CodeFuture {
            seen.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if context.attempt == 1 {
                    assert!(context.error.is_none());
                    Some("000000".into())
                } else {
                    assert_eq!(context.error.as_deref(), Some("Invalid code."));
                    Some(" 123456\n".into())
                }
            })
        });
        let token = acquire(
            no_redirect_client().unwrap(),
            "me@example.com".into(),
            code,
            AttestationRequest {
                audience: "https://api.example".into(),
                issuer: issuer.clone(),
                attestation_type: "email".into(),
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(token.split('.').count(), 3);
        assert_eq!(
            requests.lock().unwrap()[0],
            serde_json::json!({ "audience": "https://api.example", "email": "me@example.com" })
        );
    }

    #[tokio::test]
    async fn gives_up_after_three_rejected_codes_and_stops_when_declined() {
        let issuer = issuer(Arc::default()).await;
        let request = AttestationRequest {
            audience: "https://api.example".into(),
            issuer,
            attestation_type: "email".into(),
        };
        let wrong: Arc<CodeCallback> =
            Arc::new(|_| -> CodeFuture { Box::pin(async { Some("000000".into()) }) });
        let error = acquire(
            no_redirect_client().unwrap(),
            "me@example.com".into(),
            wrong,
            request.clone(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            IdentityError::EmailOtp {
                status: Some(400),
                ..
            }
        ));

        let declined: Arc<CodeCallback> = Arc::new(|_| -> CodeFuture { Box::pin(async { None }) });
        let result = acquire(
            no_redirect_client().unwrap(),
            "me@example.com".into(),
            declined,
            request,
        )
        .await
        .unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn refuses_plain_http_issuers() {
        let error = send_code(
            &reqwest::Client::new(),
            "http://issuer.example",
            "me@example.com",
            "https://api.example",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("https"));
    }

    #[test]
    fn build_requires_issuers_and_scope() {
        let code = |_: CodeContext| async { None };
        let none: [&str; 0] = [];
        assert!(
            EmailOtpProver::new("me@example.com", none, ["https://api.example"], code)
                .build()
                .is_err()
        );
        assert!(
            EmailOtpProver::new("me@example.com", ["https://issuer.example"], none, code)
                .build()
                .is_err()
        );
        assert!(EmailOtpProver::new(
            "me@example.com",
            ["http://issuer.example"],
            ["https://api.example"],
            code
        )
        .build()
        .is_err());
        assert!(EmailOtpProver::new(
            "me@example.com",
            ["https://issuer.example"],
            ["https://api.example"],
            code
        )
        .build()
        .is_ok());
    }
}
