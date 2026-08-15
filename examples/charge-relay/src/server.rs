//! Payment-gated photo API backed by Tempo API's MPP relay.

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use mpp::server::{
    tempo, ChargeOptions, Mpp, TempoChargeMethod, TempoConfig, TempoProvider, TempoRelayConfig,
};
use mpp::{format_www_authenticate, parse_authorization, PrivateKeySigner};
use std::sync::Arc;

type Payment = Mpp<TempoChargeMethod<TempoProvider>>;

#[tokio::main]
async fn main() {
    let api_key = std::env::var("TEMPO_API_KEY")
        .expect("Set TEMPO_API_KEY to a Tempo API key with the mpp:write scope");
    let api_url =
        std::env::var("TEMPO_API_URL").unwrap_or_else(|_| "https://api.tempo.xyz".to_string());
    let rpc_url =
        std::env::var("RPC_URL").unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".to_string());
    let signer = PrivateKeySigner::random();
    let recipient = signer.address().to_string();

    let payment = Mpp::create(
        tempo(TempoConfig {
            recipient: &recipient,
        })
        .rpc_url(&rpc_url)
        .relay(TempoRelayConfig::new(api_key).api_base_url(api_url))
        .secret_key(
            &std::env::var("MPP_SECRET_KEY")
                .unwrap_or_else(|_| "mpp-rs-demo-tempo-api-relay-secret-key".to_string()),
        ),
    )
    .expect("failed to create relay-backed payment handler");

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/photo", get(photo))
        .with_state(Arc::new(payment));
    let port = std::env::var("PORT").unwrap_or_else(|_| "5173".to_string());
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .expect("failed to bind");

    println!("Charge relay API listening on http://localhost:{port}");
    println!("Recipient: {recipient}");
    axum::serve(listener, app).await.expect("server error");
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn photo(State(payment): State<Arc<Payment>>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        if let Ok(credential) = auth
            .to_str()
            .map_err(|_| ())
            .and_then(|value| parse_authorization(value).map_err(|_| ()))
        {
            return match payment.broadcast_credential(&credential).await {
                Ok(receipt) => (
                    StatusCode::OK,
                    [("payment-receipt", receipt.to_header().unwrap_or_default())],
                    Json(serde_json::json!({ "url": "https://picsum.photos/1024/1024" })),
                )
                    .into_response(),
                Err(error) => (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(serde_json::json!({ "error": error.to_string() })),
                )
                    .into_response(),
            };
        }
    }

    match payment.charge_with_options(
        "0.01",
        ChargeOptions {
            description: Some("Random stock photo"),
            supported_modes: Some(&["pull"]),
            ..Default::default()
        },
    ) {
        Ok(challenge) => match format_www_authenticate(&challenge) {
            Ok(value) => (
                StatusCode::PAYMENT_REQUIRED,
                [(header::WWW_AUTHENTICATE, value)],
                Json(serde_json::json!({ "error": "Payment Required" })),
            )
                .into_response(),
            Err(error) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": error.to_string() })),
            )
                .into_response(),
        },
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": error.to_string() })),
        )
            .into_response(),
    }
}
