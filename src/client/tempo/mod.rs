//! Tempo-specific client implementations.
//!
//! Contains the Tempo payment providers, transaction building,
//! signing strategies, charge builder, and channel operations.

mod accounts_provider;
pub mod autoswap;
pub mod charge;
mod error;
mod provider;
pub mod session;
pub mod signing;
pub mod zone;

pub use accounts_provider::TempoAccountsProvider;
pub use autoswap::AutoswapConfig;
pub use error::TempoClientError;

pub use provider::TempoProvider;
pub use zone::TempoZone;

/// Build the RPC provider used while preparing Tempo payments.
///
/// Tempo RPC reports transient overloads as JSON-RPC error `-32005` and
/// includes a millisecond retry hint. Alloy's rate-limit layer recognizes both
/// the code and the hint, so keep that policy at the transport boundary rather
/// than duplicating retries around every balance, quote, and gas-estimation
/// call.
///
/// With `http_client`, every RPC request goes through that client, so its
/// default headers (such as a Tempo Console API key in `tempo-api-key`),
/// proxy and TLS settings apply; without it alloy's default client is used.
pub(crate) fn rpc_provider(
    rpc_url: reqwest::Url,
    http_client: Option<&reqwest::Client>,
) -> alloy::providers::RootProvider<tempo_alloy::TempoNetwork> {
    // Pace retrying bursts at 50 RPC/s (Alloy's default 20 compute units per
    // request against a 1,000 CU/s budget) so concurrent payment preparation
    // does not immediately exhaust the server-provided retry window again.
    let retry = alloy::transports::layers::RetryBackoffLayer::new(20, 10, 1_000);
    let builder = alloy::rpc::client::ClientBuilder::default().layer(retry);
    let client = match http_client {
        Some(http_client) => builder.http_with_client(http_client.clone(), rpc_url),
        None => builder.http(rpc_url),
    };
    alloy::providers::ProviderBuilder::<_, _, tempo_alloy::TempoNetwork>::default()
        .connect_client(client)
}

/// Static max fee per gas: 41 gwei (`base_fee * 2 + priority_fee`).
///
/// Tempo networks use a fixed 20 gwei base fee. Using 2× base fee
/// plus priority ensures the transaction is always accepted.
pub const MAX_FEE_PER_GAS: u128 = 20_000_000_000 * 2 + 1_000_000_000; // 41 gwei

/// Static max priority fee per gas: 1 gwei.
pub const MAX_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;

/// A local JSON-RPC server for tests of the caller-supplied HTTP client.
#[cfg(test)]
pub(crate) mod test_rpc {
    use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    /// The `tempo-api-key` header of each request the server received.
    pub(crate) type SeenKeys = Arc<Mutex<Vec<Option<String>>>>;

    /// Serve every JSON-RPC request with chain ID 4217 on localhost and
    /// record its `tempo-api-key` header.
    pub(crate) async fn spawn() -> (reqwest::Url, SeenKeys, tokio::task::JoinHandle<()>) {
        async fn rpc(
            State(seen): State<SeenKeys>,
            headers: HeaderMap,
            Json(request): Json<Value>,
        ) -> Json<Value> {
            let key = headers
                .get("tempo-api-key")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            seen.lock().unwrap().push(key);
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            Json(json!({"jsonrpc": "2.0", "id": id, "result": "0x1079"}))
        }

        let seen = SeenKeys::default();
        let app = Router::new().route("/", post(rpc)).with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (url, seen, server)
    }

    /// A client sending `tempo-api-key: test-key` on every request.
    pub(crate) fn api_key_client() -> reqwest::Client {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("tempo-api-key", "test-key".parse().unwrap());
        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap()
    }

    /// Assert every request so far carried the client's API key.
    pub(crate) fn assert_api_key(seen: &SeenKeys) {
        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty());
        assert!(seen.iter().all(|key| key.as_deref() == Some("test-key")));
    }
}

#[cfg(test)]
mod tests {
    use super::rpc_provider;
    use alloy::providers::Provider;
    use axum::{extract::State, routing::post, Json, Router};
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn rpc_provider_retries_tempo_rate_limits() {
        async fn rpc(
            State(attempts): State<Arc<AtomicUsize>>,
            Json(request): Json<Value>,
        ) -> Json<Value> {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            let id = request.get("id").cloned().unwrap_or(Value::Null);
            if attempt < 2 {
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32005,
                        "message": "rate limited, try again in 1ms"
                    }
                }))
            } else {
                Json(json!({"jsonrpc": "2.0", "id": id, "result": "0x1079"}))
            }
        }

        let attempts = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/", post(rpc))
            .with_state(attempts.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let chain_id = rpc_provider(url, None).get_chain_id().await.unwrap();

        assert_eq!(chain_id, 4217);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        server.abort();
    }

    #[tokio::test]
    async fn rpc_provider_sends_the_http_clients_default_headers() {
        let (url, seen, server) = super::test_rpc::spawn().await;

        let client = super::test_rpc::api_key_client();
        let chain_id = rpc_provider(url.clone(), Some(&client))
            .get_chain_id()
            .await
            .unwrap();
        assert_eq!(chain_id, 4217);
        super::test_rpc::assert_api_key(&seen);

        seen.lock().unwrap().clear();
        rpc_provider(url, None).get_chain_id().await.unwrap();
        assert_eq!(*seen.lock().unwrap(), vec![None]);
        server.abort();
    }
}
