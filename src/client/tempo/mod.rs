//! Tempo-specific client implementations.
//!
//! Contains the Tempo payment providers, transaction building,
//! signing strategies, charge builder, and channel operations.

pub mod autoswap;
pub mod charge;
mod error;
mod provider;
pub mod session;
pub mod signing;
#[cfg(feature = "sqlite")]
pub mod wallet;

pub use autoswap::AutoswapConfig;
pub use error::TempoClientError;

#[cfg(all(feature = "sqlite", not(windows)))]
fn default_wallet_directory() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|home| home.join(".tempo").join("wallet"))
}

#[cfg(all(feature = "sqlite", windows))]
fn default_wallet_directory() -> Option<std::path::PathBuf> {
    std::env::var_os("USERPROFILE")
        .map(std::path::PathBuf::from)
        .or_else(|| {
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            Some(std::path::PathBuf::from(drive).join(path))
        })
        .map(|home| home.join(".tempo").join("wallet"))
}
pub use provider::TempoProvider;

/// Build the RPC provider used while preparing Tempo payments.
///
/// Tempo RPC reports transient overloads as JSON-RPC error `-32005` and
/// includes a millisecond retry hint. Alloy's rate-limit layer recognizes both
/// the code and the hint, so keep that policy at the transport boundary rather
/// than duplicating retries around every balance, quote, and gas-estimation
/// call.
pub(crate) fn rpc_provider(
    rpc_url: reqwest::Url,
) -> alloy::providers::RootProvider<tempo_alloy::TempoNetwork> {
    // Pace retrying bursts at 50 RPC/s (Alloy's default 20 compute units per
    // request against a 1,000 CU/s budget) so concurrent payment preparation
    // does not immediately exhaust the server-provided retry window again.
    let retry = alloy::transports::layers::RetryBackoffLayer::new(20, 10, 1_000);
    let client = alloy::rpc::client::ClientBuilder::default()
        .layer(retry)
        .http(rpc_url);
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

        let chain_id = rpc_provider(url).get_chain_id().await.unwrap();

        assert_eq!(chain_id, 4217);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        server.abort();
    }
}
