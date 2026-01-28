//! CLI tool for fetching URLs with automatic payment handling.

use clap::Parser;
use mpay::client::{Fetch, TempoProvider};
use mpay::PrivateKeySigner;
use reqwest::Client;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "fetch")]
#[command(about = "Fetch URLs with automatic payment handling")]
struct Args {
    /// URL to fetch
    url: String,

    /// HTTP method (GET, POST, PUT, DELETE)
    #[arg(short = 'X', long, default_value = "GET")]
    method: String,

    /// Request body data
    #[arg(short, long)]
    data: Option<String>,

    /// Tempo private key (or set TEMPO_PRIVATE_KEY)
    #[arg(long, env = "TEMPO_PRIVATE_KEY")]
    key: Option<String>,

    /// Tempo RPC URL (or set TEMPO_RPC_URL)
    #[arg(long, env = "TEMPO_RPC_URL", default_value = "https://rpc.testnet.tempo.xyz/")]
    rpc_url: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    let key = match args.key {
        Some(k) => k,
        None => {
            eprintln!("Error: --key or TEMPO_PRIVATE_KEY required");
            return ExitCode::from(2);
        }
    };

    let key_bytes = match parse_hex_key(&key) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error: invalid private key: {e}");
            return ExitCode::from(2);
        }
    };

    let signer = match PrivateKeySigner::from_slice(&key_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: failed to create signer: {e}");
            return ExitCode::from(2);
        }
    };

    let provider = match TempoProvider::new(signer, &args.rpc_url) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: failed to create provider: {e}");
            return ExitCode::from(2);
        }
    };

    let client = Client::new();

    let request = match args.method.to_uppercase().as_str() {
        "GET" => client.get(&args.url),
        "POST" => {
            let req = client.post(&args.url);
            if let Some(ref data) = args.data {
                req.header("content-type", "application/json").body(data.clone())
            } else {
                req
            }
        }
        "PUT" => {
            let req = client.put(&args.url);
            if let Some(ref data) = args.data {
                req.header("content-type", "application/json").body(data.clone())
            } else {
                req
            }
        }
        "DELETE" => client.delete(&args.url),
        other => {
            eprintln!("Error: unsupported HTTP method: {other}");
            return ExitCode::from(2);
        }
    };

    match request.send_with_payment(&provider).await {
        Ok(response) => {
            let status = response.status();
            match response.text().await {
                Ok(body) => {
                    if status.is_client_error() || status.is_server_error() {
                        eprintln!("{body}");
                        ExitCode::from(1)
                    } else {
                        println!("{body}");
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("Error reading response: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(1)
        }
    }
}

fn parse_hex_key(key: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let key = key.strip_prefix("0x").unwrap_or(key);
    hex::decode(key)
}
