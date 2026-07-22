use std::{env, sync::Arc};

use mpp::{
    client::{
        stripe::StripeProvider,
        tempo::{
            session::store::{SqliteChannelStore, SqliteChannelStoreOptions},
            signing::{KeychainVersion, TempoSigningMode},
            wallet::TempoWallet,
        },
        Fetch, MultiProvider, TempoProvider, TempoSessionProvider,
    },
    protocol::methods::{stripe::CreateTokenResult, tempo::TempoNetwork},
    MppError,
};
use reqwest::{
    header::{HeaderMap, HeaderName},
    Client, Method,
};

const DEFAULT_DEPOSIT: u128 = 20_000;
const DEFAULT_MAX_DEPOSIT: u128 = 1_000_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let method = args
        .next()
        .ok_or("usage: mpp-catalog-client METHOD URL [BODY]")?
        .parse::<Method>()?;
    let url = args
        .next()
        .ok_or("usage: mpp-catalog-client METHOD URL [BODY]")?;
    let body = args.next();
    if args.next().is_some() {
        return Err("usage: mpp-catalog-client METHOD URL [BODY]".into());
    }

    let target = reqwest::Url::parse(&url)?;
    let wallet = TempoWallet::load_default()?;
    let rpc_url = env::var("TEMPO_RPC_URL").unwrap_or_else(|_| {
        TempoNetwork::from_chain_id(wallet.chain_id)
            .map(TempoNetwork::default_rpc_url)
            .unwrap_or("https://rpc.tempo.xyz")
            .to_owned()
    });
    let signing_mode = TempoSigningMode::Keychain {
        wallet: wallet.account,
        key_authorization: None,
        version: KeychainVersion::V2,
    };

    let charge = TempoProvider::new(wallet.signer.clone(), &rpc_url)?
        .with_expected_chain_id(wallet.chain_id)
        .with_signing_mode(signing_mode.clone());
    let channel_store = SqliteChannelStore::open(SqliteChannelStoreOptions {
        namespace: target.origin().ascii_serialization(),
        path: env::var_os("MPP_CHANNEL_STORE").map(Into::into),
        request_url: Some(url.clone()),
    })?;
    let session = TempoSessionProvider::new(wallet.signer, &rpc_url)?
        .with_signing_mode(signing_mode)
        .with_authorized_signer(wallet.access_key)
        .with_channel_store(Arc::new(channel_store))
        .with_default_deposit(read_u128("MPP_DEFAULT_DEPOSIT", DEFAULT_DEPOSIT)?)
        .with_max_deposit(read_u128("MPP_MAX_DEPOSIT", DEFAULT_MAX_DEPOSIT)?);
    let client = Client::new();
    let request_headers = read_headers("MPP_REQUEST_HEADERS")?;
    session
        .bootstrap_with_headers(&client, &url, request_headers.clone())
        .await?;
    let mut providers = MultiProvider::new().with(charge).with(session);

    if let Ok(endpoint) = env::var("STRIPE_SPT_ENDPOINT") {
        let spt_client = client.clone();
        providers.add(StripeProvider::new(move |params| {
            let endpoint = endpoint.clone();
            let client = spt_client.clone();
            Box::pin(async move {
                let response = client
                    .post(endpoint)
                    .json(&params)
                    .send()
                    .await
                    .map_err(|error| MppError::Http(error.to_string()))?
                    .error_for_status()
                    .map_err(|error| MppError::Http(error.to_string()))?;
                let value = response
                    .json::<serde_json::Value>()
                    .await
                    .map_err(|error| MppError::Http(error.to_string()))?;
                let spt = value
                    .get("spt")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| MppError::Http("SPT response is missing spt".into()))?;
                Ok(CreateTokenResult {
                    spt: spt.to_owned(),
                    external_id: value
                        .get("externalId")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                })
            })
        }));
    }

    let request = client.request(method, target).headers(request_headers);
    let request = match body {
        Some(body) => match serde_json::from_str::<serde_json::Value>(&body) {
            Ok(value) => request.json(&value),
            Err(_) => request.body(body),
        },
        None => request,
    };
    let response = request.send_with_payment(&providers).await?;
    let status = response.status();
    let response_body = response.text().await?;
    println!("status={status}");
    println!("{response_body}");
    Ok(())
}

fn read_u128(name: &str, default: u128) -> Result<u128, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|error| format!("invalid {name}: {error}").into()),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

fn read_headers(variable: &str) -> Result<HeaderMap, Box<dyn std::error::Error>> {
    let mut output = HeaderMap::new();
    let Ok(encoded) = env::var(variable) else {
        return Ok(output);
    };
    let headers = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&encoded)?;
    for (name, value) in headers {
        let value = value
            .as_str()
            .ok_or_else(|| format!("{variable}.{name} must be a string"))?;
        output.insert(name.parse::<HeaderName>()?, value.parse()?);
    }
    Ok(output)
}
