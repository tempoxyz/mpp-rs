# hyper Low-Level Example

Using `mpay` with [hyper](https://docs.rs/hyper) for low-level HTTP handling.

## Dependencies

```toml
[dependencies]
mpay = "0.1"
hyper = { version = "1", features = ["full"] }
hyper-util = { version = "0.1", features = ["full"] }
http-body-util = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Client-Side

```rust
use hyper::{body::Incoming, Request, Response};
use hyper_util::client::legacy::Client;
use mpay::{Challenge, Credential};

async fn request_with_payment(
    client: &Client<HttpConnector, String>,
    uri: &str,
) -> Result<Response<Incoming>, Box<dyn std::error::Error>> {
    // Initial request
    let req = Request::get(uri).body(String::new())?;
    let resp = client.request(req).await?;

    if resp.status() == hyper::StatusCode::PAYMENT_REQUIRED {
        // Extract and parse challenge
        let header = resp
            .headers()
            .get("www-authenticate")
            .ok_or("missing challenge")?
            .to_str()?;

        let challenge = Challenge::parse_www_authenticate(header)?;

        // Execute payment
        let tx_hash = pay(&challenge).await?;

        // Build credential
        let credential = Credential::PaymentCredential::with_source(
            challenge.to_echo(),
            "did:pkh:eip155:8453:0x...",
            Credential::PaymentPayload::hash(&tx_hash),
        );

        // Retry with authorization
        let req = Request::get(uri)
            .header("authorization", Credential::format_authorization(&credential)?)
            .body(String::new())?;

        return Ok(client.request(req).await?);
    }

    Ok(resp)
}
```

## Server-Side

```rust
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Method, Request, Response};
use mpay::{Challenge, Credential, Receipt, Schema};

async fn handle_request(
    req: Request<Incoming>,
) -> Result<Response<String>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/paid") => handle_paid_request(req).await,
        _ => Ok(Response::new("Not found".into())),
    }
}

async fn handle_paid_request(
    req: Request<Incoming>,
) -> Result<Response<String>, hyper::Error> {
    // Check authorization header
    if let Some(auth) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if let Ok(credential) = Credential::parse_authorization(auth_str) {
                // Verify payment
                if verify(&credential).await {
                    let receipt = Receipt::Receipt::success("tempo", "0x...");

                    let resp = Response::builder()
                        .status(200)
                        .header("payment-receipt", Receipt::format_receipt(&receipt).unwrap())
                        .body("Paid content".into())
                        .unwrap();

                    return Ok(resp);
                }
            }
        }
    }

    // Return 402 with challenge
    let challenge = Challenge::PaymentChallenge {
        id: uuid::Uuid::new_v4().to_string(),
        realm: "api.example.com".into(),
        method: "tempo".into(),
        intent: "charge".into(),
        request: Schema::Base64UrlJson::from_value(&serde_json::json!({
            "amount": "1000000",
            "currency": "0x...",
            "recipient": "0x...",
        })).unwrap(),
        digest: None,
        expires: None,
        description: None,
    };

    let resp = Response::builder()
        .status(402)
        .header("www-authenticate", Challenge::format_www_authenticate(&challenge).unwrap())
        .body("Payment required".into())
        .unwrap();

    Ok(resp)
}
```

## Running the Server

```rust
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                eprintln!("Error: {:?}", err);
            }
        });
    }
}
```
