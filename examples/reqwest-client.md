# reqwest Client Example

Using `mpay` with [reqwest](https://docs.rs/reqwest) for client-side 402 handling.

## Dependencies

```toml
[dependencies]
mpay = { version = "0.1", features = ["http", "tempo"] }
reqwest = { version = "0.12", features = ["json"] }
tokio = { version = "1", features = ["full"] }
```

## Using PaymentExt (Recommended)

The `PaymentExt` trait provides a `.send_with_payment()` method for opt-in
per-request payment handling. This is the most idiomatic Rust approach.

```rust
use mpay::http::{PaymentExt, TempoProvider};
use mpay::PrivateKeySigner;
use reqwest::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up your signer (from private key, hardware wallet, etc.)
    let signer = PrivateKeySigner::random();
    
    // Create a Tempo payment provider
    let provider = TempoProvider::new(signer, "https://rpc.moderato.tempo.xyz");
    
    // Use standard reqwest client
    let client = Client::new();
    
    // Make a request - automatically handles 402 responses
    let resp = client
        .get("https://api.example.com/paid-resource")
        .send_with_payment(&provider)
        .await?;
    
    println!("Status: {}", resp.status());
    println!("Body: {}", resp.text().await?);
    
    Ok(())
}
```

## Flow

When using `.send_with_payment()`:

1. Initial request is sent
2. If response is 402 Payment Required:
   - Challenge is parsed from `WWW-Authenticate` header
   - Provider executes payment (signs and broadcasts transaction)
   - Request is retried with credential in `Authorization` header
3. Final response is returned

## Manual 402 Handling

For full control, handle the 402 flow manually:

```rust
use mpay::{Challenge, Credential};
use reqwest::Client;

async fn fetch_paid_resource(
    client: &Client,
    url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Initial request
    let resp = client.get(url).send().await?;

    if resp.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
        // Parse challenge from WWW-Authenticate header
        let header = resp
            .headers()
            .get("www-authenticate")
            .ok_or("missing www-authenticate")?
            .to_str()?;

        let challenge = Challenge::parse_www_authenticate(header)?;

        // Execute payment (your logic here)
        let tx_hash = execute_payment(&challenge).await?;

        // Build credential
        let credential = Credential::PaymentCredential::with_source(
            challenge.to_echo(),
            "did:pkh:eip155:88153:0xYourAddress",
            Credential::PaymentPayload::hash(tx_hash),
        );

        // Retry with payment credential
        let auth_header = Credential::format_authorization(&credential)?;
        let resp = client
            .get(url)
            .header("authorization", auth_header)
            .send()
            .await?;

        return Ok(resp.text().await?);
    }

    Ok(resp.text().await?)
}
```

## With Receipt Parsing

```rust
use mpay::{Challenge, Credential, Receipt};

async fn fetch_with_receipt(
    client: &Client,
    url: &str,
    auth_header: &str,
) -> Result<(String, Option<Receipt::PaymentReceipt>), Box<dyn std::error::Error>> {
    let resp = client
        .get(url)
        .header("authorization", auth_header)
        .send()
        .await?;

    // Parse receipt if present
    let receipt = resp
        .headers()
        .get("payment-receipt")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| Receipt::parse_receipt(h).ok());

    Ok((resp.text().await?, receipt))
}
```

## Custom Provider

Implement `PaymentProvider` for custom payment methods:

```rust
use mpay::http::PaymentProvider;
use mpay::protocol::core::{PaymentChallenge, PaymentCredential, PaymentPayload};
use mpay::MppError;

#[derive(Clone)]
struct MyProvider {
    api_key: String,
}

impl PaymentProvider for MyProvider {
    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        // Your payment logic here
        // 1. Parse the challenge request
        // 2. Execute payment via your method
        // 3. Return credential with proof
        
        Ok(PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::hash("0x..."),
        ))
    }
}
```
