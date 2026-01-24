# reqwest Client Example

Using `mpay` with [reqwest](https://docs.rs/reqwest) for client-side 402 handling.

## Dependencies

```toml
[dependencies]
mpay = "0.1"
reqwest = { version = "0.12", features = ["json"] }
tokio = { version = "1", features = ["full"] }
serde_json = "1"
```

## Basic 402 Handling

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

        let challenge = Challenge::from_www_authenticate(header)?;

        // Execute payment (your logic here)
        let tx_hash = execute_payment(&challenge).await?;

        // Build credential
        let credential = Credential {
            id: challenge.id,
            source: Some("did:pkh:eip155:8453:0xYourAddress".into()),
            payload: serde_json::json!({ "hash": tx_hash }),
        };

        // Retry with payment credential
        let resp = client
            .get(url)
            .header("authorization", credential.to_authorization())
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
) -> Result<(String, Option<Receipt>), Box<dyn std::error::Error>> {
    let resp = client
        .get(url)
        .header("authorization", credential.to_authorization())
        .send()
        .await?;

    // Parse receipt if present
    let receipt = resp
        .headers()
        .get("payment-receipt")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| Receipt::from_payment_receipt(h).ok());

    Ok((resp.text().await?, receipt))
}
```

## Retry Wrapper

```rust
use mpay::{Challenge, Credential};

struct PayingClient {
    client: Client,
    wallet: Wallet,
}

impl PayingClient {
    /// Automatically handles 402 responses
    pub async fn get(&self, url: &str) -> Result<Response, Error> {
        let resp = self.client.get(url).send().await?;

        if resp.status() == StatusCode::PAYMENT_REQUIRED {
            let challenge = self.parse_challenge(&resp)?;
            let credential = self.pay_challenge(&challenge).await?;

            return self
                .client
                .get(url)
                .header("authorization", credential.to_authorization())
                .send()
                .await;
        }

        Ok(resp)
    }

    async fn pay_challenge(&self, challenge: &Challenge) -> Result<Credential, Error> {
        let tx_hash = self.wallet.send_payment(&challenge.request).await?;

        Ok(Credential {
            id: challenge.id.clone(),
            source: Some(self.wallet.did()),
            payload: serde_json::json!({ "hash": tx_hash }),
        })
    }
}
```
