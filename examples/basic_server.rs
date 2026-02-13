//! Basic server example demonstrating payment-gated endpoints with mpay.
//!
//! This mirrors the TypeScript example from mpay/examples/basic/src/server.ts,
//! showing how to create a payment handler and use it to gate access to a
//! fortune-telling endpoint that costs $1.00.
//!
//! Because this is an inline example (no axum dependency), it demonstrates the
//! payment flow by printing the challenge and showing how verification works.
//! For a full HTTP server, see the `examples/server/` crate which uses axum.
//!
//! # Running
//!
//! ```bash
//! MERCHANT_ADDRESS=0x... cargo run --example basic_server --features "tempo,server"
//! ```

use mpay::server::{tempo, Mpay, TempoChargeMethod, TempoConfig};
// Used in a real server to parse the Authorization header — shown in comments below.
#[allow(unused_imports)]
use mpay::{parse_authorization, PaymentCredential};

const RPC_URL: &str = "https://rpc.moderato.tempo.xyz";
const REALM: &str = "api.example.com";
const SECRET_KEY: &str = "example-server-secret-key";

type PaymentHandler = Mpay<TempoChargeMethod<mpay::server::TempoProvider>>;

const FORTUNES: &[&str] = &[
    "A beautiful, smart, and loving person will come into your life.",
    "A dubious friend may be an enemy in camouflage.",
    "A faithful friend is a strong defense.",
    "A fresh start will put you on your way.",
    "A golden egg of opportunity falls into your lap this month.",
    "A good time to finish up old tasks.",
    "A hunch is creativity trying to tell you something.",
    "A lifetime of happiness lies ahead of you.",
    "A light heart carries you through all the hard times.",
    "A new perspective will come with the new year.",
];

#[tokio::main]
async fn main() {
    let merchant_address =
        std::env::var("MERCHANT_ADDRESS").expect("MERCHANT_ADDRESS must be set");

    // Create the payment handler — mirrors the TS:
    //   const mpay = Mpay.create({ methods: [tempo({ currency, recipient })] })
    let payment: PaymentHandler = Mpay::create(
        tempo(TempoConfig {
            currency: "0x20c0000000000000000000000000000000000001",
            recipient: &merchant_address,
        })
        .rpc_url(RPC_URL)
        .realm(REALM)
        .secret_key(SECRET_KEY),
    )
    .expect("failed to create payment handler");

    // === Free endpoint: /health ===
    println!("=== GET /health (free) ===");
    println!("Response: {{\"status\": \"ok\"}}\n");

    // === Paid endpoint: /fortune ($1.00) ===
    println!("=== GET /fortune (paid, no credential) ===");

    // Generate a $1.00 charge challenge — mirrors: mpay.charge({ amount: '1' })
    let challenge = payment.charge("1.00").expect("failed to create charge");
    let www_authenticate = challenge.to_header().expect("failed to format challenge");

    println!("HTTP/1.1 402 Payment Required");
    println!("WWW-Authenticate: {www_authenticate}\n");

    // === Simulating a paid request ===
    // In a real server you would parse the Authorization header from the request:
    //
    //   fn parse_credential(headers: &HeaderMap) -> Option<PaymentCredential> {
    //       headers.get(AUTHORIZATION)
    //           .and_then(|h| h.to_str().ok())
    //           .and_then(|s| parse_authorization(s).ok())
    //   }
    //
    // Then verify and return the fortune with a receipt:
    //
    //   if let Some(credential) = parse_credential(&headers) {
    //       match payment.verify_credential(&credential).await {
    //           Ok(receipt) => {
    //               let fortune = FORTUNES[rand_index];
    //               // 200 OK with Payment-Receipt header
    //               return (StatusCode::OK,
    //                   [("Payment-Receipt", receipt.to_header().unwrap())],
    //                   json!({ "fortune": fortune }));
    //           }
    //           Err(e) => eprintln!("Payment verification failed: {e}"),
    //       }
    //   }

    println!("=== GET /fortune (paid, with valid credential) ===");
    println!("To test the full flow, use the axum server example:");
    println!("  cd examples/server && MERCHANT_ADDRESS=0x... cargo run");
    println!("Then pay with purl:");
    println!("  purl http://localhost:3000/paid");

    // Show a random fortune as the expected response body
    let index = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as usize
        % FORTUNES.len();
    let fortune = FORTUNES[index];
    println!("\nExample response body: {{\"fortune\": \"{fortune}\"}}");
}
