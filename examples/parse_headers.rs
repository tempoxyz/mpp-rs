//! Demonstrates core protocol header parsing and formatting.
//!
//! Run with: `cargo run --example parse_headers`

use mpay::{
    parse_authorization, parse_receipt, parse_www_authenticate, format_authorization,
    format_receipt, format_www_authenticate, Base64UrlJson, ChargeRequest, PaymentChallenge,
    PaymentCredential, PaymentPayload, Receipt,
};

fn main() {
    // ── Step 1: Create a PaymentChallenge and format as WWW-Authenticate ──

    println!("=== Step 1: Server creates a PaymentChallenge ===\n");

    let charge_request = ChargeRequest {
        amount: "50000".to_string(),
        currency: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string()),
        description: Some("API access - 100 requests".to_string()),
        ..Default::default()
    };

    let request = Base64UrlJson::from_typed(&charge_request).expect("serialize request");

    let challenge = PaymentChallenge::with_secret_key(
        "my-server-secret",
        "api.example.com",
        "tempo",
        "charge",
        request,
    )
    .with_description("Pay for API access");

    let www_authenticate = format_www_authenticate(&challenge).expect("format challenge");
    println!("WWW-Authenticate: {}\n", www_authenticate);

    // ── Step 2: Parse it back ──

    println!("=== Step 2: Client parses the WWW-Authenticate header ===\n");

    let parsed_challenge = parse_www_authenticate(&www_authenticate).expect("parse challenge");
    println!("  Challenge ID:  {}", parsed_challenge.id);
    println!("  Realm:         {}", parsed_challenge.realm);
    println!("  Method:        {}", parsed_challenge.method);
    println!("  Intent:        {}", parsed_challenge.intent);

    let decoded_request: ChargeRequest = parsed_challenge.request.decode().expect("decode request");
    println!("  Amount:        {}", decoded_request.amount);
    println!("  Currency:      {}", decoded_request.currency);
    println!(
        "  Recipient:     {}",
        decoded_request.recipient.as_deref().unwrap_or("(none)")
    );
    println!();

    // ── Step 3: Create a PaymentCredential and format as Authorization ──

    println!("=== Step 3: Client creates a PaymentCredential ===\n");

    let credential = PaymentCredential::with_source(
        parsed_challenge.to_echo(),
        "did:pkh:eip155:42431:0xAbC1234567890aBcDeF1234567890AbCdEf123456",
        PaymentPayload::transaction("0x02f8b20182...signed_tx_bytes"),
    );

    let authorization = format_authorization(&credential).expect("format credential");
    println!("Authorization: {}\n", authorization);

    // ── Step 4: Parse it back ──

    println!("=== Step 4: Server parses the Authorization header ===\n");

    let parsed_credential = parse_authorization(&authorization).expect("parse credential");
    println!("  Challenge ID:  {}", parsed_credential.challenge.id);
    println!(
        "  Source (payer): {}",
        parsed_credential.source.as_deref().unwrap_or("(none)")
    );

    let payload = parsed_credential
        .charge_payload()
        .expect("decode payload");
    println!("  Payload type:  {}", payload.payload_type());
    println!("  Signed tx:     {}", payload.signed_tx().unwrap_or("N/A"));
    println!();

    // Verify the HMAC-bound challenge ID
    let is_valid = parsed_challenge.verify("my-server-secret");
    println!("  HMAC verification: {}", if is_valid { "✓ valid" } else { "✗ invalid" });
    println!();

    // ── Step 5: Create and parse a Receipt ──

    println!("=== Step 5: Server sends a Receipt ===\n");

    let receipt = Receipt::success("tempo", "0xdeadbeef1234567890abcdef");

    let receipt_header = format_receipt(&receipt).expect("format receipt");
    println!("Payment-Receipt: {}\n", receipt_header);

    let parsed_receipt = parse_receipt(&receipt_header).expect("parse receipt");
    println!("  Status:    {}", parsed_receipt.status);
    println!("  Method:    {}", parsed_receipt.method);
    println!("  Timestamp: {}", parsed_receipt.timestamp);
    println!("  Reference: {}", parsed_receipt.reference);
    println!();

    println!("=== Done! Full protocol round-trip complete. ===");
}
