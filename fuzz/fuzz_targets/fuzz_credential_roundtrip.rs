//! Format → parse round trip over structured credentials.
//!
//! - `format_authorization` output is a single `Payment <base64url>` token.
//! - Every credential whose challenge echo is well formed parses back field
//!   for field, also when other schemes share the header field.
//! - Charge payloads keep their type and data.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mpp::{format_authorization, parse_authorization, PaymentCredential, PaymentPayload};
use mpp_fuzz::{
    assert_same, has_supported_header, is_well_formed, wire_header, ChallengeInput, Json,
};

#[derive(Debug, Arbitrary)]
struct Input {
    challenge: ChallengeInput,
    source: Option<String>,
    payload: PayloadInput,
    /// Place a `Bearer` credential before (`Some(true)`) or after the Payment one.
    bearer_first: Option<bool>,
}

#[derive(Debug, Arbitrary)]
enum PayloadInput {
    Json(Json),
    Transaction(String),
    Hash(String),
    Proof(String),
}

impl PayloadInput {
    fn charge(&self) -> Option<PaymentPayload> {
        match self {
            Self::Json(_) => None,
            Self::Transaction(signature) => Some(PaymentPayload::transaction(signature)),
            Self::Hash(hash) => Some(PaymentPayload::hash(hash)),
            Self::Proof(signature) => Some(PaymentPayload::proof(signature)),
        }
    }
}

fuzz_target!(|input: Input| {
    let challenge = input.challenge.build();
    let well_formed = is_well_formed(&challenge);
    let echo = challenge.to_echo();
    let charge = input.payload.charge();
    let mut credential = match (&input.payload, &charge) {
        (PayloadInput::Json(json), _) => PaymentCredential::new(echo, json.to_value()),
        (_, Some(payload)) => PaymentCredential::new(echo, payload),
        _ => unreachable!(),
    };
    credential.source = input.source.clone();

    let formatted = format_authorization(&credential).expect("credentials always format");
    let token = formatted.strip_prefix("Payment ").expect("Payment scheme");
    assert!(token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));

    let header = match input.bearer_first {
        None => formatted.clone(),
        Some(true) => format!("Bearer dG9rZW4, {formatted}"),
        Some(false) => format!("{formatted}, Bearer dG9rZW4"),
    };
    let parsed = match parse_authorization(&header) {
        Ok(parsed) => parsed,
        Err(error) => {
            assert!(
                !well_formed
                    || !has_supported_header(credential.challenge.header.as_deref())
                    || token.len() > 16 * 1024,
                "{error}: {credential:?}"
            );
            return;
        }
    };
    assert!(well_formed, "parsed {credential:?}");
    credential.challenge.header = wire_header(credential.challenge.header.as_deref());
    assert_same(&parsed, &credential);

    if let Some(charge) = charge {
        let parsed = parsed.charge_payload().expect("charge payload");
        assert_eq!(parsed.payload_type(), charge.payload_type());
        assert_eq!(parsed.data(), charge.data());
    }
});
