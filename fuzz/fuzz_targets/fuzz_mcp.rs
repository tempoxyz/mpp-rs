//! MCP payment metadata.
//!
//! - The extractors never panic on untrusted JSON. The JSON is what the
//!   server helpers emit, with one node replaced or removed.
//! - A challenge sent with `payment_required_error` is extracted unchanged;
//!   its `request` travels as a JSON object and is re-canonicalized to the
//!   same bytes.
//! - A credential attached with `try_attach_credential` is extracted
//!   unchanged.
//! - A receipt attached with `try_attach_receipt` reads back unchanged.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use mpp::mcp::{self, McpReceipt};
use mpp::{Base64UrlJson, PaymentCredential, PaymentErrorDetails, Receipt};
use mpp_fuzz::{assert_same, ChallengeInput, Json};
use serde_json::{json, Value};

#[derive(Debug, Arbitrary)]
struct Input {
    challenge: ChallengeInput,
    source: Option<String>,
    payload: Json,
    reference: String,
    problem: Option<String>,
    mutation: Mutation,
}

/// Replace (or remove) the node reached by taking child `path[i] % len` at
/// each level.
#[derive(Debug, Arbitrary)]
struct Mutation {
    path: Vec<u8>,
    replacement: Option<Json>,
}

impl Mutation {
    fn apply(&self, root: &mut Value) {
        mutate(root, &self.path, self.replacement.as_ref());
    }
}

fn mutate(node: &mut Value, path: &[u8], replacement: Option<&Json>) {
    let Some((step, rest)) = path.split_first() else {
        if let Some(replacement) = replacement {
            *node = replacement.to_value();
        }
        return;
    };
    let step = *step as usize;
    match node {
        Value::Object(object) if !object.is_empty() => {
            let key = object.keys().nth(step % object.len()).cloned();
            let key = key.expect("index is in range");
            if rest.is_empty() && replacement.is_none() {
                object.remove(&key);
            } else {
                mutate(&mut object[&key], rest, replacement);
            }
        }
        Value::Array(items) if !items.is_empty() => {
            let index = step % items.len();
            mutate(&mut items[index], rest, replacement);
        }
        leaf => mutate(leaf, &[], replacement),
    }
}

fuzz_target!(|input: Input| {
    let mut challenge = input.challenge.build();
    // `request` crosses MCP as a JSON object; the receiver canonicalizes it.
    let request = challenge
        .request
        .decode_value()
        .expect("generated request is JSON");
    let canonical = Base64UrlJson::from_value(&request).expect("JSON values canonicalize");
    if input.challenge.request.is_canonical() {
        assert_eq!(canonical.raw(), challenge.request.raw());
    }
    challenge.request = canonical;

    let error = match &input.problem {
        None => mcp::payment_required_error(&challenge),
        Some(detail) => mcp::payment_required_error_with_problem(
            &challenge,
            PaymentErrorDetails::core("verification-failed").with_detail(detail),
        ),
    };
    let mut error = serde_json::to_value(&error).expect("payment error serializes");
    // The same payload can arrive in a tool result's `_meta`.
    let mut meta = json!({ mcp::PAYMENT_REQUIRED_META_KEY: error["data"] });
    for extracted in [
        mcp::extract_challenges(&error),
        mcp::extract_result_challenges(&meta),
    ] {
        let extracted = extracted.expect("challenge is present");
        assert_eq!(extracted.len(), 1);
        assert_same(&extracted[0], &challenge);
    }
    assert!(mcp::is_payment_required(&error));

    let mut credential = PaymentCredential::new(challenge.to_echo(), input.payload.to_value());
    credential.source = input.source.clone();
    let mut params = json!({ "name": "tool" });
    // Fails when `opaque` is not base64url JSON; it has no MCP form then.
    if mcp::try_attach_credential(&mut params, &credential).is_ok() {
        let extracted = mcp::extract_credential(&params["_meta"]).expect("credential is present");
        assert_same(&extracted, &credential);
    }

    let receipt = Receipt::success(challenge.method.clone(), &input.reference);
    let mut result = json!({ "content": [] });
    mcp::try_attach_receipt(&mut result, &receipt, &challenge.id).expect("result is an object");
    let attached: McpReceipt =
        serde_json::from_value(result["_meta"][mcp::RECEIPT_META_KEY].clone())
            .expect("attached receipt deserializes");
    assert_same(&attached.receipt, &receipt);
    assert_eq!(attached.challenge_id, challenge.id);

    for value in [&mut error, &mut meta, &mut params, &mut result] {
        input.mutation.apply(value);
        let _ = mcp::is_payment_required(value);
        let _ = mcp::extract_challenges(value);
        let _ = mcp::extract_challenges_from_data(&value["data"]);
        let _ = mcp::extract_result_challenges(value);
        let _ = mcp::extract_credential(&value["_meta"]);
        let _ = serde_json::from_value::<mcp::McpPaymentError>(value.clone());
        let _ = mcp::try_attach_receipt(value, &receipt, &challenge.id);
        let _ = mcp::try_attach_credential(value, &credential);
    }
});
