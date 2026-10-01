//! Tempo JSON payloads that arrive from the other side: session credential
//! payloads, session and charge method details, session snapshots, session
//! receipts.
//!
//! - Deserializing arbitrary JSON never panics.
//! - An accepted value serializes to JSON that deserializes to the same
//!   value.
//! - A session receipt header round-trips the same way.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::protocol::methods::tempo::session::SessionSnapshot;
use mpp::protocol::methods::tempo::{
    SessionCredentialPayload, SessionReceipt, TempoMethodDetails, TempoSessionMethodDetails,
};
use mpp::{base64url_encode, ChargeRequest, SessionRequest};
use mpp_fuzz::json_eq;
use serde::{de::DeserializeOwned, Serialize};

fuzz_target!(|json: &str| {
    roundtrip::<SessionCredentialPayload>(json);
    roundtrip::<TempoSessionMethodDetails>(json);
    roundtrip::<TempoMethodDetails>(json);
    roundtrip::<SessionSnapshot>(json);
    roundtrip::<SessionRequest>(json);
    roundtrip::<ChargeRequest>(json);

    let _ = SessionReceipt::from_header(json);
    if let Ok(receipt) = SessionReceipt::from_header(&base64url_encode(json.as_bytes())) {
        let header = receipt.to_header().expect("session receipt formats");
        assert_eq!(SessionReceipt::from_header(&header).ok(), Some(receipt));
    }
});

fn roundtrip<T: Serialize + DeserializeOwned>(json: &str) {
    let Ok(value) = serde_json::from_str::<T>(json) else {
        return;
    };
    let first = serde_json::to_value(&value).expect("accepted value serializes");
    let again: T = serde_json::from_value(first.clone()).expect("serialized value deserializes");
    let second = serde_json::to_value(&again).expect("accepted value serializes");
    assert!(
        json_eq(&first, &second),
        "\n first: {first}\nsecond: {second}"
    );
}
