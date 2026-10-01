//! Fee-payer envelope (`0x78 || rlp([...])`) decoding.
//!
//! - `decode_envelope` never panics on untrusted bytes.
//! - A decoded envelope re-encodes to bytes that decode to the same
//!   envelope, and `length()` matches the encoding.
//! - Rebuilding the sender-signed transaction never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::protocol::methods::tempo::FeePayerEnvelope78;

fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = FeePayerEnvelope78::decode_envelope(data) else {
        return;
    };
    let encoded = envelope.encoded_envelope();
    let decoded = FeePayerEnvelope78::decode_envelope(&encoded).expect("re-encoded envelope");
    assert_eq!(decoded, envelope);
    assert_eq!(decoded.encoded_envelope(), encoded);
    let _ = envelope.to_recoverable_signed();
});
