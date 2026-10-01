//! MPP attribution memos.
//!
//! - `decode` never panics and accepts exactly the memos `is_mpp_memo`
//!   recognizes; the verifiers reject every other memo.
//! - An encoded memo decodes, verifies against its own server and challenge,
//!   and does not verify against different ones.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::tempo::attribution::{
    challenge_nonce, decode, encode, encode_hex, is_mpp_memo, verify_challenge_binding,
    verify_server,
};

fuzz_target!(|input: ([u8; 32], &str, &str, Option<&str>, &str)| {
    let (untrusted, challenge_id, server_id, client_id, other) = input;

    let decoded = decode(&untrusted);
    assert_eq!(decoded.is_some(), is_mpp_memo(&untrusted));
    if decoded.is_none() {
        assert!(!verify_server(&untrusted, server_id));
        assert!(!verify_challenge_binding(&untrusted, challenge_id));
    }

    let memo = encode(challenge_id, server_id, client_id);
    assert_eq!(encode_hex(challenge_id, server_id, client_id), hex(&memo));
    let decoded = decode(&memo).expect("encoded memo decodes");
    assert_eq!(decoded.nonce, challenge_nonce(challenge_id));
    assert_eq!(decoded.client_fingerprint.is_some(), client_id.is_some());
    assert!(verify_server(&memo, server_id));
    assert!(verify_challenge_binding(&memo, challenge_id));
    assert_eq!(verify_server(&memo, other), other == server_id);
    assert_eq!(
        verify_challenge_binding(&memo, other),
        other == challenge_id
    );
});

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
