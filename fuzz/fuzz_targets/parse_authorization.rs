#![no_main]
use libfuzzer_sys::fuzz_target;
use mpay::parse_authorization;

fuzz_target!(|data: &str| {
    let _ = parse_authorization(data);
});
