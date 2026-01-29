#![no_main]
use libfuzzer_sys::fuzz_target;
use mpay::parse_www_authenticate;

fuzz_target!(|data: &str| {
    let _ = parse_www_authenticate(data);
});
