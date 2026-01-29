#![no_main]
use libfuzzer_sys::fuzz_target;
use mpay::parse_receipt;

fuzz_target!(|data: &str| {
    let _ = parse_receipt(data);
});
