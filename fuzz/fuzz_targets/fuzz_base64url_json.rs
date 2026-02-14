#![no_main]

use libfuzzer_sys::fuzz_target;
use mpp::Base64UrlJson;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let b64 = Base64UrlJson::from_raw(s);
        let _ = b64.decode_value();
    }
});
