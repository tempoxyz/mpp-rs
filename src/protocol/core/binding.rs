//! Challenge id binding.
//!
//! The challenge `id` is an HMAC-SHA256 over the challenge parameters, so a
//! server can verify an echoed challenge without storing it.

use subtle::ConstantTimeEq;

/// Minimum HMAC secret key length in bytes, matching mppx.
#[cfg(any(feature = "tempo", all(feature = "server", feature = "stripe")))]
const MIN_SECRET_KEY_BYTES: usize = 32;

/// Reject HMAC secret keys shorter than 32 bytes.
///
/// Whoever can guess the key can mint challenges for any amount, so the
/// fallible entry points that take a secret call this before signing.
#[cfg(any(feature = "tempo", all(feature = "server", feature = "stripe")))]
pub(crate) fn validate_secret_key(secret_key: &str) -> crate::error::Result<()> {
    if secret_key.len() < MIN_SECRET_KEY_BYTES {
        return Err(crate::error::MppError::InvalidConfig(format!(
            "Secret key must be at least {MIN_SECRET_KEY_BYTES} bytes. \
             Generate one with `openssl rand -base64 32`."
        )));
    }
    Ok(())
}

/// Compute an HMAC-SHA256 challenge ID from challenge parameters.
///
/// This is the canonical implementation used by both `PaymentChallenge::verify()`
/// and challenge creation. The algorithm matches the TypeScript and Python SDKs:
///
/// 1. Concatenate all fields `realm|method|intent|request|expires|digest|opaque` with `|` (empty string for absent optional fields)
/// 2. When a credential header is advertised, insert it immediately before the final opaque slot
/// 3. Compute HMAC-SHA256 with the secret key
/// 4. Base64url-encode the result (no padding)
///
/// # Examples
///
/// ```
/// use mpp::protocol::core::compute_challenge_id;
///
/// let id = compute_challenge_id(
///     "my-secret-key",
///     "api.example.com",
///     "tempo",
///     "charge",
///     "eyJhbW91bnQiOiIxMDAwMDAwIn0",
///     None,
///     None,
///     None,
/// );
/// ```
#[allow(clippy::too_many_arguments)]
pub fn compute_challenge_id(
    secret_key: &str,
    realm: &str,
    method: &str,
    intent: &str,
    request: &str,
    expires: Option<&str>,
    digest: Option<&str>,
    opaque: Option<&str>,
) -> String {
    compute_challenge_id_with_header(
        secret_key, realm, method, intent, request, expires, digest, opaque, None,
    )
}

/// Compute an HMAC-SHA256 challenge ID, including an advertised credential header.
///
/// `Authorization` is the implicit protocol default and is never included in the
/// HMAC input, matching mppx. An advertised header (`Payment-Authorization`)
/// is inserted immediately before the final opaque slot.
#[allow(clippy::too_many_arguments)]
pub fn compute_challenge_id_with_header(
    secret_key: &str,
    realm: &str,
    method: &str,
    intent: &str,
    request: &str,
    expires: Option<&str>,
    digest: Option<&str>,
    opaque: Option<&str>,
    header: Option<&str>,
) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // Legacy slots: realm | method | intent | request | expires | digest | opaque.
    // Challenges advertising a credential header insert it immediately before
    // the final opaque slot. Authorization is the implicit default and is never
    // included, preserving the legacy binding.
    let mut hmac_input = vec![
        realm,
        method,
        intent,
        request,
        expires.unwrap_or(""),
        digest.unwrap_or(""),
    ];
    let advertised = advertised_credential_header(header);
    if let Some(ref header) = advertised {
        hmac_input.push(header);
    }
    hmac_input.push(opaque.unwrap_or(""));
    let hmac_input = hmac_input.join("|");

    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(hmac_input.as_bytes());
    let result = mac.finalize();

    super::base64url_encode(&result.into_bytes())
}

/// Returns whether a credential header is omitted or is the implicit Authorization default.
pub fn is_default_credential_header(header: Option<&str>) -> bool {
    match header {
        None => true,
        Some(h) => h.is_empty() || h.eq_ignore_ascii_case("Authorization"),
    }
}

/// Returns whether a credential header selects `Payment-Authorization`.
pub(super) fn is_payment_authorization_header(header: &str) -> bool {
    header.eq_ignore_ascii_case(super::PAYMENT_AUTHORIZATION_HEADER)
}

/// Returns an advertised credential header, or `None` for the Authorization default.
///
/// `Payment-Authorization` is the only field a challenge may select. Other
/// values are ignored and treated as absent; parsers reject them separately.
pub fn advertised_credential_header(header: Option<&str>) -> Option<String> {
    let name = header?;
    is_payment_authorization_header(name).then(|| name.to_string())
}

/// Parse an advertised credential header from the wire, rejecting any value
/// other than `Payment-Authorization`.
pub fn parse_advertised_credential_header(
    header: Option<&str>,
) -> crate::error::Result<Option<String>> {
    if is_default_credential_header(header) {
        return Ok(None);
    }
    let name = header.unwrap_or("");
    if !is_payment_authorization_header(name) {
        return Err(crate::error::MppError::invalid_challenge_reason(
            "Unsupported credential header: must be Payment-Authorization",
        ));
    }
    Ok(Some(name.to_string()))
}

/// Constant-time string comparison to prevent timing attacks.
///
/// Delegated to the audited [`subtle`] crate: a hand-rolled loop carries no
/// guarantee the compiler won't reintroduce data-dependent branches, and
/// timing behavior is impractical to assert as conformance. Length is not
/// secret (inputs are fixed-size protocol strings: a `sha-256=` base64
/// body digest, or a base64url SHA-256 HMAC tag), so the length-mismatch
/// fast-path in `ct_eq` is acceptable.
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::core::Base64UrlJson;

    #[test]
    fn test_compute_challenge_id_cross_sdk() {
        // This test vector matches the cross-SDK conformance tests
        let id = compute_challenge_id(
            "test-secret-key-12345",
            "api.example.com",
            "tempo",
            "charge",
            &crate::protocol::core::base64url_encode(
                br#"{"amount":"1000000","currency":"0x20c0000000000000000000000000000000000000","recipient":"0x1234567890abcdef1234567890abcdef12345678"}"#,
            ),
            None,
            None,
            None,
        );
        assert_eq!(id, "XmJ98SdsAdzwP9Oa-8In322Uh6yweMO6rywdomWk_V4");
    }

    /// Cross-SDK golden vectors (shared with mppx and pympp).
    ///
    /// HMAC input: realm | method | intent | base64url(canonicalize(request)) | expires | digest | opaque
    /// HMAC key:   UTF-8 bytes of secret_key ("test-vector-secret")
    /// Output:     base64url(HMAC-SHA256(key, input), no padding)
    ///
    /// These vectors cover every combination of optional HMAC fields (expires, digest)
    /// and variations in each required field (realm, method, intent, request).
    #[test]
    fn test_golden_vectors() {
        use crate::protocol::core::base64url_encode as b64;
        let secret = "test-vector-secret";

        let req_amount = b64(br#"{"amount":"1000000"}"#);
        let req_multi = b64(br#"{"amount":"1000000","currency":"0x1234","recipient":"0xabcd"}"#);
        let req_nested =
            b64(br#"{"amount":"1000000","currency":"0x1234","methodDetails":{"chainId":42431}}"#);
        let req_empty = b64(br#"{}"#);

        #[allow(clippy::type_complexity)]
        let vectors: Vec<(
            &str,
            &str,
            &str,
            &str,
            &str,
            Option<&str>,
            Option<&str>,
            &str,
        )> = vec![
            (
                "required fields only",
                "api.example.com",
                "tempo",
                "charge",
                &req_amount,
                None,
                None,
                "X6v1eo7fJ76gAxqY0xN9Jd__4lUyDDYmriryOM-5FO4",
            ),
            (
                "with expires",
                "api.example.com",
                "tempo",
                "charge",
                &req_amount,
                Some("2025-01-06T12:00:00Z"),
                None,
                "ChPX33RkKSZoSUyZcu8ai4hhkvjZJFkZVnvWs5s0iXI",
            ),
            (
                "with digest",
                "api.example.com",
                "tempo",
                "charge",
                &req_amount,
                None,
                Some("sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE"),
                "JHB7EFsPVb-xsYCo8LHcOzeX1gfXWVoUSzQsZhKAfKM",
            ),
            (
                "with expires and digest",
                "api.example.com",
                "tempo",
                "charge",
                &req_amount,
                Some("2025-01-06T12:00:00Z"),
                Some("sha-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE"),
                "m39jbWWCIfmfJZSwCfvKFFtBl0Qwf9X4nOmDb21peLA",
            ),
            (
                "multi-field request",
                "api.example.com",
                "tempo",
                "charge",
                &req_multi,
                None,
                None,
                "_H5TOnnlW0zduQ5OhQ3EyLVze_TqxLDPda2CGZPZxOc",
            ),
            (
                "nested methodDetails",
                "api.example.com",
                "tempo",
                "charge",
                &req_nested,
                None,
                None,
                "TqujwpuDDg_zsWGINAd5XObO2rRe6uYufpqvtDmr6N8",
            ),
            (
                "empty request",
                "api.example.com",
                "tempo",
                "charge",
                &req_empty,
                None,
                None,
                "yLN7yChAejW9WNmb54HpJIWpdb1WWXeA3_aCx4dxmkU",
            ),
            (
                "different realm",
                "payments.other.com",
                "tempo",
                "charge",
                &req_amount,
                None,
                None,
                "3F5bOo2a9RUihdwKk4hGRvBvzQmVPBMDvW0YM-8GD00",
            ),
            (
                "different method",
                "api.example.com",
                "stripe",
                "charge",
                &req_amount,
                None,
                None,
                "o0ra2sd7HcB4Ph0Vns69gRDUhSj5WNOnUopcDqKPLz4",
            ),
            (
                "different intent",
                "api.example.com",
                "tempo",
                "session",
                &req_amount,
                None,
                None,
                "aAY7_IEDzsznNYplhOSE8cERQxvjFcT4Lcn-7FHjLVE",
            ),
        ];

        for (label, realm, method, intent, request, expires, digest, expected) in &vectors {
            let id = compute_challenge_id(
                secret, realm, method, intent, request, *expires, *digest, None,
            );
            assert_eq!(&id, expected, "golden vector failed: {}", label);
        }
    }

    #[test]
    fn test_compute_challenge_id_deterministic() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();

        let id1 = compute_challenge_id(
            "secret",
            "api",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );
        let id2 = compute_challenge_id(
            "secret",
            "api",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_compute_challenge_id_different_secrets() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000"})).unwrap();

        let id1 = compute_challenge_id(
            "secret-a",
            "api",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );
        let id2 = compute_challenge_id(
            "secret-b",
            "api",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_opaque_affects_challenge_id() {
        let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();
        let id_without = compute_challenge_id(
            "test-secret",
            "api.example.com",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            None,
        );
        let opaque =
            Base64UrlJson::from_value(&serde_json::json!({"pi": "pi_3abc123XYZ"})).unwrap();
        let id_with = compute_challenge_id(
            "test-secret",
            "api.example.com",
            "tempo",
            "charge",
            request.raw(),
            None,
            None,
            Some(opaque.raw()),
        );
        assert_ne!(id_without, id_with);
    }

    /// Cross-SDK opaque golden vectors (computed from mppx reference SDK).
    ///
    /// These vectors verify that opaque (meta) data produces identical HMAC
    /// challenge IDs across mpp-rs and mppx. The opaque value is JCS-serialized
    /// then base64url-encoded before entering the HMAC computation.
    #[test]
    fn test_opaque_golden_vectors() {
        let secret = "test-vector-secret";
        let req = Base64UrlJson::from_value(&serde_json::json!({"amount": "1000000"})).unwrap();

        // Vector 1: with opaque {pi: "pi_3abc123XYZ"}
        let opaque1 =
            Base64UrlJson::from_value(&serde_json::json!({"pi": "pi_3abc123XYZ"})).unwrap();
        let id1 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            req.raw(),
            None,
            None,
            Some(opaque1.raw()),
        );
        assert_eq!(
            id1, "rxzKZ2qjXvinqCH96RORTZEPs1KXsA-0AUjrCAPFOWc",
            "opaque golden vector failed: with opaque"
        );

        // Vector 2: with opaque and expires
        let id2 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            req.raw(),
            Some("2025-01-06T12:00:00Z"),
            None,
            Some(opaque1.raw()),
        );
        assert_eq!(
            id2, "KAfoMrA4fnzS1DPWN_cUv_b3_yHxCizdp6OhH7gluMY",
            "opaque golden vector failed: with opaque and expires"
        );

        // Vector 3: with empty opaque {}
        let opaque_empty = Base64UrlJson::from_value(&serde_json::json!({})).unwrap();
        let id3 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            req.raw(),
            None,
            None,
            Some(opaque_empty.raw()),
        );
        assert_eq!(
            id3, "vb4IyH-0LdJ3s7L0QAw8jIzcZkyxksPhIvEfmHmzA9k",
            "opaque golden vector failed: with empty opaque"
        );

        // Vector 4: with multi-key opaque (JCS sorts keys alphabetically)
        let opaque_multi = Base64UrlJson::from_value(
            &serde_json::json!({"deposit": "dep_456", "pi": "pi_3abc123XYZ"}),
        )
        .unwrap();
        let id4 = compute_challenge_id(
            secret,
            "api.example.com",
            "tempo",
            "charge",
            req.raw(),
            None,
            None,
            Some(opaque_multi.raw()),
        );
        assert_eq!(
            id4, "aKskU8sadR5ZuFbUCsIwhO-ENxuVpTw17FdwHEXsJDk",
            "opaque golden vector failed: with multi-key opaque"
        );
    }
}
