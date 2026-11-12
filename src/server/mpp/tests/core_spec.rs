use super::*;

// ── Core spec behaviors: nonce, secret length, check order ────────────

#[cfg(feature = "tempo")]
fn spec_mpp() -> Mpp<TempoSuccessMethod> {
    Mpp::new_with_config(
        TempoSuccessMethod,
        "api.example.com",
        TEST_SECRET,
        "0x20c0000000000000000000000000000000000000",
        TEST_RECIPIENT,
    )
}

#[cfg(feature = "tempo")]
fn nonce_of(challenge: &PaymentChallenge) -> Option<String> {
    let opaque = challenge.opaque.as_ref()?.decode_value().ok()?;
    opaque.get("_mpp_nonce")?.as_str().map(str::to_string)
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_challenges_carry_a_fresh_nonce_by_default() {
    let mpp = spec_mpp();
    assert!(mpp.nonce());
    let first = mpp.charge("0.10").unwrap().remove(0);
    let second = mpp.charge("0.10").unwrap().remove(0);
    let nonce = nonce_of(&first).unwrap();
    // 16 random bytes, base64url without padding.
    assert_eq!(nonce.len(), 22);
    assert_eq!(
        crate::protocol::core::base64url_decode(&nonce)
            .unwrap()
            .len(),
        16
    );
    assert_ne!(Some(nonce), nonce_of(&second));
    assert_ne!(first.id, second.id);
    assert!(first.verify(TEST_SECRET));

    let credential = PaymentCredential::new(first.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    assert!(mpp.verify_charge(&credential, "0.10").await.is_ok());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_nonce_keeps_route_opaque_and_can_be_disabled() {
    let mpp = spec_mpp().with_opaque(route_opaque());
    let challenge = mpp.charge("0.10").unwrap().remove(0);
    let opaque = challenge.opaque.as_ref().unwrap().decode_value().unwrap();
    assert_eq!(opaque["route"], "a");
    assert!(opaque.get("_mpp_nonce").is_some());
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    assert!(mpp.verify_charge(&credential, "0.10").await.is_ok());

    let request = ChargeRequest {
        amount: "100000".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some(TEST_RECIPIENT.into()),
        ..Default::default()
    };
    let issue = || {
        spec_mpp()
            .with_nonce(false)
            .charge_challenge_with_options(&request, Some("2099-01-01T00:00:00Z"), None)
            .unwrap()
    };
    let plain = issue();
    assert!(plain.opaque.is_none());
    assert_eq!(plain.id, issue().id);
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verification_ignores_legacy_mppx_nonce() {
    let mpp = spec_mpp().with_nonce(false).with_opaque(route_opaque());
    let mut challenge = mpp.charge("0.10").unwrap().remove(0);
    challenge.opaque = Some(
        Base64UrlJson::from_value(&serde_json::json!({"route": "a", "_mppx_nonce": "abc"}))
            .unwrap(),
    );
    challenge.id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        &challenge.realm,
        challenge.method.as_str(),
        challenge.intent.as_str(),
        challenge.request.raw(),
        challenge.expires.as_deref(),
        None,
        challenge.opaque.as_ref().map(|o| o.raw()),
    );
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    assert!(mpp.verify_charge(&credential, "0.10").await.is_ok());

    // Any other extra member still fails the route match.
    challenge.opaque = Some(
        Base64UrlJson::from_value(&serde_json::json!({"route": "b", "_mpp_nonce": "abc"})).unwrap(),
    );
    challenge.id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        &challenge.realm,
        challenge.method.as_str(),
        challenge.intent.as_str(),
        challenge.request.raw(),
        challenge.expires.as_deref(),
        None,
        challenge.opaque.as_ref().map(|o| o.raw()),
    );
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    let err = mpp.verify_charge(&credential, "0.10").await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_short_secret_is_refused() {
    let short = "0123456789abcdef0123456789abcde"; // 31 bytes
    assert!(Mpp::try_new(TempoSuccessMethod, "api.example.com", short).is_err());
    assert!(Mpp::try_new(TempoSuccessMethod, "api.example.com", TEST_SECRET).is_ok());

    let mpp = Mpp::new_with_config(
        TempoSuccessMethod,
        "api.example.com",
        short,
        "0x20c0000000000000000000000000000000000000",
        TEST_RECIPIENT,
    );
    assert!(matches!(
        mpp.charge("0.10"),
        Err(crate::error::MppError::InvalidConfig(_))
    ));

    // A credential bound with the short key is refused too.
    let issuer = spec_mpp();
    let challenge = issuer.charge("0.10").unwrap().remove(0);
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    assert!(mpp.verify_charge(&credential, "0.10").await.is_err());
    let err = mpp.broadcast_credential(&credential).await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::Internal));
    assert!(err.message.contains("32 bytes"), "{}", err.message);
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_binding_mismatch_is_reported_before_expiry() {
    let mpp = spec_mpp().with_nonce(false);
    let request = ChargeRequest {
        amount: "100000".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some(TEST_RECIPIENT.into()),
        ..Default::default()
    };
    let past = "2020-01-01T00:00:00Z";
    // An expired challenge this server issued for another realm.
    let other_realm = Mpp::new_with_config(
        TempoSuccessMethod,
        "other.example.com",
        TEST_SECRET,
        "0x20c0000000000000000000000000000000000000",
        TEST_RECIPIENT,
    )
    .with_nonce(false);
    let mut challenge = other_realm
        .charge_challenge_with_options(&request, Some("2099-01-01T00:00:00Z"), None)
        .unwrap();
    challenge.expires = Some(past.into());
    challenge.id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        "api.example.com",
        challenge.method.as_str(),
        challenge.intent.as_str(),
        challenge.request.raw(),
        Some(past),
        None,
        None,
    );
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    let err = mpp.verify_charge(&credential, "0.10").await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge), "{err}");

    // The same challenge for this realm is reported as expired.
    challenge.realm = "api.example.com".into();
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    let err = mpp.verify_charge(&credential, "0.10").await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::Expired), "{err}");
}

/// A route opaque that is an empty object, another JSON value, raw JSON with
/// numbers JCS rewrites, or not JSON at all is issued and matched with the nonce on and off, so a handler accepts
/// its own Challenges.
#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_any_route_opaque_verifies_its_own_challenges() {
    let opaques = [
        Base64UrlJson::from_value(&serde_json::json!({})).unwrap(),
        Base64UrlJson::from_value(&serde_json::json!("route-a")).unwrap(),
        Base64UrlJson::from_value(&serde_json::json!(["a", 1])).unwrap(),
        Base64UrlJson::from_raw("bm90LWpzb24"),
        // Raw JSON whose numbers JCS rewrites when the nonce is added.
        Base64UrlJson::from_raw(crate::protocol::core::base64url_encode(
            br#"{"price":1.0,"big":9007199254740993}"#,
        )),
    ];
    for opaque in opaques {
        for nonce in [true, false] {
            let mpp = spec_mpp().with_nonce(nonce).with_opaque(opaque.clone());
            let challenge = mpp.charge("0.10").unwrap().remove(0);
            let credential =
                PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
            let result = mpp.verify_charge(&credential, "0.10").await;
            assert!(result.is_ok(), "{} nonce={nonce}: {result:?}", opaque.raw());
        }
    }

    // A different raw opaque still fails the route match.
    let mpp = spec_mpp()
        .with_nonce(false)
        .with_opaque(Base64UrlJson::from_raw("bm90LWpzb24"));
    let mut challenge = mpp.charge("0.10").unwrap().remove(0);
    challenge.opaque = Some(Base64UrlJson::from_raw("b3RoZXI"));
    challenge.id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        &challenge.realm,
        challenge.method.as_str(),
        challenge.intent.as_str(),
        challenge.request.raw(),
        challenge.expires.as_deref(),
        None,
        challenge.opaque.as_ref().map(|o| o.raw()),
    );
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    let err = mpp.verify_charge(&credential, "0.10").await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge), "{err}");
}
