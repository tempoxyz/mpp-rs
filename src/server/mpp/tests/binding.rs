use super::*;

// ── Real HMAC challenge verification tests ─────────────────────────

/// Helper: build an Mpp with TempoSuccessMethod whose realm, secret_key,
/// currency, recipient, and decimals match create_test_mpp().
#[cfg(feature = "tempo")]
fn create_hmac_test_mpp() -> Mpp<TempoSuccessMethod> {
    Mpp {
        method: TempoSuccessMethod,
        session_method: None,
        realm: "MPP Payment".into(),
        secret_key: TEST_SECRET.into(),
        currencies: vec!["0x20c0000000000000000000000000000000000000".into()],
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
        decimals: DEFAULT_DECIMALS,
        fee_payer: false,
        machine_token_enabled: false,
        chain_id: None,
        opaque: None,
        credential_header: None,
        events: ServerEvents::default(),
    }
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_hmac_verify_happy_path() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

    let receipt = mpp.verify_credential(&credential).await.unwrap();
    assert!(receipt.is_success());
    assert_eq!(receipt.reference, "0xtxhash");
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_requires_auth_advertises_payment_authorization_header() {
    let mpp = create_hmac_test_mpp().with_requires_auth(true);
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    assert!(mpp.requires_auth());
    assert_eq!(mpp.credential_header(), "Payment-Authorization");
    assert_eq!(challenge.header.as_deref(), Some("Payment-Authorization"));
    assert!(challenge
        .to_header()
        .unwrap()
        .contains(r#"header="Payment-Authorization""#));
    assert!(challenge.verify(TEST_SECRET));

    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    let receipt = mpp.verify_credential(&credential).await.unwrap();
    assert!(receipt.is_success());

    let implicit = create_hmac_test_mpp().charge("0.10").unwrap().remove(0);
    assert_ne!(implicit.id, challenge.id);
    assert!(implicit.header.is_none());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_hmac_verify_expected_request_with_body_digest_happy_path() {
    let mpp = create_hmac_test_mpp();
    let body = br#"{"query":"paid"}"#;
    let challenge = mpp.charge_with_body("0.10", body).unwrap().remove(0);
    let expected_request: ChargeRequest = challenge.request.decode().unwrap();
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));

    let receipt = mpp
        .verify_credential_with_expected_request_and_body(&credential, &expected_request, body)
        .await
        .unwrap();

    assert!(receipt.is_success());
    assert_eq!(receipt.reference, "0xtxhash");

    let err = mpp
        .verify_credential_with_expected_request_and_body(
            &credential,
            &expected_request,
            br#"{"query":"tampered"}"#,
        )
        .await
        .unwrap_err();
    assert!(err.message.contains("body digest mismatch"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_hmac_tampered_request_rejected() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    let mut echo = challenge.to_echo();
    // Tamper: replace the request with a different amount
    let tampered_request = ChargeRequest {
        amount: "999999".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
        ..Default::default()
    };
    let encoded = Base64UrlJson::from_typed(&tampered_request).unwrap();
    echo.request = encoded;

    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().message.contains("mismatch"),
        "expected HMAC mismatch error"
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_hmac_tampered_realm_rejected() {
    // HMAC (Tier 1) passes because the server recomputes using its own
    // realm, but Tier-2 pinned field verification catches the mismatch.
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    let mut echo = challenge.to_echo();
    echo.realm = "evil.example.com".into();

    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().message.contains("realm"),
        "expected realm mismatch error"
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_hmac_tampered_method_rejected() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    let mut echo = challenge.to_echo();
    echo.method = "evil-method".into();

    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().message.contains("mismatch"),
        "expected HMAC mismatch error"
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_hmac_tampered_intent_rejected() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    let mut echo = challenge.to_echo();
    echo.intent = "session".into();

    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().message.contains("mismatch"),
        "expected HMAC mismatch error"
    );
}

// ── Tier-2 pinned field verification tests ──────────────────────

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_currency_mismatch_rejected() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);
    let mut request: ChargeRequest = challenge.request.decode().unwrap();
    request.currency = "0xDEAD000000000000000000000000000000000000".into();
    let encoded = Base64UrlJson::from_typed(&request).unwrap();

    let mut echo = challenge.to_echo();
    echo.request = encoded;
    // Re-sign with server secret so HMAC passes
    let id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "tempo",
        "charge",
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(|o| o.raw()),
    );
    echo.id = id;
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("currency"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_recipient_mismatch_rejected() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);
    let mut request: ChargeRequest = challenge.request.decode().unwrap();
    request.recipient = Some("0xDEAD000000000000000000000000000000000000".into());
    let encoded = Base64UrlJson::from_typed(&request).unwrap();

    let mut echo = challenge.to_echo();
    echo.request = encoded;
    let id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "tempo",
        "charge",
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(|o| o.raw()),
    );
    echo.id = id;
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("recipient"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_chain_id_mismatch_rejected() {
    let mut mpp = create_hmac_test_mpp();
    mpp.chain_id = Some(42431);
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    // Tamper chainId in the request, re-sign HMAC
    let mut request: ChargeRequest = challenge.request.decode().unwrap();
    let md = request.method_details.get_or_insert(serde_json::json!({}));
    md["chainId"] = serde_json::json!(9999);
    let encoded = Base64UrlJson::from_typed(&request).unwrap();

    let mut echo = challenge.to_echo();
    echo.request = encoded;
    let id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "tempo",
        "charge",
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(|o| o.raw()),
    );
    echo.id = id;
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("chainId"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_chain_id_missing_rejected() {
    // Server expects chainId but credential omits it entirely (fail-closed)
    let mut mpp = create_hmac_test_mpp();
    mpp.chain_id = Some(42431);
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    // Strip chainId from request, re-sign
    let mut request: ChargeRequest = challenge.request.decode().unwrap();
    if let Some(md) = request.method_details.as_mut() {
        md.as_object_mut().unwrap().remove("chainId");
    }
    let encoded = Base64UrlJson::from_typed(&request).unwrap();

    let mut echo = challenge.to_echo();
    echo.request = encoded;
    let id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "tempo",
        "charge",
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(|o| o.raw()),
    );
    echo.id = id;
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("chainId"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_charge_challenge_pins_chain_id() {
    const CURRENCY: &str = "0x20c0000000000000000000000000000000000000";

    let mut mpp = create_hmac_test_mpp();
    mpp.chain_id = Some(42431);

    let request = ChargeRequest {
        amount: "1000".into(),
        currency: CURRENCY.into(),
        recipient: Some(TEST_RECIPIENT.into()),
        method_details: Some(serde_json::json!({ "feePayer": true })),
        ..Default::default()
    };
    let challenges = [
        mpp.charge_challenge("1000", CURRENCY, TEST_RECIPIENT)
            .unwrap(),
        mpp.charge_challenge_with_options(&request, None, None)
            .unwrap(),
    ];
    for challenge in &challenges {
        let credential =
            PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
        mpp.verify_credential(&credential)
            .await
            .expect("a challenge issued by this handler must verify");
    }

    let issued: ChargeRequest = challenges[1].request.decode().unwrap();
    assert!(issued.fee_payer(), "caller methodDetails must be kept");

    // An explicit chainId is the caller's choice and is not overwritten.
    let explicit = ChargeRequest {
        method_details: Some(serde_json::json!({ "chainId": 4217 })),
        ..request
    };
    let challenge = mpp
        .charge_challenge_with_options(&explicit, None, None)
        .unwrap();
    let issued: ChargeRequest = challenge.request.decode().unwrap();
    assert_eq!(issued.chain_id(), Some(4217));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_opaque_mismatch_rejected() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    let mut echo = challenge.to_echo();
    echo.opaque = Some(Base64UrlJson::from_value(&serde_json::json!({"route": "other"})).unwrap());
    echo.id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "tempo",
        "charge",
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(|o| o.raw()),
    );

    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("opaque"));
}

/// Mint a credential whose echoed `opaque` is `opaque`, with a valid HMAC
/// recomputed over it (all test handlers share the same realm/secret).
#[cfg(feature = "tempo")]
fn opaque_credential(opaque: Option<Base64UrlJson>) -> PaymentCredential {
    let mut echo = create_hmac_test_mpp()
        .charge("0.10")
        .unwrap()
        .remove(0)
        .to_echo();
    echo.opaque = opaque;
    echo.id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "tempo",
        "charge",
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(|o| o.raw()),
    );
    PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"))
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_opaque_configured_match_accepted() {
    let mpp = create_hmac_test_mpp().with_opaque(route_opaque());
    let credential = opaque_credential(Some(route_opaque()));

    assert!(mpp.verify_credential(&credential).await.is_ok());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_opaque_configured_mismatch_rejected() {
    let mpp = create_hmac_test_mpp().with_opaque(route_opaque());
    let other = Base64UrlJson::from_value(&serde_json::json!({"route": "b"})).unwrap();
    let credential = opaque_credential(Some(other));

    let err = mpp.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("opaque"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_opaque_configured_but_absent_rejected() {
    let mpp = create_hmac_test_mpp().with_opaque(route_opaque());
    let credential = opaque_credential(None);

    let err = mpp.verify_credential(&credential).await.unwrap_err();
    assert!(err.message.contains("opaque"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_opaque_charge_helper_roundtrips() {
    // charge() emits the configured opaque, so its credential verifies.
    let mpp = create_hmac_test_mpp().with_opaque(route_opaque());
    let challenge = mpp.charge("0.10").unwrap().remove(0);
    assert_eq!(
        challenge.opaque.as_ref().map(|o| o.raw()),
        Some(route_opaque().raw())
    );

    let credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xbeef"));
    assert!(mpp.verify_credential(&credential).await.is_ok());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_intent_mismatch_rejected() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    // Tamper intent to "session", re-sign so HMAC passes
    let mut echo = challenge.to_echo();
    echo.intent = "session".into();
    let id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "tempo",
        "session",
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(|o| o.raw()),
    );
    echo.id = id;
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("intent"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_method_mismatch_rejected() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    // Tamper method to "stripe", re-sign so HMAC passes
    let mut echo = challenge.to_echo();
    echo.method = "stripe".into();
    let id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "stripe",
        "charge",
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(|o| o.raw()),
    );
    echo.id = id;
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().message.contains("method"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_pinned_fields_pass_when_matching() {
    // Happy path: all pinned fields match → verification succeeds
    let mut mpp = create_hmac_test_mpp();
    mpp.chain_id = Some(42431);
    let challenge = mpp.charge("0.10").unwrap().remove(0);
    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let receipt = mpp.verify_credential(&credential).await.unwrap();
    assert!(receipt.is_success());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_hmac_charge_with_options_roundtrip() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp
        .charge_with_options(
            "2.50",
            ChargeOptions {
                description: Some("Premium access"),
                fee_payer: true,
                ..Default::default()
            },
        )
        .unwrap()
        .remove(0);

    // Verify challenge fields
    assert_eq!(challenge.description, Some("Premium access".to_string()));
    let request: ChargeRequest = challenge.request.decode().unwrap();
    assert_eq!(request.amount, "2500000");
    let details = request.method_details.unwrap();
    assert_eq!(details["feePayer"], serde_json::json!(true));

    // Roundtrip: credential built from this challenge verifies
    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));
    let receipt = mpp.verify_credential(&credential).await.unwrap();
    assert!(receipt.is_success());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_expired_challenge_rejected() {
    let mpp = create_hmac_test_mpp();

    // Create a credential with an expired timestamp so the HMAC matches
    let past = (time::OffsetDateTime::now_utc() - time::Duration::minutes(10))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let challenge = mpp
        .charge_with_options(
            "0.10",
            crate::server::ChargeOptions {
                expires: Some(&past),
                ..Default::default()
            },
        )
        .unwrap()
        .remove(0);
    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::Expired));
    assert!(
        err.message.contains("expired"),
        "expected expiry error, got: {}",
        err.message
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_non_expired_challenge_accepted() {
    let mpp = create_hmac_test_mpp();
    // Default charge generates an expires 5 minutes in the future
    let challenge = mpp.charge("0.10").unwrap().remove(0);
    assert!(
        challenge.expires.is_some(),
        "charge should have default expires"
    );

    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_ok(), "non-expired challenge should be accepted");
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_malformed_expires_rejected() {
    let mpp = create_hmac_test_mpp();

    // Manually create a credential with a malformed expires that has a valid HMAC
    let challenge = mpp
        .charge_with_options(
            "0.10",
            crate::server::ChargeOptions {
                expires: Some("not-a-timestamp"),
                ..Default::default()
            },
        )
        .unwrap()
        .remove(0);
    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().message.contains("Invalid expires"),
        "expected invalid expires error"
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_missing_expires_rejected() {
    let mpp = create_hmac_test_mpp();

    // Manually create a credential without expires — HMAC computed without expires
    let request = ChargeRequest {
        amount: "100000".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
        ..Default::default()
    };
    let encoded = Base64UrlJson::from_typed(&request).unwrap();
    let id = crate::protocol::methods::tempo::generate_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "tempo",
        "charge",
        encoded.raw(),
        None,
        None,
        None,
    );

    let echo = ChallengeEcho {
        id,
        realm: "MPP Payment".into(),
        method: "tempo".into(),
        intent: "charge".into(),
        request: encoded,
        expires: None,
        description: None,
        digest: None,
        opaque: None,
        header: None,
    };
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

    let result = mpp.verify_credential(&credential).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(
        err.message.contains("missing required expires"),
        "expected missing expires error, got: {}",
        err.message
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_credential_with_wrong_amount_rejected() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0); // 100000 base units

    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

    let wrong_request = ChargeRequest {
        amount: "999999999".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
        ..Default::default()
    };
    let result = mpp
        .verify_credential_with_expected_request(&credential, &wrong_request)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(
        err.message.contains("Amount mismatch"),
        "expected amount mismatch error, got: {}",
        err.message
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_credential_with_correct_request_accepted() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0); // 100000 base units

    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

    let expected_request = ChargeRequest {
        amount: "100000".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
        ..Default::default()
    };
    let result = mpp
        .verify_credential_with_expected_request(&credential, &expected_request)
        .await;
    assert!(result.is_ok(), "correct request should be accepted");
}

/// One handler serves a $0.01 and a $1 route, as in `examples/basic`.
#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_charge_rejects_credential_paid_for_cheaper_route() {
    let mpp = create_hmac_test_mpp();
    let cheap = mpp.charge("0.01").unwrap().remove(0);
    let credential = PaymentCredential::new(cheap.to_echo(), PaymentPayload::hash("0xdeadbeef"));

    let err = mpp.verify_charge(&credential, "1").await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(err.message.contains("Amount mismatch"), "{}", err.message);

    let receipt = mpp.verify_charge(&credential, "0.01").await.unwrap();
    assert!(receipt.is_success());

    // The unbound primitive still accepts it on any route.
    assert!(mpp.broadcast_credential(&credential).await.is_ok());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_charge_accepts_every_offered_currency() {
    use crate::protocol::methods::tempo::{OUSD, USDC};

    let mpp = success_mpp_from(offers_builder().chain_id(CHAIN_ID));
    let challenges = mpp.charge("0.10").unwrap();
    for currency in [OUSD, USDC] {
        let credential = offered_credential(&challenges, currency);
        assert!(
            mpp.verify_charge(&credential, "0.10").await.is_ok(),
            "{currency} should match the route"
        );
        let err = mpp.verify_charge(&credential, "0.20").await.unwrap_err();
        assert!(err.message.contains("Amount mismatch"), "{}", err.message);
    }
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_expected_charge_request_matches_issued_request() {
    let mpp = create_hmac_test_mpp();
    let scope = serde_json::json!({ "route": "/api/fortune" });
    let options = || ChargeOptions {
        fee_payer: true,
        mppx_scope: Some(&scope),
        ..Default::default()
    };
    let challenge = mpp
        .charge_with_options("0.10", options())
        .unwrap()
        .remove(0);
    let issued: serde_json::Value = challenge.request.decode_value().unwrap();
    let expected = mpp.expected_charge_request("0.10", options()).unwrap();
    assert_eq!(serde_json::to_value(&expected).unwrap(), issued);

    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));
    assert!(mpp
        .verify_charge_with_options(&credential, "0.10", options())
        .await
        .is_ok());
    // `verify_charge` expects an unscoped challenge.
    let err = mpp.verify_charge(&credential, "0.10").await.unwrap_err();
    assert!(err.message.contains("scope mismatch"), "{}", err.message);
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_charge_rejects_without_bound_currency() {
    use crate::protocol::methods::tempo::PATH_USD;

    let mpp = Mpp::new(TempoSuccessMethod, "MPP Payment", "test-secret");
    let challenge = mpp
        .charge_challenge("10000", PATH_USD, TEST_RECIPIENT)
        .unwrap();
    let credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0x01"));

    let err = mpp.verify_charge(&credential, "0.01").await.unwrap_err();
    assert!(
        err.message.contains("expected charge request"),
        "{}",
        err.message
    );
    assert!(err.code.is_none());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_credential_with_wrong_recipient_rejected() {
    let mpp = create_hmac_test_mpp();
    let challenge = mpp.charge("0.10").unwrap().remove(0);

    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

    let wrong_recipient = ChargeRequest {
        amount: "100000".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some("0x0000000000000000000000000000000000000001".into()),
        ..Default::default()
    };
    let result = mpp
        .verify_credential_with_expected_request(&credential, &wrong_recipient)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(
        err.message.contains("Recipient mismatch"),
        "expected recipient mismatch error, got: {}",
        err.message
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_credential_with_split_routing_mismatch_rejected() {
    let mpp = create_hmac_test_mpp();

    let challenge = mpp
        .charge_challenge_with_options(
            &ChargeRequest {
                amount: "100000".into(),
                currency: "0x20c0000000000000000000000000000000000000".into(),
                recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
                method_details: Some(serde_json::json!({
                    "splits": [{
                        "amount": "10000",
                        "recipient": "0x0000000000000000000000000000000000000003"
                    }]
                })),
                ..Default::default()
            },
            None,
            None,
        )
        .unwrap();

    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

    let no_splits_request = ChargeRequest {
        amount: "100000".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
        ..Default::default()
    };

    let result = mpp
        .verify_credential_with_expected_request(&credential, &no_splits_request)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(
        err.message.contains("Tempo transfer routing mismatch"),
        "expected split routing mismatch error, got: {}",
        err.message
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_credential_accepts_equivalent_reordered_splits() {
    let mpp = create_hmac_test_mpp();
    let split_a = serde_json::json!({
        "amount": "10000",
        "recipient": "0x0000000000000000000000000000000000000003",
        "memo": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    let split_b = serde_json::json!({
        "amount": "20000",
        "recipient": "0x0000000000000000000000000000000000000004",
        "memo": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    });
    let request = |splits| ChargeRequest {
        amount: "100000".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
        method_details: Some(serde_json::json!({ "splits": splits })),
        ..Default::default()
    };
    let challenge = mpp
        .charge_challenge_with_options(&request(vec![split_a.clone(), split_b.clone()]), None, None)
        .unwrap();
    let credential =
        PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"));

    let result = mpp
        .verify_credential_with_expected_request(&credential, &request(vec![split_b, split_a]))
        .await;

    assert!(result.is_ok(), "equivalent split routes should match");
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_credential_with_split_memo_routing_mismatch_rejected() {
    let mpp = create_hmac_test_mpp();

    let challenge = mpp
        .charge_challenge_with_options(
            &ChargeRequest {
                amount: "100000".into(),
                currency: "0x20c0000000000000000000000000000000000000".into(),
                recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
                method_details: Some(serde_json::json!({
                    "splits": [{
                        "amount": "10000",
                        "recipient": "0x0000000000000000000000000000000000000003",
                        "memo": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                    }]
                })),
                ..Default::default()
            },
            None,
            None,
        )
        .unwrap();

    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0xdeadbeef"));

    let request_without_memo = ChargeRequest {
        amount: "100000".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
        method_details: Some(serde_json::json!({
            "splits": [{
                "amount": "10000",
                "recipient": "0x0000000000000000000000000000000000000003"
            }]
        })),
        ..Default::default()
    };

    let result = mpp
        .verify_credential_with_expected_request(&credential, &request_without_memo)
        .await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(
        err.message.contains("Tempo transfer routing mismatch"),
        "expected memo routing mismatch error, got: {}",
        err.message
    );
}
