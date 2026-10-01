use super::*;

#[test]
fn test_mpp_creation() {
    let payment = Mpp::new(MockMethod, "api.example.com", "secret");
    assert_eq!(payment.realm(), "api.example.com");
    assert_eq!(payment.method_name(), "mock");
    assert!(payment.currency().is_none());
    assert!(payment.recipient().is_none());
}

#[cfg(feature = "tempo")]
#[test]
fn test_charge_challenge_generation() {
    let payment = Mpp::new(MockMethod, "api.example.com", TEST_SECRET);
    let challenge = payment
        .charge_challenge(
            "1000000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

    assert_eq!(challenge.realm, "api.example.com");
    assert_eq!(challenge.method.as_str(), "tempo");
    assert_eq!(challenge.intent.as_str(), "charge");
    assert_eq!(challenge.id.len(), 43);
}

#[tokio::test]
async fn test_verify_returns_error_for_failed_transaction() {
    use crate::error::{MppError, PaymentError};
    use crate::protocol::traits::ErrorCode;

    let payment = Mpp::new(FailedTransactionMethod, "api.example.com", "secret");
    let credential = test_credential("secret");
    let request = test_request();

    let result = payment.verify(&credential, &request).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::TransactionFailed));
    assert!(err.message.contains("reverted"));

    let mpp_err: MppError = err.into();
    let problem = mpp_err.to_problem_details(None);
    assert_eq!(problem.status, 402);
}

#[tokio::test]
async fn test_verify_returns_receipt_for_success() {
    let payment = Mpp::new(MockMethod, "api.example.com", "secret");
    let credential = test_credential("secret");
    let request = test_request();

    let receipt = payment.verify(&credential, &request).await.unwrap();

    assert!(receipt.is_success());
    assert_eq!(receipt.reference, "mock_ref");
}

#[tokio::test]
async fn test_payment_success_event_fires_after_verify() {
    let payment = Mpp::new(MockMethod, "api.example.com", "secret");
    let credential = test_credential("secret");
    let request = test_request();
    let seen = Arc::new(Mutex::new(None));
    let _sub = payment.on_payment_success({
        let seen = seen.clone();
        move |ctx| {
            *seen.lock().unwrap() = Some(ctx);
            async {}
        }
    });

    let receipt = payment.verify(&credential, &request).await.unwrap();

    assert!(receipt.is_success());
    let event = seen.lock().unwrap().clone().unwrap();
    assert_eq!(event.method, "mock");
    assert_eq!(event.intent, "charge");
    assert_eq!(event.receipt.reference, "mock_ref");
    assert_eq!(event.request["amount"], "1000");
    assert!(!event.management_response);
}

#[tokio::test]
async fn test_payment_success_event_panic_does_not_fail_verify() {
    let payment = Mpp::new(MockMethod, "api.example.com", "secret");
    let credential = test_credential("secret");
    let request = test_request();
    let _sub = payment.on_payment_success(|_| async move {
        panic!("hook panic should be isolated");
        #[allow(unreachable_code)]
        ()
    });

    let receipt = payment.verify(&credential, &request).await.unwrap();

    assert!(receipt.is_success());
    assert_eq!(receipt.reference, "mock_ref");
}

#[tokio::test]
async fn test_verify_credential_decodes_request() {
    let request = ChargeRequest {
        amount: "500000".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
        ..Default::default()
    };
    let encoded = Base64UrlJson::from_typed(&request).unwrap();
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let secret = TEST_SECRET;
    let id = crate::protocol::core::compute_challenge_id(
        secret,
        "api.example.com",
        "mock",
        "charge",
        encoded.raw(),
        Some(&expires),
        None,
        None,
    );
    let credential = PaymentCredential::new(
        ChallengeEcho {
            id,
            realm: "api.example.com".into(),
            method: "mock".into(),
            intent: "charge".into(),
            request: encoded,
            expires: Some(expires),
            description: None,
            digest: None,
            opaque: None,
            header: None,
        },
        PaymentPayload::hash("0x123"),
    );
    let seen_request = Arc::new(Mutex::new(None));
    let payment = Mpp::new(
        RecordingMethod {
            seen_request: seen_request.clone(),
        },
        "api.example.com",
        secret,
    );

    let receipt = payment.verify_credential(&credential).await.unwrap();

    assert!(receipt.is_success());
    assert_eq!(receipt.reference, "0xabc123");
    let seen = seen_request.lock().unwrap().clone().unwrap();
    assert_eq!(seen.amount, request.amount);
    assert_eq!(seen.currency, request.currency);
    assert_eq!(seen.recipient, request.recipient);
}

#[tokio::test]
async fn test_verify_credential_with_body_digest_accepts_matching_body() {
    let payment = Mpp::new(MockMethod, "api.example.com", "secret");
    let body = br#"{"query":"paid"}"#;
    let credential = test_credential_with_body_digest("secret", body);

    let receipt = payment
        .verify_credential_with_body(&credential, body)
        .await
        .unwrap();

    assert!(receipt.is_success());
}

#[tokio::test]
async fn test_verify_credential_with_body_digest_rejects_mismatch() {
    let payment = Mpp::new(MockMethod, "api.example.com", "secret");
    let credential = test_credential_with_body_digest("secret", br#"{"query":"paid"}"#);

    let err = payment
        .verify_credential_with_body(&credential, br#"{"query":"tampered"}"#)
        .await
        .unwrap_err();

    assert!(err.message.contains("body digest mismatch"));
}

#[tokio::test]
async fn test_verify_credential_rejects_digest_without_body() {
    let payment = Mpp::new(MockMethod, "api.example.com", "secret");
    let credential = test_credential_with_body_digest("secret", br#"{"query":"paid"}"#);

    let err = payment.verify_credential(&credential).await.unwrap_err();

    assert!(err.message.contains("request body was not provided"));
}

#[tokio::test]
async fn test_verify_credential_with_body_rejects_missing_digest() {
    let payment = Mpp::new(MockMethod, "api.example.com", "secret");
    let mut credential = test_credential_with_body_digest("secret", br#"{"query":"paid"}"#);
    credential.challenge.digest = None;
    credential.challenge.id = crate::protocol::core::compute_challenge_id(
        "secret",
        "api.example.com",
        "mock",
        "charge",
        credential.challenge.request.raw(),
        credential.challenge.expires.as_deref(),
        None,
        None,
    );

    let err = payment
        .verify_credential_with_body(&credential, br#"{"query":"paid"}"#)
        .await
        .unwrap_err();

    assert!(err.message.contains("missing body digest"));
}
