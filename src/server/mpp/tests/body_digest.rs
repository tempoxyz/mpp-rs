use super::*;
use crate::protocol::core::{Base64UrlJson, PaymentChallenge};

const BODY: &[u8] = b"hello";
const BARE: &str = "sha-256=LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=";
const STRUCTURED: &str = "sha-256=:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=:";

fn credential(digest: &str) -> (PaymentCredential, ChargeRequest) {
    let request = ChargeRequest {
        amount: "100".into(),
        currency: "usd".into(),
        ..Default::default()
    };
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let challenge = PaymentChallenge::with_secret_key_full(
        TEST_SECRET,
        "api.example.com",
        "mock",
        "charge",
        Base64UrlJson::from_typed(&request).unwrap(),
        Some(&expires),
        Some(digest),
        None,
        None,
        None,
    );
    assert!(challenge.verify(TEST_SECRET));
    let parsed = PaymentChallenge::from_header(&challenge.to_header().unwrap()).unwrap();
    assert_eq!(parsed.digest.as_deref(), Some(digest));
    (
        PaymentCredential::new(parsed.to_echo(), PaymentPayload::hash("mock-proof")),
        request,
    )
}

#[tokio::test]
async fn matching_body_accepts_both_digest_encodings() {
    for digest in [BARE, STRUCTURED] {
        let seen = Arc::new(Mutex::new(None));
        let mpp = Mpp::new(
            RecordingMethod {
                seen_request: seen.clone(),
            },
            "api.example.com",
            TEST_SECRET,
        );
        let (credential, expected) = credential(digest);
        let receipt = mpp
            .verify_credential_with_expected_request_and_body(&credential, &expected, BODY)
            .await
            .unwrap();
        assert!(receipt.is_success());
        assert!(seen.lock().unwrap().is_some());
    }
}

#[tokio::test]
async fn changed_body_is_rejected_before_method_verification() {
    for digest in [BARE, STRUCTURED] {
        let seen = Arc::new(Mutex::new(None));
        let mpp = Mpp::new(
            RecordingMethod {
                seen_request: seen.clone(),
            },
            "api.example.com",
            TEST_SECRET,
        );
        let (credential, expected) = credential(digest);
        let error = mpp
            .verify_credential_with_expected_request_and_body(&credential, &expected, b"changed")
            .await
            .unwrap_err();
        assert_eq!(error.code, Some(ErrorCode::InvalidChallenge));
        assert!(error.message.contains("body digest mismatch"));
        assert!(seen.lock().unwrap().is_none());
    }
}

#[tokio::test]
async fn equivalent_digest_text_does_not_bypass_challenge_binding() {
    for (original, replacement) in [(BARE, STRUCTURED), (STRUCTURED, BARE)] {
        let seen = Arc::new(Mutex::new(None));
        let mpp = Mpp::new(
            RecordingMethod {
                seen_request: seen.clone(),
            },
            "api.example.com",
            TEST_SECRET,
        );
        let (mut credential, expected) = credential(original);
        credential.challenge.digest = Some(replacement.into());
        let error = mpp
            .verify_credential_with_expected_request_and_body(&credential, &expected, BODY)
            .await
            .unwrap_err();
        assert_eq!(error.code, Some(ErrorCode::InvalidChallenge));
        assert!(error.message.contains("Challenge ID mismatch"));
        assert!(seen.lock().unwrap().is_none());
    }
}
