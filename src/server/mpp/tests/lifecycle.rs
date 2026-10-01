use super::*;

#[derive(Clone)]
struct LifecycleMethod {
    calls: Arc<Mutex<Vec<&'static str>>>,
    reject_broadcast: bool,
    reject_validation: bool,
}

impl ChargeMethod for LifecycleMethod {
    fn method(&self) -> &str {
        "mock"
    }

    fn supports_validation(&self) -> bool {
        true
    }

    fn validate(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = std::result::Result<ChargeValidation, VerificationError>> + Send {
        let calls = Arc::clone(&self.calls);
        let reject_validation = self.reject_validation;
        let credential = credential.clone();
        let request = request.clone();
        async move {
            calls.lock().unwrap().push("validate");
            if reject_validation {
                return Err(VerificationError::new("validation rejected"));
            }
            Ok(ChargeValidation::new(
                &credential,
                &request,
                serde_json::json!({ "mode": "test" }),
            ))
        }
    }

    fn broadcast(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
        let calls = Arc::clone(&self.calls);
        let reject_broadcast = self.reject_broadcast;
        async move {
            calls.lock().unwrap().push("broadcast");
            if reject_broadcast {
                return Err(VerificationError::new("broadcast rejected"));
            }
            Ok(Receipt::success("mock", "broadcast_ref"))
        }
    }

    fn verify(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
        let calls = Arc::clone(&self.calls);
        async move {
            calls.lock().unwrap().push("verify");
            Err(VerificationError::new("legacy verify must stay inert"))
        }
    }
}

fn lifecycle_payment(
    reject_validation: bool,
) -> (Mpp<LifecycleMethod>, Arc<Mutex<Vec<&'static str>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    (
        Mpp::new(
            LifecycleMethod {
                calls: Arc::clone(&calls),
                reject_broadcast: false,
                reject_validation,
            },
            "api.example.com",
            TEST_SECRET,
        ),
        calls,
    )
}

fn lifecycle_payment_rejecting_broadcast() -> (Mpp<LifecycleMethod>, Arc<Mutex<Vec<&'static str>>>)
{
    let calls = Arc::new(Mutex::new(Vec::new()));
    (
        Mpp::new(
            LifecycleMethod {
                calls: Arc::clone(&calls),
                reject_broadcast: true,
                reject_validation: false,
            },
            "api.example.com",
            TEST_SECRET,
        ),
        calls,
    )
}

#[derive(Clone)]
struct LegacyLifecycleMethod {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl ChargeMethod for LegacyLifecycleMethod {
    fn method(&self) -> &str {
        "mock"
    }

    fn verify(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
        let calls = Arc::clone(&self.calls);
        async move {
            calls.lock().unwrap().push("verify");
            Ok(Receipt::success("mock", "legacy_ref"))
        }
    }
}

#[tokio::test]
async fn validate_credential_is_non_mutating() {
    let (payment, calls) = lifecycle_payment(false);
    let credential = test_credential_with_body_digest(TEST_SECRET, b"body");

    let validation = payment
        .validate_credential_with_body(&credential, b"body")
        .await
        .unwrap();

    assert_eq!(validation.details, serde_json::json!({ "mode": "test" }));
    assert_eq!(*calls.lock().unwrap(), ["validate"]);
}

#[tokio::test]
async fn every_validation_entry_point_only_validates() {
    #[derive(Clone, Copy, Debug)]
    enum EntryPoint {
        ValidateCredential,
        ValidateCredentialWithBody,
        ValidateCredentialWithExpectedRequest,
        ValidateCredentialWithExpectedRequestAndBody,
        Validate,
    }

    let entry_points = [
        EntryPoint::ValidateCredential,
        EntryPoint::ValidateCredentialWithBody,
        EntryPoint::ValidateCredentialWithExpectedRequest,
        EntryPoint::ValidateCredentialWithExpectedRequestAndBody,
        EntryPoint::Validate,
    ];

    for entry_point in entry_points {
        let (payment, calls) = lifecycle_payment(false);
        let uses_body = matches!(
            entry_point,
            EntryPoint::ValidateCredentialWithBody
                | EntryPoint::ValidateCredentialWithExpectedRequestAndBody
        );
        let credential =
            test_lifecycle_credential(TEST_SECRET, uses_body.then_some(b"body".as_slice()));
        let expected = test_request();

        let validation = match entry_point {
            EntryPoint::ValidateCredential => payment.validate_credential(&credential).await,
            EntryPoint::ValidateCredentialWithBody => {
                payment
                    .validate_credential_with_body(&credential, b"body")
                    .await
            }
            EntryPoint::ValidateCredentialWithExpectedRequest => {
                payment
                    .validate_credential_with_expected_request(&credential, &expected)
                    .await
            }
            EntryPoint::ValidateCredentialWithExpectedRequestAndBody => {
                payment
                    .validate_credential_with_expected_request_and_body(
                        &credential,
                        &expected,
                        b"body",
                    )
                    .await
            }
            EntryPoint::Validate => payment.validate(&credential, &expected).await,
        }
        .unwrap_or_else(|error| panic!("{entry_point:?} failed: {error}"));

        assert_eq!(
            validation.details,
            serde_json::json!({ "mode": "test" }),
            "{entry_point:?}"
        );
        assert_eq!(*calls.lock().unwrap(), ["validate"], "{entry_point:?}");
    }
}

#[tokio::test]
async fn broadcast_credential_validates_then_broadcasts_without_legacy_verify() {
    let (payment, calls) = lifecycle_payment(false);
    let credential = test_credential_with_body_digest(TEST_SECRET, b"body");

    let receipt = payment
        .broadcast_credential_with_body(&credential, b"body")
        .await
        .unwrap();

    assert_eq!(receipt.reference, "broadcast_ref");
    assert_eq!(*calls.lock().unwrap(), ["validate", "broadcast"]);
}

#[tokio::test]
async fn verify_credential_is_broadcast_compatibility_alias() {
    let (payment, calls) = lifecycle_payment(false);
    let credential = test_credential_with_body_digest(TEST_SECRET, b"body");

    let receipt = payment
        .verify_credential_with_body(&credential, b"body")
        .await
        .unwrap();

    assert_eq!(receipt.reference, "broadcast_ref");
    assert_eq!(*calls.lock().unwrap(), ["validate", "broadcast"]);
}

#[tokio::test]
async fn broadcast_credential_stops_when_validation_fails() {
    let (payment, calls) = lifecycle_payment(true);
    let credential = test_credential_with_body_digest(TEST_SECRET, b"body");

    let error = payment
        .broadcast_credential_with_body(&credential, b"body")
        .await
        .unwrap_err();

    assert_eq!(error.message, "validation rejected");
    assert_eq!(*calls.lock().unwrap(), ["validate"]);
}

#[tokio::test]
async fn every_broadcast_and_verify_entry_point_validates_before_broadcast() {
    #[derive(Clone, Copy, Debug)]
    enum EntryPoint {
        BroadcastCredential,
        BroadcastCredentialWithBody,
        BroadcastCredentialWithExpectedRequest,
        BroadcastCredentialWithExpectedRequestAndBody,
        VerifyCredential,
        VerifyCredentialWithBody,
        VerifyCredentialWithExpectedRequest,
        VerifyCredentialWithExpectedRequestAndBody,
        Broadcast,
        Verify,
    }

    let entry_points = [
        EntryPoint::BroadcastCredential,
        EntryPoint::BroadcastCredentialWithBody,
        EntryPoint::BroadcastCredentialWithExpectedRequest,
        EntryPoint::BroadcastCredentialWithExpectedRequestAndBody,
        EntryPoint::VerifyCredential,
        EntryPoint::VerifyCredentialWithBody,
        EntryPoint::VerifyCredentialWithExpectedRequest,
        EntryPoint::VerifyCredentialWithExpectedRequestAndBody,
        EntryPoint::Broadcast,
        EntryPoint::Verify,
    ];

    for entry_point in entry_points {
        let (payment, calls) = lifecycle_payment(false);
        let uses_body = matches!(
            entry_point,
            EntryPoint::BroadcastCredentialWithBody
                | EntryPoint::BroadcastCredentialWithExpectedRequestAndBody
                | EntryPoint::VerifyCredentialWithBody
                | EntryPoint::VerifyCredentialWithExpectedRequestAndBody
        );
        let credential =
            test_lifecycle_credential(TEST_SECRET, uses_body.then_some(b"body".as_slice()));
        let expected = test_request();

        let receipt = match entry_point {
            EntryPoint::BroadcastCredential => payment.broadcast_credential(&credential).await,
            EntryPoint::BroadcastCredentialWithBody => {
                payment
                    .broadcast_credential_with_body(&credential, b"body")
                    .await
            }
            EntryPoint::BroadcastCredentialWithExpectedRequest => {
                payment
                    .broadcast_credential_with_expected_request(&credential, &expected)
                    .await
            }
            EntryPoint::BroadcastCredentialWithExpectedRequestAndBody => {
                payment
                    .broadcast_credential_with_expected_request_and_body(
                        &credential,
                        &expected,
                        b"body",
                    )
                    .await
            }
            EntryPoint::VerifyCredential => payment.verify_credential(&credential).await,
            EntryPoint::VerifyCredentialWithBody => {
                payment
                    .verify_credential_with_body(&credential, b"body")
                    .await
            }
            EntryPoint::VerifyCredentialWithExpectedRequest => {
                payment
                    .verify_credential_with_expected_request(&credential, &expected)
                    .await
            }
            EntryPoint::VerifyCredentialWithExpectedRequestAndBody => {
                payment
                    .verify_credential_with_expected_request_and_body(
                        &credential,
                        &expected,
                        b"body",
                    )
                    .await
            }
            EntryPoint::Broadcast => payment.broadcast(&credential, &expected).await,
            EntryPoint::Verify => payment.verify(&credential, &expected).await,
        }
        .unwrap_or_else(|error| panic!("{entry_point:?} failed: {error}"));

        assert_eq!(receipt.reference, "broadcast_ref", "{entry_point:?}");
        assert_eq!(
            *calls.lock().unwrap(),
            ["validate", "broadcast"],
            "{entry_point:?}"
        );
    }
}

#[tokio::test]
async fn broadcast_reports_terminal_failure_after_validation() {
    let (payment, calls) = lifecycle_payment_rejecting_broadcast();
    let credential = test_lifecycle_credential(TEST_SECRET, None);

    let error = payment.broadcast_credential(&credential).await.unwrap_err();

    assert_eq!(error.message, "broadcast rejected");
    assert_eq!(*calls.lock().unwrap(), ["validate", "broadcast"]);
}

#[tokio::test]
async fn failed_validation_or_broadcast_never_emits_payment_success() {
    for reject_validation in [true, false] {
        let (payment, _) = if reject_validation {
            lifecycle_payment(true)
        } else {
            lifecycle_payment_rejecting_broadcast()
        };
        let success_count = Arc::new(AtomicUsize::new(0));
        let _subscription = payment.on_payment_success({
            let success_count = Arc::clone(&success_count);
            move |_| {
                let success_count = Arc::clone(&success_count);
                async move {
                    success_count.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        let credential = test_lifecycle_credential(TEST_SECRET, None);

        assert!(payment.broadcast_credential(&credential).await.is_err());
        assert_eq!(success_count.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn broadcast_prechecks_run_before_method_validation() {
    let cases = ["invalid-hmac", "body-mismatch", "route-mismatch"];

    for case in cases {
        let (payment, calls) = lifecycle_payment(false);
        let mut credential = test_lifecycle_credential(TEST_SECRET, Some(b"body"));
        let result = match case {
            "invalid-hmac" => {
                credential.challenge.id = "invalid".into();
                payment
                    .broadcast_credential_with_body(&credential, b"body")
                    .await
            }
            "body-mismatch" => {
                payment
                    .broadcast_credential_with_body(&credential, b"different")
                    .await
            }
            "route-mismatch" => {
                let mut expected = test_request();
                expected.amount = "9999".into();
                payment
                    .broadcast_credential_with_expected_request_and_body(
                        &credential,
                        &expected,
                        b"body",
                    )
                    .await
            }
            _ => unreachable!(),
        };

        assert!(result.is_err(), "{case}");
        assert!(calls.lock().unwrap().is_empty(), "{case}");
    }
}

#[tokio::test]
async fn legacy_broadcast_falls_back_to_verify_without_validation() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payment = Mpp::new(
        LegacyLifecycleMethod {
            calls: Arc::clone(&calls),
        },
        "api.example.com",
        TEST_SECRET,
    );
    let credential = test_lifecycle_credential(TEST_SECRET, None);

    let receipt = payment.broadcast_credential(&credential).await.unwrap();

    assert_eq!(receipt.reference, "legacy_ref");
    assert_eq!(*calls.lock().unwrap(), ["verify"]);
}

#[tokio::test]
async fn validation_only_api_rejects_legacy_method_without_verifying() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let payment = Mpp::new(
        LegacyLifecycleMethod {
            calls: Arc::clone(&calls),
        },
        "api.example.com",
        TEST_SECRET,
    );
    let credential = test_lifecycle_credential(TEST_SECRET, None);

    let error = payment.validate_credential(&credential).await.unwrap_err();

    assert!(error.message.contains("does not support non-mutating"));
    assert!(calls.lock().unwrap().is_empty());
}
