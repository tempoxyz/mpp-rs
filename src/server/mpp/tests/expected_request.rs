use super::*;

#[derive(Clone, Copy)]
enum Binding {
    MerchantAccount,
    Accept,
    Reject,
}

#[derive(Clone)]
struct BindingMethod {
    calls: Arc<Mutex<Vec<&'static str>>>,
    binding: Binding,
    split: bool,
}

impl ChargeMethod for BindingMethod {
    fn method(&self) -> &str {
        "mock"
    }

    fn prepare_request(&self, _: ChargeRequest, _: Option<&PaymentCredential>) -> ChargeRequest {
        panic!("expected-request comparison must not prepare requests")
    }

    fn validate_expected_request(
        &self,
        request: &ChargeRequest,
        expected: &ChargeRequest,
    ) -> std::result::Result<(), VerificationError> {
        self.calls.lock().unwrap().push("binding");
        match self.binding {
            Binding::Accept => Ok(()),
            Binding::Reject => {
                Err(VerificationError::internal("method binding rejected").retryable())
            }
            Binding::MerchantAccount => {
                fn account(request: &ChargeRequest) -> Option<&str> {
                    request
                        .method_details
                        .as_ref()?
                        .get("merchantAccount")?
                        .as_str()
                }
                if account(request).is_none() || account(request) != account(expected) {
                    return Err(VerificationError::invalid_challenge(
                        "Merchant account mismatch",
                    ));
                }
                Ok(())
            }
        }
    }

    fn supports_validation(&self) -> bool {
        self.split
    }

    async fn validate(
        &self,
        credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> std::result::Result<ChargeValidation, VerificationError> {
        self.calls.lock().unwrap().push("validate");
        Ok(ChargeValidation::new(
            credential,
            request,
            serde_json::Value::Null,
        ))
    }

    async fn broadcast(
        &self,
        _: &PaymentCredential,
        _: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        self.calls.lock().unwrap().push("broadcast");
        Ok(Receipt::success("mock", "broadcast_ref"))
    }

    async fn verify(
        &self,
        _: &PaymentCredential,
        _: &ChargeRequest,
    ) -> std::result::Result<Receipt, VerificationError> {
        panic!("split lifecycle must not call legacy verify")
    }
}

fn payment(binding: Binding, split: bool) -> (Mpp<BindingMethod>, Arc<Mutex<Vec<&'static str>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    (
        Mpp::new(
            BindingMethod {
                calls: Arc::clone(&calls),
                binding,
                split,
            },
            "api.example.com",
            TEST_SECRET,
        ),
        calls,
    )
}

fn request() -> ChargeRequest {
    ChargeRequest {
        method_details: Some(serde_json::json!({
            "merchantAccount": "merchant-a", "quote": "issued-quote"
        })),
        ..test_request()
    }
}

fn sign(credential: &mut PaymentCredential) {
    let challenge = &mut credential.challenge;
    challenge.id = crate::protocol::core::compute_challenge_id_with_header(
        TEST_SECRET,
        "api.example.com",
        challenge.method.as_str(),
        challenge.intent.as_str(),
        challenge.request.raw(),
        challenge.expires.as_deref(),
        challenge.digest.as_deref(),
        challenge.opaque.as_ref().map(|value| value.raw()),
        challenge.header.as_deref(),
    );
}

fn credential(request: &ChargeRequest, body: Option<&[u8]>) -> PaymentCredential {
    let mut credential = test_lifecycle_credential(TEST_SECRET, body);
    credential.challenge.request = Base64UrlJson::from_typed(request).unwrap();
    sign(&mut credential);
    credential
}

#[derive(Clone, Copy, Debug)]
enum EntryPoint {
    Validate,
    ValidateBody,
    Broadcast,
    BroadcastBody,
    Verify,
    VerifyBody,
}

impl EntryPoint {
    const ALL: [Self; 6] = [
        Self::Validate,
        Self::ValidateBody,
        Self::Broadcast,
        Self::BroadcastBody,
        Self::Verify,
        Self::VerifyBody,
    ];

    fn uses_body(self) -> bool {
        matches!(
            self,
            Self::ValidateBody | Self::BroadcastBody | Self::VerifyBody
        )
    }

    fn validates_only(self) -> bool {
        matches!(self, Self::Validate | Self::ValidateBody)
    }

    async fn run<M: ChargeMethod>(
        self,
        payment: &Mpp<M>,
        credential: &PaymentCredential,
        expected: &ChargeRequest,
        body: &[u8],
    ) -> std::result::Result<(), VerificationError> {
        match self {
            Self::Validate => payment
                .validate_credential_with_expected_request(credential, expected)
                .await
                .map(|_| ()),
            Self::ValidateBody => payment
                .validate_credential_with_expected_request_and_body(credential, expected, body)
                .await
                .map(|_| ()),
            Self::Broadcast => payment
                .broadcast_credential_with_expected_request(credential, expected)
                .await
                .map(|_| ()),
            Self::BroadcastBody => payment
                .broadcast_credential_with_expected_request_and_body(credential, expected, body)
                .await
                .map(|_| ()),
            Self::Verify => payment
                .verify_credential_with_expected_request(credential, expected)
                .await
                .map(|_| ()),
            Self::VerifyBody => payment
                .verify_credential_with_expected_request_and_body(credential, expected, body)
                .await
                .map(|_| ()),
        }
    }
}

#[tokio::test]
async fn selected_binding_allows_volatile_fields_and_runs_before_method_operations() {
    for entry in EntryPoint::ALL {
        for split in [false, true] {
            let (payment, calls) = payment(Binding::MerchantAccount, split);
            let request = request();
            let credential = credential(&request, entry.uses_body().then_some(b"body"));
            let expected = ChargeRequest {
                method_details: Some(serde_json::json!({
                    "merchantAccount": "merchant-a", "quote": "new-quote"
                })),
                description: Some("new description".into()),
                ..request
            };
            entry
                .run(&payment, &credential, &expected, b"body")
                .await
                .unwrap();
            let expected_calls: &[&str] = if entry.validates_only() {
                &["binding", "validate"]
            } else if split {
                &["binding", "validate", "broadcast"]
            } else {
                &["binding", "broadcast"]
            };
            assert_eq!(
                *calls.lock().unwrap(),
                expected_calls,
                "{entry:?}, split={split}"
            );
        }
    }
}

#[tokio::test]
async fn selected_binding_rejects_different_or_missing_accounts_before_method_operations() {
    for entry in EntryPoint::ALL {
        for (actual, expected) in [
            (Some("merchant-a"), Some("merchant-b")),
            (None, Some("merchant-a")),
            (Some("merchant-a"), None),
            (None, None),
        ] {
            let (payment, calls) = payment(Binding::MerchantAccount, true);
            let request = ChargeRequest {
                method_details: actual
                    .map(|account| serde_json::json!({"merchantAccount": account})),
                ..test_request()
            };
            let expected = ChargeRequest {
                method_details: expected
                    .map(|account| serde_json::json!({"merchantAccount": account})),
                ..request.clone()
            };
            let credential = credential(&request, entry.uses_body().then_some(b"body"));
            let error = entry
                .run(&payment, &credential, &expected, b"body")
                .await
                .unwrap_err();
            assert_eq!(error.code, Some(ErrorCode::InvalidChallenge));
            assert_eq!(error.message, "Merchant account mismatch");
            assert_eq!(*calls.lock().unwrap(), ["binding"], "{entry:?}");
        }
    }
}

#[tokio::test]
async fn binding_errors_preserve_code_message_and_retryability() {
    for entry in EntryPoint::ALL {
        let (payment, calls) = payment(Binding::Reject, true);
        let request = request();
        let credential = credential(&request, entry.uses_body().then_some(b"body"));
        let error = entry
            .run(&payment, &credential, &request, b"body")
            .await
            .unwrap_err();
        assert_eq!(error.code, Some(ErrorCode::Internal));
        assert_eq!(error.message, "method binding rejected");
        assert!(error.retryable);
        assert_eq!(*calls.lock().unwrap(), ["binding"], "{entry:?}");
    }
}

#[tokio::test]
async fn core_comparisons_cannot_be_overridden_by_a_permissive_binding() {
    for entry in EntryPoint::ALL {
        for field in ["amount", "currency", "recipient", "scope", "externalId"] {
            let (payment, calls) = payment(Binding::Accept, true);
            let request = request();
            let credential = credential(&request, entry.uses_body().then_some(b"body"));
            let mut expected = request.clone();
            match field {
                "amount" => expected.amount = "2000".into(),
                "currency" => expected.currency = "other-currency".into(),
                "recipient" => expected.recipient = None,
                "scope" => expected.mppx_scope = Some(serde_json::json!({"route": "/other"})),
                "externalId" => expected.external_id = Some("other-order".into()),
                _ => unreachable!(),
            }
            let error = entry
                .run(&payment, &credential, &expected, b"body")
                .await
                .unwrap_err();
            assert_eq!(
                error.code,
                Some(ErrorCode::InvalidChallenge),
                "{entry:?}, {field}"
            );
            assert!(calls.lock().unwrap().is_empty(), "{entry:?}, {field}");
        }
    }
}

#[tokio::test]
async fn accepting_binding_cannot_bypass_credential_guards() {
    for entry in EntryPoint::ALL {
        for guard in [
            "signature",
            "expired",
            "missing-expiry",
            "method",
            "intent",
            "realm",
            "opaque",
            "digest",
        ] {
            let (payment, calls) = payment(Binding::Accept, true);
            let request = request();
            let mut credential = credential(&request, entry.uses_body().then_some(b"body"));
            match guard {
                "signature" => credential.challenge.id = "invalid-id".into(),
                "expired" => {
                    credential.challenge.expires = Some(
                        (time::OffsetDateTime::now_utc() - time::Duration::minutes(1))
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap(),
                    );
                    sign(&mut credential);
                }
                "missing-expiry" => {
                    credential.challenge.expires = None;
                    sign(&mut credential);
                }
                "method" => {
                    credential.challenge.method = "other".into();
                    sign(&mut credential);
                }
                "intent" => {
                    credential.challenge.intent = "session".into();
                    sign(&mut credential);
                }
                "realm" => {
                    credential.challenge.realm = "other.example.com".into();
                    sign(&mut credential);
                }
                "opaque" => {
                    credential.challenge.opaque = Some(
                        Base64UrlJson::from_value(&serde_json::json!({"route": "other"})).unwrap(),
                    );
                    sign(&mut credential);
                }
                "digest" => {
                    credential.challenge.digest =
                        Some(crate::body_digest::compute(b"different body"));
                    sign(&mut credential);
                }
                _ => unreachable!(),
            }
            let error = entry
                .run(&payment, &credential, &request, b"body")
                .await
                .unwrap_err();
            let expected_code = if guard == "expired" {
                ErrorCode::Expired
            } else {
                ErrorCode::InvalidChallenge
            };
            assert_eq!(error.code, Some(expected_code), "{entry:?}, {guard}");
            assert_eq!(*calls.lock().unwrap(), ["binding"], "{entry:?}, {guard}");
        }
    }
}

#[tokio::test]
#[allow(deprecated)]
async fn unbound_apis_do_not_call_the_expected_request_hook() {
    for entry in 0..9 {
        let (payment, calls) = payment(Binding::Reject, true);
        let request = request();
        let uses_body = matches!(entry, 1 | 3 | 5);
        let credential = credential(&request, uses_body.then_some(b"body"));
        match entry {
            0 => payment.validate_credential(&credential).await.map(|_| ()),
            1 => payment
                .validate_credential_with_body(&credential, b"body")
                .await
                .map(|_| ()),
            2 => payment.broadcast_credential(&credential).await.map(|_| ()),
            3 => payment
                .broadcast_credential_with_body(&credential, b"body")
                .await
                .map(|_| ()),
            4 => payment.verify_credential(&credential).await.map(|_| ()),
            5 => payment
                .verify_credential_with_body(&credential, b"body")
                .await
                .map(|_| ()),
            6 => payment.validate(&credential, &request).await.map(|_| ()),
            7 => payment.broadcast(&credential, &request).await.map(|_| ()),
            8 => payment.verify(&credential, &request).await.map(|_| ()),
            _ => unreachable!(),
        }
        .unwrap();
        let expected_calls: &[&str] = if matches!(entry, 0 | 1 | 6) {
            &["validate"]
        } else {
            &["validate", "broadcast"]
        };
        assert_eq!(*calls.lock().unwrap(), expected_calls, "entry={entry}");
    }
}

#[tokio::test]
async fn legacy_binding_hook_runs_before_default_broadcast_delegates_to_verify() {
    #[derive(Clone)]
    struct LegacyBindingMethod {
        calls: Arc<Mutex<Vec<&'static str>>>,
        reject_binding: bool,
    }

    impl ChargeMethod for LegacyBindingMethod {
        fn method(&self) -> &str {
            "mock"
        }

        fn validate_expected_request(
            &self,
            _: &ChargeRequest,
            _: &ChargeRequest,
        ) -> std::result::Result<(), VerificationError> {
            self.calls.lock().unwrap().push("binding");
            if self.reject_binding {
                return Err(VerificationError::invalid_challenge(
                    "legacy binding rejected",
                ));
            }
            Ok(())
        }

        async fn verify(
            &self,
            _: &PaymentCredential,
            _: &ChargeRequest,
        ) -> std::result::Result<Receipt, VerificationError> {
            self.calls.lock().unwrap().push("verify");
            Ok(Receipt::success("mock", "legacy_ref"))
        }
    }

    for entry in EntryPoint::ALL
        .into_iter()
        .filter(|entry| !entry.validates_only())
    {
        for reject_binding in [false, true] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let payment = Mpp::new(
                LegacyBindingMethod {
                    calls: Arc::clone(&calls),
                    reject_binding,
                },
                "api.example.com",
                TEST_SECRET,
            );
            assert!(!payment.method.supports_validation());
            let request = request();
            let credential = credential(&request, entry.uses_body().then_some(b"body"));
            let result = entry.run(&payment, &credential, &request, b"body").await;
            if reject_binding {
                let error = result.unwrap_err();
                assert_eq!(error.code, Some(ErrorCode::InvalidChallenge));
                assert_eq!(error.message, "legacy binding rejected");
                assert_eq!(*calls.lock().unwrap(), ["binding"], "{entry:?}");
            } else {
                result.unwrap();
                assert_eq!(*calls.lock().unwrap(), ["binding", "verify"], "{entry:?}");
            }
        }
    }
}

#[tokio::test]
async fn legacy_method_without_binding_override_keeps_accepting_additional_fields() {
    for entry in EntryPoint::ALL {
        let seen_request = Arc::new(Mutex::new(None));
        let payment = Mpp::new(
            RecordingMethod {
                seen_request: Arc::clone(&seen_request),
            },
            "api.example.com",
            TEST_SECRET,
        );
        let request = request();
        let expected = ChargeRequest {
            method_details: None,
            ..request.clone()
        };
        let credential = credential(&request, entry.uses_body().then_some(b"body"));
        let result = entry.run(&payment, &credential, &expected, b"body").await;
        if entry.validates_only() {
            assert!(result
                .unwrap_err()
                .message
                .contains("does not support non-mutating"));
            assert!(seen_request.lock().unwrap().is_none());
        } else {
            result.unwrap();
            assert_eq!(
                seen_request
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .method_details,
                request.method_details
            );
        }
    }
}
