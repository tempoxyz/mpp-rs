use super::*;

#[cfg(feature = "tempo")]
fn session_opaque_credential(
    mpp: &Mpp<TempoSuccessMethod, MockSessionMethod>,
    opaque: Option<Base64UrlJson>,
) -> PaymentCredential {
    let mut echo = mpp
        .session_challenge(
            "1000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap()
        .to_echo();
    echo.opaque = opaque;
    echo.id = crate::protocol::core::compute_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "tempo",
        "session",
        echo.request.raw(),
        echo.expires.as_deref(),
        echo.digest.as_deref(),
        echo.opaque.as_ref().map(|o| o.raw()),
    );
    let payload_json = serde_json::json!({
        "action": "open",
        "type": "transaction",
        "channelId": "0xabc",
        "transaction": "0x1234",
        "cumulativeAmount": "5000",
        "signature": "0xdef"
    });
    PaymentCredential::new(echo, payload_json)
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_session_pinned_opaque_match_accepted() {
    let mpp = create_session_test_mpp().with_opaque(route_opaque());
    let credential = session_opaque_credential(&mpp, Some(route_opaque()));

    assert!(mpp.verify_session(&credential).await.is_ok());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_session_pinned_opaque_mismatch_rejected() {
    let mpp = create_session_test_mpp().with_opaque(route_opaque());
    let other = Base64UrlJson::from_value(&serde_json::json!({"route": "b"})).unwrap();
    let credential = session_opaque_credential(&mpp, Some(other));

    let err = mpp.verify_session(&credential).await.unwrap_err();
    assert!(err.message.contains("opaque"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_session_pinned_opaque_absent_rejected() {
    let mpp = create_session_test_mpp().with_opaque(route_opaque());
    let credential = session_opaque_credential(&mpp, None);

    let err = mpp.verify_session(&credential).await.unwrap_err();
    assert!(err.message.contains("opaque"));
}

// ── Mock SessionMethod for session verification tests ─────────────

#[derive(Clone)]
struct MockSessionMethod {
    receipt: Receipt,
    management_response: Option<serde_json::Value>,
}

impl MockSessionMethod {
    fn success() -> Self {
        Self {
            receipt: Receipt::success("tempo", "0xsession_ref"),
            management_response: None,
        }
    }

    fn with_management_response(mut self, resp: serde_json::Value) -> Self {
        self.management_response = Some(resp);
        self
    }
}

impl crate::protocol::traits::SessionMethod for MockSessionMethod {
    fn method(&self) -> &str {
        "tempo"
    }

    fn verify_session(
        &self,
        _credential: &PaymentCredential,
        _request: &crate::protocol::intents::SessionRequest,
    ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
        let receipt = self.receipt.clone();
        async move { Ok(receipt) }
    }

    fn respond(
        &self,
        _credential: &PaymentCredential,
        _receipt: &Receipt,
    ) -> Option<serde_json::Value> {
        self.management_response.clone()
    }
}

// ── Mock SessionMethod that always returns an error ─────────────────

#[derive(Clone)]
struct MockFailingSessionMethod {
    error: VerificationError,
}

impl MockFailingSessionMethod {
    fn with_error(code: ErrorCode, message: &str) -> Self {
        Self {
            error: VerificationError::with_code(message, code),
        }
    }
}

impl crate::protocol::traits::SessionMethod for MockFailingSessionMethod {
    fn method(&self) -> &str {
        "tempo"
    }

    fn verify_session(
        &self,
        _credential: &PaymentCredential,
        _request: &crate::protocol::intents::SessionRequest,
    ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
        let error = self.error.clone();
        async move { Err(error) }
    }

    fn respond(
        &self,
        _credential: &PaymentCredential,
        _receipt: &Receipt,
    ) -> Option<serde_json::Value> {
        None
    }
}

#[cfg(feature = "tempo")]
fn create_session_test_mpp() -> Mpp<TempoSuccessMethod, MockSessionMethod> {
    Mpp {
        method: TempoSuccessMethod,
        session_method: Some(MockSessionMethod::success()),
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
fn make_session_credential(
    mpp: &Mpp<TempoSuccessMethod, MockSessionMethod>,
    payload: serde_json::Value,
) -> PaymentCredential {
    let challenge = mpp
        .session_challenge(
            "1000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();
    PaymentCredential::new(challenge.to_echo(), payload)
}

#[cfg(feature = "tempo")]
#[test]
fn test_session_challenge_roundtrip() {
    let mpp = create_session_test_mpp();
    let challenge = mpp
        .session_challenge(
            "1000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();
    assert_eq!(challenge.method.as_str(), "tempo");
    assert_eq!(challenge.intent.as_str(), "session");
    assert!(!challenge.id.is_empty());
    assert!(
        challenge.expires.is_some(),
        "session challenge should have default expires"
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_session_happy_path() {
    let mpp = create_session_test_mpp();
    let credential = make_session_credential(
        &mpp,
        serde_json::json!({
            "action": "voucher",
            "channelId": "0xabc",
            "cumulativeAmount": "5000",
            "signature": "0xdef"
        }),
    );

    let result = mpp.verify_session(&credential).await;
    assert!(result.is_ok());
    let session_result = result.unwrap();
    assert!(session_result.receipt.is_success());
    assert_eq!(session_result.receipt.reference, "0xsession_ref");
    assert!(session_result.management_response.is_none());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_session_management_response() {
    let mock_session = MockSessionMethod::success()
        .with_management_response(serde_json::json!({"status": "ok", "channelId": "0xabc"}));
    let mpp: Mpp<TempoSuccessMethod, MockSessionMethod> = Mpp {
        method: TempoSuccessMethod,
        session_method: Some(mock_session),
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
    };

    let challenge = mpp
        .session_challenge(
            "1000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

    let echo = challenge.to_echo();
    let payload_json = serde_json::json!({
        "action": "open",
        "type": "transaction",
        "channelId": "0xabc",
        "transaction": "0x1234",
        "cumulativeAmount": "5000",
        "signature": "0xdef"
    });
    let credential = PaymentCredential::new(echo, payload_json);

    let result = mpp.verify_session(&credential).await;
    assert!(result.is_ok());
    let session_result = result.unwrap();
    assert!(session_result.management_response.is_some());
    let mgmt = session_result.management_response.unwrap();
    assert_eq!(mgmt["channelId"], "0xabc");
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_session_no_session_method() {
    let mpp: Mpp<TempoSuccessMethod, MockSessionMethod> = Mpp {
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
    };

    let echo = ChallengeEcho {
        id: "test".into(),
        realm: "MPP Payment".into(),
        method: "tempo".into(),
        intent: "session".into(),
        request: Base64UrlJson::from_raw("eyJ0ZXN0IjoidmFsdWUifQ"),
        expires: None,
        description: None,
        digest: None,
        opaque: None,
        header: None,
    };
    let credential = PaymentCredential::new(echo, PaymentPayload::hash("0x123"));

    let result = mpp.verify_session(&credential).await;
    let err = result.unwrap_err();
    assert!(err.message.contains("No session method"));
    assert!(
        err.code.is_none(),
        "no-session-method should not have an error code"
    );
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_session_hmac_mismatch() {
    let mpp = create_session_test_mpp();
    let challenge = mpp
        .session_challenge(
            "1000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

    let mut echo = challenge.to_echo();
    let tampered = crate::protocol::intents::SessionRequest {
        amount: "999999".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        ..Default::default()
    };
    let encoded = Base64UrlJson::from_typed(&tampered).unwrap();
    echo.request = encoded;

    let payload_json = serde_json::json!({
        "action": "voucher",
        "channelId": "0xabc",
        "cumulativeAmount": "5000",
        "signature": "0xdef"
    });
    let credential = PaymentCredential::new(echo, payload_json);

    let result = mpp.verify_session(&credential).await;
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
}

#[cfg(feature = "tempo")]
#[test]
fn test_session_challenge_with_details() {
    let mpp = create_session_test_mpp();
    let challenge = mpp
        .session_challenge_with_details(
            "1000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            crate::server::SessionChallengeOptions {
                unit_type: Some("second"),
                suggested_deposit: Some("60000"),
                fee_payer: true,
                ..Default::default()
            },
        )
        .unwrap();

    assert_eq!(challenge.method.as_str(), "tempo");
    assert_eq!(challenge.intent.as_str(), "session");
    let request: crate::protocol::intents::SessionRequest = challenge.request.decode().unwrap();
    assert_eq!(request.amount, "1000");
    assert_eq!(request.unit_type.as_deref(), Some("second"));
    assert_eq!(request.suggested_deposit.as_deref(), Some("60000"));
}

/// A handler with fee sponsorship and machine tokens enabled for charges,
/// combined with the given session method.
#[cfg(feature = "tempo")]
fn sponsoring_machine_token_mpp<S>(
    session_method: S,
) -> Mpp<crate::protocol::methods::tempo::ChargeMethod<crate::server::TempoProvider>, S> {
    Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .chain_id(CHAIN_ID)
        .fee_payer(true)
        .fee_payer_signer(alloy::signers::local::PrivateKeySigner::random())
        .machine_token_enabled(true)
        .secret_key(TEST_SECRET),
    )
    .unwrap()
    .with_session_method(session_method)
}

#[cfg(feature = "tempo")]
fn session_challenge_details<M, S>(
    mpp: &Mpp<M, S>,
) -> crate::protocol::methods::tempo::session::TempoSessionMethodDetails
where
    M: ChargeMethod,
    S: crate::protocol::traits::SessionMethod,
{
    use crate::protocol::methods::tempo::session::TempoSessionExt;

    let challenge = mpp
        .session_challenge_with_details(
            "1000",
            DEFAULT_CURRENCY_MAINNET,
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            crate::server::SessionChallengeOptions {
                fee_payer: true,
                ..Default::default()
            },
        )
        .unwrap();
    let request: crate::protocol::intents::SessionRequest = challenge.request.decode().unwrap();
    request.tempo_session_details().unwrap()
}

/// The Tempo session method broadcasts client transactions as submitted and
/// has no machine-token open path, so its challenges must not advertise
/// either capability even when the handler enables them for charges.
#[cfg(feature = "tempo")]
#[test]
fn test_session_challenge_omits_unsupported_capabilities() {
    use crate::protocol::methods::tempo::session_method::{
        InMemoryChannelStore, SessionMethod, SessionMethodConfig,
    };

    let mpp = sponsoring_machine_token_mpp(SessionMethod::new(
        crate::server::tempo_provider("https://rpc.test.invalid").unwrap(),
        Arc::new(InMemoryChannelStore::new()),
        SessionMethodConfig {
            escrow_contract: Address::ZERO,
            chain_id: CHAIN_ID,
            min_voucher_delta: 0,
        },
    ));

    let details = session_challenge_details(&mpp);
    assert_eq!(details.chain_id, Some(CHAIN_ID));
    assert_eq!(details.fee_payer, None);
    assert_eq!(details.machine_token_enabled, None);
    assert_eq!(details.settlement_adapter, None);
    assert_eq!(details.settlement_recipient, None);
    assert_eq!(details.settlement_token, None);

    let charge: ChargeRequest = mpp.charge("1").unwrap().remove(0).request.decode().unwrap();
    assert!(charge.fee_payer());
    assert!(charge.machine_token_enabled());
}

/// Session methods that report support keep getting both advertised.
#[cfg(feature = "tempo")]
#[test]
fn test_session_challenge_advertises_supported_capabilities() {
    #[derive(Clone)]
    struct CapableSessionMethod;

    impl crate::protocol::traits::SessionMethod for CapableSessionMethod {
        fn method(&self) -> &str {
            "tempo"
        }

        fn verify_session(
            &self,
            _credential: &PaymentCredential,
            _request: &crate::protocol::intents::SessionRequest,
        ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
            std::future::ready(Err(VerificationError::new("unused")))
        }

        fn challenge_method_details(&self) -> Option<serde_json::Value> {
            Some(serde_json::json!({ "escrowContract": Address::ZERO }))
        }

        fn supports_fee_payer(&self) -> bool {
            true
        }

        fn supports_machine_tokens(&self) -> bool {
            true
        }
    }

    let details = session_challenge_details(&sponsoring_machine_token_mpp(CapableSessionMethod));
    assert_eq!(details.fee_payer, Some(true));
    assert_eq!(details.machine_token_enabled, Some(true));
    assert!(details.settlement_adapter.is_some());
    assert!(details.settlement_recipient.is_some());
    assert!(details.settlement_token.is_some());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_session_method_returns_error() {
    let mock_session = MockFailingSessionMethod::with_error(
        ErrorCode::InsufficientBalance,
        "channel balance exhausted",
    );
    let mpp: Mpp<TempoSuccessMethod, MockFailingSessionMethod> = Mpp {
        method: TempoSuccessMethod,
        session_method: Some(mock_session),
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
    };

    let challenge = mpp
        .session_challenge(
            "1000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();

    let echo = challenge.to_echo();
    let payload_json = serde_json::json!({
        "action": "voucher",
        "channelId": "0xabc",
        "cumulativeAmount": "5000",
        "signature": "0xdef"
    });
    let credential = PaymentCredential::new(echo, payload_json);

    let result = mpp.verify_session(&credential).await;
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InsufficientBalance));
    assert!(err.message.contains("channel balance exhausted"));
}

#[test]
fn test_session_verify_result_debug() {
    let result = SessionVerifyResult {
        receipt: Receipt::success("tempo", "0xref"),
        management_response: Some(serde_json::json!({"status": "ok"})),
    };
    let debug = format!("{:?}", result);
    assert!(debug.contains("0xref"));
    assert!(debug.contains("status"));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_verify_session_expired_challenge_rejected() {
    let mpp = create_session_test_mpp();

    let past = (time::OffsetDateTime::now_utc() - time::Duration::minutes(10))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();

    let challenge = mpp
        .session_challenge_with_details(
            "1000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            crate::server::SessionChallengeOptions {
                expires: Some(&past),
                ..Default::default()
            },
        )
        .unwrap();

    let echo = challenge.to_echo();
    let payload_json = serde_json::json!({
        "action": "voucher",
        "channelId": "0xabc",
        "cumulativeAmount": "5000",
        "signature": "0xdef"
    });
    let credential = PaymentCredential::new(echo, payload_json);

    let result = mpp.verify_session(&credential).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::Expired));
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_session_missing_expires_rejected() {
    let mpp = create_session_test_mpp();

    let request = crate::protocol::intents::SessionRequest {
        amount: "1000".into(),
        currency: "0x20c0000000000000000000000000000000000000".into(),
        recipient: Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".into()),
        ..Default::default()
    };
    let encoded = Base64UrlJson::from_typed(&request).unwrap();
    let id = crate::protocol::methods::tempo::generate_challenge_id(
        TEST_SECRET,
        "MPP Payment",
        "tempo",
        "session",
        encoded.raw(),
        None,
        None,
        None,
    );

    let echo = ChallengeEcho {
        id,
        realm: "MPP Payment".into(),
        method: "tempo".into(),
        intent: "session".into(),
        request: encoded,
        expires: None,
        description: None,
        digest: None,
        opaque: None,
        header: None,
    };
    let credential = PaymentCredential::new(
        echo,
        serde_json::json!({
            "action": "voucher",
            "channelId": "0xabc",
            "cumulativeAmount": "5000",
            "signature": "0xdef"
        }),
    );

    let result = mpp.verify_session(&credential).await;
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
async fn test_session_default_expires_accepted() {
    let mpp = create_session_test_mpp();

    let challenge = mpp
        .session_challenge(
            "1000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        )
        .unwrap();
    assert!(
        challenge.expires.is_some(),
        "session_challenge should set default expires"
    );

    let echo = challenge.to_echo();
    let credential = PaymentCredential::new(
        echo,
        serde_json::json!({
            "action": "voucher",
            "channelId": "0xabc",
            "cumulativeAmount": "5000",
            "signature": "0xdef"
        }),
    );

    let result = mpp.verify_session(&credential).await;
    assert!(
        result.is_ok(),
        "session with default expires should be accepted"
    );
}

#[cfg(feature = "tempo")]
#[test]
fn test_session_challenge_with_details_default_expires() {
    let mpp = create_session_test_mpp();

    let challenge = mpp
        .session_challenge_with_details(
            "1000",
            "0x20c0000000000000000000000000000000000000",
            "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            Default::default(),
        )
        .unwrap();
    assert!(
        challenge.expires.is_some(),
        "session_challenge_with_details with default options should set default expires"
    );
}

#[cfg(feature = "tempo")]
fn session_mpp_with(currencies: &[&str]) -> Mpp<TempoSuccessMethod, MockSessionMethod> {
    let mut mpp = create_session_test_mpp();
    mpp.currencies = currencies.iter().map(|c| c.to_string()).collect();
    mpp
}

#[cfg(feature = "tempo")]
fn session_voucher_credential(
    mpp: &Mpp<TempoSuccessMethod, MockSessionMethod>,
    currency: &str,
) -> PaymentCredential {
    let challenge = mpp
        .session_challenge("1000", currency, TEST_RECIPIENT)
        .unwrap();
    PaymentCredential::new(
        challenge.to_echo(),
        serde_json::json!({
            "action": "voucher",
            "channelId": "0xabc",
            "cumulativeAmount": "5000",
            "signature": "0xdef"
        }),
    )
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_session_accepts_every_offered_currency_including_existing_channels() {
    use crate::protocol::methods::tempo::{OUSD, PATH_USD, USDC};

    let mpp = session_mpp_with(&[OUSD, USDC]);
    // New OUSD sessions and channels opened in the legacy default (USDC.e)
    // both verify; matching is case-insensitive as before.
    for currency in [OUSD.to_string(), USDC.to_string(), USDC.to_lowercase()] {
        let credential = session_voucher_credential(&mpp, &currency);
        let result = mpp.verify_session(&credential).await;
        assert!(result.is_ok(), "{currency}: {:?}", result.err());
    }

    let credential = session_voucher_credential(&mpp, PATH_USD);
    let err = mpp.verify_session(&credential).await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(err.message.contains("Currency mismatch"), "{}", err.message);
    assert!(
        err.message.contains(OUSD) && err.message.contains(USDC),
        "{}",
        err.message
    );
}
