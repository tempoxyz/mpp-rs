use super::*;

#[cfg(feature = "tempo")]
#[test]
fn test_mpp_create() {
    let mpp = create_test_mpp();
    assert_eq!(mpp.realm(), "localhost");
    assert_eq!(mpp.currency(), Some(crate::protocol::methods::tempo::OUSD));
    assert_eq!(mpp.chain_id(), Some(CHAIN_ID));
    assert_eq!(
        mpp.recipient(),
        Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2")
    );
    assert_eq!(mpp.decimals(), 6);
}

#[test]
fn test_realm_detection_ignores_host_and_hostname() {
    let env = |vars: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    };

    assert_eq!(
        realm_from_env(env(&[
            ("HOST", "0.0.0.0"),
            ("HOSTNAME", "pod-7f9c5d-abcde")
        ])),
        DEFAULT_REALM
    );
    assert_eq!(
        realm_from_env(env(&[
            ("HOSTNAME", "pod-7f9c5d-abcde"),
            ("VERCEL_URL", "app.vercel.app"),
        ])),
        "app.vercel.app"
    );
    assert_eq!(
        realm_from_env(env(&[("MPP_REALM", ""), ("FLY_APP_NAME", "my-app")])),
        "my-app"
    );
}

#[cfg(feature = "tempo")]
#[test]
fn test_default_fee_payer_charges_offer_ousd_first() {
    use crate::protocol::methods::tempo::OUSD;

    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .chain_id(CHAIN_ID)
        .fee_payer(true)
        .fee_payer_signer(fee_payer_signer)
        .secret_key(TEST_SECRET),
    )
    .unwrap();

    let challenge = mpp.charge("1").unwrap().remove(0);
    let request: ChargeRequest = challenge.request.decode().unwrap();
    assert!(mpp.fee_payer());
    assert!(request.fee_payer());
    assert_eq!(request.chain_id(), Some(CHAIN_ID));
    // Sponsorship no longer restricts the charge currency: the fee token is
    // chosen independently from the fee-token allowlist when co-signing.
    assert_eq!(request.currency, OUSD);
    assert!(!FeePayerPolicy::default_allows_fee_token(
        CHAIN_ID,
        request.currency_address().unwrap()
    ));
    assert!(FeePayerPolicy::default_allows_fee_token(
        CHAIN_ID,
        DEFAULT_CURRENCY_MAINNET.parse().unwrap()
    ));
}

#[cfg(feature = "tempo")]
#[test]
fn test_unknown_chain_fee_payer_charge_uses_allowlisted_local_currency() {
    let chain_id = 31337;
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .chain_id(chain_id)
        .fee_payer(true)
        .fee_payer_signer(fee_payer_signer)
        .secret_key(TEST_SECRET),
    )
    .unwrap();

    let challenge = mpp.charge("1").unwrap().remove(0);
    let request: ChargeRequest = challenge.request.decode().unwrap();
    assert!(request.fee_payer());
    assert_eq!(request.chain_id(), Some(chain_id));
    assert_eq!(request.currency, DEFAULT_CURRENCY_TESTNET);
    assert!(FeePayerPolicy::default_allows_fee_token(
        chain_id,
        request.currency_address().unwrap()
    ));
}

#[cfg(feature = "tempo")]
#[test]
fn test_fee_payer_custom_currency_can_override_allowed_fee_tokens() {
    let custom_token: Address = "0x9999999999999999999999999999999999999999"
        .parse()
        .unwrap();
    let fee_payer_signer = alloy::signers::local::PrivateKeySigner::random();
    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .currency("0x9999999999999999999999999999999999999999")
        .fee_payer(true)
        .fee_payer_signer(fee_payer_signer)
        .fee_payer_allowed_fee_tokens(vec![custom_token])
        .secret_key(TEST_SECRET),
    )
    .unwrap();

    let challenge = mpp.charge("1").unwrap().remove(0);
    let request: ChargeRequest = challenge.request.decode().unwrap();
    assert!(request.fee_payer());
    assert_eq!(request.currency_address().unwrap(), custom_token);
    assert!(!FeePayerPolicy::default_allows_fee_token(
        request.chain_id().unwrap_or(CHAIN_ID),
        custom_token
    ));
    assert_eq!(
        mpp.method.fee_payer_allowed_fee_tokens(),
        Some([custom_token].as_slice())
    );
}

#[cfg(feature = "tempo")]
#[test]
fn test_mpp_create_rejects_fee_payer_without_sponsor() {
    let builder = || {
        tempo(TempoConfig {
            recipient: TEST_RECIPIENT,
        })
        .secret_key("fee-payer-test-secret-key-32-bytes")
        .fee_payer(true)
    };

    let err = Mpp::create(builder()).err().expect("no signer or relay");
    assert!(
        matches!(&err, crate::error::MppError::InvalidConfig(msg) if msg.contains("fee_payer")),
        "{err}"
    );

    let signer = alloy::signers::local::PrivateKeySigner::random();
    assert!(Mpp::create(builder().fee_payer_signer(signer)).is_ok());
    let relay = crate::server::TempoRelayConfig::new("test-api-key");
    assert!(Mpp::create(builder().relay(relay)).is_ok());
}

#[cfg(feature = "tempo")]
#[test]
fn test_shared_runtime_detection() {
    use std::ffi::OsString;
    let env = |vars: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| OsString::from(value))
        }
    };
    assert_eq!(shared_runtime(env(&[])), None);
    assert_eq!(
        shared_runtime(env(&[("NODE_ENV", "production")])).as_deref(),
        Some("NODE_ENV is \"production\"")
    );
    assert_eq!(
        shared_runtime(env(&[("MPP_ENV", "Production")])).as_deref(),
        Some("MPP_ENV is \"production\"")
    );
    assert_eq!(shared_runtime(env(&[("NODE_ENV", "development")])), None);
    for name in SHARED_PLATFORM_ENV_VARS {
        let lookup = |key: &str| (key == *name).then(|| OsString::from("1"));
        assert_eq!(shared_runtime(lookup), Some(format!("{name} is set")));
    }
    // An empty platform variable is ignored.
    assert_eq!(shared_runtime(env(&[("VERCEL", "")])), None);
}

/// A platform variable set to a value that is not valid Unicode still counts
/// as set.
#[cfg(all(feature = "tempo", unix))]
#[test]
fn test_shared_runtime_detects_non_unicode_values() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let invalid = || OsString::from_vec(vec![0x66, 0x6f, 0x80]);
    assert!(invalid().to_str().is_none());
    let vercel = |name: &str| (name == "VERCEL").then(invalid);
    assert_eq!(shared_runtime(vercel).as_deref(), Some("VERCEL is set"));
    let node_env = |name: &str| (name == "NODE_ENV").then(invalid);
    assert_eq!(shared_runtime(node_env), None);
}

#[cfg(feature = "tempo")]
fn store_test_builder() -> crate::server::TempoBuilder {
    tempo(TempoConfig {
        recipient: TEST_RECIPIENT,
    })
    .secret_key(TEST_SECRET)
}

#[cfg(feature = "tempo")]
fn vercel(name: &str) -> Option<std::ffi::OsString> {
    (name == "VERCEL").then(|| "1".into())
}

#[cfg(feature = "tempo")]
#[test]
fn test_default_store_refused_in_production() {
    let builder = store_test_builder;
    let production = |name: &str| (name == "NODE_ENV").then(|| "production".into());

    // Development and tests keep the in-memory fallback.
    assert_eq!(default_store_refusal(&builder(), |_| None), None);

    for lookup in [
        &vercel as &dyn Fn(&str) -> Option<std::ffi::OsString>,
        &production,
    ] {
        let refusal = default_store_refusal(&builder(), lookup).expect("default store");
        assert!(
            refusal.starts_with("tempo has no store configured")
                && refusal.contains("MemoryStore::new()"),
            "{refusal}"
        );
    }
    let refusal = default_store_refusal(&builder(), vercel).unwrap();
    assert!(refusal.contains("VERCEL is set"), "{refusal}");

    // An explicit store, an explicit MemoryStore included, opts out.
    let memory: Arc<dyn crate::store::Store> = Arc::new(crate::store::MemoryStore::new());
    assert_eq!(
        default_store_refusal(&builder().store(memory), vercel),
        None
    );
    assert_eq!(
        default_store_refusal(&builder().without_store(), vercel),
        None
    );
    // A relay enforces single use itself, so it needs no local store.
    let relay = crate::server::TempoRelayConfig::new("test-api-key");
    assert_eq!(default_store_refusal(&builder().relay(relay), vercel), None);
}

/// `Mpp::create` still builds the handler, so it can serve sessions, but
/// refuses to issue or verify a charge with the default store in production.
#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_mpp_create_refuses_charges_with_the_default_store_in_production() {
    let refused = Mpp::create_with_env(store_test_builder(), vercel).expect("handler");
    let is_refusal = |err: &crate::error::MppError| {
        matches!(err, crate::error::MppError::InvalidConfig(msg)
            if msg.starts_with("tempo has no store configured") && msg.contains("VERCEL is set"))
    };
    let err = refused.charge("1.00").unwrap_err();
    assert!(is_refusal(&err), "{err}");
    let err = refused
        .charge_challenge("1000000", DEFAULT_CURRENCY_TESTNET, TEST_RECIPIENT)
        .unwrap_err();
    assert!(is_refusal(&err), "{err}");
    let err = refused
        .expected_charge_request("1.00", ChargeOptions::default())
        .unwrap_err();
    assert!(is_refusal(&err), "{err}");

    // A credential another instance issued is not settled here either.
    let issuer = Mpp::create_with_env(store_test_builder(), |_| None).unwrap();
    let challenges = issuer.charge("1.00").unwrap();
    let credential =
        PaymentCredential::new(challenges[0].to_echo(), PaymentPayload::hash("0xdeadbeef"));
    let refused: Mpp<TempoSuccessMethod> = Mpp {
        method: Arc::new(TempoSuccessMethod),
        session_method: None,
        config: refused.config,
        events: refused.events,
    };
    let err = refused.verify_credential(&credential).await.unwrap_err();
    assert!(
        err.message.starts_with("tempo has no store configured"),
        "{}",
        err.message
    );
    let request = credential.challenge.request.decode().unwrap();
    let err = refused.validate(&credential, &request).await.unwrap_err();
    assert!(
        err.message.starts_with("tempo has no store configured"),
        "{}",
        err.message
    );

    // It is the server's fault, so it maps to a masked 500, not a 402.
    assert_eq!(err.code, Some(crate::protocol::traits::ErrorCode::Internal));
    use crate::error::PaymentError;
    let problem = err.to_problem_details(None);
    assert_eq!(problem.status, 500);
    assert!(!problem.detail.contains("VERCEL"), "{}", problem.detail);
    let err = refused
        .verify_charge(&credential, "1.00")
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(crate::protocol::traits::ErrorCode::Internal));
    assert!(
        err.message.starts_with("tempo has no store configured"),
        "{}",
        err.message
    );

    // An explicit store opts out.
    let memory: Arc<dyn crate::store::Store> = Arc::new(crate::store::MemoryStore::new());
    let stored = Mpp::create_with_env(store_test_builder().store(memory), vercel).unwrap();
    assert!(stored.charge("1.00").is_ok());
}

/// The refusal is logged when the handler is created, so an operator sees it
/// before the first charge fails.
#[cfg(feature = "tempo")]
#[test]
fn test_mpp_create_logs_the_default_store_refusal() {
    let logs = crate::server::capture_logs(|| {
        Mpp::create_with_env(store_test_builder(), vercel).unwrap();
    });
    assert!(
        logs.iter()
            .any(|(level, message)| *level == tracing::Level::WARN
                && message.contains("tempo has no store configured")
                && message.contains("VERCEL is set")),
        "{logs:?}"
    );

    let memory: Arc<dyn crate::store::Store> = Arc::new(crate::store::MemoryStore::new());
    let logs = crate::server::capture_logs(|| {
        Mpp::create_with_env(store_test_builder(), |_| None).unwrap();
        Mpp::create_with_env(store_test_builder().store(memory), vercel).unwrap();
    });
    assert!(logs.is_empty(), "{logs:?}");
}

/// Library tests build default-store handlers with `Mpp::create`, which reads
/// no markers under test, so they pass whatever the host's environment.
#[cfg(feature = "tempo")]
#[test]
fn test_mpp_create_ignores_the_host_environment_in_tests() {
    let mpp = Mpp::create(store_test_builder()).unwrap();
    assert!(mpp.charge("1.00").is_ok());
}

#[cfg(feature = "tempo")]
#[test]
fn test_mpp_create_requires_secret_key() {
    struct EnvGuard(Option<String>);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.0 {
                unsafe { std::env::set_var(SECRET_KEY_ENV_VAR, value) };
            } else {
                unsafe { std::env::remove_var(SECRET_KEY_ENV_VAR) };
            }
        }
    }

    let _guard = EnvGuard(std::env::var(SECRET_KEY_ENV_VAR).ok());
    unsafe { std::env::remove_var(SECRET_KEY_ENV_VAR) };

    let result = Mpp::create(tempo(TempoConfig {
        recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
    }));
    match result {
        Ok(_) => panic!("missing secret key should fail creation"),
        Err(err) => assert!(err.to_string().contains("Missing secret key")),
    }

    unsafe { std::env::set_var(SECRET_KEY_ENV_VAR, "   ") };
    let whitespace_env = Mpp::create(tempo(TempoConfig {
        recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
    }));
    match whitespace_env {
        Ok(_) => panic!("whitespace-only env secret key should fail creation"),
        Err(err) => assert!(err.to_string().contains("Missing secret key")),
    }

    let whitespace_builder = Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .secret_key(""),
    );
    match whitespace_builder {
        Ok(_) => panic!("empty builder secret key should fail creation"),
        Err(err) => assert!(err.to_string().contains("Missing secret key")),
    }
}

#[cfg(feature = "tempo")]
#[test]
fn test_mpp_create_rejects_short_secret_key() {
    let create = |secret_key: &str| {
        Mpp::create(
            tempo(TempoConfig {
                recipient: TEST_RECIPIENT,
            })
            .secret_key(secret_key),
        )
    };

    let err = create(&"k".repeat(31)).err().expect("31-byte key");
    assert!(err.to_string().contains("at least 32 bytes"), "{err}");
    assert!(create(&"k".repeat(32)).is_ok());
}

#[cfg(feature = "tempo")]
#[test]
fn test_mpp_create_rejects_realm_a_challenge_cannot_carry() {
    let create = |realm: &str| {
        Mpp::create(
            tempo(TempoConfig {
                recipient: TEST_RECIPIENT,
            })
            .realm(realm)
            .secret_key(&"k".repeat(32)),
        )
    };

    for realm in ["Caf\u{e9} API", "api\u{2014}example.com", "bell\u{7}"] {
        let err = create(realm).err().expect("non-ASCII realm");
        assert!(
            err.to_string().contains("Invalid realm"),
            "{realm:?}: {err}"
        );
    }
    assert!(create("api.example.com").is_ok());
}

#[cfg(feature = "tempo")]
#[test]
fn test_charge_dollar_amount() {
    let mpp = create_test_mpp();

    let challenge = mpp.charge("0.10").unwrap().remove(0);
    assert_eq!(challenge.method.as_str(), "tempo");
    assert_eq!(challenge.intent.as_str(), "charge");
    assert_eq!(challenge.realm, "localhost");

    let request: ChargeRequest = challenge.request.decode().unwrap();
    assert_eq!(request.amount, "100000");
    assert_eq!(request.currency, crate::protocol::methods::tempo::OUSD);
    assert_eq!(
        request.recipient,
        Some("0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2".to_string())
    );
}

#[cfg(feature = "tempo")]
#[test]
fn test_charge_one_dollar() {
    let mpp = create_test_mpp();
    let challenge = mpp.charge("1").unwrap().remove(0);
    let request: ChargeRequest = challenge.request.decode().unwrap();
    assert_eq!(request.amount, "1000000");
}

#[cfg(feature = "tempo")]
#[test]
fn test_machine_token_charge_hint() {
    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .chain_id(CHAIN_ID)
        .machine_token_enabled(true)
        .secret_key(TEST_SECRET),
    )
    .unwrap();

    let challenge = mpp.charge("1").unwrap().remove(0);
    let request: ChargeRequest = challenge.request.decode().unwrap();
    assert!(mpp.machine_token_enabled());
    assert!(request.machine_token_enabled());
}

#[cfg(feature = "tempo")]
#[test]
fn test_machine_token_rejects_unsupported_chain() {
    let result = Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .chain_id(1)
        .machine_token_enabled(true)
        .secret_key(TEST_SECRET),
    );
    match result {
        Ok(_) => panic!("unsupported machine-token chain should fail"),
        Err(error) => assert!(error
            .to_string()
            .contains("machine tokens are not supported")),
    }
}

#[cfg(feature = "tempo")]
#[test]
fn test_charge_default_expires() {
    let mpp = create_test_mpp();
    let challenge = mpp.charge("1").unwrap().remove(0);
    assert!(challenge.expires.is_some());
}

#[cfg(feature = "tempo")]
#[test]
fn test_charge_requires_bound_currency() {
    let payment = Mpp::new(
        MockMethod,
        "api.example.com",
        "test-secret-key-at-least-32-bytes",
    );
    let result = payment.charge("1.00").map(|mut offers| offers.remove(0));
    assert!(result.is_err());
}

#[cfg(feature = "tempo")]
#[test]
fn test_charge_with_options() {
    let mpp = create_test_mpp();
    let challenge = mpp
        .charge_with_options(
            "5.50",
            ChargeOptions {
                description: Some("API access fee"),
                supported_modes: Some(&["pull"]),
                ..Default::default()
            },
        )
        .unwrap()
        .remove(0);

    let request: ChargeRequest = challenge.request.decode().unwrap();
    assert_eq!(request.amount, "5500000");
    assert_eq!(challenge.description, Some("API access fee".to_string()));
    assert_eq!(
        request.method_details.unwrap()["supportedModes"],
        serde_json::json!(["pull"])
    );
}

#[cfg(feature = "tempo")]
#[test]
fn test_charge_supported_modes_advertisement() {
    let mpp = create_test_mpp();
    let modes = |fee_payer, supported_modes| {
        let options = ChargeOptions {
            fee_payer,
            supported_modes,
            ..Default::default()
        };
        mpp.charge_with_options("1", options).map(|mut offers| {
            let request: ChargeRequest = offers.remove(0).request.decode().unwrap();
            request
                .method_details
                .unwrap()
                .get("supportedModes")
                .cloned()
        })
    };

    assert_eq!(modes(None, None).unwrap(), None);
    assert_eq!(
        modes(None, Some(&["push", "pull"])).unwrap(),
        Some(serde_json::json!(["push", "pull"]))
    );
    assert_eq!(
        modes(Some(true), Some(&["pull"])).unwrap(),
        Some(serde_json::json!(["pull"]))
    );

    assert!(modes(None, Some(&[])).is_err());
    assert!(modes(None, Some(&["Pull"])).is_err());
}

#[cfg(feature = "tempo")]
#[test]
fn test_charge_with_options_binds_request_body_digest() {
    let mpp = create_test_mpp();
    let body = br#"{"query":"paid"}"#;
    let challenge = mpp
        .charge_with_options_and_body(
            "0.10",
            ChargeOptions {
                ..Default::default()
            },
            body,
        )
        .unwrap()
        .remove(0);

    let digest = crate::body_digest::compute(body);
    assert_eq!(challenge.digest.as_deref(), Some(digest.as_str()));
    assert!(challenge.verify(TEST_SECRET));
}

#[cfg(feature = "tempo")]
#[test]
fn test_sponsored_charge_refuses_expiry_under_floor() {
    let mpp = create_sponsored_test_mpp(None);
    let charge = |amount: &str, fee_payer, supported_modes, expires: &str| {
        mpp.charge_with_options(
            amount,
            ChargeOptions {
                fee_payer,
                supported_modes,
                expires: Some(expires),
                ..Default::default()
            },
        )
    };
    let short = crate::expires::seconds(10);

    let error = charge("1", None, None, &short).unwrap_err();
    assert!(
        matches!(error, crate::error::MppError::InvalidConfig(_)),
        "{error:?}"
    );
    assert!(charge("1", None, Some(&["push", "pull"]), &short).is_err());
    charge("1", None, None, &crate::expires::seconds(30)).unwrap();
    charge("1", Some(false), None, &short).unwrap();
    // Zero-amount proofs and push-only charges never reach the fee payer
    // (mppx `Charge.request`).
    charge("0", None, None, &short).unwrap();
    charge("1", None, Some(&["push"]), &short).unwrap();
}

/// A handler with a fee-payer signer, optionally with `fee_payer(enabled)`.
#[cfg(feature = "tempo")]
fn create_sponsored_test_mpp(
    fee_payer: Option<bool>,
) -> Mpp<crate::server::TempoChargeMethod<crate::server::TempoProvider>> {
    let mut builder = tempo(TempoConfig {
        recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
    })
    .fee_payer_signer(alloy::signers::local::PrivateKeySigner::random())
    .secret_key(TEST_SECRET);
    if let Some(enabled) = fee_payer {
        builder = builder.fee_payer(enabled);
    }
    Mpp::create(builder).unwrap()
}

/// As in mppx, a configured fee payer sponsors every charge unless a route
/// sets `feePayer: false`, and a handler without one never advertises
/// sponsorship.
#[cfg(feature = "tempo")]
#[test]
fn test_fee_payer_sponsors_routes_by_default() {
    let sponsored = |mpp: &Mpp<_>, fee_payer| {
        let challenge = mpp
            .charge_with_options(
                "1",
                ChargeOptions {
                    fee_payer,
                    ..Default::default()
                },
            )
            .unwrap()
            .remove(0);
        challenge
            .request
            .decode::<ChargeRequest>()
            .unwrap()
            .fee_payer()
    };

    let mpp = create_sponsored_test_mpp(None);
    assert!(mpp.fee_payer());
    assert!(sponsored(&mpp, None));
    assert!(sponsored(&mpp, Some(true)));
    assert!(!sponsored(&mpp, Some(false)));

    let off = create_sponsored_test_mpp(Some(false));
    assert!(!sponsored(&off, None));
    assert!(sponsored(&off, Some(true)));

    let unsponsored = create_test_mpp();
    assert!(!sponsored(&unsponsored, None));
    assert!(!sponsored(&unsponsored, Some(true)));
}

/// A hosted fee payer (mppx `feePayer: url`) sponsors routes by default and
/// excludes a local fee token or signer.
#[cfg(feature = "tempo")]
#[test]
fn test_hosted_fee_payer_configuration() {
    let builder = || {
        tempo(TempoConfig {
            recipient: TEST_RECIPIENT,
        })
        .secret_key(TEST_SECRET)
    };

    let mpp = Mpp::create(builder().fee_payer_url("https://sponsor.example/rpc")).unwrap();
    assert!(mpp.fee_payer());
    let request: ChargeRequest = mpp.charge("1").unwrap().remove(0).request.decode().unwrap();
    assert!(request.fee_payer());

    let error = |builder| Mpp::create(builder).err().expect("invalid configuration");
    assert!(matches!(
        error(
            builder()
                .fee_payer_url("https://sponsor.example/rpc")
                .fee_payer_fee_token(crate::protocol::methods::tempo::PATH_USD.parse().unwrap())
        ),
        crate::error::MppError::InvalidConfig(_)
    ));
    assert!(matches!(
        error(
            builder()
                .fee_payer_url("https://sponsor.example/rpc")
                .fee_payer_signer(alloy::signers::local::PrivateKeySigner::random())
        ),
        crate::error::MppError::InvalidConfig(_)
    ));
    assert!(matches!(
        error(builder().fee_payer_url("not a url")),
        crate::error::MppError::InvalidConfig(_)
    ));
}

#[cfg(feature = "tempo")]
#[test]
fn test_zones_advertised_in_charge_challenges() {
    use crate::protocol::methods::tempo::zone::Zones;

    for (zones, json) in [
        (Zones::ids([3, 7]).unwrap(), serde_json::json!([3, 7])),
        (Zones::Any, serde_json::json!(true)),
    ] {
        let mpp = Mpp::create(offers_builder().chain_id(CHAIN_ID).zones(zones.clone())).unwrap();
        for challenge in mpp.charge("1").unwrap() {
            let request: ChargeRequest = challenge.request.decode().unwrap();
            assert_eq!(request.method_details.as_ref().unwrap()["zones"], json);
            assert_eq!(
                request.tempo_method_details().unwrap().zones,
                Some(zones.clone())
            );
        }
    }
    let request: ChargeRequest = create_test_mpp().charge("1").unwrap()[0]
        .request
        .decode()
        .unwrap();
    assert!(request.tempo_method_details().unwrap().zones.is_none());
}

#[cfg(feature = "tempo")]
#[test]
fn test_zones_rejects_invalid_config() {
    use crate::protocol::methods::tempo::zone::Zones;

    for zones in [
        Zones::Ids(vec![]),
        Zones::Ids(vec![0]),
        Zones::Ids(vec![3, 421_700_003]),
    ] {
        let error = Mpp::create(offers_builder().zones(zones)).err().unwrap();
        assert!(error.to_string().contains("zones must be"), "{error}");
    }
}

#[cfg(feature = "tempo")]
#[test]
fn test_zones_reject_relay() {
    use crate::protocol::methods::tempo::zone::Zones;

    let relay = crate::server::TempoRelayConfig::new("test-api-key");
    let error = Mpp::create(offers_builder().zones(Zones::Any).relay(relay))
        .err()
        .unwrap();
    assert!(
        matches!(error, crate::error::MppError::InvalidConfig(_)),
        "{error}"
    );
    assert!(error.to_string().contains("relay"), "{error}");
}

#[cfg(feature = "tempo")]
#[test]
fn test_relay_refuses_explicit_zone_challenges() {
    let relay = crate::server::TempoRelayConfig::new("test-api-key");
    let mpp = Mpp::create(offers_builder().relay(relay)).unwrap();
    let request = |details: serde_json::Value| ChargeRequest {
        amount: "1000".into(),
        currency: crate::protocol::methods::tempo::OUSD.into(),
        recipient: Some(TEST_RECIPIENT.into()),
        method_details: Some(details),
        ..Default::default()
    };
    // A relay does not verify Zone credentials, so a challenge that lets the
    // payer withdraw from a Zone must not be issued.
    for zones in [serde_json::json!(true), serde_json::json!([3])] {
        let error = mpp
            .charge_challenge_with_options(
                &request(serde_json::json!({ "zones": zones })),
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(error, crate::error::MppError::InvalidConfig(_)),
            "{error}"
        );
        assert!(error.to_string().contains("relay"), "{error}");
    }
    mpp.charge_challenge_with_options(&request(serde_json::json!({ "zones": null })), None, None)
        .unwrap();
    mpp.charge_challenge_with_options(&request(serde_json::json!({})), None, None)
        .unwrap();
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_explicit_charge_challenges_advertise_zones() {
    use crate::protocol::methods::tempo::zone::Zones;

    let mpp = success_mpp_from(
        offers_builder()
            .chain_id(CHAIN_ID)
            .zones(Zones::ids([3]).unwrap()),
    );
    let expected = mpp
        .expected_charge_request("0.10", ChargeOptions::default())
        .unwrap();
    // Challenges built from explicit parameters bind the same Zones as
    // `charge()`, so they verify against the route's expected request.
    let challenge = mpp
        .charge_challenge(
            &expected.amount,
            &expected.currency,
            expected.recipient.as_deref().unwrap(),
        )
        .unwrap();
    let request: ChargeRequest = challenge.request.decode().unwrap();
    assert_eq!(
        request.method_details.as_ref().unwrap()["zones"],
        serde_json::json!([3])
    );
    let credential = PaymentCredential::new(
        challenge.to_echo(),
        PaymentPayload::zone(
            format!("0x{}", "ab".repeat(32)),
            format!("0x{}", "a1".repeat(32)),
            3,
        ),
    );
    mpp.verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap();
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_zones_bind_credentials_to_the_route() {
    use crate::protocol::methods::tempo::zone::Zones;

    let mpp = success_mpp_from(
        offers_builder()
            .chain_id(CHAIN_ID)
            .zones(Zones::ids([3]).unwrap()),
    );
    let challenges = mpp.charge("0.10").unwrap();
    let credential = PaymentCredential::new(
        challenges[0].to_echo(),
        PaymentPayload::zone(
            format!("0x{}", "ab".repeat(32)),
            format!("0x{}", "a1".repeat(32)),
            3,
        ),
    );
    let expected = mpp
        .expected_charge_request("0.10", ChargeOptions::default())
        .unwrap();
    mpp.verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap();

    // A route listing the same Zones in another order, or with repeats, takes it.
    let reordered_mpp = success_mpp_from(
        offers_builder()
            .chain_id(CHAIN_ID)
            .zones(Zones::ids([5, 3]).unwrap()),
    );
    let challenges = reordered_mpp.charge("0.10").unwrap();
    let reordered = PaymentCredential::new(
        challenges[0].to_echo(),
        PaymentPayload::zone(
            format!("0x{}", "ab".repeat(32)),
            format!("0x{}", "a1".repeat(32)),
            3,
        ),
    );
    for zones in [serde_json::json!([3, 5]), serde_json::json!([5, 3, 5])] {
        let mut same = reordered_mpp
            .expected_charge_request("0.10", ChargeOptions::default())
            .unwrap();
        same.method_details
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("zones".into(), zones);
        reordered_mpp
            .verify_credential_with_expected_request(&reordered, &same)
            .await
            .unwrap();
    }

    // A route that accepts other Zones, or explicitly none, does not take it.
    for zones in [Some(serde_json::json!([4])), Some(serde_json::Value::Null)] {
        let mut other = expected.clone();
        let details = other
            .method_details
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap();
        if let Some(zones) = zones {
            details.insert("zones".into(), zones);
        }
        let err = mpp
            .verify_credential_with_expected_request(&credential, &other)
            .await
            .unwrap_err();
        assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
        assert!(err.message.contains("Zone mismatch"), "{}", err.message);
    }
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_unbound_verification_rejects_withdrawals_from_other_zones() {
    use crate::protocol::methods::tempo::zone::Zones;

    // Two handlers share a secret and realm: one accepts Zone 3, the other Zone 5.
    let zone_3 = success_mpp_from(
        offers_builder()
            .chain_id(CHAIN_ID)
            .zones(Zones::ids([3]).unwrap()),
    );
    let zone_5 = success_mpp_from(
        offers_builder()
            .chain_id(CHAIN_ID)
            .zones(Zones::ids([5]).unwrap()),
    );
    let zone_credential = |mpp: &Mpp<TempoSuccessMethod>, zone_id| {
        PaymentCredential::new(
            mpp.charge("0.10").unwrap()[0].to_echo(),
            PaymentPayload::zone(
                format!("0x{}", "ab".repeat(32)),
                format!("0x{}", "a1".repeat(32)),
                zone_id,
            ),
        )
    };

    // A Zone 5 withdrawal for the Zone 5 handler's challenge does not pay the
    // Zone 3 handler.
    let err = zone_3
        .broadcast_credential(&zone_credential(&zone_5, 5))
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(err.message.contains("Zone"), "{}", err.message);
    zone_3
        .broadcast_credential(&zone_credential(&zone_3, 3))
        .await
        .unwrap();

    // A handler without Zones is unchanged.
    let no_zones = success_mpp_from(offers_builder().chain_id(CHAIN_ID));
    no_zones
        .broadcast_credential(&zone_credential(&zone_5, 5))
        .await
        .unwrap();
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_route_zones_override_handler_zones() {
    use crate::protocol::methods::tempo::zone::Zones;

    let mpp = success_mpp_from(
        offers_builder()
            .chain_id(CHAIN_ID)
            .zones(Zones::ids([3]).unwrap()),
    );
    let route = mpp
        .expected_charge_request("0.10", ChargeOptions::default())
        .unwrap();
    // A route that issues its challenges for Zone 7 instead of the handler's.
    let request = ChargeRequest {
        amount: route.amount.clone(),
        currency: route.currency.clone(),
        recipient: route.recipient.clone(),
        method_details: Some(serde_json::json!({ "chainId": CHAIN_ID, "zones": [7] })),
        ..Default::default()
    };
    let challenge = mpp
        .charge_challenge_with_options(&request, None, None)
        .unwrap();
    let credential = |zone_id| {
        PaymentCredential::new(
            challenge.to_echo(),
            PaymentPayload::zone(
                format!("0x{}", "ab".repeat(32)),
                format!("0x{}", "a1".repeat(32)),
                zone_id,
            ),
        )
    };

    mpp.verify_credential_with_expected_request(&credential(7), &request)
        .await
        .unwrap();

    // A Zone the challenge does not accept is rejected on every path.
    let zone_9 = credential(9);
    let errors = [
        mpp.verify_credential_with_expected_request(&zone_9, &request)
            .await
            .unwrap_err(),
        mpp.validate_credential_with_expected_request(&zone_9, &request)
            .await
            .unwrap_err(),
        mpp.broadcast_credential(&zone_9).await.unwrap_err(),
        mpp.validate_credential(&zone_9).await.unwrap_err(),
    ];
    for err in errors {
        assert_eq!(
            err.code,
            Some(ErrorCode::InvalidChallenge),
            "{}",
            err.message
        );
        assert!(err.message.contains("Zone"), "{}", err.message);
    }
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_explicit_charge_challenge_verifies_against_its_own_request() {
    use crate::protocol::methods::tempo::zone::Zones;

    let mpp = success_mpp_from(
        offers_builder()
            .chain_id(CHAIN_ID)
            .zones(Zones::ids([3]).unwrap()),
    );
    let route = mpp
        .expected_charge_request("0.10", ChargeOptions::default())
        .unwrap();
    // A caller-built request without Zones, issued and verified as is: the
    // handler's Zones apply to both sides.
    let request = ChargeRequest {
        amount: route.amount.clone(),
        currency: route.currency.clone(),
        recipient: route.recipient.clone(),
        method_details: Some(serde_json::json!({ "chainId": CHAIN_ID })),
        ..Default::default()
    };
    let challenge = mpp
        .charge_challenge_with_options(&request, None, None)
        .unwrap();
    let credential = PaymentCredential::new(
        challenge.to_echo(),
        PaymentPayload::zone(
            format!("0x{}", "ab".repeat(32)),
            format!("0x{}", "a1".repeat(32)),
            3,
        ),
    );
    mpp.verify_credential_with_expected_request(&credential, &request)
        .await
        .unwrap();
}

/// A credential for a zone challenge issued with an expiry `ago` in the past.
#[cfg(feature = "tempo")]
fn expired_offer(
    mpp: &Mpp<TempoSuccessMethod>,
    ago: time::Duration,
    payload: PaymentPayload,
) -> (PaymentCredential, ChargeRequest) {
    let expires = (time::OffsetDateTime::now_utc() - ago)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let options = || ChargeOptions {
        expires: Some(&expires),
        ..Default::default()
    };
    let challenges = mpp.charge_with_options("0.10", options()).unwrap();
    let expected = mpp.expected_charge_request("0.10", options()).unwrap();
    (
        PaymentCredential::new(challenges[0].to_echo(), payload),
        expected,
    )
}

#[cfg(feature = "tempo")]
fn zone_payload() -> PaymentPayload {
    PaymentPayload::zone(
        format!("0x{}", "ab".repeat(32)),
        format!("0x{}", "a1".repeat(32)),
        3,
    )
}

#[cfg(feature = "tempo")]
fn grace_mpp(grace: std::time::Duration) -> Mpp<TempoSuccessMethod> {
    use crate::protocol::methods::tempo::zone::Zones;
    success_mpp_from(
        offers_builder()
            .chain_id(CHAIN_ID)
            .zones(Zones::ids([3]).unwrap())
            .zone_credential_grace(grace),
    )
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_zone_credential_grace_applies_only_to_zone_credentials() {
    let grace = std::time::Duration::from_secs(60);
    let mpp = grace_mpp(grace);
    let (credential, expected) = expired_offer(&mpp, time::Duration::seconds(1), zone_payload());
    mpp.verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap();

    // A hash credential for an expired challenge gets no grace.
    let (credential, expected) = expired_offer(
        &mpp,
        time::Duration::seconds(1),
        PaymentPayload::hash(format!("0x{}", "cd".repeat(32))),
    );
    let error = mpp
        .verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap_err();
    assert_eq!(error.code, Some(ErrorCode::Expired), "{error}");

    // Nor does a zone credential past the grace, or one with the default grace.
    let (credential, expected) = expired_offer(&mpp, time::Duration::seconds(61), zone_payload());
    let error = mpp
        .verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap_err();
    assert_eq!(error.code, Some(ErrorCode::Expired), "{error}");
    let mpp = grace_mpp(std::time::Duration::ZERO);
    let (credential, expected) = expired_offer(&mpp, time::Duration::seconds(1), zone_payload());
    let error = mpp
        .verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap_err();
    assert_eq!(error.code, Some(ErrorCode::Expired), "{error}");
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_zone_credential_grace_needs_a_challenge_issued_with_it() {
    use crate::protocol::core::expiry_grace::has_expiry_grace;

    // Issued with the grace off: no marker, so turning the grace on later
    // never extends it.
    let issued = grace_mpp(std::time::Duration::ZERO);
    let (credential, expected) = expired_offer(&issued, time::Duration::seconds(1), zone_payload());
    assert!(!has_expiry_grace(credential.challenge.opaque.as_ref()));
    let error = grace_mpp(std::time::Duration::from_secs(60))
        .verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap_err();
    assert_eq!(error.code, Some(ErrorCode::Expired), "{error}");

    // Issued with it on, the HMAC-bound marker rides beside the route's
    // pinned `opaque`, which verification still checks.
    let route = Base64UrlJson::from_value(&serde_json::json!({ "plan": "pro" })).unwrap();
    let mpp = grace_mpp(std::time::Duration::from_secs(60)).with_opaque(route.clone());
    let (credential, expected) = expired_offer(&mpp, time::Duration::seconds(1), zone_payload());
    assert!(has_expiry_grace(credential.challenge.opaque.as_ref()));
    mpp.verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap();
    let other = Base64UrlJson::from_value(&serde_json::json!({ "plan": "free" })).unwrap();
    let error = grace_mpp(std::time::Duration::from_secs(60))
        .with_opaque(other)
        .verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap_err();
    assert_ne!(error.code, None, "{error}");
}

#[cfg(feature = "tempo")]
#[test]
fn test_zone_credential_grace_is_refused_with_a_relay() {
    let error = Mpp::create(
        offers_builder()
            .zone_credential_grace(std::time::Duration::from_secs(60))
            .relay(crate::server::TempoRelayConfig::new("test-api-key")),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("relay"), "{error}");
}

#[cfg(feature = "tempo")]
#[test]
fn test_zone_credential_grace_rejects_more_than_five_minutes() {
    let error = Mpp::create(
        offers_builder().zone_credential_grace(std::time::Duration::from_millis(300_001)),
    )
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("zone_credential_grace"),
        "{error}"
    );
    Mpp::create(offers_builder().zone_credential_grace(std::time::Duration::from_secs(300)))
        .unwrap();
}

/// `Mpp::new` honors the method's own Zone settings, as `Mpp::create` does:
/// its `zone_credential_grace`, and a relay's refusal of Zone Challenges.
#[cfg(feature = "tempo")]
#[test]
fn test_mpp_new_honors_the_method_zone_settings() {
    use crate::protocol::core::expiry_grace::has_expiry_grace;
    use crate::protocol::methods::tempo::{ChargeMethod as TempoChargeMethod, RelayConfig};

    let provider =
        alloy::providers::ProviderBuilder::new_with_network::<tempo_alloy::TempoNetwork>()
            .connect_mocked_client(alloy::providers::mock::Asserter::new());
    let new_mpp = |method| {
        Mpp::new_with_config(
            method,
            "api.example.com",
            TEST_SECRET,
            crate::protocol::methods::tempo::OUSD,
            TEST_RECIPIENT,
        )
    };

    let grace = std::time::Duration::from_secs(60);
    let mpp = new_mpp(
        TempoChargeMethod::new(provider.clone())
            .with_zone_credential_grace(grace)
            .unwrap(),
    );
    assert_eq!(mpp.config.zone_credential_grace, grace);
    let challenges = mpp
        .charge_with_options("0.10", ChargeOptions::default())
        .unwrap();
    assert!(has_expiry_grace(challenges[0].opaque.as_ref()));

    let mpp = new_mpp(TempoChargeMethod::new(provider.clone()));
    assert!(mpp.config.zone_credential_grace.is_zero());
    let challenges = mpp
        .charge_with_options("0.10", ChargeOptions::default())
        .unwrap();
    assert!(!has_expiry_grace(challenges[0].opaque.as_ref()));

    let mpp = new_mpp(
        TempoChargeMethod::new(provider)
            .with_relay(RelayConfig::new("test-api-key"))
            .unwrap(),
    );
    let request = ChargeRequest {
        amount: "1000".into(),
        currency: crate::protocol::methods::tempo::OUSD.into(),
        recipient: Some(TEST_RECIPIENT.into()),
        method_details: Some(serde_json::json!({ "zones": [3] })),
        ..Default::default()
    };
    let error = mpp
        .charge_challenge_with_options(&request, None, None)
        .unwrap_err();
    assert!(error.to_string().contains("relay"), "{error}");
}
