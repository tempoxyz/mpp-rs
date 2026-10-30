use super::*;

#[cfg(feature = "tempo")]
#[test]
fn test_mpp_create() {
    let mpp = create_test_mpp();
    assert_eq!(mpp.realm(), "MPP Payment");
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
fn test_charge_dollar_amount() {
    let mpp = create_test_mpp();

    let challenge = mpp.charge("0.10").unwrap().remove(0);
    assert_eq!(challenge.method.as_str(), "tempo");
    assert_eq!(challenge.intent.as_str(), "charge");
    assert_eq!(challenge.realm, "MPP Payment");

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
    let payment = Mpp::new(MockMethod, "api.example.com", "secret");
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

/// A route that opts out of sponsorship refuses a credential issued for a
/// sponsored route at the same price.
#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_unsponsored_route_rejects_sponsored_credential() {
    let mpp = Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .chain_id(CHAIN_ID)
        .fee_payer(true)
        .fee_payer_signer(alloy::signers::local::PrivateKeySigner::random())
        .secret_key(TEST_SECRET),
    )
    .unwrap();
    let sponsored = mpp.charge("1").unwrap().remove(0);
    let credential =
        PaymentCredential::new(sponsored.to_echo(), PaymentPayload::hash("0xdeadbeef"));

    let err = mpp
        .verify_charge_with_options(
            &credential,
            "1",
            crate::server::ChargeOptions {
                fee_payer: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(
        err.message.contains("Fee payer mismatch"),
        "{}",
        err.message
    );
}
