use super::*;

// ==================== OUSD-first currency offers ====================

#[cfg(feature = "tempo")]
fn created_currencies(builder: crate::server::TempoBuilder) -> Vec<String> {
    Mpp::create(builder).unwrap().currencies().to_vec()
}

#[cfg(feature = "tempo")]
fn create_error(builder: crate::server::TempoBuilder) -> String {
    match Mpp::create(builder) {
        Ok(mpp) => panic!("expected an error, got currencies {:?}", mpp.currencies()),
        Err(err) => err.to_string(),
    }
}

#[cfg(feature = "tempo")]
fn challenge_currencies(challenges: &[PaymentChallenge]) -> Vec<String> {
    challenges
        .iter()
        .map(|challenge| {
            challenge
                .request
                .decode::<ChargeRequest>()
                .unwrap()
                .currency
        })
        .collect()
}

#[cfg(feature = "tempo")]
#[test]
fn test_ousd_constant_matches_onchain_address() {
    assert_eq!(
        crate::protocol::methods::tempo::OUSD,
        "0x20c0000000000000000000006a37DA5C996874BE"
    );
    assert!(crate::protocol::methods::tempo::OUSD
        .parse::<Address>()
        .is_ok());
}

#[cfg(feature = "tempo")]
#[test]
fn test_charge_variants_offer_every_currency_and_currency_aliases_first() {
    use crate::protocol::methods::tempo::{MODERATO_CHAIN_ID, OUSD, PATH_USD, USDC};

    for (chain_id, currencies) in [
        (CHAIN_ID, vec![OUSD, USDC]),
        (MODERATO_CHAIN_ID, vec![OUSD, PATH_USD]),
    ] {
        for accepted in [currencies, vec![USDC]] {
            let mpp = Mpp::create(
                offers_builder()
                    .chain_id(chain_id)
                    .currencies(accepted.clone()),
            )
            .unwrap();
            assert_eq!(mpp.currency(), mpp.currencies().first().map(String::as_str));
            let body = b"request";
            for (offers, body_bound) in [
                (mpp.charge("1").unwrap(), false),
                (
                    mpp.charge_with_options("1", ChargeOptions::default())
                        .unwrap(),
                    false,
                ),
                (mpp.charge_with_body("1", body).unwrap(), true),
                (
                    mpp.charge_with_options_and_body("1", ChargeOptions::default(), body)
                        .unwrap(),
                    true,
                ),
            ] {
                assert_eq!(challenge_currencies(&offers), accepted);
                for offer in offers {
                    assert!(offer.verify(TEST_SECRET));
                    assert_eq!(
                        offer.digest,
                        body_bound.then(|| crate::body_digest::compute(body))
                    );
                }
            }
        }
    }
    let mpp = Mpp::create(offers_builder().currency(USDC)).unwrap();
    assert_eq!(mpp.currency(), Some(USDC));
    assert_eq!(mpp.currencies(), [USDC]);
    assert_eq!(challenge_currencies(&mpp.charge("1").unwrap()), [USDC]);
}

#[cfg(feature = "tempo")]
#[test]
fn test_mainnet_defaults_offer_ousd_then_usdc() {
    use crate::protocol::methods::tempo::{OUSD, USDC};

    let mpp = Mpp::create(offers_builder().chain_id(CHAIN_ID)).unwrap();
    assert_eq!(mpp.currencies(), [OUSD, USDC]);
    assert_eq!(mpp.currency(), Some(OUSD));
    assert_eq!(
        mpp.charge("1")
            .unwrap()
            .remove(0)
            .request
            .decode::<ChargeRequest>()
            .unwrap()
            .currency,
        OUSD
    );

    let challenges = mpp.charge("0.25").unwrap();
    assert_eq!(challenges.len(), 2);
    assert_eq!(challenge_currencies(&challenges), [OUSD, USDC]);
    for challenge in &challenges {
        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(challenge.method.as_str(), "tempo");
        assert_eq!(challenge.intent.as_str(), "charge");
        assert_eq!(request.amount, "250000");
        assert_eq!(request.recipient.as_deref(), Some(TEST_RECIPIENT));
        assert_eq!(request.chain_id(), Some(CHAIN_ID));
        assert!(challenge.verify(TEST_SECRET));
    }
    assert_ne!(challenges[0].id, challenges[1].id);
}

#[cfg(feature = "tempo")]
#[test]
fn test_moderato_defaults_offer_ousd_then_path_usd() {
    use crate::protocol::methods::tempo::{MODERATO_CHAIN_ID, OUSD, PATH_USD};

    let mpp = Mpp::create(offers_builder().chain_id(MODERATO_CHAIN_ID)).unwrap();
    assert_eq!(mpp.currencies(), [OUSD, PATH_USD]);
    let challenges = mpp.charge("1").unwrap();
    assert_eq!(challenge_currencies(&challenges), [OUSD, PATH_USD]);
    for challenge in &challenges {
        let request: ChargeRequest = challenge.request.decode().unwrap();
        assert_eq!(request.chain_id(), Some(MODERATO_CHAIN_ID));
    }
}

#[cfg(feature = "tempo")]
#[test]
fn test_moderato_rpc_url_infers_moderato_defaults() {
    use crate::protocol::methods::tempo::{MODERATO_CHAIN_ID, OUSD, PATH_USD};

    let mpp = Mpp::create(offers_builder().rpc_url("https://rpc.moderato.tempo.xyz")).unwrap();
    assert_eq!(mpp.chain_id(), Some(MODERATO_CHAIN_ID));
    assert_eq!(mpp.currencies(), [OUSD, PATH_USD]);
}

#[cfg(feature = "tempo")]
#[test]
fn test_mainnet_rpc_url_infers_mainnet_defaults() {
    use crate::protocol::methods::tempo::{OUSD, USDC};

    let mpp = Mpp::create(offers_builder().rpc_url("https://rpc.tempo.xyz")).unwrap();
    assert_eq!(mpp.chain_id(), Some(CHAIN_ID));
    assert_eq!(mpp.currencies(), [OUSD, USDC]);
}

#[cfg(feature = "tempo")]
#[test]
fn test_explicit_chain_id_beats_rpc_inferred_chain() {
    use crate::protocol::methods::tempo::{MODERATO_CHAIN_ID, OUSD, PATH_USD, USDC};

    // Explicit chain ID set before the RPC URL is not overwritten by inference.
    let before = Mpp::create(
        offers_builder()
            .chain_id(CHAIN_ID)
            .rpc_url("https://rpc.moderato.tempo.xyz"),
    )
    .unwrap();
    assert_eq!(before.chain_id(), Some(CHAIN_ID));
    assert_eq!(before.currencies(), [OUSD, USDC]);

    // Explicit chain ID set after the RPC URL replaces the inferred one.
    let after = Mpp::create(
        offers_builder()
            .rpc_url("https://rpc.tempo.xyz")
            .chain_id(MODERATO_CHAIN_ID),
    )
    .unwrap();
    assert_eq!(after.chain_id(), Some(MODERATO_CHAIN_ID));
    assert_eq!(after.currencies(), [OUSD, PATH_USD]);
}

#[cfg(feature = "tempo")]
#[test]
fn test_default_builder_and_last_rpc_select_network_offers() {
    use crate::protocol::methods::tempo::{MODERATO_CHAIN_ID, OUSD, PATH_USD, USDC};

    for (builder, chain, fallback) in [
        (offers_builder(), CHAIN_ID, USDC),
        (
            offers_builder()
                .rpc_url("https://rpc.tempo.xyz")
                .rpc_url("https://rpc.moderato.tempo.xyz"),
            MODERATO_CHAIN_ID,
            PATH_USD,
        ),
        (
            offers_builder()
                .rpc_url("https://rpc.moderato.tempo.xyz")
                .rpc_url("https://rpc.tempo.xyz"),
            CHAIN_ID,
            USDC,
        ),
    ] {
        let mpp = Mpp::create(builder).unwrap();
        assert_eq!(mpp.chain_id(), Some(chain));
        assert_eq!(
            challenge_currencies(&mpp.charge("1").unwrap()),
            [OUSD, fallback]
        );
    }
}

#[cfg(feature = "tempo")]
#[test]
fn test_fee_token_requires_local_signer_and_nonempty_allowlist() {
    use crate::protocol::methods::tempo::USDC;
    assert!(
        create_error(offers_builder().fee_payer_fee_token(USDC.parse().unwrap()))
            .contains("local fee payer signer")
    );
    assert!(
        create_error(offers_builder().fee_payer_allowed_fee_tokens(vec![]))
            .contains("at least one token")
    );
}

#[cfg(feature = "tempo")]
#[test]
fn test_unknown_chain_keeps_single_legacy_default() {
    use crate::protocol::methods::tempo::PATH_USD;

    assert_eq!(
        created_currencies(offers_builder().chain_id(31337)),
        [PATH_USD]
    );
    assert_eq!(
        created_currencies(
            offers_builder()
                .rpc_url("http://localhost:8545")
                .chain_id(1337)
        ),
        [PATH_USD]
    );

    let mpp = Mpp::create(offers_builder().chain_id(31337)).unwrap();
    let challenges = mpp.charge("1").unwrap();
    assert_eq!(challenge_currencies(&challenges), [PATH_USD]);
}

#[cfg(feature = "tempo")]
#[test]
fn test_explicit_currencies_replace_defaults_in_order() {
    use crate::protocol::methods::tempo::{OUSD, PATH_USD, USDC};

    let mpp = Mpp::create(
        offers_builder()
            .chain_id(CHAIN_ID)
            .currencies([PATH_USD, OUSD, USDC]),
    )
    .unwrap();
    assert_eq!(mpp.currencies(), [PATH_USD, OUSD, USDC]);
    assert_eq!(mpp.currency(), Some(PATH_USD));
    assert_eq!(
        challenge_currencies(&mpp.charge("1").unwrap()),
        [PATH_USD, OUSD, USDC]
    );

    // Owned strings are accepted too.
    let custom = "0x9999999999999999999999999999999999999999".to_string();
    assert_eq!(
        created_currencies(
            offers_builder()
                .chain_id(CHAIN_ID)
                .currencies(vec![custom.clone()])
        ),
        [custom]
    );
}

#[cfg(feature = "tempo")]
#[test]
fn test_single_element_currencies_list() {
    use crate::protocol::methods::tempo::{MODERATO_CHAIN_ID, USDC};

    let mpp = Mpp::create(
        offers_builder()
            .chain_id(MODERATO_CHAIN_ID)
            .currencies([USDC]),
    )
    .unwrap();
    assert_eq!(mpp.currencies(), [USDC]);
    assert_eq!(challenge_currencies(&mpp.charge("1").unwrap()), [USDC]);
}

#[cfg(feature = "tempo")]
#[test]
fn test_legacy_currency_restricts_to_one_token() {
    use crate::protocol::methods::tempo::{MODERATO_CHAIN_ID, PATH_USD, USDC};

    let mainnet = Mpp::create(offers_builder().chain_id(CHAIN_ID).currency(PATH_USD)).unwrap();
    assert_eq!(mainnet.currencies(), [PATH_USD]);
    assert_eq!(
        challenge_currencies(&mainnet.charge("1").unwrap()),
        [PATH_USD]
    );

    let moderato =
        Mpp::create(offers_builder().chain_id(MODERATO_CHAIN_ID).currency(USDC)).unwrap();
    assert_eq!(moderato.currencies(), [USDC]);
    assert_eq!(moderato.currency(), Some(USDC));
}

#[cfg(feature = "tempo")]
#[test]
fn test_currency_and_currencies_together_is_an_error() {
    use crate::protocol::methods::tempo::{OUSD, USDC};

    let err = create_error(
        offers_builder()
            .chain_id(CHAIN_ID)
            .currency(USDC)
            .currencies([OUSD]),
    );
    assert!(
        err.contains("Specify either `currency` or `currencies`, not both."),
        "{err}"
    );

    // Order of builder calls does not matter.
    let err = create_error(offers_builder().currencies([OUSD]).currency(USDC));
    assert!(err.contains("not both"), "{err}");
}

#[cfg(feature = "tempo")]
#[test]
fn test_empty_currencies_is_an_error() {
    let err = create_error(
        offers_builder()
            .chain_id(CHAIN_ID)
            .currencies(Vec::<String>::new()),
    );
    assert!(err.contains("`currencies` must not be empty"), "{err}");
}

#[cfg(feature = "tempo")]
#[test]
fn test_duplicate_currencies_dedupe_case_insensitively() {
    use crate::protocol::methods::tempo::{OUSD, USDC};

    let mpp = Mpp::create(offers_builder().chain_id(CHAIN_ID).currencies([
        OUSD.to_string(),
        USDC.to_lowercase(),
        OUSD.to_lowercase(),
        USDC.to_string(),
        format!("0x{}", OUSD[2..].to_uppercase()),
    ]))
    .unwrap();
    // First occurrence wins, including its spelling.
    assert_eq!(mpp.currencies(), [OUSD.to_string(), USDC.to_lowercase()]);
    assert_eq!(mpp.charge("1").unwrap().len(), 2);
}

#[cfg(feature = "tempo")]
#[test]
fn test_invalid_currency_address_is_an_error() {
    use crate::protocol::methods::tempo::OUSD;

    for invalid in [
        "not-an-address",
        "0x1234",
        "",
        "0xzz00000000000000000000000000000000000000",
    ] {
        let err = create_error(
            offers_builder()
                .chain_id(CHAIN_ID)
                .currencies([OUSD, invalid]),
        );
        assert!(
            err.contains(&format!("Invalid Tempo currency address: {invalid}.")),
            "{err}"
        );
    }

    let err = create_error(offers_builder().currency("0xcustom_token_address"));
    assert!(err.contains("Invalid Tempo currency address"), "{err}");
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_credential_for_any_offered_currency_verifies() {
    use crate::protocol::methods::tempo::{OUSD, USDC};

    let mpp = success_mpp_from(offers_builder().chain_id(CHAIN_ID));
    let challenges = mpp.charge("0.10").unwrap();
    // The route-level expected request is built from the preferred offer.
    let expected: ChargeRequest = mpp
        .charge("0.10")
        .unwrap()
        .remove(0)
        .request
        .decode()
        .unwrap();
    assert_eq!(expected.currency, OUSD);

    for currency in [OUSD, USDC] {
        let credential = offered_credential(&challenges, currency);
        let receipt = mpp.verify_credential(&credential).await.unwrap();
        assert!(receipt.is_success(), "{currency} should verify");

        let receipt = mpp
            .verify_credential_with_expected_request(&credential, &expected)
            .await
            .unwrap();
        assert!(receipt.is_success(), "{currency} should match the route");
    }
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_credential_for_non_offered_currency_is_rejected() {
    use crate::protocol::methods::tempo::PATH_USD;

    let mpp = success_mpp_from(offers_builder().chain_id(CHAIN_ID));
    // Server-signed (valid HMAC) challenge for a token the route does not accept.
    let foreign = mpp
        .charge_challenge_with_options(
            &ChargeRequest {
                amount: "100000".into(),
                currency: PATH_USD.into(),
                recipient: Some(TEST_RECIPIENT.into()),
                method_details: Some(serde_json::json!({ "chainId": CHAIN_ID })),
                ..Default::default()
            },
            None,
            None,
        )
        .unwrap();
    let credential = PaymentCredential::new(foreign.to_echo(), PaymentPayload::hash("0x01"));

    let err = mpp.verify_credential(&credential).await.unwrap_err();
    assert_eq!(err.code, Some(ErrorCode::InvalidChallenge));
    assert!(
        err.message.contains("credential currency"),
        "{}",
        err.message
    );

    let expected: ChargeRequest = mpp
        .charge("0.10")
        .unwrap()
        .remove(0)
        .request
        .decode()
        .unwrap();
    let err = mpp
        .verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap_err();
    assert!(err.message.contains("Currency mismatch"), "{}", err.message);
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_expected_request_for_foreign_currency_stays_exact() {
    use crate::protocol::methods::tempo::{OUSD, PATH_USD};

    // An expected request that names a currency outside the accepted set
    // (per-request override) still requires an exact currency match.
    let mpp = success_mpp_from(offers_builder().chain_id(CHAIN_ID));
    let challenges = mpp.charge("0.10").unwrap();
    let credential = offered_credential(&challenges, OUSD);
    let mut expected: ChargeRequest = challenges[0].request.decode().unwrap();
    expected.currency = PATH_USD.into();

    let err = mpp
        .verify_credential_with_expected_request(&credential, &expected)
        .await
        .unwrap_err();
    assert!(err.message.contains("Currency mismatch"), "{}", err.message);
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_expected_request_binds_external_id() {
    use crate::protocol::methods::tempo::OUSD;

    let mpp = success_mpp_from(offers_builder().chain_id(CHAIN_ID));
    let challenges = mpp
        .charge_with_options(
            "0.10",
            ChargeOptions {
                external_id: Some("order-1"),
                ..Default::default()
            },
        )
        .unwrap();
    let credential = offered_credential(&challenges, OUSD);
    let issued: ChargeRequest = challenges[0].request.decode().unwrap();

    // Another order at the same price, and a route that expects no order id.
    for external_id in [Some("order-2".to_string()), None] {
        let expected = ChargeRequest {
            external_id,
            ..issued.clone()
        };
        let err = mpp
            .verify_credential_with_expected_request(&credential, &expected)
            .await
            .unwrap_err();
        assert!(
            err.message.contains("External ID mismatch"),
            "{}",
            err.message
        );
    }

    assert!(mpp
        .verify_credential_with_expected_request(&credential, &issued)
        .await
        .is_ok());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_legacy_currency_rejects_other_default_offers() {
    use crate::protocol::methods::tempo::{OUSD, USDC};

    let mpp = success_mpp_from(offers_builder().chain_id(CHAIN_ID).currency(USDC));
    let ousd_offer = success_mpp_from(offers_builder().chain_id(CHAIN_ID))
        .charge("0.10")
        .unwrap();
    let credential = offered_credential(&ousd_offer, OUSD);

    let err = mpp.verify_credential(&credential).await.unwrap_err();
    assert!(
        err.message.contains("credential currency"),
        "{}",
        err.message
    );

    let usdc = offered_credential(&mpp.charge("0.10").unwrap(), USDC);
    assert!(mpp.verify_credential(&usdc).await.is_ok());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_per_request_currency_override_still_works() {
    use crate::protocol::methods::tempo::{OUSD, USDC};

    let mpp = success_mpp_from(offers_builder().chain_id(CHAIN_ID));

    // Overriding with an accepted currency issues exactly that one offer.
    let challenge = mpp
        .charge_challenge_with_options(
            &ChargeRequest {
                amount: "100000".into(),
                currency: USDC.into(),
                recipient: Some(TEST_RECIPIENT.into()),
                method_details: Some(serde_json::json!({ "chainId": CHAIN_ID })),
                ..Default::default()
            },
            None,
            None,
        )
        .unwrap();
    let request: ChargeRequest = challenge.request.decode().unwrap();
    assert_eq!(request.currency, USDC);
    let credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0x01"));
    assert!(mpp.verify_credential(&credential).await.is_ok());

    // Unbound handlers accept whatever currency the request names, as before.
    let unbound = Mpp::new(TempoSuccessMethod, "MPP Payment", TEST_SECRET);
    assert!(unbound.currencies().is_empty());
    assert!(unbound.currency().is_none());
    let challenge = unbound
        .charge_challenge("100000", OUSD, TEST_RECIPIENT)
        .unwrap();
    let credential = PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0x01"));
    assert!(unbound.verify_credential(&credential).await.is_ok());
    assert!(unbound.charge("1").is_err());
}

#[cfg(feature = "tempo")]
#[tokio::test]
async fn test_charges_with_body_bind_every_offer() {
    use crate::protocol::methods::tempo::{OUSD, USDC};

    let mpp = success_mpp_from(offers_builder().chain_id(CHAIN_ID));
    let body = br#"{"query":"paid"}"#;
    let challenges = mpp
        .charge_with_options_and_body(
            "0.10",
            ChargeOptions {
                description: Some("offer"),
                ..Default::default()
            },
            body,
        )
        .unwrap();
    assert_eq!(challenge_currencies(&challenges), [OUSD, USDC]);
    let digest = crate::body_digest::compute(body);
    for currency in [OUSD, USDC] {
        let credential = offered_credential(&challenges, currency);
        assert_eq!(
            credential.challenge.digest.as_deref(),
            Some(digest.as_str())
        );
        assert!(mpp
            .verify_credential_with_body(&credential, body)
            .await
            .is_ok());
        assert!(mpp
            .verify_credential_with_body(&credential, b"tampered")
            .await
            .is_err());
    }
    assert!(challenges
        .iter()
        .all(|challenge| challenge.description.as_deref() == Some("offer")));
}

#[cfg(feature = "tempo")]
#[test]
fn test_fee_payer_allowed_fee_token_defaults_match_mppx() {
    use crate::protocol::methods::tempo::{MODERATO_CHAIN_ID, OUSD, PATH_USD, USDC};

    let usdc: Address = USDC.parse().unwrap();
    let path_usd: Address = PATH_USD.parse().unwrap();
    let ousd: Address = OUSD.parse().unwrap();
    assert_eq!(
        FeePayerPolicy::default_allowed_fee_tokens(CHAIN_ID),
        vec![path_usd, usdc]
    );
    assert_eq!(
        FeePayerPolicy::default_allowed_fee_tokens(MODERATO_CHAIN_ID),
        vec![path_usd]
    );
    assert_eq!(
        FeePayerPolicy::default_allowed_fee_tokens(31337),
        vec![path_usd]
    );
    // OUSD is accepted as a charge currency but never as a default fee token.
    for chain_id in [CHAIN_ID, MODERATO_CHAIN_ID, 31337] {
        assert!(!FeePayerPolicy::default_allows_fee_token(chain_id, ousd));
    }
    // The single-value network defaults are untouched.
    assert_eq!(DEFAULT_CURRENCY_MAINNET, USDC);
    assert_eq!(DEFAULT_CURRENCY_TESTNET, PATH_USD);
}

#[cfg(feature = "tempo")]
#[test]
fn test_fee_payer_defaults_emit_every_offer() {
    use crate::protocol::methods::tempo::{MODERATO_CHAIN_ID, OUSD, PATH_USD, USDC};

    let sponsored = |chain_id| {
        offers_builder()
            .chain_id(chain_id)
            .fee_payer(true)
            .fee_payer_signer(alloy::signers::local::PrivateKeySigner::random())
    };

    let mainnet = Mpp::create(sponsored(CHAIN_ID)).unwrap();
    assert_eq!(mainnet.currencies(), [OUSD, USDC]);
    let offers = mainnet.charge("1").unwrap();
    assert_eq!(challenge_currencies(&offers), [OUSD, USDC]);
    assert!(offers
        .iter()
        .all(|c| c.request.decode::<ChargeRequest>().unwrap().fee_payer()));

    let moderato = Mpp::create(sponsored(MODERATO_CHAIN_ID)).unwrap();
    assert_eq!(
        challenge_currencies(&moderato.charge("1").unwrap()),
        [OUSD, PATH_USD]
    );

    // A custom allowlist or fee token does not change the offers.
    let custom = Mpp::create(
        sponsored(CHAIN_ID)
            .fee_payer_allowed_fee_tokens(vec![USDC.parse().unwrap()])
            .fee_payer_fee_token(USDC.parse().unwrap()),
    )
    .unwrap();
    assert_eq!(custom.currencies(), [OUSD, USDC]);
}

#[cfg(feature = "tempo")]
#[test]
fn test_per_request_fee_payer_offers_ousd() {
    use crate::protocol::methods::tempo::{OUSD, USDC};

    let mpp = Mpp::create(
        offers_builder()
            .chain_id(CHAIN_ID)
            .fee_payer_signer(alloy::signers::local::PrivateKeySigner::random()),
    )
    .unwrap();
    assert!(!mpp.fee_payer());
    let offers = mpp
        .charge_with_options(
            "1",
            ChargeOptions {
                fee_payer: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(challenge_currencies(&offers), [OUSD, USDC]);
    for offer in &offers {
        let request: ChargeRequest = offer.request.decode().unwrap();
        assert!(request.fee_payer());
    }
}
