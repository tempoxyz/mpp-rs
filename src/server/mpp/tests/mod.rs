use super::*;
use crate::protocol::core::{ChallengeEcho, PaymentPayload};
#[cfg(feature = "tempo")]
use crate::protocol::methods::tempo::{
    FeePayerPolicy, TempoChargeExt, CHAIN_ID, DEFAULT_CURRENCY_MAINNET, DEFAULT_CURRENCY_TESTNET,
};
use crate::protocol::traits::ErrorCode;
#[cfg(feature = "tempo")]
use crate::server::{tempo, ChargeOptions, TempoConfig};
#[cfg(feature = "tempo")]
use alloy::primitives::Address;
use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

#[cfg(feature = "tempo")]
mod binding;
mod charge;
#[cfg(feature = "tempo")]
mod currencies;
mod lifecycle;
mod session;
#[cfg(feature = "stripe")]
mod stripe;
mod verify;

const TEST_SECRET: &str = "test-secret-key-at-least-32-bytes";

#[derive(Clone)]
struct MockMethod;

#[allow(clippy::manual_async_fn)]
impl ChargeMethod for MockMethod {
    fn method(&self) -> &str {
        "mock"
    }

    fn verify(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
        async { Ok(Receipt::success("mock", "mock_ref")) }
    }
}

#[derive(Clone)]
struct RecordingMethod {
    seen_request: Arc<Mutex<Option<ChargeRequest>>>,
}

#[allow(clippy::manual_async_fn)]
impl ChargeMethod for RecordingMethod {
    fn method(&self) -> &str {
        "mock"
    }

    fn verify(
        &self,
        _credential: &PaymentCredential,
        request: &ChargeRequest,
    ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
        let seen_request = self.seen_request.clone();
        let request = request.clone();
        async move {
            *seen_request.lock().unwrap() = Some(request);
            Ok(Receipt::success("mock", "0xabc123"))
        }
    }
}

#[derive(Clone)]
struct FailedTransactionMethod;

#[allow(clippy::manual_async_fn)]
impl ChargeMethod for FailedTransactionMethod {
    fn method(&self) -> &str {
        "mock"
    }

    fn verify(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
        async {
            Err(VerificationError::transaction_failed(
                "Transaction reverted on-chain",
            ))
        }
    }
}

fn test_credential(secret_key: &str) -> PaymentCredential {
    let request = "eyJ0ZXN0IjoidmFsdWUifQ";
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let id = crate::protocol::core::compute_challenge_id(
        secret_key,
        "api.example.com",
        "mock",
        "charge",
        request,
        Some(&expires),
        None,
        None,
    );

    let echo = ChallengeEcho {
        id,
        realm: "api.example.com".into(),
        method: "mock".into(),
        intent: "charge".into(),
        request: Base64UrlJson::from_raw(request),
        expires: Some(expires),
        description: None,
        digest: None,
        opaque: None,
        header: None,
    };
    PaymentCredential::new(echo, PaymentPayload::hash("0x123"))
}

fn test_request() -> ChargeRequest {
    ChargeRequest {
        amount: "1000".into(),
        currency: "0x123".into(),
        recipient: Some("0x456".into()),
        ..Default::default()
    }
}

fn test_credential_with_body_digest(secret_key: &str, body: &[u8]) -> PaymentCredential {
    test_lifecycle_credential(secret_key, Some(body))
}

fn test_lifecycle_credential(secret_key: &str, body: Option<&[u8]>) -> PaymentCredential {
    let request = test_request();
    let encoded = Base64UrlJson::from_typed(&request).unwrap();
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let digest = body.map(crate::body_digest::compute);
    let id = crate::protocol::core::compute_challenge_id(
        secret_key,
        "api.example.com",
        "mock",
        "charge",
        encoded.raw(),
        Some(&expires),
        digest.as_deref(),
        None,
    );

    let echo = ChallengeEcho {
        id,
        realm: "api.example.com".into(),
        method: "mock".into(),
        intent: "charge".into(),
        request: encoded,
        expires: Some(expires),
        description: None,
        digest,
        opaque: None,
        header: None,
    };
    PaymentCredential::new(echo, PaymentPayload::hash("0x123"))
}

#[cfg(feature = "tempo")]
fn create_test_mpp() -> Mpp<crate::server::TempoChargeMethod<crate::server::TempoProvider>> {
    Mpp::create(
        tempo(TempoConfig {
            recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
        })
        .secret_key(TEST_SECRET),
    )
    .unwrap()
}

/// A mock ChargeMethod that always returns a success receipt, using
/// the "tempo" method name so it matches challenges from create_test_mpp().
#[derive(Clone)]
struct TempoSuccessMethod;

#[allow(clippy::manual_async_fn)]
impl ChargeMethod for TempoSuccessMethod {
    fn method(&self) -> &str {
        "tempo"
    }

    fn verify(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
        async { Ok(Receipt::success("tempo", "0xtxhash")) }
    }
}

#[cfg(feature = "tempo")]
fn route_opaque() -> Base64UrlJson {
    Base64UrlJson::from_value(&serde_json::json!({"route": "a"})).unwrap()
}

#[cfg(feature = "tempo")]
const TEST_RECIPIENT: &str = "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2";

#[cfg(feature = "tempo")]
fn offers_builder() -> crate::server::TempoBuilder {
    tempo(TempoConfig {
        recipient: TEST_RECIPIENT,
    })
    .secret_key(TEST_SECRET)
}

/// Build an RPC-free handler with the same resolved configuration as
/// `Mpp::create(builder)`, so credentials can be verified end to end.
#[cfg(feature = "tempo")]
fn success_mpp_from(builder: crate::server::TempoBuilder) -> Mpp<TempoSuccessMethod> {
    let created = Mpp::create(builder).unwrap();
    Mpp {
        method: TempoSuccessMethod,
        session_method: None,
        realm: created.realm,
        secret_key: created.secret_key,
        currencies: created.currencies,
        recipient: created.recipient,
        decimals: created.decimals,
        fee_payer: created.fee_payer,
        machine_token_enabled: created.machine_token_enabled,
        chain_id: created.chain_id,
        opaque: created.opaque,
        credential_header: created.credential_header,
        events: created.events,
    }
}

#[cfg(feature = "tempo")]
fn offered_credential(challenges: &[PaymentChallenge], currency: &str) -> PaymentCredential {
    let challenge = challenges
        .iter()
        .find(|challenge| {
            challenge
                .request
                .decode::<ChargeRequest>()
                .unwrap()
                .currency
                == currency
        })
        .unwrap_or_else(|| panic!("no challenge offered for {currency}"));
    PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("0xdeadbeef"))
}
