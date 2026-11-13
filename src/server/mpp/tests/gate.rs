//! The gate an identity payment check uses runs after the Credential's HMAC
//! and pinned fields are checked, and before the payment settles.

use super::*;
use crate::server::CredentialGate;

#[derive(Clone)]
struct CountingMethod {
    settled: Arc<AtomicUsize>,
}

#[allow(clippy::manual_async_fn)]
impl ChargeMethod for CountingMethod {
    fn method(&self) -> &str {
        "mock"
    }

    fn verify(
        &self,
        _credential: &PaymentCredential,
        _request: &ChargeRequest,
    ) -> impl Future<Output = std::result::Result<Receipt, VerificationError>> + Send {
        let settled = self.settled.clone();
        async move {
            settled.fetch_add(1, Ordering::SeqCst);
            Ok(Receipt::success("mock", "0xsettled"))
        }
    }
}

struct Gate {
    admit: bool,
    runs: AtomicUsize,
}

impl CredentialGate for Gate {
    fn admit<'a>(
        &'a self,
        _credential: &'a PaymentCredential,
    ) -> std::pin::Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        self.runs.fetch_add(1, Ordering::SeqCst);
        Box::pin(std::future::ready(self.admit))
    }
}

fn credential_for(secret: &str, request: &ChargeRequest) -> PaymentCredential {
    let encoded = Base64UrlJson::from_typed(request).unwrap();
    let expires = (time::OffsetDateTime::now_utc() + time::Duration::minutes(5))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
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
    PaymentCredential::new(
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
    )
}

fn setup() -> (Mpp<CountingMethod>, Arc<AtomicUsize>, ChargeRequest) {
    let settled = Arc::new(AtomicUsize::new(0));
    let mpp = Mpp::new(
        CountingMethod {
            settled: settled.clone(),
        },
        "api.example.com",
        TEST_SECRET,
    );
    (mpp, settled, test_request())
}

#[tokio::test]
async fn refused_credential_never_settles() {
    let (mpp, settled, request) = setup();
    let credential = credential_for(TEST_SECRET, &request);
    let gate = Gate {
        admit: false,
        runs: AtomicUsize::new(0),
    };
    let receipt = mpp
        .verify_credential_with_expected_request_gated(&credential, &request, None, Some(&gate))
        .await
        .unwrap();
    assert!(receipt.is_none());
    assert_eq!(gate.runs.load(Ordering::SeqCst), 1);
    assert_eq!(settled.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn admitted_credential_settles() {
    let (mpp, settled, request) = setup();
    let credential = credential_for(TEST_SECRET, &request);
    let gate = Gate {
        admit: true,
        runs: AtomicUsize::new(0),
    };
    let receipt = mpp
        .verify_credential_with_expected_request_gated(&credential, &request, None, Some(&gate))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.reference, "0xsettled");
    assert_eq!(settled.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn gate_runs_only_after_the_hmac_and_route_checks() {
    let (mpp, settled, request) = setup();
    let gate = Gate {
        admit: true,
        runs: AtomicUsize::new(0),
    };
    // Another server's Challenge.
    let forged = credential_for("another-secret-key-at-least-32-bytes", &request);
    assert!(mpp
        .verify_credential_with_expected_request_gated(&forged, &request, None, Some(&gate))
        .await
        .is_err());
    // A Credential issued for another amount.
    let cheaper = ChargeRequest {
        amount: "1".into(),
        ..request.clone()
    };
    let credential = credential_for(TEST_SECRET, &cheaper);
    assert!(mpp
        .verify_credential_with_expected_request_gated(&credential, &request, None, Some(&gate))
        .await
        .is_err());
    assert_eq!(gate.runs.load(Ordering::SeqCst), 0);
    assert_eq!(settled.load(Ordering::SeqCst), 0);
}
