//! Automatic client-side payments for MCP tool calls.
//!
//! [`McpClient`] owns the payment retry and provider lifecycle while
//! [`ToolCaller`] adapts a concrete MCP SDK. The wrapper deliberately knows
//! nothing about one SDK's request, result, or error types.

use std::{future::Future, sync::Mutex};

use thiserror::Error;

pub use crate::client::PendingPayment;
use crate::{
    client::{
        challenge_selection::{
            expired_payment_error, select_supported_challenge, ChallengeSelectionError,
        },
        ManagementFuture, ManagementTransport, PaymentContext, PaymentProvider,
    },
    MppError, PaymentChallenge, PaymentCredential, Receipt,
};

/// Adapts one concrete MCP SDK's tool-call boundary.
///
/// Implementations identify payment challenges in both JSON-RPC errors and
/// successful tool results, attach a typed credential to request metadata,
/// and distinguish definitive server rejection from ambiguous delivery
/// failure. Ambiguous failures are never rolled back.
pub trait ToolCaller: Send + Sync {
    /// SDK-specific tool-call parameters.
    type Params: Clone + Send;
    /// SDK-specific successful tool result.
    type Output: Send;
    /// SDK-specific tool-call error.
    type Error: Send;

    /// Calls one MCP tool exactly once.
    fn call_tool(
        &self,
        params: Self::Params,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send;

    /// Extracts valid payment challenges from a JSON-RPC error.
    ///
    /// Both payment-required (`-32042`) and verification-failed (`-32043`)
    /// errors carry challenges; see [`is_payment_required`](super::is_payment_required).
    fn payment_challenges_from_error(&self, error: &Self::Error) -> Option<Vec<PaymentChallenge>>;

    /// Extracts valid payment challenges from tool-result metadata.
    fn payment_challenges_from_output(
        &self,
        _output: &Self::Output,
    ) -> Option<Vec<PaymentChallenge>> {
        None
    }

    /// Extracts the payment receipt from tool-result metadata, such as
    /// [`extract_receipt`](super::extract_receipt) of its `_meta`.
    ///
    /// Session providers learn what each call charged from it, and session
    /// management calls (top-ups and closes) return it.
    fn receipt_from_output(&self, _output: &Self::Output) -> Option<Receipt> {
        None
    }

    /// Adds a payment credential to the outgoing request metadata.
    fn attach_credential(
        &self,
        params: &mut Self::Params,
        credential: &PaymentCredential,
    ) -> Result<(), MppError>;

    /// Returns whether the server definitively rejected the paid retry.
    ///
    /// Transport errors and cancellation must return `false`: the server may
    /// have accepted the credential even when the response was lost.
    fn is_definitive_error(&self, _error: &Self::Error) -> bool {
        false
    }
}

/// Failure from an automatic paid MCP tool call.
#[derive(Debug, Error)]
pub enum McpClientError<E> {
    /// The underlying MCP SDK failed.
    #[error("MCP tool call failed: {0}")]
    Transport(E),
    /// Payment challenge selection, credential creation, or reconciliation failed.
    #[error(transparent)]
    Payment(#[from] MppError),
}

/// Provider-backed payment preparation for an MCP transport.
///
/// This lower-level API lets an MCP SDK adapter own its native request and
/// retry types while MPP owns challenge selection and payment lifecycle.
#[derive(Clone)]
pub struct McpPayment<P> {
    provider: P,
    context: PaymentContext,
}

impl<P> McpPayment<P> {
    /// Creates payment state for one MCP resource.
    pub fn new(provider: P, context: PaymentContext) -> Self {
        Self { provider, context }
    }

    /// Returns the payment provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Returns the challenged resource context.
    pub fn context(&self) -> &PaymentContext {
        &self.context
    }
}

impl<P> McpPayment<P>
where
    P: PaymentProvider,
{
    /// Selects and pays one supported challenge.
    ///
    /// When paying the preferred challenge fails, for example because the
    /// wallet cannot fund a session's suggested deposit, the next supported
    /// challenge in preference order is paid instead, such as the server's
    /// one-time charge. The first failure is returned when none can be paid.
    ///
    /// Returns `Ok(None)` when the provider supports none of the challenges,
    /// so the caller can preserve the original MCP result or error.
    pub async fn prepare(
        &self,
        challenges: &[PaymentChallenge],
    ) -> Result<Option<PendingPayment<P>>, MppError> {
        self.prepare_inner(challenges, None).await
    }

    /// Selects and pays one supported challenge like [`prepare`](Self::prepare),
    /// sending any management credential the payment needs first, such as a
    /// session top-up when the channel's deposit does not cover the call,
    /// through `management`, for example an [`McpManagement`] for the same
    /// tool call.
    pub async fn prepare_with_management(
        &self,
        challenges: &[PaymentChallenge],
        management: &dyn ManagementTransport,
    ) -> Result<Option<PendingPayment<P>>, MppError> {
        self.prepare_inner(challenges, Some(management)).await
    }

    /// Records the receipt of a paid call that accepted `challenge`'s credential
    /// and returns what it charged when the provider tracks it, such as the
    /// change in a session channel's `spent`.
    pub fn record_receipt(&self, challenge: &PaymentChallenge, receipt: &Receipt) -> Option<u128> {
        self.provider
            .record_receipt(&self.context, challenge, receipt)
    }

    async fn prepare_inner(
        &self,
        challenges: &[PaymentChallenge],
        management: Option<&dyn ManagementTransport>,
    ) -> Result<Option<PendingPayment<P>>, MppError> {
        let ranking = self.provider.accept_payment_header();
        let mut remaining = challenges.to_vec();
        let mut failure = None;
        loop {
            let challenge = match select_supported_challenge(
                &remaining,
                ranking.as_deref(),
                |challenge| {
                    self.provider
                        .supports(challenge.method.as_str(), challenge.intent.as_str())
                },
                |candidates| self.provider.select_challenge(candidates),
            ) {
                Ok(challenge) => challenge.clone(),
                Err(ChallengeSelectionError::Expired(challenge)) => {
                    return Err(failure.unwrap_or_else(|| expired_payment_error(&challenge)));
                }
                Err(ChallengeSelectionError::NoSupportedChallenge(_)) => {
                    return failure.map_or(Ok(None), Err);
                }
            };

            if crate::client::is_cross_realm_proof_with_trust(
                &challenge,
                &self.context.url,
                &self.context.headers,
                self.provider.trusted_tempo_proof_realm(&self.context.url),
            ) {
                return Err(MppError::InvalidConfig(
                    "refusing to sign Tempo proof for a different HTTP realm".into(),
                ));
            }

            let paid = match management {
                Some(management) => {
                    self.provider
                        .pay_with_management(&challenge, self.context.clone(), management)
                        .await
                }
                None => {
                    self.provider
                        .pay_with_context(&challenge, self.context.clone())
                        .await
                }
            };
            match paid {
                Ok(credential) => {
                    return Ok(Some(PendingPayment::new(
                        self.provider.clone(),
                        challenge,
                        credential,
                    )));
                }
                Err(error) => {
                    failure.get_or_insert(error);
                    remaining.retain(|candidate| {
                        candidate.id != challenge.id
                            || candidate.method != challenge.method
                            || candidate.intent != challenge.intent
                    });
                }
            }
        }
    }
}

/// Sends session management credentials as a repeat of one MCP tool call,
/// with the credential in its `_meta`, as MPP servers on MCP accept them.
///
/// The server answers a top-up or close with a result carrying only its
/// receipt; a result asking for payment again rejects the credential.
pub struct McpManagement<'a, C: ToolCaller> {
    caller: &'a C,
    params: Mutex<C::Params>,
}

impl<'a, C: ToolCaller> McpManagement<'a, C> {
    /// Sends management credentials through `caller` as `params` with the
    /// credential attached.
    pub fn new(caller: &'a C, params: C::Params) -> Self {
        Self {
            caller,
            params: Mutex::new(params),
        }
    }
}

impl<C: ToolCaller> ManagementTransport for McpManagement<'_, C> {
    fn send<'b>(
        &'b self,
        _challenge: &'b PaymentChallenge,
        credential: &'b PaymentCredential,
    ) -> ManagementFuture<'b> {
        Box::pin(async move {
            let mut params = self.params.lock().unwrap().clone();
            self.caller.attach_credential(&mut params, credential)?;
            let output = self.caller.call_tool(params).await.map_err(|error| {
                // Only a definitive rejection (-32042 or -32043, as reported by
                // is_definitive_error) means the credential was refused. Other
                // errors, even ones carrying challenges such as -32603
                // internal-payment-error after a broadcast, leave the top-up
                // outcome unknown.
                if self.caller.is_definitive_error(&error) {
                    MppError::InvalidConfig(
                        "the MCP server rejected the payment management credential".to_owned(),
                    )
                } else {
                    MppError::Http("MCP payment management call failed".to_owned())
                }
            })?;
            if self
                .caller
                .payment_challenges_from_output(&output)
                .is_some()
            {
                return Err(MppError::InvalidConfig(
                    "the MCP server rejected the payment management credential".to_owned(),
                ));
            }
            Ok(self.caller.receipt_from_output(&output))
        })
    }
}

/// An MCP tool caller wrapped with automatic MPP payment handling.
#[derive(Clone)]
pub struct McpClient<C, P> {
    caller: C,
    payment: McpPayment<P>,
}

/// Wraps an MCP SDK adapter with automatic MPP payment handling.
pub fn wrap<C, P>(caller: C, provider: P, context: PaymentContext) -> McpClient<C, P> {
    McpClient::new(caller, provider, context)
}

impl<C, P> McpClient<C, P> {
    /// Wraps an MCP SDK adapter with the supplied payment provider and resource context.
    pub fn new(caller: C, provider: P, context: PaymentContext) -> Self {
        Self {
            caller,
            payment: McpPayment::new(provider, context),
        }
    }

    /// Returns the wrapped MCP SDK adapter.
    pub fn caller(&self) -> &C {
        &self.caller
    }

    /// Consumes the wrapper and returns the MCP SDK adapter.
    pub fn into_caller(self) -> C {
        self.caller
    }

    /// Sends session management credentials as `params`, a call of a paid
    /// tool, for example to close a session channel with
    /// [`TempoSessionProvider::close_with`](crate::client::TempoSessionProvider::close_with).
    pub fn management(&self, params: C::Params) -> McpManagement<'_, C>
    where
        C: ToolCaller,
    {
        McpManagement::new(&self.caller, params)
    }
}

impl<C, P> McpClient<C, P>
where
    C: ToolCaller,
    P: PaymentProvider,
{
    /// Calls a tool, satisfying one MCP payment challenge when necessary.
    ///
    /// Free calls pass through unchanged. A supported, unexpired challenge is
    /// paid once and the exact request is retried with its credential in
    /// `_meta`. A session channel whose deposit does not cover the call is
    /// topped up first by the same call carrying the top-up credential.
    /// Successful retries record their receipt and commit provider state.
    /// Definitive rejection rolls it back; cancellation and transport
    /// ambiguity invoke only the provider's synchronous abandonment hook.
    pub async fn call_tool(
        &self,
        params: C::Params,
    ) -> Result<C::Output, McpClientError<C::Error>> {
        let initial = self.caller.call_tool(params.clone()).await;
        let challenges = match &initial {
            Ok(output) => self.caller.payment_challenges_from_output(output),
            Err(error) => self.caller.payment_challenges_from_error(error),
        };
        let Some(challenges) = challenges else {
            return initial.map_err(McpClientError::Transport);
        };

        let management = McpManagement::new(&self.caller, params.clone());
        let Some(pending) = self
            .payment
            .prepare_with_management(&challenges, &management)
            .await?
        else {
            return initial.map_err(McpClientError::Transport);
        };

        let mut paid = params;
        if let Err(error) = self
            .caller
            .attach_credential(&mut paid, pending.credential())
        {
            pending.rollback().await?;
            return Err(error.into());
        }

        match self.caller.call_tool(paid).await {
            Ok(output) => {
                if self
                    .caller
                    .payment_challenges_from_output(&output)
                    .is_some()
                {
                    pending.rollback().await?;
                } else {
                    if let Some(receipt) = self.caller.receipt_from_output(&output) {
                        self.payment.record_receipt(pending.challenge(), &receipt);
                    }
                    pending.commit().await?;
                }
                Ok(output)
            }
            Err(error) if self.caller.is_definitive_error(&error) => {
                pending.rollback().await?;
                Err(McpClientError::Transport(error))
            }
            Err(error) => Err(McpClientError::Transport(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        future::pending,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use serde_json::{json, Value};

    use super::*;
    use crate::{
        mcp::{
            extract_receipt, extract_result_challenges, CREDENTIAL_META_KEY,
            PAYMENT_REQUIRED_META_KEY, RECEIPT_META_KEY,
        },
        Base64UrlJson, PaymentPayload,
    };

    #[derive(Default)]
    struct Lifecycle {
        abandons: AtomicUsize,
        commits: AtomicUsize,
        fail_commit: AtomicBool,
        management_receipts: Mutex<Vec<Option<Receipt>>>,
        pays: AtomicUsize,
        receipts: AtomicUsize,
        rollbacks: AtomicUsize,
    }

    #[derive(Clone)]
    struct TestProvider {
        lifecycle: Arc<Lifecycle>,
        supported: bool,
        tops_up: bool,
    }

    impl TestProvider {
        fn new() -> Self {
            Self {
                lifecycle: Arc::new(Lifecycle::default()),
                supported: true,
                tops_up: false,
            }
        }

        fn unsupported() -> Self {
            Self {
                supported: false,
                ..Self::new()
            }
        }

        fn topping_up() -> Self {
            Self {
                tops_up: true,
                ..Self::new()
            }
        }
    }

    impl PaymentProvider for TestProvider {
        fn supports(&self, method: &str, intent: &str) -> bool {
            self.supported && method == "tempo" && intent == "charge"
        }

        async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
            self.lifecycle.pays.fetch_add(1, Ordering::SeqCst);
            Ok(PaymentCredential::new(
                challenge.to_echo(),
                PaymentPayload::hash("test-proof"),
            ))
        }

        async fn pay_with_management(
            &self,
            challenge: &PaymentChallenge,
            _context: PaymentContext,
            management: &dyn ManagementTransport,
        ) -> Result<PaymentCredential, MppError> {
            if self.tops_up {
                let top_up =
                    PaymentCredential::new(challenge.to_echo(), PaymentPayload::hash("top-up"));
                let receipt = management.send(challenge, &top_up).await?;
                self.lifecycle
                    .management_receipts
                    .lock()
                    .unwrap()
                    .push(receipt);
            }
            self.pay(challenge).await
        }

        fn record_receipt(
            &self,
            _context: &PaymentContext,
            _challenge: &PaymentChallenge,
            _receipt: &Receipt,
        ) -> Option<u128> {
            self.lifecycle.receipts.fetch_add(1, Ordering::SeqCst);
            None
        }

        async fn commit_payment(
            &self,
            _challenge: &PaymentChallenge,
            _credential: &PaymentCredential,
        ) -> Result<(), MppError> {
            self.lifecycle.commits.fetch_add(1, Ordering::SeqCst);
            if self.lifecycle.fail_commit.load(Ordering::SeqCst) {
                Err(MppError::InvalidConfig(
                    "injected commit failure".to_owned(),
                ))
            } else {
                Ok(())
            }
        }

        async fn rollback_payment(
            &self,
            _challenge: &PaymentChallenge,
            _credential: &PaymentCredential,
        ) -> Result<(), MppError> {
            self.lifecycle.rollbacks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn abandon_payment(&self, _challenge: &PaymentChallenge, _credential: &PaymentCredential) {
            self.lifecycle.abandons.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[derive(Debug)]
    struct TestError {
        challenges: Option<Vec<PaymentChallenge>>,
        definitive: bool,
        message: &'static str,
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(self.message)
        }
    }

    impl std::error::Error for TestError {}

    #[derive(Clone)]
    struct TestCaller {
        calls: Arc<Mutex<Vec<Value>>>,
        outcomes: Arc<Mutex<VecDeque<Result<Value, TestError>>>>,
    }

    impl TestCaller {
        fn new(outcomes: impl IntoIterator<Item = Result<Value, TestError>>) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                outcomes: Arc::new(Mutex::new(outcomes.into_iter().collect())),
            }
        }
    }

    impl ToolCaller for TestCaller {
        type Params = Value;
        type Output = Value;
        type Error = TestError;

        async fn call_tool(&self, params: Self::Params) -> Result<Self::Output, Self::Error> {
            self.calls.lock().unwrap().push(params);
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .expect("test outcome")
        }

        fn payment_challenges_from_error(
            &self,
            error: &Self::Error,
        ) -> Option<Vec<PaymentChallenge>> {
            error.challenges.clone()
        }

        fn payment_challenges_from_output(
            &self,
            output: &Self::Output,
        ) -> Option<Vec<PaymentChallenge>> {
            output.get("_meta").and_then(extract_result_challenges)
        }

        fn receipt_from_output(&self, output: &Self::Output) -> Option<Receipt> {
            output.get("_meta").and_then(extract_receipt)
        }

        fn attach_credential(
            &self,
            params: &mut Self::Params,
            credential: &PaymentCredential,
        ) -> Result<(), MppError> {
            crate::mcp::attach_credential(params, credential);
            Ok(())
        }

        fn is_definitive_error(&self, error: &Self::Error) -> bool {
            error.definitive
        }
    }

    fn receipt_result(reference: &str) -> Value {
        json!({
            "content": [],
            "_meta": {
                RECEIPT_META_KEY: {
                    "status": "success",
                    "method": "tempo",
                    "timestamp": "2026-10-20T00:00:00Z",
                    "reference": reference,
                    "challengeId": "challenge-1",
                }
            }
        })
    }

    fn challenge() -> PaymentChallenge {
        PaymentChallenge::new(
            "challenge-1",
            "mcp.example.test",
            "tempo",
            "charge",
            Base64UrlJson::from_value(&json!({"amount": "1"})).unwrap(),
        )
    }

    fn payment_error(definitive: bool) -> TestError {
        TestError {
            challenges: Some(vec![challenge()]),
            definitive,
            message: "payment required",
        }
    }

    fn transport_error(definitive: bool) -> TestError {
        TestError {
            challenges: None,
            definitive,
            message: "tool failed",
        }
    }

    fn context() -> PaymentContext {
        PaymentContext {
            http_client: None,
            url: "https://mcp.example.test/mcp".parse().unwrap(),
            headers: reqwest::header::HeaderMap::new(),
        }
    }

    fn params() -> Value {
        json!({"name": "paid_tool", "arguments": {}})
    }

    #[tokio::test]
    async fn free_tool_calls_pass_through() {
        let caller = TestCaller::new([Ok(json!({"content": "free"}))]);
        let provider = TestProvider::new();
        let client = McpClient::new(caller.clone(), provider.clone(), context());

        let result = client.call_tool(params()).await.unwrap();

        assert_eq!(result["content"], "free");
        assert_eq!(caller.calls.lock().unwrap().len(), 1);
        assert_eq!(provider.lifecycle.pays.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn payment_errors_retry_once_and_commit() {
        let caller = TestCaller::new([Err(payment_error(true)), Ok(json!({"content": "paid"}))]);
        let provider = TestProvider::new();
        let client = McpClient::new(caller.clone(), provider.clone(), context());

        let result = client.call_tool(params()).await.unwrap();

        assert_eq!(result["content"], "paid");
        let calls = caller.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls[1]["_meta"].get(CREDENTIAL_META_KEY).is_some());
        assert_eq!(provider.lifecycle.pays.load(Ordering::SeqCst), 1);
        assert_eq!(provider.lifecycle.commits.load(Ordering::SeqCst), 1);
        assert_eq!(provider.lifecycle.rollbacks.load(Ordering::SeqCst), 0);
        assert_eq!(provider.lifecycle.abandons.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn payment_required_results_retry_once_and_commit() {
        let caller = TestCaller::new([
            Ok(json!({
                "_meta": {
                    PAYMENT_REQUIRED_META_KEY: {"challenges": [challenge()]}
                },
                "isError": true
            })),
            Ok(json!({"content": "paid"})),
        ]);
        let provider = TestProvider::new();
        let client = McpClient::new(caller, provider.clone(), context());

        let result = client.call_tool(params()).await.unwrap();

        assert_eq!(result["content"], "paid");
        assert_eq!(provider.lifecycle.commits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn paid_calls_record_their_receipt() {
        let caller = TestCaller::new([Err(payment_error(true)), Ok(receipt_result("0xpaid"))]);
        let provider = TestProvider::new();
        let client = McpClient::new(caller, provider.clone(), context());

        client.call_tool(params()).await.unwrap();

        assert_eq!(provider.lifecycle.receipts.load(Ordering::SeqCst), 1);
        assert_eq!(provider.lifecycle.commits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn management_credentials_repeat_the_tool_call() {
        let caller = TestCaller::new([
            Err(payment_error(true)),
            Ok(receipt_result("0xtopup")),
            Ok(json!({"content": "paid"})),
        ]);
        let provider = TestProvider::topping_up();
        let client = McpClient::new(caller.clone(), provider.clone(), context());

        let result = client.call_tool(params()).await.unwrap();

        assert_eq!(result["content"], "paid");
        let calls = caller.calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[1]["name"], "paid_tool");
        let top_up = crate::mcp::extract_credential(&calls[1]["_meta"]).unwrap();
        assert_eq!(top_up.charge_payload().unwrap().tx_hash(), Some("top-up"));
        assert!(calls[2]["_meta"].get(CREDENTIAL_META_KEY).is_some());
        let receipts = provider.lifecycle.management_receipts.lock().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].as_ref().unwrap().reference, "0xtopup");
        assert_eq!(provider.lifecycle.commits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn rejected_management_credentials_fail_the_payment() {
        let caller = TestCaller::new([
            Err(payment_error(true)),
            Ok(json!({
                "_meta": {
                    PAYMENT_REQUIRED_META_KEY: {"challenges": [challenge()]}
                },
                "isError": true
            })),
        ]);
        let provider = TestProvider::topping_up();
        let client = McpClient::new(caller, provider.clone(), context());

        let error = client.call_tool(params()).await.unwrap_err();

        assert!(matches!(error, McpClientError::Payment(_)));
        assert_eq!(provider.lifecycle.pays.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn definitive_management_rejections_are_not_transport_failures() {
        let credential = PaymentCredential::new(challenge().to_echo(), PaymentPayload::hash("x"));
        for (outcome, ambiguous) in [
            (payment_error(true), false),
            // Challenges alone (for example -32603 internal-payment-error after
            // a broadcast) do not make a rejection definitive.
            (payment_error(false), true),
            (transport_error(true), false),
            (transport_error(false), true),
        ] {
            let caller = TestCaller::new([Err(outcome)]);
            let management = McpManagement::new(&caller, params());
            let error = management
                .send(&challenge(), &credential)
                .await
                .unwrap_err();
            // Sessions treat only MppError::Http as an unknown top-up outcome.
            assert_eq!(matches!(error, MppError::Http(_)), ambiguous, "{error}");
        }
    }

    #[derive(Clone, Default)]
    struct UnfundedSessionProvider {
        paid: Arc<Mutex<Vec<String>>>,
    }

    impl PaymentProvider for UnfundedSessionProvider {
        fn supports(&self, method: &str, intent: &str) -> bool {
            method == "tempo" && (intent == "session" || intent == "charge")
        }

        async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
            if challenge.intent.as_str() == "session" {
                return Err(MppError::InvalidConfig(
                    "insufficient balance for the suggested deposit".to_owned(),
                ));
            }
            self.paid.lock().unwrap().push(challenge.id.clone());
            Ok(PaymentCredential::new(
                challenge.to_echo(),
                PaymentPayload::hash("charge"),
            ))
        }
    }

    #[tokio::test]
    async fn unpayable_preferred_challenges_fall_back_to_the_next() {
        let session = PaymentChallenge::new(
            "session-1",
            "mcp.example.test",
            "tempo",
            "session",
            Base64UrlJson::from_value(&json!({"amount": "1"})).unwrap(),
        );
        let provider = UnfundedSessionProvider::default();
        let payment = McpPayment::new(provider.clone(), context());

        let pending = payment
            .prepare(&[session.clone(), challenge()])
            .await
            .unwrap()
            .unwrap();

        assert_eq!(pending.challenge().id, "challenge-1");
        assert_eq!(
            *provider.paid.lock().unwrap(),
            vec!["challenge-1".to_owned()]
        );
        pending.commit().await.unwrap();

        let error = payment.prepare(&[session]).await.err().unwrap();
        assert!(error.to_string().contains("insufficient balance"));
    }

    #[tokio::test]
    async fn unsupported_challenges_preserve_the_original_error() {
        let caller = TestCaller::new([Err(payment_error(true))]);
        let provider = TestProvider::unsupported();
        let client = McpClient::new(caller, provider.clone(), context());

        let error = client.call_tool(params()).await.unwrap_err();

        assert!(matches!(error, McpClientError::Transport(_)));
        assert_eq!(provider.lifecycle.pays.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn definitive_rejection_rolls_back() {
        let caller = TestCaller::new([Err(payment_error(true)), Err(transport_error(true))]);
        let provider = TestProvider::new();
        let client = McpClient::new(caller, provider.clone(), context());

        let error = client.call_tool(params()).await.unwrap_err();

        assert!(matches!(error, McpClientError::Transport(_)));
        assert_eq!(provider.lifecycle.rollbacks.load(Ordering::SeqCst), 1);
        assert_eq!(provider.lifecycle.abandons.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn ambiguous_delivery_only_abandons_transient_state() {
        let caller = TestCaller::new([Err(payment_error(true)), Err(transport_error(false))]);
        let provider = TestProvider::new();
        let client = McpClient::new(caller, provider.clone(), context());

        let error = client.call_tool(params()).await.unwrap_err();

        assert!(matches!(error, McpClientError::Transport(_)));
        assert_eq!(provider.lifecycle.rollbacks.load(Ordering::SeqCst), 0);
        assert_eq!(provider.lifecycle.abandons.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn commit_failure_preserves_ambiguous_payment_state() {
        let caller = TestCaller::new([Err(payment_error(true)), Ok(json!({"content": "paid"}))]);
        let provider = TestProvider::new();
        provider.lifecycle.fail_commit.store(true, Ordering::SeqCst);
        let client = McpClient::new(caller, provider.clone(), context());

        let error = client.call_tool(params()).await.unwrap_err();

        assert!(matches!(error, McpClientError::Payment(_)));
        assert_eq!(provider.lifecycle.commits.load(Ordering::SeqCst), 1);
        assert_eq!(provider.lifecycle.rollbacks.load(Ordering::SeqCst), 0);
        assert_eq!(provider.lifecycle.abandons.load(Ordering::SeqCst), 1);
    }

    #[derive(Clone)]
    struct BlockingCaller {
        calls: Arc<AtomicUsize>,
    }

    impl ToolCaller for BlockingCaller {
        type Params = Value;
        type Output = Value;
        type Error = TestError;

        async fn call_tool(&self, _params: Self::Params) -> Result<Self::Output, Self::Error> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Err(payment_error(true))
            } else {
                pending().await
            }
        }

        fn payment_challenges_from_error(
            &self,
            error: &Self::Error,
        ) -> Option<Vec<PaymentChallenge>> {
            error.challenges.clone()
        }

        fn attach_credential(
            &self,
            params: &mut Self::Params,
            credential: &PaymentCredential,
        ) -> Result<(), MppError> {
            crate::mcp::attach_credential(params, credential);
            Ok(())
        }
    }

    #[tokio::test]
    async fn cancellation_abandons_transient_state_without_rollback() {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = TestProvider::new();
        let client = wrap(
            BlockingCaller {
                calls: Arc::clone(&calls),
            },
            provider.clone(),
            context(),
        );
        let task = tokio::spawn(async move { client.call_tool(params()).await });
        while calls.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }

        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        assert_eq!(provider.lifecycle.rollbacks.load(Ordering::SeqCst), 0);
        assert_eq!(provider.lifecycle.abandons.load(Ordering::SeqCst), 1);
    }
}
