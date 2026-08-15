//! Automatic client-side payments for MCP tool calls.
//!
//! [`McpClient`] owns the payment retry and provider lifecycle while
//! [`ToolCaller`] adapts a concrete MCP SDK. The wrapper deliberately knows
//! nothing about one SDK's request, result, or error types.

use std::future::Future;

use thiserror::Error;

use crate::{
    client::{
        challenge_selection::{
            expired_payment_error, select_supported_challenge, ChallengeSelectionError,
        },
        PaymentContext, PaymentProvider,
    },
    MppError, PaymentChallenge, PaymentCredential,
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
    fn payment_challenges_from_error(&self, error: &Self::Error) -> Option<Vec<PaymentChallenge>>;

    /// Extracts valid payment challenges from tool-result metadata.
    fn payment_challenges_from_output(
        &self,
        _output: &Self::Output,
    ) -> Option<Vec<PaymentChallenge>> {
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
    /// Returns `Ok(None)` when the provider supports none of the challenges,
    /// so the caller can preserve the original MCP result or error.
    pub async fn prepare(
        &self,
        challenges: &[PaymentChallenge],
    ) -> Result<Option<PendingPayment<P>>, MppError> {
        let ranking = self.provider.accept_payment_header();
        let challenge = match select_supported_challenge(
            challenges,
            ranking.as_deref(),
            |challenge| {
                self.provider
                    .supports(challenge.method.as_str(), challenge.intent.as_str())
            },
            |candidates| self.provider.select_challenge(candidates),
        ) {
            Ok(challenge) => challenge.clone(),
            Err(ChallengeSelectionError::Expired(challenge)) => {
                return Err(expired_payment_error(&challenge));
            }
            Err(ChallengeSelectionError::NoSupportedChallenge(_)) => return Ok(None),
        };

        let credential = self
            .provider
            .pay_with_context(&challenge, self.context.clone())
            .await?;
        Ok(Some(PendingPayment {
            provider: self.provider.clone(),
            challenge,
            credential,
            active: true,
        }))
    }
}

/// A prepared MCP payment awaiting a definitive delivery outcome.
///
/// Dropping an active payment invokes [`PaymentProvider::abandon_payment`],
/// which is the cancellation and ambiguous-delivery path. Call [`Self::commit`]
/// after acceptance or [`Self::rollback`] when the credential was not sent or
/// was definitively rejected.
pub struct PendingPayment<P: PaymentProvider> {
    provider: P,
    challenge: PaymentChallenge,
    credential: PaymentCredential,
    active: bool,
}

impl<P: PaymentProvider> PendingPayment<P> {
    /// Returns the selected challenge.
    pub fn challenge(&self) -> &PaymentChallenge {
        &self.challenge
    }

    /// Returns the credential to attach to MCP request metadata.
    pub fn credential(&self) -> &PaymentCredential {
        &self.credential
    }

    /// Commits provider state after the server accepts the credential.
    pub async fn commit(mut self) -> Result<(), MppError> {
        self.provider
            .commit_payment(&self.challenge, &self.credential)
            .await?;
        self.active = false;
        Ok(())
    }

    /// Rolls back provider state after definitive non-delivery or rejection.
    pub async fn rollback(mut self) -> Result<(), MppError> {
        self.provider
            .rollback_payment(&self.challenge, &self.credential)
            .await?;
        self.active = false;
        Ok(())
    }
}

impl<P: PaymentProvider> Drop for PendingPayment<P> {
    fn drop(&mut self) {
        if self.active {
            self.provider
                .abandon_payment(&self.challenge, &self.credential);
        }
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
    /// `_meta`. Successful retries commit provider state. Definitive rejection
    /// rolls it back; cancellation and transport ambiguity invoke only the
    /// provider's synchronous abandonment hook.
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

        let Some(pending) = self.payment.prepare(&challenges).await? else {
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
        mcp::{extract_result_challenges, CREDENTIAL_META_KEY, PAYMENT_REQUIRED_META_KEY},
        Base64UrlJson, PaymentPayload,
    };

    #[derive(Default)]
    struct Lifecycle {
        abandons: AtomicUsize,
        commits: AtomicUsize,
        fail_commit: AtomicBool,
        pays: AtomicUsize,
        rollbacks: AtomicUsize,
    }

    #[derive(Clone)]
    struct TestProvider {
        lifecycle: Arc<Lifecycle>,
        supported: bool,
    }

    impl TestProvider {
        fn new() -> Self {
            Self {
                lifecycle: Arc::new(Lifecycle::default()),
                supported: true,
            }
        }

        fn unsupported() -> Self {
            Self {
                lifecycle: Arc::new(Lifecycle::default()),
                supported: false,
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
