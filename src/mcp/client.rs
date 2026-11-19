//! Automatic client-side payments for MCP tool calls.
//!
//! [`McpClient`] owns the payment retry and provider lifecycle while
//! [`ToolCaller`] adapts a concrete MCP SDK. The wrapper deliberately knows
//! nothing about one SDK's request, result, or error types.

use std::{future::Future, sync::Mutex};

use thiserror::Error;

pub use super::PaymentAnswer;
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

    /// Classifies a JSON-RPC error answering a tool call, such as
    /// [`error_payment_answer`](super::error_payment_answer) of its error
    /// object when it carries payment challenges.
    ///
    /// Only [`PaymentAnswer::PaymentRequired`] starts a payment round. After
    /// a paid call, [`PaymentAnswer::ServerError`] ends the call without
    /// rolling the payment back, as the HTTP client treats a 5xx response,
    /// since the payment may have settled. Defaults to payment required
    /// whenever the error carries challenges.
    fn payment_answer_from_error(&self, error: &Self::Error) -> Option<PaymentAnswer> {
        self.payment_challenges_from_error(error)
            .map(|_| PaymentAnswer::PaymentRequired)
    }

    /// Classifies a tool result's payment requirement like
    /// [`payment_answer_from_error`](Self::payment_answer_from_error), such as
    /// [`result_payment_answer`](super::result_payment_answer) of its `_meta`.
    /// Defaults to payment required whenever the result carries challenges.
    fn payment_answer_from_output(&self, output: &Self::Output) -> Option<PaymentAnswer> {
        self.payment_challenges_from_output(output)
            .map(|_| PaymentAnswer::PaymentRequired)
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
    /// Selects and pays one supported challenge: the best-ranked by the
    /// caller's or provider's preferences.
    ///
    /// As in mppx, a failure to pay it is returned as is, without paying
    /// another offer: a failed payment cannot always prove no funds moved,
    /// so a second offer could pay twice.
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
        match self.select(challenges)? {
            Some(challenge) => self.pay(challenge, management).await.map(Some),
            None => Ok(None),
        }
    }

    /// Selects the best-ranked supported challenge, refusing an expired one
    /// or a Tempo proof for another realm. Returns `Ok(None)` when the
    /// provider supports none of them.
    fn select(
        &self,
        challenges: &[PaymentChallenge],
    ) -> Result<Option<PaymentChallenge>, MppError> {
        let mut preferences = self.context.headers.get_all("accept-payment").iter();
        let first = preferences.next();
        if preferences.next().is_some() {
            return Ok(None);
        }
        let ranking = if let Some(header) = first {
            let value = header.to_str().map_err(|_| {
                MppError::InvalidConfig("invalid caller Accept-Payment header".into())
            })?;
            if value.split(',').all(|part| part.trim().is_empty()) {
                return Ok(None);
            }
            crate::protocol::core::accept_payment::parse(value).map_err(|_| {
                MppError::InvalidConfig("invalid caller Accept-Payment header".into())
            })?;
            Some(value.to_owned())
        } else {
            self.provider.accept_payment_header()
        };
        // As mppx does, pay only the best-ranked offer and return its error
        // as is: trying another offer after a failure could pay twice.
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

        if crate::client::is_cross_realm_proof_with_trust(
            &challenge,
            &self.context.url,
            &self.context.headers,
            self.provider.trusted_tempo_proof_realm(&self.context.url),
        ) {
            return Err(MppError::InvalidConfig(
                "refusing to sign a Tempo proof or session payment for a different HTTP realm"
                    .into(),
            ));
        }
        Ok(Some(challenge))
    }

    /// Creates a credential for a challenge [`select`](Self::select) chose.
    async fn pay(
        &self,
        challenge: PaymentChallenge,
        management: Option<&dyn ManagementTransport>,
    ) -> Result<PendingPayment<P>, MppError> {
        // A Zone withdrawal still settling is resumed for this challenge,
        // not paid again.
        let credential = crate::client::resume_pending_settlement(
            crate::client::DEFAULT_MAX_PAYMENT_RETRIES,
            || async {
                match management {
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
                }
            },
        )
        .await?;
        Ok(PendingPayment::new(
            self.provider.clone(),
            challenge,
            credential,
        ))
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
    /// Calls a tool, satisfying MCP payment challenges when necessary.
    ///
    /// Free calls pass through unchanged. A supported, unexpired challenge is
    /// paid and the exact request is retried with its credential in `_meta`.
    /// A session channel whose deposit does not cover the call is topped up
    /// first by the same call carrying the top-up credential. Successful
    /// retries record their receipt and commit provider state. Definitive
    /// rejection rolls it back; cancellation and transport ambiguity invoke
    /// only the provider's synchronous abandonment hook.
    ///
    /// As mppx's client does, a paid retry answered with a new challenge,
    /// such as a server that refuses a zero-amount proof and then offers only
    /// its real charge, starts another round, up to
    /// [`DEFAULT_MAX_PAYMENT_RETRIES`](crate::client::DEFAULT_MAX_PAYMENT_RETRIES)
    /// Credentials sent. Each round selects and checks its challenge like the
    /// first.
    /// A Challenge offered again gets the same Credential resent, never a new
    /// payment. Only a payment requirement starts a round
    /// ([`ToolCaller::payment_answer_from_output`]): any other answer, one
    /// without a challenge the provider can pay, or a refused Credential whose
    /// payment already settled ends the call with the server's answer. A server
    /// failure may have settled the payment, so it is neither rolled back nor
    /// committed.
    pub async fn call_tool(
        &self,
        params: C::Params,
    ) -> Result<C::Output, McpClientError<C::Error>> {
        let mut response = self.caller.call_tool(params.clone()).await;
        // Only a payment requirement (HTTP 402) starts a payment round.
        if self.payment_answer(&response) != Some(PaymentAnswer::PaymentRequired) {
            return response.map_err(McpClientError::Transport);
        }
        // The last credential sent, answered by another payment requirement.
        let mut previous: Option<PendingPayment<P>> = None;
        for _ in 0..crate::client::DEFAULT_MAX_PAYMENT_RETRIES {
            let challenges = match &response {
                Ok(output) => self.caller.payment_challenges_from_output(output),
                Err(error) => self.caller.payment_challenges_from_error(error),
            }
            .unwrap_or_default();
            let selected = match self.payment.select(&challenges) {
                Ok(selected) => selected,
                Err(error) => {
                    // An expired or cross-realm Challenge ends the call, so a
                    // refused Credential is settled as refused first.
                    reject(previous.take()).await?;
                    return Err(error.into());
                }
            };
            let Some(challenge) = selected else {
                // Nothing payable after a credential is the server's final answer.
                reject(previous.take()).await?;
                return response.map_err(McpClientError::Transport);
            };

            let pending = match previous.take() {
                // The same Challenge again: resend its Credential rather than
                // paying it twice.
                Some(previous) if previous.challenge().id == challenge.id => previous,
                Some(previous) => {
                    // A refused hash or Zone credential's payment is already
                    // on chain: paying a new challenge would pay twice.
                    let settled = crate::client::flow::already_settled(previous.credential());
                    previous.rollback().await?;
                    if settled {
                        return response.map_err(McpClientError::Transport);
                    }
                    let management = McpManagement::new(&self.caller, params.clone());
                    self.payment.pay(challenge, Some(&management)).await?
                }
                None => {
                    let management = McpManagement::new(&self.caller, params.clone());
                    self.payment.pay(challenge, Some(&management)).await?
                }
            };

            let mut paid = params.clone();
            if let Err(error) = self
                .caller
                .attach_credential(&mut paid, pending.credential())
            {
                pending.rollback().await?;
                return Err(error.into());
            }

            response = self.caller.call_tool(paid).await;
            if let Err(error) = &response {
                // The server may have accepted a credential whose answer was
                // lost: leave the payment unsettled.
                if !self.caller.is_definitive_error(error) {
                    return response.map_err(McpClientError::Transport);
                }
            }
            match self.payment_answer(&response) {
                None => {
                    return match response {
                        Ok(output) => {
                            if let Some(receipt) = self.caller.receipt_from_output(&output) {
                                self.payment.record_receipt(pending.challenge(), &receipt);
                            }
                            pending.commit().await?;
                            Ok(output)
                        }
                        Err(error) => {
                            pending.rollback().await?;
                            Err(McpClientError::Transport(error))
                        }
                    };
                }
                // The server failed after taking the credential, so the
                // payment may have settled: like the HTTP client's 5xx, stop
                // without paying again or rolling back.
                Some(PaymentAnswer::ServerError) => {
                    return response.map_err(McpClientError::Transport)
                }
                Some(PaymentAnswer::Rejected) => {
                    pending.rollback().await?;
                    return response.map_err(McpClientError::Transport);
                }
                Some(PaymentAnswer::PaymentRequired) => previous = Some(pending),
            }
        }
        // The payment requirement answering the last round is final.
        reject(previous).await?;
        response.map_err(McpClientError::Transport)
    }

    fn payment_answer(&self, response: &Result<C::Output, C::Error>) -> Option<PaymentAnswer> {
        match response {
            Ok(output) => self.caller.payment_answer_from_output(output),
            Err(error) => self.caller.payment_answer_from_error(error),
        }
    }
}

/// Settles a previous round's Credential as refused: the server answered it
/// with a payment requirement that the call does not answer with it again.
async fn reject<P: PaymentProvider>(previous: Option<PendingPayment<P>>) -> Result<(), MppError> {
    match previous {
        Some(previous) => previous.rollback().await,
        None => Ok(()),
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
        server_error: bool,
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

        fn payment_answer_from_error(&self, error: &Self::Error) -> Option<PaymentAnswer> {
            if error.server_error {
                return Some(PaymentAnswer::ServerError);
            }
            error
                .challenges
                .as_ref()
                .map(|_| PaymentAnswer::PaymentRequired)
        }

        fn payment_answer_from_output(&self, output: &Self::Output) -> Option<PaymentAnswer> {
            output
                .get("_meta")
                .and_then(crate::mcp::result_payment_answer)
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
            server_error: false,
            message: "payment required",
        }
    }

    fn transport_error(definitive: bool) -> TestError {
        TestError {
            challenges: None,
            definitive,
            server_error: false,
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
    async fn caller_payment_preferences_control_credential_creation() {
        for (header, allowed, invalid) in [
            ("", false, false),
            (", ,", false, false),
            ("tempo/charge;q=0", false, false),
            ("stripe/charge", false, false),
            ("tempo/charge", true, false),
            ("tempo/charge;q=invalid", false, true),
        ] {
            let provider = TestProvider::new();
            let mut context = context();
            context
                .headers
                .insert("accept-payment", header.parse().unwrap());
            let session = McpPayment::new(provider.clone(), context);
            let result = session.prepare(&[challenge()]).await;
            if invalid {
                assert!(result.is_err(), "{header}");
            } else {
                assert_eq!(result.unwrap().is_some(), allowed, "{header}");
            }
            assert_eq!(
                provider.lifecycle.pays.load(Ordering::SeqCst),
                usize::from(allowed)
            );
        }
    }

    #[tokio::test]
    async fn repeated_caller_preferences_never_create_credentials() {
        let provider = TestProvider::new();
        let mut context = context();
        for value in ["*/*", "tempo/charge;q=0"] {
            context
                .headers
                .append("accept-payment", value.parse().unwrap());
        }
        let session = McpPayment::new(provider.clone(), context);
        assert!(session.prepare(&[challenge()]).await.unwrap().is_none());
        assert_eq!(provider.lifecycle.pays.load(Ordering::SeqCst), 0);
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
    async fn unpayable_preferred_challenge_is_not_replaced_by_the_next() {
        let session = PaymentChallenge::new(
            "session-1",
            "mcp.example.test",
            "tempo",
            "session",
            Base64UrlJson::from_value(&json!({"amount": "1"})).unwrap(),
        );
        let provider = UnfundedSessionProvider::default();
        let payment = McpPayment::new(provider.clone(), context());

        // As in mppx, only the preferred offer is paid and its error returned.
        let error = payment
            .prepare(&[session, challenge()])
            .await
            .err()
            .unwrap();

        assert!(error.to_string().contains("insufficient balance"));
        assert!(provider.paid.lock().unwrap().is_empty());
    }

    #[derive(Clone, Default)]
    struct AmbiguousProvider(Arc<AtomicUsize>, u8);

    impl PaymentProvider for AmbiguousProvider {
        fn supports(&self, method: &str, intent: &str) -> bool {
            method == "tempo" && intent == "charge"
        }
        async fn pay(&self, _: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(match self.1 {
                0 => MppError::PaymentOutcomeUnknown {
                    transaction_hash: "0x1234".into(),
                },
                1 => MppError::SessionPaymentOutcomeUnknown {
                    context: "top-up timed out".into(),
                },
                _ => MppError::ZoneWithdrawalBounced {
                    challenge_id: "challenge-1".into(),
                    sender_tag: "0x22".into(),
                    zone_id: 3,
                },
            })
        }
    }

    #[tokio::test]
    async fn ambiguous_payment_does_not_try_another_offer() {
        for kind in 0..3 {
            let provider = AmbiguousProvider(Arc::new(AtomicUsize::new(0)), kind);
            let payment = McpPayment::new(provider.clone(), context());
            let first = challenge();
            let mut second = challenge();
            second.id = "second-offer".into();
            let error = payment.prepare(&[first, second]).await.err().unwrap();
            assert!(matches!(
                error,
                MppError::PaymentOutcomeUnknown { .. }
                    | MppError::SessionPaymentOutcomeUnknown { .. }
                    | MppError::ZoneWithdrawalBounced { .. }
            ));
            assert_eq!(provider.0.load(Ordering::SeqCst), 1);
        }
    }

    /// Fails every payment with the error `fail` builds, counting attempts.
    #[derive(Clone)]
    struct FailingProvider {
        attempts: Arc<Mutex<Vec<String>>>,
        fail: fn() -> MppError,
    }

    impl FailingProvider {
        fn new(fail: fn() -> MppError) -> Self {
            Self {
                attempts: Arc::default(),
                fail,
            }
        }
    }

    impl PaymentProvider for FailingProvider {
        fn supports(&self, method: &str, intent: &str) -> bool {
            method == "tempo" && intent == "charge"
        }
        async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
            self.attempts.lock().unwrap().push(challenge.id.clone());
            Err((self.fail)())
        }
    }

    fn two_offers() -> [PaymentChallenge; 2] {
        let first = challenge();
        let mut second = challenge();
        second.id = "second-offer".into();
        [first, second]
    }

    #[tokio::test]
    async fn uncertain_failures_do_not_try_another_offer() {
        let cases: [fn() -> MppError; 3] = [
            || MppError::UnknownPaymentOutcome { reference: None },
            || MppError::UnknownPaymentOutcome {
                reference: Some("req-1".into()),
            },
            || MppError::Http("response lost".into()),
        ];
        for fail in cases {
            let provider = FailingProvider::new(fail);
            let payment = McpPayment::new(provider.clone(), context());
            let error = payment.prepare(&two_offers()).await.err().unwrap();
            assert_eq!(error.to_string(), fail().to_string());
            assert_eq!(
                *provider.attempts.lock().unwrap(),
                vec!["challenge-1".to_owned()]
            );
        }
    }

    #[tokio::test]
    async fn definitive_failures_do_not_try_another_offer() {
        let provider = FailingProvider::new(|| MppError::InsufficientBalance(Some("empty".into())));
        let payment = McpPayment::new(provider.clone(), context());
        let error = payment.prepare(&two_offers()).await.err().unwrap();
        assert!(matches!(error, MppError::InsufficientBalance(_)));
        assert_eq!(
            *provider.attempts.lock().unwrap(),
            vec!["challenge-1".to_owned()]
        );
    }

    #[test]
    fn unknown_payment_outcome_names_its_reference() {
        assert_eq!(
            MppError::UnknownPaymentOutcome { reference: None }.to_string(),
            "payment outcome unknown; reconcile before retrying"
        );
        assert_eq!(
            MppError::UnknownPaymentOutcome {
                reference: Some("req-1".into())
            }
            .to_string(),
            "payment outcome unknown (ref req-1); reconcile before retrying"
        );
    }

    /// A wire challenge whose `header` selects `name`.
    fn challenge_with_header(id: &str, name: &str) -> Value {
        let mut value = serde_json::to_value(challenge()).unwrap();
        value["id"] = id.into();
        value["header"] = name.into();
        value
    }

    fn payment_required_result(challenges: Vec<Value>) -> Value {
        json!({
            "_meta": {PAYMENT_REQUIRED_META_KEY: {"challenges": challenges}},
            "isError": true
        })
    }

    #[tokio::test]
    async fn unsupported_credential_header_offer_is_skipped_for_valid_challenge() {
        for name in ["Authorization", "", "X-Payment"] {
            let offers = vec![
                challenge_with_header("unsupported", name),
                serde_json::to_value(challenge()).unwrap(),
            ];
            let caller = TestCaller::new([
                Ok(payment_required_result(offers)),
                Ok(json!({"content": "paid"})),
            ]);
            let provider = TestProvider::new();
            let client = McpClient::new(caller.clone(), provider.clone(), context());

            let result = client.call_tool(params()).await.unwrap();

            assert_eq!(result["content"], "paid", "{name:?}");
            assert_eq!(
                provider.lifecycle.pays.load(Ordering::SeqCst),
                1,
                "{name:?}"
            );
            let calls = caller.calls.lock().unwrap();
            assert_eq!(
                calls[1]["_meta"][CREDENTIAL_META_KEY]["challenge"]["id"], "challenge-1",
                "{name:?}"
            );
        }
    }

    #[tokio::test]
    async fn only_unsupported_credential_header_offer_is_never_paid() {
        for name in ["Authorization", "", "X-Payment"] {
            let caller =
                TestCaller::new([Ok(payment_required_result(vec![challenge_with_header(
                    "unsupported",
                    name,
                )]))]);
            let provider = TestProvider::new();
            let client = McpClient::new(caller.clone(), provider.clone(), context());

            let result = client.call_tool(params()).await.unwrap();

            // Treated as offering no supported challenge: the result is returned unpaid.
            assert_eq!(result["isError"], true, "{name:?}");
            assert_eq!(
                provider.lifecycle.pays.load(Ordering::SeqCst),
                0,
                "{name:?}"
            );
            assert_eq!(caller.calls.lock().unwrap().len(), 1, "{name:?}");
        }
    }

    #[tokio::test]
    async fn paid_retry_answered_only_with_unsupported_header_offer_is_rolled_back() {
        for offers in [
            vec![challenge_with_header("unsupported", "Authorization")],
            // A malformed neighbour must not hide the payment requirement.
            vec![
                challenge_with_header("unsupported", "Authorization"),
                json!({}),
            ],
        ] {
            let caller = TestCaller::new([
                Err(payment_error(true)),
                Ok(payment_required_result(offers)),
            ]);
            let provider = TestProvider::new();
            let client = McpClient::new(caller.clone(), provider.clone(), context());

            client.call_tool(params()).await.unwrap();

            assert_eq!(provider.lifecycle.pays.load(Ordering::SeqCst), 1);
            assert_eq!(provider.lifecycle.commits.load(Ordering::SeqCst), 0);
            assert_eq!(provider.lifecycle.rollbacks.load(Ordering::SeqCst), 1);
        }
    }

    /// A caller that inherits the default payment-answer classification.
    #[derive(Clone)]
    struct DefaultAnswerCaller(TestCaller);

    impl ToolCaller for DefaultAnswerCaller {
        type Params = Value;
        type Output = Value;
        type Error = TestError;

        async fn call_tool(&self, params: Self::Params) -> Result<Self::Output, Self::Error> {
            self.0.call_tool(params).await
        }

        fn payment_challenges_from_error(
            &self,
            error: &Self::Error,
        ) -> Option<Vec<PaymentChallenge>> {
            self.0.payment_challenges_from_error(error)
        }

        fn payment_challenges_from_output(
            &self,
            output: &Self::Output,
        ) -> Option<Vec<PaymentChallenge>> {
            self.0.payment_challenges_from_output(output)
        }

        fn attach_credential(
            &self,
            params: &mut Self::Params,
            credential: &PaymentCredential,
        ) -> Result<(), MppError> {
            self.0.attach_credential(params, credential)
        }

        fn is_definitive_error(&self, error: &Self::Error) -> bool {
            self.0.is_definitive_error(error)
        }
    }

    #[tokio::test]
    async fn paid_retry_answered_only_with_invalid_method_offers_is_rolled_back() {
        for method in ["tempo-v2", "x402"] {
            let mut offer = serde_json::to_value(challenge()).unwrap();
            offer["id"] = "other".into();
            offer["method"] = method.into();
            let caller = TestCaller::new([
                Err(payment_error(true)),
                Ok(payment_required_result(vec![offer])),
            ]);
            let provider = TestProvider::new();
            let client = McpClient::new(DefaultAnswerCaller(caller), provider.clone(), context());

            let result = client.call_tool(params()).await.unwrap();

            assert_eq!(result["isError"], true, "{method}");
            assert_eq!(
                provider.lifecycle.pays.load(Ordering::SeqCst),
                1,
                "{method}"
            );
            assert_eq!(
                provider.lifecycle.commits.load(Ordering::SeqCst),
                0,
                "{method}"
            );
            assert_eq!(
                provider.lifecycle.rollbacks.load(Ordering::SeqCst),
                1,
                "{method}"
            );
        }
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

    /// A zero-amount Tempo proof refused with a `credit_insufficient`
    /// payment requirement that offers only the real charge starts a new
    /// challenge round, as mppx's MCP client does.
    #[cfg(feature = "tempo")]
    mod new_challenge_rounds {
        use super::*;
        use crate::client::{TempoProvider, DEFAULT_MAX_PAYMENT_RETRIES};
        use crate::error::PaymentErrorDetails;

        const CURRENCY: &str = "0x20c0000000000000000000000000000000000000";
        const REALM: &str = "mcp.example.test";

        /// Signs zero-amount proofs with a real `TempoProvider` and its
        /// policy (charges capped at 10000), and pays other charges with a
        /// pull-mode transaction credential, recording what it pays.
        #[derive(Clone)]
        struct CreditProvider {
            tempo: TempoProvider,
            paid: Arc<Mutex<Vec<String>>>,
            commits: Arc<AtomicUsize>,
            rollbacks: Arc<AtomicUsize>,
            abandons: Arc<AtomicUsize>,
        }

        impl CreditProvider {
            fn new() -> Self {
                let signer = alloy::signers::local::PrivateKeySigner::random();
                Self {
                    tempo: TempoProvider::new(signer, "https://rpc.example.com")
                        .unwrap()
                        .with_expected_chain_id(42431)
                        .with_currencies([CURRENCY])
                        .with_max_atomic_amount(alloy::primitives::U256::from(10_000)),
                    paid: Arc::default(),
                    commits: Arc::default(),
                    rollbacks: Arc::default(),
                    abandons: Arc::default(),
                }
            }

            fn paid(&self) -> Vec<String> {
                self.paid.lock().unwrap().clone()
            }
        }

        impl PaymentProvider for CreditProvider {
            fn supports(&self, method: &str, intent: &str) -> bool {
                self.tempo.supports(method, intent)
            }

            fn select_challenge<'a>(
                &self,
                challenges: &[&'a PaymentChallenge],
            ) -> Option<&'a PaymentChallenge> {
                self.tempo.select_challenge(challenges)
            }

            async fn pay(
                &self,
                challenge: &PaymentChallenge,
            ) -> Result<PaymentCredential, MppError> {
                self.paid.lock().unwrap().push(challenge.id.clone());
                let request: crate::protocol::intents::ChargeRequest =
                    challenge.request.decode()?;
                if request.amount == "0" {
                    return self.tempo.pay(challenge).await;
                }
                Ok(PaymentCredential::new(
                    challenge.to_echo(),
                    PaymentPayload::transaction("0x76signed"),
                ))
            }

            async fn commit_payment(
                &self,
                _: &PaymentChallenge,
                _: &PaymentCredential,
            ) -> Result<(), MppError> {
                self.commits.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            async fn rollback_payment(
                &self,
                _: &PaymentChallenge,
                _: &PaymentCredential,
            ) -> Result<(), MppError> {
                self.rollbacks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn abandon_payment(&self, _: &PaymentChallenge, _: &PaymentCredential) {
                self.abandons.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn charge_in(id: &str, realm: &str, amount: &str) -> PaymentChallenge {
            let request = Base64UrlJson::from_value(&json!({
                "amount": amount,
                "currency": CURRENCY,
                "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
                "methodDetails": { "chainId": 42431 }
            }))
            .unwrap();
            PaymentChallenge::new(id, realm, "tempo", "charge", request)
        }

        fn charge(id: &str, amount: &str) -> PaymentChallenge {
            charge_in(id, REALM, amount)
        }

        /// A definitive payment-required error offering `challenges`.
        fn required(challenges: Vec<PaymentChallenge>) -> TestError {
            TestError {
                challenges: Some(challenges),
                definitive: true,
                server_error: false,
                message: "credit_insufficient",
            }
        }

        fn proof_then_charge() -> TestError {
            required(vec![charge("proof-1", "0"), charge("charge-1", "10000")])
        }

        fn required_result(challenges: Vec<PaymentChallenge>) -> Value {
            payment_required_result(
                challenges
                    .iter()
                    .map(|challenge| serde_json::to_value(challenge).unwrap())
                    .collect(),
            )
        }

        fn sent_credentials(caller: &TestCaller) -> Vec<Value> {
            caller
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter_map(|call| call["_meta"].get(CREDENTIAL_META_KEY).cloned())
                .collect()
        }

        fn paying_client(
            outcomes: impl IntoIterator<Item = Result<Value, TestError>>,
        ) -> (
            McpClient<TestCaller, CreditProvider>,
            TestCaller,
            CreditProvider,
        ) {
            let caller = TestCaller::new(outcomes);
            let provider = CreditProvider::new();
            let client = McpClient::new(caller.clone(), provider.clone(), context());
            (client, caller, provider)
        }

        #[tokio::test]
        async fn refused_proof_then_real_charge_is_paid() {
            // The refusal arrives as a JSON-RPC error or as a result's `_meta`.
            for refusal in [
                Err(required(vec![charge("charge-2", "10000")])),
                Ok(required_result(vec![charge("charge-2", "10000")])),
            ] {
                let (client, caller, provider) = paying_client([
                    Err(proof_then_charge()),
                    refusal,
                    Ok(json!({"content": "paid"})),
                ]);

                let result = client.call_tool(params()).await.unwrap();

                assert_eq!(result["content"], "paid");
                assert_eq!(provider.paid(), ["proof-1", "charge-2"]);
                let credentials = sent_credentials(&caller);
                assert_eq!(credentials.len(), 2);
                assert_eq!(credentials[0]["challenge"]["id"], "proof-1");
                assert_eq!(credentials[0]["payload"]["type"], "proof");
                assert_eq!(credentials[1]["challenge"]["id"], "charge-2");
                assert_eq!(credentials[1]["payload"]["type"], "transaction");
                // Every retry repeats the original tool call.
                for call in caller.calls.lock().unwrap().iter() {
                    assert_eq!(call["name"], "paid_tool");
                    assert_eq!(call["arguments"], json!({}));
                }
                assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 1);
                assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
            }
        }

        #[tokio::test]
        async fn accepted_proof_never_pays_the_real_charge() {
            let (client, caller, provider) =
                paying_client([Err(proof_then_charge()), Ok(json!({"content": "credit"}))]);

            let result = client.call_tool(params()).await.unwrap();

            assert_eq!(result["content"], "credit");
            assert_eq!(provider.paid(), ["proof-1"]);
            assert_eq!(sent_credentials(&caller).len(), 1);
            assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn reoffered_challenge_resends_the_same_credential() {
            for reoffered in [charge("proof-1", "0"), charge("charge-1", "10000")] {
                let id = reoffered.id.clone();
                // The same Challenge is identified by its id, not by display
                // fields such as its description.
                let relabeled = reoffered.clone().with_description("try again");
                let outcomes = std::iter::once(Err(required(vec![reoffered.clone()]))).chain(
                    (0..DEFAULT_MAX_PAYMENT_RETRIES)
                        .map(|_| Ok(required_result(vec![relabeled.clone()]))),
                );
                let (client, caller, provider) = paying_client(outcomes);

                let result = client.call_tool(params()).await.unwrap();

                // The last payment requirement is the final answer.
                assert_eq!(result["isError"], true);
                // Signed once, and that Credential resent each round, at most
                // DEFAULT_MAX_PAYMENT_RETRIES times.
                assert_eq!(provider.paid(), [id]);
                let credentials = sent_credentials(&caller);
                assert_eq!(credentials.len(), DEFAULT_MAX_PAYMENT_RETRIES);
                assert!(credentials.iter().all(|sent| *sent == credentials[0]));
                assert_eq!(
                    caller.calls.lock().unwrap().len(),
                    DEFAULT_MAX_PAYMENT_RETRIES + 1
                );
                assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 1);
                assert_eq!(provider.commits.load(Ordering::SeqCst), 0);
            }
        }

        #[tokio::test]
        async fn resent_credential_accepted_is_committed_once() {
            let (client, caller, provider) = paying_client([
                Err(required(vec![charge("charge-1", "10000")])),
                Err(required(vec![charge("charge-1", "10000")])),
                Ok(json!({"content": "paid"})),
            ]);

            let result = client.call_tool(params()).await.unwrap();

            assert_eq!(result["content"], "paid");
            assert_eq!(provider.paid(), ["charge-1"]);
            let credentials = sent_credentials(&caller);
            assert_eq!(credentials.len(), 2);
            assert_eq!(credentials[0], credentials[1]);
            assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
            assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn new_challenge_with_the_same_fields_is_paid() {
            // A new id is a new Challenge, even with every other field equal.
            let (client, caller, provider) = paying_client([
                Err(required(vec![charge("charge-1", "100")])),
                Err(required(vec![charge("charge-2", "100")])),
                Ok(json!({"content": "paid"})),
            ]);

            let result = client.call_tool(params()).await.unwrap();

            assert_eq!(result["content"], "paid");
            assert_eq!(provider.paid(), ["charge-1", "charge-2"]);
            assert_eq!(sent_credentials(&caller).len(), 2);
            assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 1);
            assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn rejection_other_than_payment_required_is_final() {
            // A 410 offering a new Challenge after payment is not paid.
            let gone = PaymentErrorDetails::session("channel-not-found").with_status(410);
            let (client, caller, provider) = paying_client([
                Err(required(vec![charge("charge-1", "10000")])),
                Ok(problem_result(&[charge("charge-2", "10000")], gone)),
                Ok(json!({"content": "paid twice"})),
            ]);

            let result = client.call_tool(params()).await.unwrap();

            assert_eq!(
                result["_meta"][PAYMENT_REQUIRED_META_KEY]["httpStatus"],
                410
            );
            assert_eq!(provider.paid(), ["charge-1"]);
            assert_eq!(sent_credentials(&caller).len(), 1);
            assert_eq!(caller.calls.lock().unwrap().len(), 2);
            assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn unpaid_server_error_is_not_paid() {
            // Only a payment requirement starts the first round too.
            let (client, caller, provider) = paying_client([Ok(problem_result(
                &[charge("charge-1", "10000")],
                internal_payment_error(),
            ))]);

            let result = client.call_tool(params()).await.unwrap();

            assert_eq!(result["isError"], true);
            assert!(provider.paid().is_empty());
            assert_eq!(caller.calls.lock().unwrap().len(), 1);
        }

        #[tokio::test]
        async fn refusal_without_payable_challenge_is_final() {
            // A definitive rejection without challenges is returned as is.
            let (client, caller, provider) =
                paying_client([Err(proof_then_charge()), Err(transport_error(true))]);
            let error = client.call_tool(params()).await.unwrap_err();
            assert!(matches!(error, McpClientError::Transport(_)));
            assert_eq!(provider.paid(), ["proof-1"]);
            assert_eq!(caller.calls.lock().unwrap().len(), 2);

            // So is a refusal offering only challenges the provider cannot pay.
            let stripe = PaymentChallenge::new(
                "stripe-1",
                REALM,
                "stripe",
                "charge",
                Base64UrlJson::from_value(&json!({"amount": "100"})).unwrap(),
            );
            let (client, caller, provider) =
                paying_client([Err(proof_then_charge()), Ok(required_result(vec![stripe]))]);
            let result = client.call_tool(params()).await.unwrap();
            assert_eq!(result["isError"], true);
            assert_eq!(provider.paid(), ["proof-1"]);
            assert_eq!(caller.calls.lock().unwrap().len(), 2);
        }

        #[tokio::test]
        async fn endless_new_challenges_stop_at_the_retry_limit() {
            let outcomes = (0..=DEFAULT_MAX_PAYMENT_RETRIES)
                .map(|n| Err(required(vec![charge(&format!("charge-{n}"), "100")])));
            let (client, caller, provider) = paying_client(outcomes);

            let error = client.call_tool(params()).await.unwrap_err();

            assert!(matches!(error, McpClientError::Transport(_)));
            let expected: Vec<_> = (0..DEFAULT_MAX_PAYMENT_RETRIES)
                .map(|n| format!("charge-{n}"))
                .collect();
            assert_eq!(provider.paid(), expected);
            assert_eq!(
                caller.calls.lock().unwrap().len(),
                DEFAULT_MAX_PAYMENT_RETRIES + 1
            );
        }

        #[tokio::test]
        async fn new_round_challenge_over_the_spending_cap_is_not_paid() {
            let (client, caller, provider) = paying_client([
                Err(proof_then_charge()),
                Err(required(vec![charge("charge-2", "20000")])),
            ]);

            let error = client.call_tool(params()).await.unwrap_err();

            assert!(matches!(error, McpClientError::Transport(_)));
            assert_eq!(provider.paid(), ["proof-1"]);
            assert_eq!(caller.calls.lock().unwrap().len(), 2);
            // The refused proof is rolled back, not only abandoned.
            assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 1);
            assert_eq!(provider.abandons.load(Ordering::SeqCst), 0);
            assert_eq!(provider.commits.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn new_round_proof_for_another_realm_is_not_signed() {
            let (client, caller, provider) = paying_client([
                Err(proof_then_charge()),
                Err(required(vec![charge_in(
                    "proof-2",
                    "other.example.com",
                    "0",
                )])),
            ]);

            let error = client.call_tool(params()).await.unwrap_err();

            assert!(matches!(error, McpClientError::Payment(_)));
            assert_eq!(provider.paid(), ["proof-1"]);
            assert_eq!(caller.calls.lock().unwrap().len(), 2);
            // The refused proof is rolled back, not only abandoned.
            assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 1);
            assert_eq!(provider.abandons.load(Ordering::SeqCst), 0);
            assert_eq!(provider.commits.load(Ordering::SeqCst), 0);
        }

        #[tokio::test]
        async fn expired_new_round_challenge_is_not_paid() {
            let mut expired = charge("charge-2", "10000");
            expired.expires = Some("2020-01-01T00:00:00Z".to_owned());
            let (client, caller, provider) =
                paying_client([Err(proof_then_charge()), Err(required(vec![expired]))]);

            let error = client.call_tool(params()).await.unwrap_err();

            assert!(matches!(error, McpClientError::Payment(_)));
            assert_eq!(provider.paid(), ["proof-1"]);
            assert_eq!(caller.calls.lock().unwrap().len(), 2);
            // The refused proof is rolled back, not only abandoned.
            assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 1);
            assert_eq!(provider.abandons.load(Ordering::SeqCst), 0);
            assert_eq!(provider.commits.load(Ordering::SeqCst), 0);
        }

        /// `problem` offering `challenges` in a tool result, as
        /// [`payment_required_error_with_problem`](crate::mcp::payment_required_error_with_problem)
        /// builds a server's payment requirement.
        fn problem_result(challenges: &[PaymentChallenge], problem: PaymentErrorDetails) -> Value {
            let mut data = crate::mcp::payment_required_error_with_problem(&challenges[0], problem)
                .data
                .unwrap();
            data.challenges = challenges.to_vec();
            json!({"_meta": {PAYMENT_REQUIRED_META_KEY: data}, "isError": true})
        }

        fn internal_payment_error() -> PaymentErrorDetails {
            PaymentErrorDetails::core("internal-payment-error").with_status(500)
        }

        #[tokio::test]
        async fn server_error_result_after_payment_is_returned_without_paying_again() {
            let (client, caller, provider) = paying_client([
                Err(required(vec![charge("charge-1", "10000")])),
                Ok(problem_result(
                    &[charge("charge-2", "10000")],
                    internal_payment_error(),
                )),
                Ok(json!({"content": "paid twice"})),
            ]);

            let result = client.call_tool(params()).await.unwrap();

            assert_eq!(result["isError"], true);
            assert_eq!(
                result["_meta"][PAYMENT_REQUIRED_META_KEY]["httpStatus"],
                500
            );
            assert_eq!(provider.paid(), ["charge-1"]);
            let credentials = sent_credentials(&caller);
            assert_eq!(credentials.len(), 1);
            assert_eq!(credentials[0]["payload"]["type"], "transaction");
            assert_eq!(caller.calls.lock().unwrap().len(), 2);
            // The pull payment may have settled: it is neither committed nor
            // rolled back, as the HTTP client treats a 5xx.
            assert_eq!(provider.commits.load(Ordering::SeqCst), 0);
            assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 0);
            assert_eq!(provider.abandons.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn server_error_after_payment_is_raised_without_paying_again() {
            let server_error = TestError {
                challenges: Some(vec![charge("charge-2", "10000")]),
                definitive: true,
                server_error: true,
                message: "internal-payment-error",
            };
            let (client, caller, provider) = paying_client([
                Err(required(vec![charge("charge-1", "10000")])),
                Err(server_error),
                Ok(json!({"content": "paid twice"})),
            ]);

            let error = client.call_tool(params()).await.unwrap_err();

            assert!(matches!(
                error,
                McpClientError::Transport(TestError {
                    message: "internal-payment-error",
                    ..
                })
            ));
            assert_eq!(provider.paid(), ["charge-1"]);
            assert_eq!(sent_credentials(&caller).len(), 1);
            assert_eq!(caller.calls.lock().unwrap().len(), 2);
            assert_eq!(provider.commits.load(Ordering::SeqCst), 0);
            assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 0);
            assert_eq!(provider.abandons.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn definitive_refusal_offering_a_new_challenge_is_paid() {
            for refusal in [
                Ok(problem_result(
                    &[charge("charge-2", "10000")],
                    PaymentErrorDetails::core("credit_insufficient"),
                )),
                Err(required(vec![charge("charge-2", "10000")])),
            ] {
                let (client, caller, provider) = paying_client([
                    Err(proof_then_charge()),
                    refusal,
                    Ok(json!({"content": "paid"})),
                ]);

                let result = client.call_tool(params()).await.unwrap();

                assert_eq!(result["content"], "paid");
                assert_eq!(provider.paid(), ["proof-1", "charge-2"]);
                assert_eq!(sent_credentials(&caller).len(), 2);
                assert_eq!(provider.rollbacks.load(Ordering::SeqCst), 1);
                assert_eq!(provider.commits.load(Ordering::SeqCst), 1);
            }
        }
    }

    #[tokio::test]
    async fn refused_settled_payment_is_not_followed_by_another() {
        // TestProvider pays with a broadcast hash: its funds already moved.
        let mut next = challenge();
        next.id = "challenge-2".to_owned();
        let caller = TestCaller::new([
            Err(payment_error(true)),
            Ok(payment_required_result(vec![
                serde_json::to_value(next).unwrap()
            ])),
        ]);
        let provider = TestProvider::new();
        let client = McpClient::new(caller.clone(), provider.clone(), context());

        let result = client.call_tool(params()).await.unwrap();

        assert_eq!(result["isError"], true);
        assert_eq!(provider.lifecycle.pays.load(Ordering::SeqCst), 1);
        assert_eq!(caller.calls.lock().unwrap().len(), 2);
    }
}
