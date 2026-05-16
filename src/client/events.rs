//! Client-side payment event callbacks.

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use reqwest::StatusCode;

use crate::protocol::core::{PaymentChallenge, PaymentCredential};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type EventHandler = Arc<dyn Fn(ClientEvent) -> BoxFuture<Option<PaymentCredential>> + Send + Sync>;
type ChallengeReceivedHandler =
    Arc<dyn Fn(ChallengeReceivedContext) -> BoxFuture<Option<PaymentCredential>> + Send + Sync>;

/// Return type for client event callbacks.
///
/// Most observers return `()`. `challenge.received` handlers may return a
/// credential to bypass the default provider payment flow.
pub trait IntoClientEventResult {
    /// Convert the callback result into an optional override credential.
    fn into_credential(self) -> Option<PaymentCredential>;
}

impl IntoClientEventResult for () {
    fn into_credential(self) -> Option<PaymentCredential> {
        None
    }
}

impl IntoClientEventResult for Option<PaymentCredential> {
    fn into_credential(self) -> Option<PaymentCredential> {
        self
    }
}

impl IntoClientEventResult for PaymentCredential {
    fn into_credential(self) -> Option<PaymentCredential> {
        Some(self)
    }
}

/// Client event names emitted by automatic 402 handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientEventKind {
    /// A 402 challenge was selected from `WWW-Authenticate`.
    ChallengeReceived,
    /// A provider or hook created a credential for the selected challenge.
    CredentialCreated,
    /// The retried request completed after payment.
    PaymentResponse,
    /// The payment flow failed after a 402 response.
    PaymentFailed,
}

impl ClientEventKind {
    /// Stable event name, matching mppx-style event names.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChallengeReceived => "challenge.received",
            Self::CredentialCreated => "credential.created",
            Self::PaymentResponse => "payment.response",
            Self::PaymentFailed => "payment.failed",
        }
    }
}

/// Context for `challenge.received`.
#[derive(Debug, Clone)]
pub struct ChallengeReceivedContext {
    /// Selected challenge.
    pub challenge: PaymentChallenge,
    /// All parseable challenges from the 402 response.
    pub challenges: Vec<PaymentChallenge>,
}

/// Context for `credential.created`.
#[derive(Debug, Clone)]
pub struct CredentialCreatedContext {
    /// Challenge used to create the credential.
    pub challenge: PaymentChallenge,
    /// Credential sent on the retry.
    pub credential: PaymentCredential,
}

/// Context for `payment.response`.
#[derive(Debug, Clone)]
pub struct PaymentResponseContext {
    /// Challenge used for the paid retry.
    pub challenge: PaymentChallenge,
    /// Credential sent on the retry.
    pub credential: PaymentCredential,
    /// Status returned by the retried request.
    pub status: StatusCode,
}

/// Context for `payment.failed`.
#[derive(Debug, Clone)]
pub struct PaymentFailedContext {
    /// Selected challenge, when one was available.
    pub challenge: Option<PaymentChallenge>,
    /// Human-readable failure.
    pub error: String,
}

/// Client payment event payload.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    /// A 402 challenge was selected.
    ChallengeReceived(ChallengeReceivedContext),
    /// A credential was created.
    CredentialCreated(CredentialCreatedContext),
    /// A retried request completed after payment.
    PaymentResponse(PaymentResponseContext),
    /// The payment flow failed.
    PaymentFailed(PaymentFailedContext),
}

impl ClientEvent {
    /// Event kind.
    pub fn kind(&self) -> ClientEventKind {
        match self {
            Self::ChallengeReceived(_) => ClientEventKind::ChallengeReceived,
            Self::CredentialCreated(_) => ClientEventKind::CredentialCreated,
            Self::PaymentResponse(_) => ClientEventKind::PaymentResponse,
            Self::PaymentFailed(_) => ClientEventKind::PaymentFailed,
        }
    }
}

/// Subscription handle. Dropping it unregisters the callback.
#[must_use = "dropping the subscription immediately unregisters the callback"]
pub struct ClientEventSubscription {
    remove: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl ClientEventSubscription {
    fn new(remove: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self {
            remove: Some(Box::new(remove)),
        }
    }

    /// Unregister the callback before the handle is dropped.
    pub fn unsubscribe(mut self) {
        if let Some(remove) = self.remove.take() {
            remove();
        }
    }
}

impl Drop for ClientEventSubscription {
    fn drop(&mut self) {
        if let Some(remove) = self.remove.take() {
            remove();
        }
    }
}

#[derive(Default)]
struct ClientEventsInner {
    next_id: AtomicUsize,
    challenge_received: Mutex<Vec<(usize, ChallengeReceivedHandler)>>,
    event_handlers: Mutex<Vec<(usize, Option<ClientEventKind>, EventHandler)>>,
}

/// Cloneable registry for client payment event callbacks.
#[derive(Clone, Default)]
pub struct ClientEvents {
    inner: Arc<ClientEventsInner>,
}

impl ClientEvents {
    /// Register a callback for one event kind.
    ///
    /// Returning a credential from `challenge.received` bypasses the provider's
    /// default payment flow. Returned credentials are ignored for other events.
    pub fn on<F, Fut, R>(&self, kind: ClientEventKind, handler: F) -> ClientEventSubscription
    where
        F: Fn(ClientEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: IntoClientEventResult + Send + 'static,
    {
        self.push_event_handler(Some(kind), handler)
    }

    /// Register a callback for every client event.
    ///
    /// Returning a credential from `challenge.received` bypasses the provider's
    /// default payment flow. Returned credentials are ignored for other events.
    pub fn on_any<F, Fut, R>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(ClientEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: IntoClientEventResult + Send + 'static,
    {
        self.push_event_handler(None, handler)
    }

    /// Register a `challenge.received` callback.
    ///
    /// Returning `Some(credential)` bypasses the provider's default payment
    /// flow for this challenge.
    pub fn on_challenge_received<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(ChallengeReceivedContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<PaymentCredential>> + Send + 'static,
    {
        let id = self.next_id();
        let wrapped: ChallengeReceivedHandler =
            Arc::new(move |ctx| Box::pin(handler(ctx)) as BoxFuture<Option<PaymentCredential>>);
        self.inner
            .challenge_received
            .lock()
            .unwrap()
            .push((id, wrapped));
        let inner = self.inner.clone();
        ClientEventSubscription::new(move || {
            inner
                .challenge_received
                .lock()
                .unwrap()
                .retain(|(handler_id, _)| *handler_id != id);
        })
    }

    /// Register a `credential.created` observer.
    pub fn on_credential_created<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(CredentialCreatedContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.on(ClientEventKind::CredentialCreated, move |event| {
            let fut = match event {
                ClientEvent::CredentialCreated(ctx) => Some(handler(ctx)),
                _ => None,
            };
            async move {
                if let Some(fut) = fut {
                    fut.await;
                }
            }
        })
    }

    /// Register a `payment.response` observer.
    pub fn on_payment_response<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(PaymentResponseContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.on(ClientEventKind::PaymentResponse, move |event| {
            let fut = match event {
                ClientEvent::PaymentResponse(ctx) => Some(handler(ctx)),
                _ => None,
            };
            async move {
                if let Some(fut) = fut {
                    fut.await;
                }
            }
        })
    }

    /// Register a `payment.failed` observer.
    pub fn on_payment_failed<F, Fut>(&self, handler: F) -> ClientEventSubscription
    where
        F: Fn(PaymentFailedContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.on(ClientEventKind::PaymentFailed, move |event| {
            let fut = match event {
                ClientEvent::PaymentFailed(ctx) => Some(handler(ctx)),
                _ => None,
            };
            async move {
                if let Some(fut) = fut {
                    fut.await;
                }
            }
        })
    }

    pub(crate) async fn emit_challenge_received(
        &self,
        context: ChallengeReceivedContext,
    ) -> Option<PaymentCredential> {
        if let Some(credential) = self
            .emit(ClientEvent::ChallengeReceived(context.clone()))
            .await
        {
            return Some(credential);
        }

        let handlers: Vec<_> = self
            .inner
            .challenge_received
            .lock()
            .unwrap()
            .iter()
            .map(|(_, handler)| handler.clone())
            .collect();

        for handler in handlers {
            if let Some(credential) =
                run_challenge_received_handler(&handler, context.clone()).await
            {
                return Some(credential);
            }
        }
        None
    }

    pub(crate) async fn emit(&self, event: ClientEvent) -> Option<PaymentCredential> {
        let handlers: Vec<_> = self
            .inner
            .event_handlers
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, kind, _)| kind.is_none_or(|kind| kind == event.kind()))
            .map(|(_, _, handler)| handler.clone())
            .collect();

        for handler in handlers {
            let result = run_event_handler(&handler, event.clone()).await;
            if event.kind() == ClientEventKind::ChallengeReceived && result.is_some() {
                return result;
            }
        }
        None
    }

    fn push_event_handler<F, Fut, R>(
        &self,
        kind: Option<ClientEventKind>,
        handler: F,
    ) -> ClientEventSubscription
    where
        F: Fn(ClientEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: IntoClientEventResult + Send + 'static,
    {
        let id = self.next_id();
        let wrapped: EventHandler = Arc::new(move |event| {
            let future = handler(event);
            Box::pin(async move { future.await.into_credential() })
                as BoxFuture<Option<PaymentCredential>>
        });
        self.inner
            .event_handlers
            .lock()
            .unwrap()
            .push((id, kind, wrapped));
        let inner = self.inner.clone();
        ClientEventSubscription::new(move || {
            inner
                .event_handlers
                .lock()
                .unwrap()
                .retain(|(handler_id, _, _)| *handler_id != id);
        })
    }

    fn next_id(&self) -> usize {
        self.inner.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

async fn run_event_handler(
    handler: &EventHandler,
    event: ClientEvent,
) -> Option<PaymentCredential> {
    let future = match catch_unwind(AssertUnwindSafe(|| handler(event))) {
        Ok(future) => future,
        Err(_) => return None,
    };
    catch_future(future).await.flatten()
}

async fn run_challenge_received_handler(
    handler: &ChallengeReceivedHandler,
    context: ChallengeReceivedContext,
) -> Option<PaymentCredential> {
    let future = match catch_unwind(AssertUnwindSafe(|| handler(context))) {
        Ok(future) => future,
        Err(_) => return None,
    };
    catch_future(future).await.flatten()
}

async fn catch_future<F>(future: F) -> Option<F::Output>
where
    F: Future,
{
    CatchUnwindFuture { future }.await.ok()
}

struct CatchUnwindFuture<F> {
    future: F,
}

impl<F> Future for CatchUnwindFuture<F>
where
    F: Future,
{
    type Output = std::thread::Result<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let future = unsafe { self.map_unchecked_mut(|this| &mut this.future) };
        match catch_unwind(AssertUnwindSafe(|| future.poll(cx))) {
            Ok(Poll::Ready(output)) => Poll::Ready(Ok(output)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(panic) => Poll::Ready(Err(panic)),
        }
    }
}
