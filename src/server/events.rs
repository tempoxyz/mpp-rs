//! Server-side payment event callbacks.

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use crate::protocol::core::{PaymentCredential, Receipt};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
type EventHandler = Arc<dyn Fn(ServerEvent) -> BoxFuture<()> + Send + Sync>;

/// Server event names emitted during payment verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServerEventKind {
    /// Payment verification completed successfully.
    PaymentSuccess,
}

impl ServerEventKind {
    /// Stable event name, matching mppx-style event names.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PaymentSuccess => "payment.success",
        }
    }
}

/// Context for `payment.success`.
#[derive(Debug, Clone)]
pub struct PaymentSuccessContext {
    /// Credential that was verified.
    pub credential: PaymentCredential,
    /// Receipt returned by the payment method.
    pub receipt: Receipt,
    /// Decoded payment request as JSON.
    pub request: serde_json::Value,
    /// Payment method name.
    pub method: String,
    /// Payment intent name.
    pub intent: String,
    /// Whether session verification produced a management response.
    pub management_response: bool,
}

/// Server payment event payload.
#[derive(Debug, Clone)]
pub enum ServerEvent {
    /// Payment verification completed successfully.
    PaymentSuccess(PaymentSuccessContext),
}

impl ServerEvent {
    /// Event kind.
    pub fn kind(&self) -> ServerEventKind {
        match self {
            Self::PaymentSuccess(_) => ServerEventKind::PaymentSuccess,
        }
    }
}

/// Subscription handle. Dropping it unregisters the callback.
#[must_use = "dropping the subscription immediately unregisters the callback"]
pub struct ServerEventSubscription {
    remove: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl ServerEventSubscription {
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

impl Drop for ServerEventSubscription {
    fn drop(&mut self) {
        if let Some(remove) = self.remove.take() {
            remove();
        }
    }
}

#[derive(Default)]
struct ServerEventsInner {
    next_id: AtomicUsize,
    event_handlers: Mutex<Vec<(usize, Option<ServerEventKind>, EventHandler)>>,
}

/// Cloneable registry for server payment event callbacks.
#[derive(Clone, Default)]
pub struct ServerEvents {
    inner: Arc<ServerEventsInner>,
}

impl ServerEvents {
    /// Register an event observer for one event kind.
    pub fn on<F, Fut>(&self, kind: ServerEventKind, handler: F) -> ServerEventSubscription
    where
        F: Fn(ServerEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.push_event_handler(Some(kind), handler)
    }

    /// Register an observer for every server event.
    pub fn on_any<F, Fut>(&self, handler: F) -> ServerEventSubscription
    where
        F: Fn(ServerEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.push_event_handler(None, handler)
    }

    /// Register a `payment.success` observer.
    pub fn on_payment_success<F, Fut>(&self, handler: F) -> ServerEventSubscription
    where
        F: Fn(PaymentSuccessContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.on(ServerEventKind::PaymentSuccess, move |event| {
            let fut = match event {
                ServerEvent::PaymentSuccess(ctx) => Some(handler(ctx)),
            };
            async move {
                if let Some(fut) = fut {
                    fut.await;
                }
            }
        })
    }

    pub(crate) async fn emit_payment_success(&self, context: PaymentSuccessContext) {
        self.emit(ServerEvent::PaymentSuccess(context)).await;
    }

    async fn emit(&self, event: ServerEvent) {
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
            run_event_handler(&handler, event.clone()).await;
        }
    }

    fn push_event_handler<F, Fut>(
        &self,
        kind: Option<ServerEventKind>,
        handler: F,
    ) -> ServerEventSubscription
    where
        F: Fn(ServerEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let id = self.next_id();
        let wrapped: EventHandler =
            Arc::new(move |event| Box::pin(handler(event)) as BoxFuture<()>);
        self.inner
            .event_handlers
            .lock()
            .unwrap()
            .push((id, kind, wrapped));
        let inner = self.inner.clone();
        ServerEventSubscription::new(move || {
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

async fn run_event_handler(handler: &EventHandler, event: ServerEvent) {
    let future = match catch_unwind(AssertUnwindSafe(|| handler(event))) {
        Ok(future) => future,
        Err(_) => return,
    };
    let _ = catch_future(future).await;
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
