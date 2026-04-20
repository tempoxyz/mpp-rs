//! Tower middleware for automatic client-side 402 handling.
//!
//! Provides a [`PaymentClientLayer`] that wraps the 402 challenge/pay/retry flow
//! into a standard Tower `Layer`/`Service`.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use http_body::Body;
use http_types::{Request, Response, StatusCode};

use crate::client::provider::PaymentProvider;
use crate::protocol::core::{
    format_authorization, parse_www_authenticate, AUTHORIZATION_HEADER, WWW_AUTHENTICATE_HEADER,
};

/// Tower [`Layer`](tower_layer::Layer) that automatically handles 402 Payment Required responses.
///
/// When a request returns 402, the layer:
/// 1. Parses the challenge from the `WWW-Authenticate` header
/// 2. Calls the provider to execute the payment
/// 3. Retries the request with the credential in the `Authorization` header
#[derive(Clone)]
pub struct PaymentClientLayer<P> {
    provider: P,
}

impl<P> PaymentClientLayer<P> {
    /// Create a new payment client layer with the given provider.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<S, P: PaymentProvider> tower_layer::Layer<S> for PaymentClientLayer<P> {
    type Service = PaymentClientService<S, P>;

    fn layer(&self, inner: S) -> Self::Service {
        PaymentClientService {
            inner,
            provider: self.provider.clone(),
        }
    }
}

/// Tower [`Service`](tower_service::Service) that wraps an inner service with
/// automatic 402 payment handling.
#[derive(Clone)]
pub struct PaymentClientService<S, P> {
    inner: S,
    provider: P,
}

impl<S, P, B, ResBody> tower_service::Service<Request<B>> for PaymentClientService<S, P>
where
    S: tower_service::Service<Request<Bytes>, Response = Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send,
    P: PaymentProvider + 'static,
    B: Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Response<ResBody>, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let provider = self.provider.clone();

        // Keep a clone in `self` for future poll_ready cycles and call the
        // currently-ready service instance moved out of `self`.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            // Buffer the body upfront so we can reconstruct the request
            // for a retry if the server responds with 402.
            let (parts, body) = req.into_parts();
            let body_bytes = collect_body(body).await?;

            let req = Request::from_parts(parts.clone(), body_bytes.clone());
            let resp = inner.call(req).await.map_err(Into::into)?;

            if resp.status() != StatusCode::PAYMENT_REQUIRED {
                return Ok(resp);
            }

            let www_auth = resp
                .headers()
                .get(WWW_AUTHENTICATE_HEADER)
                .ok_or("402 response missing WWW-Authenticate header")?
                .to_str()
                .map_err(|e| format!("invalid WWW-Authenticate header: {e}"))?;

            let challenge =
                parse_www_authenticate(www_auth).map_err(|e| format!("invalid challenge: {e}"))?;

            let credential = provider
                .pay(&challenge)
                .await
                .map_err(|e| format!("payment failed: {e}"))?;

            let auth_value = format_authorization(&credential)
                .map_err(|e| format!("failed to format credential: {e}"))?;

            let mut retry_req = Request::from_parts(parts, body_bytes);
            retry_req.headers_mut().insert(
                AUTHORIZATION_HEADER,
                auth_value
                    .parse()
                    .map_err(|e| format!("invalid authorization header: {e}"))?,
            );

            let mut retry_svc = inner.clone();
            std::future::poll_fn(|cx| retry_svc.poll_ready(cx))
                .await
                .map_err(Into::into)?;
            retry_svc.call(retry_req).await.map_err(Into::into)
        })
    }
}

async fn collect_body<B>(body: B) -> Result<Bytes, Box<dyn std::error::Error + Send + Sync>>
where
    B: Body + Send,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut body = std::pin::pin!(body);
    let mut buf = Vec::new();
    while let Some(frame) = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await {
        let frame = frame.map_err(Into::into)?;
        if let Ok(mut data) = frame.into_data() {
            buf.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
    }
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct MockProvider;

    impl PaymentProvider for MockProvider {
        fn supports(&self, _method: &str, _intent: &str) -> bool {
            true
        }

        async fn pay(
            &self,
            _challenge: &crate::protocol::core::PaymentChallenge,
        ) -> Result<crate::protocol::core::PaymentCredential, crate::error::MppError> {
            unimplemented!("mock provider")
        }
    }

    #[test]
    fn test_layer_new() {
        let _layer = PaymentClientLayer::new(MockProvider);
    }

    #[test]
    fn test_layer_produces_service() {
        #[derive(Clone)]
        struct NoopSvc;

        impl tower_service::Service<Request<Bytes>> for NoopSvc {
            type Response = Response<()>;
            type Error = Box<dyn std::error::Error + Send + Sync>;
            type Future = Pin<Box<dyn Future<Output = Result<Response<()>, Self::Error>> + Send>>;

            fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: Request<Bytes>) -> Self::Future {
                Box::pin(async { Ok(Response::new(())) })
            }
        }

        let layer = PaymentClientLayer::new(MockProvider);
        let _svc = <PaymentClientLayer<MockProvider> as tower_layer::Layer<NoopSvc>>::layer(
            &layer, NoopSvc,
        );
    }

    #[cfg(feature = "utils")]
    mod integration {
        use super::*;
        use crate::error::MppError;
        use crate::protocol::core::{
            format_www_authenticate, Base64UrlJson, PaymentChallenge, PaymentCredential,
            PaymentPayload,
        };
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        #[derive(Clone)]
        struct TestProvider {
            pay_count: Arc<AtomicU32>,
        }

        impl TestProvider {
            fn new() -> Self {
                Self {
                    pay_count: Arc::new(AtomicU32::new(0)),
                }
            }

            fn call_count(&self) -> u32 {
                self.pay_count.load(Ordering::SeqCst)
            }
        }

        impl PaymentProvider for TestProvider {
            fn supports(&self, _method: &str, _intent: &str) -> bool {
                true
            }

            async fn pay(
                &self,
                challenge: &PaymentChallenge,
            ) -> Result<PaymentCredential, MppError> {
                self.pay_count.fetch_add(1, Ordering::SeqCst);
                let echo = challenge.to_echo();
                Ok(PaymentCredential::new(
                    echo,
                    PaymentPayload::hash("0xmockhash"),
                ))
            }
        }

        fn test_challenge() -> (PaymentChallenge, String) {
            let request = Base64UrlJson::from_value(&serde_json::json!({"amount": "500"})).unwrap();
            let challenge = PaymentChallenge::new(
                "tower-test-id",
                "tower.example.com",
                "tempo",
                "charge",
                request,
            );
            let header = format_www_authenticate(&challenge).unwrap();
            (challenge, header)
        }

        #[tokio::test]
        async fn test_happy_path_402_then_200() {
            use tower_layer::Layer;
            use tower_service::Service;

            let (_, www_auth) = test_challenge();
            let call_count = Arc::new(AtomicU32::new(0));
            let counter = call_count.clone();

            #[derive(Clone)]
            struct MockInner {
                www_auth: String,
                call_count: Arc<AtomicU32>,
            }

            impl tower_service::Service<Request<Bytes>> for MockInner {
                type Response = Response<String>;
                type Error = Box<dyn std::error::Error + Send + Sync>;
                type Future =
                    Pin<Box<dyn Future<Output = Result<Response<String>, Self::Error>> + Send>>;

                fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                    Poll::Ready(Ok(()))
                }

                fn call(&mut self, req: Request<Bytes>) -> Self::Future {
                    let www_auth = self.www_auth.clone();
                    let counter = self.call_count.clone();
                    Box::pin(async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        if req.headers().get("authorization").is_some() {
                            let mut resp = Response::new("ok".to_string());
                            *resp.status_mut() = StatusCode::OK;
                            Ok(resp)
                        } else {
                            let mut resp = Response::new("pay up".to_string());
                            *resp.status_mut() = StatusCode::PAYMENT_REQUIRED;
                            resp.headers_mut()
                                .insert(WWW_AUTHENTICATE_HEADER, www_auth.parse().unwrap());
                            Ok(resp)
                        }
                    })
                }
            }

            let provider = TestProvider::new();
            let layer = PaymentClientLayer::new(provider.clone());
            let mut svc = layer.layer(MockInner {
                www_auth,
                call_count: counter,
            });

            let req = Request::builder().uri("/paid").body(String::new()).unwrap();

            let resp: Result<Response<String>, _> = svc.call(req).await;
            let resp = resp.unwrap();

            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(provider.call_count(), 1);
            assert_eq!(call_count.load(Ordering::SeqCst), 2);
        }
    }
}
