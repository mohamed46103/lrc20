use futures_util::{FutureExt, future::BoxFuture};
use prometheus::{HistogramVec, IntCounterVec, register_histogram_vec, register_int_counter_vec};
use tower::{Layer, Service};

lazy_static::lazy_static! {
    static ref JSONRPC_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "jsonrpc_requests_total",
        "Total number of JSON-RPC requests.",
        &["method"]
    ).unwrap();

    static ref JSONRPC_RESPONSES: IntCounterVec = register_int_counter_vec!(
        "jsonrpc_responses_total",
        "Total number of JSON-RPC requests.",
        &["method", "status"]
    ).unwrap();

    static ref JSONRPC_LATENCY: HistogramVec = register_histogram_vec!(
        "jsonrpc_request_duration_seconds",
        "JSON-RPC request duration in seconds.",
        &["method"]
    ).unwrap();
}

pub struct JsonRpcMetricsLayer;

impl<S> Layer<S> for JsonRpcMetricsLayer {
    type Service = JsonRpcMetricsMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JsonRpcMetricsMiddleware { inner }
    }
}

pub struct JsonRpcMetricsMiddleware<S> {
    inner: S,
}

impl<S> Service<hyper::Request<hyper::Body>> for JsonRpcMetricsMiddleware<S>
where
    S: Service<hyper::Request<hyper::Body>, Response = hyper::Response<hyper::Body>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: hyper::Request<hyper::Body>) -> Self::Future {
        // TODO(mhr): Extract method name from the request. For now just use "unknown".
        JSONRPC_REQUESTS.with_label_values(&["unknown"]).inc();

        let timer = JSONRPC_LATENCY
            .with_label_values(&["unknown"])
            .start_timer();
        let fut = self.inner.call(req);
        async move {
            let resp = fut.await;
            timer.observe_duration();

            if let Ok(ref response) = resp {
                let status = response.status().as_u16().to_string();
                JSONRPC_RESPONSES
                    .with_label_values(&["unknown", &status])
                    .inc();
            }

            resp
        }
        .boxed()
    }
}
