use futures_util::{FutureExt, future::BoxFuture};
use prometheus::{HistogramVec, IntCounterVec, register_histogram_vec, register_int_counter_vec};
use tonic::{Code, Status};
use tower::{Layer, Service};

lazy_static::lazy_static! {
    static ref GRPC_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "grpc_requests_total",
        "Total number of gRPC requests.",
        &["method"]
    ).unwrap();

    static ref GRPC_RESPONSES: IntCounterVec = register_int_counter_vec!(
        "grpc_responses_total",
        "Total number of gRPC responses.",
        &["method", "status"]
    ).unwrap();

    static ref GRPC_LATENCY: HistogramVec = register_histogram_vec!(
        "grpc_request_duration_seconds",
        "gRPC request duration in seconds.",
        &["method"]
    ).unwrap();
}

#[derive(Clone)]
pub struct GrpcMetricsLayer;

impl<S> Layer<S> for GrpcMetricsLayer {
    type Service = GrpcMetricsMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcMetricsMiddleware { inner }
    }
}

#[derive(Clone)]
pub struct GrpcMetricsMiddleware<S> {
    inner: S,
}

impl<S> Service<axum::http::Request<axum::body::Body>> for GrpcMetricsMiddleware<S>
where
    S: Service<
            axum::http::Request<axum::body::Body>,
            Response = axum::response::Response<axum::body::Body>,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
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

    fn call(&mut self, req: axum::http::Request<axum::body::Body>) -> Self::Future {
        let method = req.uri().path().to_string();
        GRPC_REQUESTS.with_label_values(&[&method]).inc();

        let timer = GRPC_LATENCY.with_label_values(&[&method]).start_timer();
        let fut = self.inner.call(req);
        async move {
            let resp = fut.await;
            timer.observe_duration();

            if let Ok(response) = &resp {
                let status_code = Status::from_header_map(response.headers())
                    .map(|status| status.code())
                    .unwrap_or(Code::Ok);

                GRPC_RESPONSES
                    .with_label_values(&[&method, &code_to_str(status_code).to_owned()])
                    .inc();
            }

            resp
        }
        .boxed()
    }
}

#[inline]
fn code_to_str(code: Code) -> &'static str {
    match code {
        Code::Ok => "OK",
        Code::Cancelled => "CANCELLED",
        Code::Unknown => "UNKNOWN",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        Code::NotFound => "NOT_FOUND",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Aborted => "ABORTED",
        Code::OutOfRange => "OUT_OF_RANGE",
        Code::Unimplemented => "UNIMPLEMENTED",
        Code::Internal => "INTERNAL",
        Code::Unavailable => "UNAVAILABLE",
        Code::DataLoss => "DATA_LOSS",
        Code::Unauthenticated => "UNAUTHENTICATED",
    }
}
