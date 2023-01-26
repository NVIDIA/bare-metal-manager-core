/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! A logging middleware for carbide API server requests

use std::task::{Context, Poll};

use tracing::Instrument;

/// A tower Layer which creates a `LogService` for every request
#[derive(Debug, Default, Clone)]
pub struct LogLayer {}

impl<S> tower::Layer<S> for LogLayer {
    type Service = LogService<S>;

    fn layer(&self, service: S) -> Self::Service {
        LogService { service }
    }
}

// This service implements the Forge API server logging behavior
#[derive(Clone, Debug)]
pub struct LogService<S> {
    service: S,
}

impl<S, RequestBody, ResponseBody> tower::Service<http::Request<RequestBody>> for LogService<S>
where
    S: tower::Service<http::Request<RequestBody>, Response = http::Response<ResponseBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    RequestBody: tonic::codegen::Body + Send + 'static,
    ResponseBody: tonic::codegen::Body + Send + 'static,
{
    type Response = http::Response<ResponseBody>;
    type Error = S::Error;
    type Future = tonic::codegen::BoxFuture<Self::Response, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, request: http::Request<RequestBody>) -> Self::Future {
        let mut service = self.service.clone();

        Box::pin(async move {
            // Start a span which tracks the API request
            // Some information about the request is only known when the request finishes
            // or the payload has been deserialized.
            // For these `tracing::field::Empty` has to be used, so that the missing
            // information can be populated later.

            // Field names are taken from the crate opentelemetry_semantic_conventions,
            // e.g. `opentelemetry_semantic_conventions::trace::HTTP_STATUS_CODE`.
            // However we can't reference these external definitions in the tracing macro
            let request_span = tracing::span!(
                tracing::Level::INFO,
                "request",
                elapsed_us = tracing::field::Empty,
                http.url = %request.uri(),
                http.status_code = tracing::field::Empty,
                request = tracing::field::Empty,
                otel.status_code = tracing::field::Empty,
                otel.status_message = tracing::field::Empty,
                rpc.method = tracing::field::Empty,
                rpc.service = tracing::field::Empty,
                rpc.grpc.status_code = tracing::field::Empty,
                rpc.grpc.status_description = tracing::field::Empty);

            // Try to extract the gRPC service and method from the URI
            let mut grpc_method: Option<String> = None;
            let mut grpc_service: Option<String> = None;
            if let Some(path) = request.uri().path_and_query() {
                if *request.method() == http::Method::POST && path.query().is_none() {
                    let parts: Vec<&str> = path.path().split('/').collect();
                    if parts.len() == 3 {
                        // the path starts with an empty segment, and the middle
                        // segment is the service name, the last segment is the
                        // method
                        grpc_service = Some(parts[1].to_string());
                        grpc_method = Some(parts[2].to_string());
                    }
                }
            }

            if let Some(service) = grpc_service {
                request_span.record(
                    opentelemetry_semantic_conventions::trace::RPC_SERVICE.as_str(),
                    service,
                );
            }
            if let Some(method) = grpc_method {
                request_span.record(
                    opentelemetry_semantic_conventions::trace::RPC_METHOD.as_str(),
                    method,
                );
            }

            let start = std::time::Instant::now();

            let result = service.call(request).instrument(request_span.clone()).await;

            let elapsed = start.elapsed();

            // Holds the overall outcome of the request as a single log message
            let mut outcome: Result<(), String> = Ok(());
            match &result {
                Ok(result) => {
                    request_span.record(
                        opentelemetry_semantic_conventions::trace::HTTP_STATUS_CODE.as_str(),
                        result.status().as_u16(),
                    );

                    if result.status() == http::StatusCode::OK {
                        // In gRPC the actual message status is not in the http status code,
                        // but actually in a header (and sometimes even a trailer - but we ignore this case here since
                        // we don't do streaming).
                        //
                        // Unfortunately we have to reconstruct the status here, by parsing
                        // those headers again
                        let code = match result.headers().get("grpc-status") {
                            Some(header) => tonic::Code::from_bytes(header.as_ref()),
                            None => {
                                // The header is not set in case of successful responses
                                tonic::Code::Ok
                            }
                        };
                        let message = result
                            .headers()
                            .get("grpc-message")
                            .map(|header| {
                                // TODO: The header is percent encoded
                                // We don't deal with decoding for now
                                // percent_decode(header.as_bytes())
                                //     .decode_utf8()
                                //     .map(|cow| cow.to_string())
                                std::str::from_utf8(header.as_bytes())
                                    .unwrap_or("Invalid UTF8 Message")
                                    .to_string()
                            })
                            .unwrap_or_else(String::new);

                        request_span.record(
                            opentelemetry_semantic_conventions::trace::RPC_GRPC_STATUS_CODE
                                .as_str(),
                            code as u64,
                        );
                        request_span.record(
                            "rpc.grpc.status_description",
                            format!("Code: {}, Message: {}", code.description(), message),
                        );
                        if code != tonic::Code::Ok {
                            outcome = Err(format!(
                                "gRPC Error: {}. Message: {}",
                                code.description(),
                                message
                            ));
                        }
                    } else {
                        outcome = Err(format!("HTTP status: {}", result.status()));
                    }
                }
                Err(_) => {
                    outcome = Err("HTTP execution error".to_string());
                }
            }

            request_span.record("elapsed_us", elapsed.as_micros());
            request_span.record(
                "otel.status_code",
                if outcome.is_ok() { "ok" } else { "error" },
            );
            if let Err(e) = outcome {
                // Writing this field will set the span status to error
                // Therefore we only write it on errors
                request_span.record("otel.status_message", e);
            }

            result
        })
    }
}
