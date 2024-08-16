/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use prometheus::{
    opts, Encoder, HistogramOpts, HistogramVec, IntCounterVec, Registry, TextEncoder,
};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::route::{Handler, Outcome};
use rocket::{Data, Request, Response, Route};
use rocket_http::{ContentType, Method};
use std::time::Instant;

#[derive(Copy, Clone)]
struct RequestStart(Option<Instant>);

/// Emit custom http request metrics
#[derive(Debug, Clone)]
pub struct RequestMetrics {
    registry: Registry,
    http_requests_total: Option<IntCounterVec>,
    http_request_duration_seconds: Option<HistogramVec>,
    http_response_size_bytes: Option<HistogramVec>,
}

const SIZE_BUCKETS: &[f64; 9] = &[
    100.0,
    1000.0,
    10000.0,
    100000.0,
    1000000.0,
    10000000.0,
    100000000.0,
    1000000000.0,
    10000000000.0,
];

impl RequestMetrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        let namespace = "carbide_pxe";

        // init http_requests_total
        let http_requests_total_opts =
            opts!("http_requests_total", "Total number of HTTP requests").namespace(namespace);
        let http_requests_total =
            match IntCounterVec::new(http_requests_total_opts, &["path", "method", "code"]) {
                Ok(counter) => Some(counter),
                Err(err) => {
                    eprintln!("Failed to initialize http_requests_total: {}", err);
                    None
                }
            };

        // init http_request_duration_seconds
        let http_request_duration_seconds_opts = opts!(
            "http_request_duration_seconds",
            "HTTP request duration in seconds"
        )
        .namespace(namespace);
        let http_request_duration_seconds = match HistogramVec::new(
            http_request_duration_seconds_opts.into(),
            &["path", "method", "code"],
        ) {
            Ok(histogram) => Some(histogram),
            Err(err) => {
                eprintln!(
                    "Failed to initialize http_request_duration_seconds: {}",
                    err
                );
                None
            }
        };

        // init http_response_size_bytes
        let http_response_size_bytes_opts = HistogramOpts {
            common_opts: opts!("http_response_size_bytes", "HTTP response size in bytes",)
                .namespace(namespace),
            buckets: Vec::from(SIZE_BUCKETS as &'static [f64]),
        };
        let http_response_size_bytes =
            match HistogramVec::new(http_response_size_bytes_opts, &["path", "method"]) {
                Ok(histogram) => Some(histogram),
                Err(err) => {
                    eprintln!("Failed to initialize http_response_size_bytes: {}", err);
                    None
                }
            };

        // register
        if let Some(total) = http_requests_total.clone() {
            registry.register(Box::new(total)).unwrap_or_else(|err| {
                eprintln!("Failed to register http_requests_total: {}", err);
            })
        }

        if let Some(duration) = http_request_duration_seconds.clone() {
            registry.register(Box::new(duration)).unwrap_or_else(|err| {
                eprintln!("Failed to register http_request_duration_seconds: {}", err);
            });
        }

        if let Some(size) = http_response_size_bytes.clone() {
            registry.register(Box::new(size)).unwrap_or_else(|err| {
                eprintln!("Failed to register http_response_size_bytes: {}", err);
            });
        }

        Self {
            registry,
            http_requests_total,
            http_request_duration_seconds,
            http_response_size_bytes,
        }
    }
}

impl Default for RequestMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[rocket::async_trait]
impl Handler for RequestMetrics {
    async fn handle<'r>(&self, req: &'r Request<'_>, _: Data<'r>) -> Outcome<'r> {
        // Gather the metrics.
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        encoder
            .encode(&self.registry.gather(), &mut buffer)
            .unwrap_or_else(|err| {
                eprintln!("Could not encode metrics data: {}", err);
            });
        let body = String::from_utf8(buffer).unwrap_or_else(|err| {
            eprintln!("Could not convert body to string: {}", err);
            "".to_string()
        });
        Outcome::from(
            req,
            (
                ContentType::new("text", "plain")
                    .with_params([("version", "0.0.4"), ("charset", "utf-8")]),
                body,
            ),
        )
    }
}

impl From<RequestMetrics> for Vec<Route> {
    fn from(other: RequestMetrics) -> Self {
        vec![Route::new(Method::Get, "/", other)]
    }
}

#[rocket::async_trait]
impl Fairing for RequestMetrics {
    fn info(&self) -> Info {
        Info {
            name: "Request metrics",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, request: &mut Request<'_>, _: &mut Data<'_>) {
        request.local_cache(|| RequestStart(Some(Instant::now())));
    }

    async fn on_response<'r>(&self, request: &'r Request<'_>, response: &mut Response<'r>) {
        if request.route().is_none() {
            return;
        }

        let endpoint = request.uri().path().to_string();

        // if this is /metrics, then do not record
        if endpoint == "/metrics" {
            return;
        }

        let method = request.method().as_str();
        let code = response.status().code.to_string();
        let body_size = response.body_mut().size().await.unwrap_or(0);

        // set http_response_size_bytes
        if let Some(http_response_size_bytes) = self.http_response_size_bytes.clone() {
            http_response_size_bytes
                .with_label_values(&[endpoint.as_str(), method])
                .observe(body_size as f64);
        }

        // set http_requests_total
        if let Some(http_requests_total) = self.http_requests_total.clone() {
            http_requests_total
                .with_label_values(&[endpoint.as_str(), method, code.as_str()])
                .inc();
        }

        // set http_request_duration_seconds
        let start_time = request.local_cache(|| RequestStart(None));
        if let Some(duration) = start_time.0.map(|st| st.elapsed()) {
            let duration_secs = duration.as_secs_f64();
            if let Some(http_request_duration_seconds) = self.http_request_duration_seconds.clone()
            {
                http_request_duration_seconds
                    .with_label_values(&[endpoint.as_str(), method, code.as_str()])
                    .observe(duration_secs);
            }
        }
    }
}
