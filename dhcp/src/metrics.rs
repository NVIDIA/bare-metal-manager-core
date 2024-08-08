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

use std::ops::Deref;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

use crate::{tls, CarbideDhcpContext, CarbideDhcpMetrics, CONFIG};

use ::metrics_endpoint::{new_metrics_setup, run_metrics_endpoint, MetricsEndpointConfig};
use opentelemetry::KeyValue;

const METRICS_CAPTURE_FREQUENCY: Duration = Duration::from_secs(30);

pub async fn certificate_loop() {
    let mut interval = tokio::time::interval(METRICS_CAPTURE_FREQUENCY);
    loop {
        interval.tick().await;
        let metrics = CONFIG
            .read()
            .expect("config lock poisoned?")
            .metrics
            .clone();
        if let Some(metrics) = metrics {
            if let Some(client_expiry) = metrics.forge_client_config.client_cert_expiry().await {
                metrics
                    .certificate_expiration_value
                    .store(client_expiry, Ordering::SeqCst);
            }
        }
    }
}

pub fn metrics_server() {
    let metrics_endpoint = CONFIG
        .read()
        .expect("config lock poisoned?")
        .metrics_endpoint;

    if let Some(metrics_endpoint) = metrics_endpoint {
        let mconf = new_metrics_setup("carbide-dhcp", "forge-system");
        match mconf {
            Ok(mconf) => {
                // initialize metrics
                let metrics = CarbideDhcpMetrics {
                    total_requests_counter: mconf
                        .meter
                        .u64_counter("carbide-dhcp.requests")
                        .with_description("The total number of DHCP requests")
                        .init(),
                    dropped_requests_counter: mconf
                        .meter
                        .u64_counter("carbide-dhcp.dropped_requests")
                        .with_description("The number of dropped DHCP requests")
                        .init(),
                    forge_client_config: tls::build_forge_client_config(),
                    certificate_expiration_value: Arc::new(AtomicI64::new(0)),
                    certificate_expiration_gauge: mconf
                        .meter
                        .i64_observable_gauge("carbide-dhcp.certificate_expiration_time")
                        .with_description("The certificate expiration time (epoch seconds)")
                        .init(),
                };
                let metrics_clone = metrics.clone();
                let certificate_expiration_value_clone =
                    metrics_clone.certificate_expiration_value.clone();
                mconf
                    .meter
                    .register_callback(
                        &[metrics_clone.certificate_expiration_gauge.as_any()],
                        move |observer| {
                            let measurement = certificate_expiration_value_clone
                                .deref()
                                .load(Ordering::SeqCst);
                            observer.observe_i64(
                                &metrics_clone.certificate_expiration_gauge,
                                measurement,
                                &[],
                            );
                        },
                    )
                    .expect("unable to register callback?");
                CONFIG.write().unwrap().metrics = Some(metrics);
                let runtime: &Runtime = CarbideDhcpContext::get_tokio_runtime();
                // start certificate loop
                runtime.spawn(async move {
                    certificate_loop().await;
                });
                // start metrics server
                runtime.block_on(async move {
                    if let Err(e) = run_metrics_endpoint(&MetricsEndpointConfig {
                        address: metrics_endpoint,
                        registry: mconf.registry,
                    })
                    .await
                    {
                        log::error!("Metrics endpoint failed with error: {}", e);
                    }
                });
            }
            Err(err) => {
                log::error!("failed to set-up metrics config: {err}");
            }
        }
    } else {
        log::warn!("no metrics endpoint configured, no metrics will be recorded");
    }
}

pub fn increment_total_requests() {
    if let Some(metrics) = CONFIG
        .read()
        .expect("config lock poisoned?")
        .metrics
        .clone()
    {
        metrics.total_requests_counter.add(1, &[]);
    }
}

pub fn increment_dropped_requests(reason: String) {
    if let Some(metrics) = CONFIG
        .read()
        .expect("config lock poisoned?")
        .metrics
        .clone()
    {
        metrics
            .dropped_requests_counter
            .add(1, &[KeyValue::new("reason", reason.clone())]);
    }
}
