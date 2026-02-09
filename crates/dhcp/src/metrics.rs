/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use ::metrics_endpoint::{MetricsEndpointConfig, new_metrics_setup, run_metrics_endpoint};
use metrics_endpoint::{HealthController, MetricsSetup};
use opentelemetry::KeyValue;
use rpc::forge_tls_client::{self, ApiConfig, ForgeClientConfig};
use tokio::runtime::Runtime;
use tokio::time::{interval, timeout};

use crate::{CONFIG, CarbideDhcpContext, CarbideDhcpMetrics, tls};

const METRICS_CAPTURE_FREQUENCY: Duration = Duration::from_secs(30);
const READINESS_CHECK_FREQUENCY: Duration = Duration::from_secs(30);

pub async fn certificate_loop() {
    let mut interval = tokio::time::interval(METRICS_CAPTURE_FREQUENCY);
    loop {
        interval.tick().await;
        let metrics = CONFIG
            .read()
            .expect("config lock poisoned?")
            .metrics
            .clone();
        if let Some(metrics) = metrics
            && let Some(client_expiry) = metrics.forge_client_config.client_cert_expiry()
        {
            metrics
                .certificate_expiration_value
                .store(client_expiry, Ordering::SeqCst);
        }
    }
}

fn initialize_metrics(mconf: &MetricsSetup) -> CarbideDhcpMetrics {
    let certificate_expiration_value = Arc::new(AtomicI64::new(0));
    // initialize metrics.
    let metrics = CarbideDhcpMetrics {
        total_requests_counter: mconf
            .meter
            .u64_counter("carbide-dhcp.requests")
            .with_description("The total number of DHCP requests")
            .build(),
        dropped_requests_counter: mconf
            .meter
            .u64_counter("carbide-dhcp.dropped_requests")
            .with_description("The number of dropped DHCP requests")
            .build(),
        forge_client_config: tls::build_forge_client_config(),
        certificate_expiration_value: certificate_expiration_value.clone(),
    };

    // Observable gauges don't need to be stored anywhere, they're
    // stored internally within the meter and the callback is run when metrics are
    // collected.
    mconf
        .meter
        .i64_observable_gauge("carbide-dhcp.certificate_expiration_time")
        .with_description("The certificate expiration time (epoch seconds)")
        .with_callback(move |observer| {
            let measurement = certificate_expiration_value.deref().load(Ordering::SeqCst);
            observer.observe(measurement, &[]);
        })
        .build();

    metrics
}

pub fn metrics_server() {
    let metrics_endpoint = CONFIG
        .read()
        .expect("config lock poisoned?")
        .metrics_endpoint;

    if let Some(metrics_endpoint) = metrics_endpoint {
        let mconf = new_metrics_setup("carbide-dhcp", "forge-system", true);
        match mconf {
            Ok(mconf) => {
                // initialize metrics.
                let metrics = initialize_metrics(&mconf);
                let health_controller = HealthController::new();

                {
                    let mut config = CONFIG.write().expect("config lock poisoned");
                    config.metrics = Some(metrics);
                    config.health_controller = Some(health_controller.clone());
                }

                let runtime: &Runtime = CarbideDhcpContext::get_tokio_runtime();
                // start certificate loop
                runtime.spawn(async move {
                    certificate_loop().await;
                });
                // start readiness loop
                runtime.spawn(async move {
                    start_readiness_monitoring().await;
                });

                // start metrics server
                runtime.block_on(async move {
                    if let Err(e) = run_metrics_endpoint(&MetricsEndpointConfig {
                        address: metrics_endpoint,
                        registry: mconf.registry,
                        health_controller: Some(health_controller),
                    })
                    .await
                    {
                        log::error!("Metrics endpoint failed with error: {e}");
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

async fn check_api_connectivity(carbide_api_url: &str, client_config: &ForgeClientConfig) -> bool {
    let api_config: ApiConfig<'_> = ApiConfig::new(carbide_api_url, client_config);
    match forge_tls_client::ForgeTlsClient::retry_build(&api_config).await {
        Ok(mut client) => {
            let request = tonic::Request::new(rpc::forge::EchoRequest {
                message: "dhcp_echo".into(),
            });

            match client.echo(request).await {
                Ok(_) => true,
                Err(e) => {
                    log::error!("error communication with carbide API: {e:?}");
                    false
                }
            }
        }
        Err(e) => {
            log::error!("api connectivity check timed out: {e:?}");
            false
        }
    }
}

pub async fn start_readiness_monitoring() {
    let mut readiness_interval = interval(READINESS_CHECK_FREQUENCY);
    let forge_client_config = tls::build_forge_client_config();

    let url = &CONFIG.read().expect("config poisoned").api_endpoint.clone();

    loop {
        readiness_interval.tick().await;
        match timeout(
            Duration::from_secs(10),
            check_api_connectivity(url, &forge_client_config),
        )
        .await
        {
            Ok(result) => set_service_ready(result),
            Err(e) => {
                log::warn!("Readiness check timed out: {e:?}");
                set_service_ready(false)
            }
        }
    }
}

pub fn increment_total_requests() {
    if let Some(metrics) = CONFIG.read().expect("config lock poisoned").metrics.clone() {
        metrics.total_requests_counter.add(1, &[]);
    }
}

pub fn increment_dropped_requests(reason: String) {
    if let Some(metrics) = CONFIG.read().expect("config lock poisoned").metrics.clone() {
        metrics
            .dropped_requests_counter
            .add(1, &[KeyValue::new("reason", reason)]);
    }
}

pub fn set_service_ready(ready: bool) {
    if let Some(health_controller) = &CONFIG
        .read()
        .expect("config lock poisoned")
        .health_controller
    {
        health_controller.set_ready(ready);
        log::debug!("DHCP readiness set to: {ready}");
    }
}

pub fn set_service_healthy(healthy: bool) {
    if let Some(health_controller) = &CONFIG
        .read()
        .expect("config lock poisoned")
        .health_controller
    {
        health_controller.set_healthy(healthy);
        log::debug!("DHCP health set to: {healthy}");
    }
}

#[cfg(test)]
mod tests {
    use prometheus::{Encoder, TextEncoder};

    use super::*;

    #[test]
    fn test_metrics() {
        let mconf = new_metrics_setup("carbide-dhcp", "forge-system", false).unwrap();
        let metrics = initialize_metrics(&mconf);
        metrics
            .certificate_expiration_value
            .store(1740173562, Ordering::SeqCst);
        metrics.total_requests_counter.add(1, &[]);
        metrics.dropped_requests_counter.add(1, &[]);

        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = mconf.registry.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        let prom_metrics = String::from_utf8(buffer).unwrap();
        assert_eq!(prom_metrics, include_str!("../tests/fixtures/metrics.txt"));
    }
}
