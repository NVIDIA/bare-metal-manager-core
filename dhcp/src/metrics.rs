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
use std::thread;
use std::time::Duration;

use tokio::runtime::Runtime;

use opentelemetry::metrics::MeterProvider;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use rpc::forge_tls_client::ForgeTlsConfig;

use crate::{tls, CarbideDhcpContext, CONFIG};

use opentelemetry_semantic_conventions as semcov;

const METRICS_CAPTURE_FREQUENCY: Duration = Duration::from_secs(30);

fn setup_metrics<E: Into<String>>(otlp_endpoint: E) -> eyre::Result<DhcpMetrics> {
    // This defines attributes that are set on the exported metrics
    let mut attributes = vec![
        semcov::resource::SERVICE_NAME.string("carbide-dhcp"),
        semcov::resource::SERVICE_NAMESPACE.string("forge-system"),
    ];
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        // helps to disambiguate this pod's metrics
        // if we ever put more than one dhcp pod into service
        // usually looks like HOSTNAME=carbide-dhcp-74ffdd5d6b-c6489
        attributes.push(semcov::resource::K8S_POD_NAME.string(hostname));
    }
    let service_telemetry_attributes = Resource::new(attributes);

    let meter_provider = opentelemetry_otlp::new_pipeline()
        .metrics(opentelemetry_sdk::runtime::Tokio)
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otlp_endpoint),
        )
        .with_resource(service_telemetry_attributes)
        .build()?;

    // After this call `global::meter()` will be available
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    let meter = meter_provider.meter("carbide-dhcp");

    let client_certificate_expiry_gauge = meter
        .i64_observable_gauge("certificate_lifetime_expiry_gauge")
        .with_description("The expiration time of the carbide dhcp server's client certificate, represented as unix epoch seconds.")
        .init();

    let client_certificate_expiry_measurement = Arc::new(AtomicI64::new(0));

    let measurement_clone = client_certificate_expiry_measurement.clone();
    meter
        .register_callback(
            &[client_certificate_expiry_gauge.as_any()],
            move |observer| {
                let measurement = measurement_clone.deref().load(Ordering::SeqCst);
                observer.observe_i64(&client_certificate_expiry_gauge, measurement, &[]);
            },
        )
        .expect("unable to register callback?");

    let forge_tls_config = tls::build_forge_tls_config();
    Ok(DhcpMetrics {
        forge_tls_config,
        client_certificate_expiry_value: client_certificate_expiry_measurement,
    })
}

#[derive(Clone, Debug)]
struct DhcpMetrics {
    forge_tls_config: ForgeTlsConfig,
    client_certificate_expiry_value: Arc<AtomicI64>,
}
impl DhcpMetrics {
    async fn update(&self) {
        log::debug!("Capturing metrics.");
        if let Some(client_expiry) = self.forge_tls_config.client_cert_expiry().await {
            self.client_certificate_expiry_value
                .store(client_expiry, Ordering::SeqCst);
        }
    }
}

// this code is synchronous because our runtime isn't being regularly polled by a server,
// so we can't just spawn an async task on it.  Instead, we spawn a sync thread loop which will
// directly run our async code against the runtime so we can still write async code
pub fn sync_metrics_loop() {
    let otlp_endpoint = CONFIG
        .read()
        .expect("config lock poisoned?")
        .otlp_endpoint
        .clone();

    if let Some(otlp_endpoint) = otlp_endpoint {
        let metrics = setup_metrics(otlp_endpoint).expect("unable to setup metrics?");

        loop {
            let runtime: &Runtime = CarbideDhcpContext::get_tokio_runtime();
            runtime.block_on(metrics.update());

            thread::sleep(METRICS_CAPTURE_FREQUENCY);
        }
    } else {
        log::warn!("no otlp endpoint configured, no metrics will be recorded.");
    }
}
