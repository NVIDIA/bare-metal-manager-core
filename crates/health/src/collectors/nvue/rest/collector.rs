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

use std::borrow::Cow;
use std::sync::Arc;

use nv_redfish::Bmc;
use prometheus::{GaugeVec, Opts};

use super::client::RestClient;
use crate::HealthError;
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::config::NvueRestConfig;
use crate::endpoint::{BmcEndpoint, EndpointMetadata};
use crate::metrics::CollectorRegistry;
use crate::sink::{CollectorEvent, DataSink, EventContext, MetricSample};

const COLLECTOR_NAME: &str = "nvue_rest";

fn health_status_to_f64(status: Option<&str>) -> f64 {
    match status {
        Some("healthy") => 1.0,
        Some("degraded") => 2.0,
        Some("unhealthy") => 3.0,
        _ => 0.0,
    }
}

fn app_status_to_f64(status: Option<&str>) -> f64 {
    match status {
        Some("running") => 1.0,
        Some("stopped") => 2.0,
        Some("error") => 3.0,
        _ => 0.0,
    }
}

fn diagnostic_status_to_f64(status: &str) -> f64 {
    match status {
        "ok" => 0.0,
        "warning" => 1.0,
        "error" => 2.0,
        _ => 0.0,
    }
}

pub struct NvueRestCollectorConfig {
    pub rest_config: NvueRestConfig,
    pub collector_registry: Arc<CollectorRegistry>,
    pub data_sink: Option<Arc<dyn DataSink>>,
}

pub struct NvueRestCollector {
    client: RestClient,
    switch_id: String,
    switch_ip: String,
    switch_mac: String,
    event_context: EventContext,
    system_health_gauge: GaugeVec,
    cluster_app_gauge: GaugeVec,
    partition_health_gauge: GaugeVec,
    partition_gpu_count_gauge: GaugeVec,
    link_diagnostic_gauge: GaugeVec,
    data_sink: Option<Arc<dyn DataSink>>,
}

impl<B: Bmc + 'static> PeriodicCollector<B> for NvueRestCollector {
    type Config = NvueRestCollectorConfig;

    fn new_runner(
        _bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let switch_id = match &endpoint.metadata {
            Some(EndpointMetadata::Switch(s)) => s.serial.clone(),
            _ => endpoint.addr.mac.to_string(),
        };
        let switch_ip = endpoint.addr.ip.to_string();
        let switch_mac = endpoint.addr.mac.to_string();
        let event_context = EventContext::from_endpoint(endpoint.as_ref(), COLLECTOR_NAME);

        let rest_cfg = &config.rest_config;
        // self_signed_tls is always true -- TLS cert provisioning on switches is not yet implemented
        let client = RestClient::new(
            switch_id.clone(),
            &switch_ip,
            Some(endpoint.credentials.username.clone()),
            Some(endpoint.credentials.password.clone()),
            rest_cfg.request_timeout,
            true,
            rest_cfg.paths.clone(),
        )?;

        let registry = config.collector_registry.registry();
        let prefix = config.collector_registry.prefix();

        let system_health_gauge = GaugeVec::new(
            Opts::new(
                format!("{prefix}_nvue_system_health_state"),
                "NVOS system health: 0=unknown, 1=healthy, 2=degraded, 3=unhealthy",
            ),
            &["switch_id", "switch_ip", "switch_mac"],
        )?;
        registry.register(Box::new(system_health_gauge.clone()))?;

        let cluster_app_gauge = GaugeVec::new(
            Opts::new(
                format!("{prefix}_nvue_cluster_app_state"),
                "NVOS cluster app status: 0=unknown, 1=running, 2=stopped, 3=error",
            ),
            &["switch_id", "switch_ip", "switch_mac", "app_name"],
        )?;
        registry.register(Box::new(cluster_app_gauge.clone()))?;

        let partition_health_gauge = GaugeVec::new(
            Opts::new(
                format!("{prefix}_nvue_partition_health"),
                "NVOS partition health: 0=unknown, 1=healthy, 2=degraded, 3=unhealthy",
            ),
            &[
                "switch_id",
                "switch_ip",
                "switch_mac",
                "partition_id",
                "partition_name",
            ],
        )?;
        registry.register(Box::new(partition_health_gauge.clone()))?;

        let partition_gpu_count_gauge = GaugeVec::new(
            Opts::new(
                format!("{prefix}_nvue_partition_gpu_count"),
                "GPU count per SDN partition",
            ),
            &[
                "switch_id",
                "switch_ip",
                "switch_mac",
                "partition_id",
                "partition_name",
            ],
        )?;
        registry.register(Box::new(partition_gpu_count_gauge.clone()))?;

        let link_diagnostic_gauge = GaugeVec::new(
            Opts::new(
                format!("{prefix}_nvue_link_diagnostic_status"),
                "Link diagnostic status: 0=ok, 1=warning, 2=error",
            ),
            &[
                "switch_id",
                "switch_ip",
                "switch_mac",
                "interface_name",
                "diagnostic_code",
            ],
        )?;
        registry.register(Box::new(link_diagnostic_gauge.clone()))?;

        Ok(Self {
            client,
            switch_id,
            switch_ip,
            switch_mac,
            event_context,
            system_health_gauge,
            cluster_app_gauge,
            partition_health_gauge,
            partition_gpu_count_gauge,
            link_diagnostic_gauge,
            data_sink: config.data_sink,
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        self.emit_event(CollectorEvent::MetricCollectionStart);
        let mut entity_count = 0usize;

        match self.client.get_system_health().await {
            Ok(Some(health)) => {
                let value = health_status_to_f64(health.status.as_deref());
                self.system_health_gauge
                    .with_label_values(&[&self.switch_id, &self.switch_ip, &self.switch_mac])
                    .set(value);
                self.emit_metric("system_health_state", None, value, "state", vec![]);
                entity_count += 1;
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect system health"
            ),
        }

        match self.client.get_cluster_apps().await {
            Ok(Some(apps)) => {
                for (name, app) in &apps {
                    let value = app_status_to_f64(app.status.as_deref());
                    self.cluster_app_gauge
                        .with_label_values(&[
                            &self.switch_id,
                            &self.switch_ip,
                            &self.switch_mac,
                            name,
                        ])
                        .set(value);
                    self.emit_metric(
                        "cluster_app_state",
                        Some(name),
                        value,
                        "state",
                        vec![(Cow::Borrowed("app_name"), name.clone())],
                    );
                    entity_count += 1;
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect cluster apps"
            ),
        }

        match self.client.get_sdn_partitions().await {
            Ok(Some(partitions)) => {
                for (part_id, summary) in &partitions {
                    let detail = match self.client.get_partition_detail(part_id).await {
                        Ok(Some(d)) => d,
                        Ok(None) => summary.clone(),
                        Err(e) => {
                            tracing::warn!(
                                error = ?e,
                                switch_id = %self.switch_id,
                                partition_id = %part_id,
                                "nvue_rest: failed to fetch partition detail, using summary"
                            );
                            summary.clone()
                        }
                    };

                    let part_name = detail.name.as_deref().unwrap_or(part_id);
                    let health_value = health_status_to_f64(detail.health.as_deref());
                    let gpu_count = detail.gpu.as_ref().map_or(0, |g| g.len()) as f64;

                    let labels = [
                        self.switch_id.as_str(),
                        self.switch_ip.as_str(),
                        self.switch_mac.as_str(),
                        part_id,
                        part_name,
                    ];
                    self.partition_health_gauge
                        .with_label_values(&labels)
                        .set(health_value);
                    self.partition_gpu_count_gauge
                        .with_label_values(&labels)
                        .set(gpu_count);

                    let partition_labels = vec![
                        (Cow::Borrowed("partition_id"), part_id.clone()),
                        (Cow::Borrowed("partition_name"), part_name.to_string()),
                    ];
                    self.emit_metric(
                        "partition_health",
                        Some(part_id),
                        health_value,
                        "state",
                        partition_labels.clone(),
                    );
                    self.emit_metric(
                        "partition_gpu_count",
                        Some(part_id),
                        gpu_count,
                        "count",
                        partition_labels,
                    );
                    entity_count += 1;
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect SDN partitions"
            ),
        }

        match self.client.get_link_diagnostics().await {
            Ok(diagnostics) => {
                for diag in &diagnostics {
                    let value = diagnostic_status_to_f64(&diag.status);
                    self.link_diagnostic_gauge
                        .with_label_values(&[
                            &self.switch_id,
                            &self.switch_ip,
                            &self.switch_mac,
                            &diag.interface,
                            &diag.code,
                        ])
                        .set(value);
                    self.emit_metric(
                        "link_diagnostic_status",
                        Some(&format!("{}:{}", diag.interface, diag.code)),
                        value,
                        "state",
                        vec![
                            (Cow::Borrowed("interface_name"), diag.interface.clone()),
                            (Cow::Borrowed("diagnostic_code"), diag.code.clone()),
                        ],
                    );
                    entity_count += 1;
                }
            }
            Err(e) => tracing::warn!(
                error = ?e,
                switch_id = %self.switch_id,
                "nvue_rest: failed to collect link diagnostics"
            ),
        }

        self.emit_event(CollectorEvent::MetricCollectionEnd);

        tracing::debug!(
            switch_id = %self.switch_id,
            entity_count,
            "nvue_rest: collection iteration complete"
        );

        Ok(IterationResult {
            refresh_triggered: true,
            entity_count: Some(entity_count),
        })
    }

    fn collector_type(&self) -> &'static str {
        COLLECTOR_NAME
    }
}

impl NvueRestCollector {
    fn emit_event(&self, event: CollectorEvent) {
        if let Some(data_sink) = &self.data_sink {
            data_sink.handle_event(&self.event_context, &event);
        }
    }

    fn emit_metric(
        &self,
        metric_type: &str,
        entity_qualifier: Option<&str>,
        value: f64,
        unit: &str,
        extra_labels: Vec<(Cow<'static, str>, String)>,
    ) {
        let key = match entity_qualifier {
            Some(q) => {
                let mut k = String::with_capacity(metric_type.len() + 1 + q.len());
                k.push_str(metric_type);
                k.push(':');
                k.push_str(q);
                k
            }
            None => metric_type.to_string(),
        };

        let mut labels = Vec::with_capacity(3 + extra_labels.len());
        labels.push((Cow::Borrowed("switch_id"), self.switch_id.clone()));
        labels.push((Cow::Borrowed("switch_ip"), self.switch_ip.clone()));
        labels.push((Cow::Borrowed("switch_mac"), self.switch_mac.clone()));
        labels.extend(extra_labels);

        self.emit_event(CollectorEvent::Metric(MetricSample {
            key,
            name: COLLECTOR_NAME.to_string(),
            metric_type: metric_type.to_string(),
            unit: unit.to_string(),
            value,
            labels,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_mapping() {
        assert_eq!(health_status_to_f64(Some("healthy")), 1.0);
        assert_eq!(health_status_to_f64(Some("degraded")), 2.0);
        assert_eq!(health_status_to_f64(Some("unhealthy")), 3.0);
        assert_eq!(health_status_to_f64(None), 0.0);
        assert_eq!(health_status_to_f64(Some("unknown_value")), 0.0);
    }

    #[test]
    fn test_app_status_mapping() {
        assert_eq!(app_status_to_f64(Some("running")), 1.0);
        assert_eq!(app_status_to_f64(Some("stopped")), 2.0);
        assert_eq!(app_status_to_f64(Some("error")), 3.0);
        assert_eq!(app_status_to_f64(None), 0.0);
        assert_eq!(app_status_to_f64(Some("other")), 0.0);
    }

    #[test]
    fn test_diagnostic_status_mapping() {
        assert_eq!(diagnostic_status_to_f64("ok"), 0.0);
        assert_eq!(diagnostic_status_to_f64("warning"), 1.0);
        assert_eq!(diagnostic_status_to_f64("error"), 2.0);
        assert_eq!(diagnostic_status_to_f64("other"), 0.0);
    }
}
