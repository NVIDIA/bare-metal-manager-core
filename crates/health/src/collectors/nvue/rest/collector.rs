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

use super::client::RestClient;
use crate::HealthError;
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::config::NvueRestConfig;
use crate::endpoint::{BmcEndpoint, EndpointMetadata};
use crate::sink::{CollectorEvent, DataSink, EventContext, MetricSample};

const COLLECTOR_NAME: &str = "nvue_rest";

fn system_health_to_f64(status: Option<&str>) -> f64 {
    match status {
        Some("OK") => 1.0,
        Some("Not OK") => 2.0,
        _ => 0.0,
    }
}

fn partition_health_to_f64(status: Option<&str>) -> f64 {
    match status {
        Some("healthy") => 1.0,
        Some("degraded_bandwidth") => 2.0,
        Some("degraded") => 3.0,
        Some("unhealthy") => 4.0,
        _ => 0.0,
    }
}

fn app_status_to_f64(status: Option<&str>) -> f64 {
    match status {
        Some("ok") => 1.0,
        Some("not ok") => 2.0,
        _ => 0.0,
    }
}

/// code "0" means no issue; any other opcode indicates a problem
fn diagnostic_opcode_to_f64(code: &str) -> f64 {
    match code {
        "0" => 0.0,
        _ => 1.0,
    }
}

pub struct NvueRestCollectorConfig {
    pub rest_config: NvueRestConfig,
    pub data_sink: Option<Arc<dyn DataSink>>,
}

pub struct NvueRestCollector {
    client: RestClient,
    switch_id: String,
    event_context: EventContext,
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

        Ok(Self {
            client,
            switch_id,
            event_context,
            data_sink: config.data_sink,
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        self.emit_event(CollectorEvent::MetricCollectionStart);
        let mut entity_count = 0usize;

        match self.client.get_system_health().await {
            Ok(Some(health)) => {
                let value = system_health_to_f64(health.status.as_deref());
                self.emit_metric("system_health", None, value, "state", vec![]);
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
                    self.emit_metric(
                        "cluster_app",
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
                for (part_id, partition) in &partitions {
                    let part_name = partition.name.as_deref().unwrap_or(part_id);
                    let health_value = partition_health_to_f64(partition.health.as_deref());
                    let gpu_count = partition.num_gpus.unwrap_or(0) as f64;

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
                        "partition_gpu",
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
                    let value = diagnostic_opcode_to_f64(&diag.code);
                    self.emit_metric(
                        "link_diagnostic",
                        Some(&format!("{}:{}", diag.interface, diag.code)),
                        value,
                        "state",
                        vec![
                            (Cow::Borrowed("interface_name"), diag.interface.clone()),
                            (Cow::Borrowed("opcode"), diag.code.clone()),
                            (Cow::Borrowed("diagnostic_status"), diag.status.clone()),
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
        labels: Vec<(Cow<'static, str>, String)>,
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
    fn test_system_health_mapping() {
        assert_eq!(system_health_to_f64(Some("OK")), 1.0);
        assert_eq!(system_health_to_f64(Some("Not OK")), 2.0);
        assert_eq!(system_health_to_f64(None), 0.0);
        assert_eq!(system_health_to_f64(Some("unknown_value")), 0.0);
    }

    #[test]
    fn test_partition_health_mapping() {
        assert_eq!(partition_health_to_f64(Some("unknown")), 0.0);
        assert_eq!(partition_health_to_f64(Some("healthy")), 1.0);
        assert_eq!(partition_health_to_f64(Some("degraded_bandwidth")), 2.0);
        assert_eq!(partition_health_to_f64(Some("degraded")), 3.0);
        assert_eq!(partition_health_to_f64(Some("unhealthy")), 4.0);
        assert_eq!(partition_health_to_f64(None), 0.0);
    }

    #[test]
    fn test_app_status_mapping() {
        assert_eq!(app_status_to_f64(Some("ok")), 1.0);
        assert_eq!(app_status_to_f64(Some("not ok")), 2.0);
        assert_eq!(app_status_to_f64(None), 0.0);
        assert_eq!(app_status_to_f64(Some("other")), 0.0);
    }

    #[test]
    fn test_diagnostic_opcode_mapping() {
        assert_eq!(diagnostic_opcode_to_f64("0"), 0.0);
        assert_eq!(diagnostic_opcode_to_f64("2"), 1.0);
        assert_eq!(diagnostic_opcode_to_f64("1024"), 1.0);
        assert_eq!(diagnostic_opcode_to_f64("57"), 1.0);
    }
}
