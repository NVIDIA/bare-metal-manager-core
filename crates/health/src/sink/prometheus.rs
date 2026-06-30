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

use dashmap::DashMap;

use super::{CollectorEvent, DataSink, EventContext, MetricSample};
use crate::HealthError;
use crate::metrics::{CollectorRegistry, GaugeMetrics, GaugeReading, MetricsManager};

pub struct PrometheusSink {
    collector_registry: Arc<CollectorRegistry>,
    stream_metrics: DashMap<String, DashMap<&'static str, Arc<GaugeMetrics>>>,
}

impl PrometheusSink {
    pub fn new(
        metrics_manager: Arc<MetricsManager>,
        metrics_prefix: &str,
    ) -> Result<Self, HealthError> {
        let collector_registry = Arc::new(metrics_manager.create_telemetry_collector_registry(
            "sink_prometheus_collector".to_string(),
            metrics_prefix,
        )?);
        Ok(Self {
            collector_registry,
            stream_metrics: DashMap::new(),
        })
    }

    fn sanitize_id(value: &str) -> String {
        value
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn stream_metric_id(context: &EventContext) -> String {
        format!(
            "sink_gauge_metrics_{}_{}",
            Self::sanitize_id(context.endpoint_key()),
            Self::sanitize_id(context.collector_type)
        )
    }

    fn metric_reading_key(sample: &MetricSample) -> String {
        const KEY_SEPARATOR: &str = "::";
        let separators_len = KEY_SEPARATOR.len() * 2;
        let mut key = String::with_capacity(
            sample.key.len() + sample.metric_type.len() + sample.unit.len() + separators_len,
        );
        key.push_str(&sample.key);
        key.push_str(KEY_SEPARATOR);
        key.push_str(&sample.metric_type);
        key.push_str(KEY_SEPARATOR);
        key.push_str(&sample.unit);
        key
    }

    fn stream_static_labels(context: &EventContext) -> Vec<(Cow<'static, str>, String)> {
        let mut labels = vec![
            (
                Cow::Borrowed("endpoint_key"),
                context.endpoint_key().to_string(),
            ),
            (Cow::Borrowed("endpoint_mac"), context.addr.mac.to_string()),
            (Cow::Borrowed("endpoint_ip"), context.addr.ip.to_string()),
            (
                Cow::Borrowed("collector_type"),
                context.collector_type.to_string(),
            ),
        ];

        if let Some(machine_id) = context.machine_id() {
            labels.push((Cow::Borrowed("machine_id"), machine_id.to_string()));
        }
        if let Some(switch_id) = context.switch_id() {
            labels.push((Cow::Borrowed("switch_id"), switch_id.to_string()));
        }
        if let Some(serial) = context.serial_number() {
            labels.push((Cow::Borrowed("serial_number"), serial.to_string()));
        }
        if let Some(rack_id) = context.rack_id() {
            labels.push((Cow::Borrowed("rack_id"), rack_id.to_string()));
        }
        if let Some(slot) = context.slot_number() {
            labels.push((Cow::Borrowed("machine_slot_number"), slot.to_string()));
        }
        if let Some(tray) = context.tray_index() {
            labels.push((Cow::Borrowed("machine_tray_index"), tray.to_string()));
        }
        if let Some(domain) = context.nvlink_domain_uuid() {
            labels.push((Cow::Borrowed("nvlink_domain_uuid"), domain.to_string()));
        }
        if let Some(slot) = context.switch_slot_number() {
            labels.push((Cow::Borrowed("switch_slot_number"), slot.to_string()));
        }
        if let Some(tray) = context.switch_tray_index() {
            labels.push((Cow::Borrowed("switch_tray_index"), tray.to_string()));
        }

        labels
    }

    fn get_or_create_stream_metrics(
        &self,
        context: &EventContext,
    ) -> Result<Arc<GaugeMetrics>, HealthError> {
        if let Some(endpoint_metrics) = self.stream_metrics.get::<str>(context.endpoint_key())
            && let Some(entry) = endpoint_metrics.get(context.collector_type)
        {
            return Ok(entry.value().clone());
        }

        let metrics = self.collector_registry.create_gauge_metrics(
            Self::stream_metric_id(context),
            "Metrics forwarded through sink pipeline",
            Self::stream_static_labels(context),
        )?;

        let endpoint_metrics = self
            .stream_metrics
            .entry(context.endpoint_key().to_string())
            .or_default();

        match endpoint_metrics.entry(context.collector_type) {
            dashmap::mapref::entry::Entry::Occupied(existing) => Ok(existing.get().clone()),
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(metrics.clone());
                Ok(metrics)
            }
        }
    }

    fn remove_collector_metrics(&self, context: &EventContext) {
        let Some(endpoint_metrics) = self.stream_metrics.get::<str>(context.endpoint_key()) else {
            return;
        };
        let Some((_, metrics)) = endpoint_metrics.remove(context.collector_type) else {
            return;
        };

        metrics.clear();
        if let Err(error) = self.collector_registry.unregister_gauge_metrics(&metrics) {
            tracing::warn!(
                ?error,
                endpoint_key = context.endpoint_key(),
                collector = context.collector_type,
                "Failed to unregister Prometheus stream metrics"
            );
        }
    }
}

impl DataSink for PrometheusSink {
    fn sink_type(&self) -> &'static str {
        "prometheus_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        match event {
            CollectorEvent::MetricCollectionStart => {
                match self.get_or_create_stream_metrics(context) {
                    Ok(stream_metrics) => stream_metrics.begin_update(),
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            endpoint_key = context.endpoint_key(),
                            collector = context.collector_type,
                            "Failed to initialize Prometheus stream metrics"
                        );
                    }
                }
            }
            CollectorEvent::Metric(sample) => match self.get_or_create_stream_metrics(context) {
                Ok(stream_metrics) => {
                    stream_metrics.record(
                        GaugeReading::new(
                            Self::metric_reading_key(sample),
                            sample.name.clone(),
                            sample.metric_type.clone(),
                            sample.unit.clone(),
                            sample.value,
                        )
                        .with_labels(sample.labels.clone()),
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        endpoint_key = context.endpoint_key(),
                        collector = context.collector_type,
                        metric = sample.name,
                        metric_type = sample.metric_type,
                        "Failed to record Prometheus metric sample"
                    );
                }
            },
            CollectorEvent::MetricCollectionEnd => {
                if let Some(endpoint_metrics) =
                    self.stream_metrics.get::<str>(context.endpoint_key())
                    && let Some(entry) = endpoint_metrics.get(context.collector_type)
                {
                    entry.value().sweep_stale();
                }
            }
            CollectorEvent::CollectorRemoved => self.remove_collector_metrics(context),
            CollectorEvent::Log(_)
            | CollectorEvent::Firmware(_)
            | CollectorEvent::HealthReport(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use carbide_uuid::nvlink::NvLinkDomainId;
    use carbide_uuid::rack::RackId;
    use carbide_uuid::switch::{SwitchId, SwitchIdSource, SwitchType};
    use mac_address::MacAddress;

    use super::*;
    use crate::endpoint::{BmcAddr, EndpointMetadata, MachineData, SwitchData, SwitchEndpointRole};

    fn test_switch_id(label: &str) -> SwitchId {
        let mut hash = [0u8; 32];
        let bytes = label.as_bytes();
        hash[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
        SwitchId::new(SwitchIdSource::Tpm, hash, SwitchType::NvLink)
    }

    #[test]
    fn test_stream_static_labels_includes_machine_metadata() {
        let context = EventContext {
            endpoint_key: "42:9e:b1:bd:9d:dd".to_string(),
            addr: BmcAddr {
                ip: "10.0.0.1".parse().expect("valid ip"),
                port: Some(443),
                mac: MacAddress::from_str("42:9e:b1:bd:9d:dd").unwrap(),
            },
            collector_type: "sensor_collector",
            metadata: Some(EndpointMetadata::Machine(MachineData {
                machine_id: "fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0"
                    .parse()
                    .expect("valid machine id"),
                machine_serial: Some("MN-001".to_string()),
                slot_number: Some(15),
                tray_index: Some(5),
                nvlink_domain_uuid: Some(NvLinkDomainId::nil()),
                driver_version: None,
            })),
            rack_id: Some(RackId::new("RACK_1")),
        };

        let labels = PrometheusSink::stream_static_labels(&context);
        let label_value = |key: &str| {
            labels
                .iter()
                .find_map(|(label, value)| (label.as_ref() == key).then_some(value.as_str()))
        };

        assert_eq!(
            label_value("machine_id"),
            Some("fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0")
        );
        assert_eq!(label_value("serial_number"), Some("MN-001"));
        assert_eq!(label_value("rack_id"), Some("RACK_1"));
        assert_eq!(label_value("machine_slot_number"), Some("15"));
        assert_eq!(label_value("machine_tray_index"), Some("5"));
        assert_eq!(
            label_value("nvlink_domain_uuid"),
            Some("00000000-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn test_stream_static_labels_includes_switch_placement_metadata() {
        let switch_id = test_switch_id("switch-a");
        let switch_id_label = switch_id.to_string();
        let context = EventContext {
            endpoint_key: "11:22:33:44:55:66".to_string(),
            addr: BmcAddr {
                ip: "10.0.1.1".parse().expect("valid ip"),
                port: Some(443),
                mac: MacAddress::from_str("11:22:33:44:55:66").unwrap(),
            },
            collector_type: "switch_collector",
            metadata: Some(EndpointMetadata::Switch(SwitchData {
                id: Some(switch_id),
                serial: "SN-SWITCH-001".to_string(),
                slot_number: Some(7),
                tray_index: Some(3),
                endpoint_role: SwitchEndpointRole::Host,
                is_primary: false,
                nmxt_enabled: false,
            })),
            rack_id: Some(RackId::new("RACK_2")),
        };

        let labels = PrometheusSink::stream_static_labels(&context);
        let label_value = |key: &str| {
            labels
                .iter()
                .find_map(|(label, value)| (label.as_ref() == key).then_some(value.as_str()))
        };

        assert_eq!(label_value("switch_id"), Some(switch_id_label.as_str()));
        assert_eq!(label_value("serial_number"), Some("SN-SWITCH-001"));
        assert_eq!(label_value("rack_id"), Some("RACK_2"));
        assert_eq!(label_value("switch_slot_number"), Some("7"));
        assert_eq!(label_value("switch_tray_index"), Some("3"));
    }
}
