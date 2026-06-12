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
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::{StreamExt, stream};
use nv_redfish::core::Bmc;
use nv_redfish::schema::memory_metrics::MemoryMetrics;
use nv_redfish::schema::pcie_device::PcieErrors;
use nv_redfish::schema::power_supply_metrics::PowerSupplyMetrics;
use nv_redfish::schema::processor_metrics::ProcessorMetrics;

use crate::HealthError;
use crate::collectors::inventory::{DiscoveredEntity, SharedInventory};
use crate::collectors::runtime::{IterationResult, PeriodicCollector};
use crate::endpoint::BmcEndpoint;
use crate::sink::{CollectorEvent, DataSink, EventContext, MetricSample};

struct MetricField {
    metric_type: Cow<'static, str>,
    unit: &'static str,
    value: f64,
}

/// Push a scalar `Option<Option<T: Into<f64>>>` field if present
macro_rules! scalar {
    ($out:expr, $src:expr, $field:ident, $mt:literal, $unit:literal) => {
        if let Some(Some(value)) = $src.$field {
            $out.push(MetricField {
                metric_type: Cow::Borrowed($mt),
                unit: $unit,
                value: value as f64,
            });
        }
    };
}

/// Push a field only when it is not backed by a sensor
macro_rules! excerpt {
    ($out:expr, $src:expr, $field:ident, $mt:literal, $unit:literal) => {
        if let Some(excerpt) = &$src.$field {
            let sensor_backed = excerpt
                .data_source_uri
                .as_ref()
                .and_then(|inner| inner.as_ref())
                .is_some();
            if !sensor_backed {
                if let Some(Some(value)) = excerpt.reading {
                    $out.push(MetricField {
                        metric_type: Cow::Borrowed($mt),
                        unit: $unit,
                        value,
                    });
                }
            }
        }
    };
}

/// Push an ISO 8601 `Edm.Duration` field (e.g. `"PT0S"`) as seconds.
macro_rules! duration_seconds {
    ($out:expr, $src:expr, $field:ident, $mt:literal) => {
        if let Some(Some(duration)) = &$src.$field {
            $out.push(MetricField {
                metric_type: Cow::Borrowed($mt),
                unit: "seconds",
                value: duration.as_f64_seconds(),
            });
        }
    };
}

fn pcie_error_fields(out: &mut Vec<MetricField>, pcie: &PcieErrors) {
    scalar!(
        out,
        pcie,
        correctable_error_count,
        "pcie_correctable_errors",
        "count"
    );
    scalar!(
        out,
        pcie,
        non_fatal_error_count,
        "pcie_non_fatal_errors",
        "count"
    );
    scalar!(out, pcie, fatal_error_count, "pcie_fatal_errors", "count");
    scalar!(
        out,
        pcie,
        l0to_recovery_count,
        "pcie_l0_to_recovery",
        "count"
    );
    scalar!(out, pcie, replay_count, "pcie_replay", "count");
    scalar!(
        out,
        pcie,
        replay_rollover_count,
        "pcie_replay_rollover",
        "count"
    );
    scalar!(out, pcie, nak_sent_count, "pcie_nak_sent", "count");
    scalar!(out, pcie, nak_received_count, "pcie_nak_received", "count");
    scalar!(
        out,
        pcie,
        unsupported_request_count,
        "pcie_unsupported_request",
        "count"
    );
    scalar!(out, pcie, bad_tlp_count, "pcie_bad_tlp", "count");
    scalar!(out, pcie, bad_dllp_count, "pcie_bad_dllp", "count");
    scalar!(
        out,
        pcie,
        flow_control_timeout_errors,
        "pcie_flow_control_timeout",
        "count"
    );
}

fn processor_metric_fields(m: &ProcessorMetrics) -> Vec<MetricField> {
    let mut out = Vec::new();
    scalar!(out, m, bandwidth_percent, "bandwidth", "percent");
    scalar!(out, m, average_frequency_mhz, "average_frequency", "mhz");
    scalar!(out, m, throttling_celsius, "throttling", "celsius");
    scalar!(out, m, temperature_celsius, "temperature", "celsius");
    scalar!(out, m, consumed_power_watt, "consumed_power", "watts");
    scalar!(out, m, frequency_ratio, "frequency_ratio", "ratio");
    scalar!(
        out,
        m,
        local_memory_bandwidth_bytes,
        "local_memory_bandwidth",
        "bytes"
    );
    scalar!(
        out,
        m,
        remote_memory_bandwidth_bytes,
        "remote_memory_bandwidth",
        "bytes"
    );
    scalar!(out, m, kernel_percent, "kernel_time", "percent");
    scalar!(out, m, user_percent, "user_time", "percent");
    scalar!(out, m, operating_speed_mhz, "operating_speed", "mhz");
    scalar!(
        out,
        m,
        correctable_core_error_count,
        "correctable_core_errors",
        "count"
    );
    scalar!(
        out,
        m,
        uncorrectable_core_error_count,
        "uncorrectable_core_errors",
        "count"
    );
    scalar!(
        out,
        m,
        correctable_other_error_count,
        "correctable_other_errors",
        "count"
    );
    scalar!(
        out,
        m,
        uncorrectable_other_error_count,
        "uncorrectable_other_errors",
        "count"
    );
    duration_seconds!(
        out,
        m,
        power_limit_throttle_duration,
        "power_limit_throttle"
    );
    duration_seconds!(
        out,
        m,
        thermal_limit_throttle_duration,
        "thermal_limit_throttle"
    );
    excerpt!(out, m, core_voltage, "core_voltage", "volts");
    if let Some(pcie) = &m.pcie_errors {
        pcie_error_fields(&mut out, pcie);
    }
    out
}

fn memory_metric_fields(m: &MemoryMetrics) -> Vec<MetricField> {
    let mut out = Vec::new();
    scalar!(out, m, block_size_bytes, "block_size", "bytes");
    scalar!(out, m, bandwidth_percent, "bandwidth", "percent");
    scalar!(out, m, operating_speed_mhz, "operating_speed", "mhz");
    scalar!(
        out,
        m,
        corrected_volatile_error_count,
        "corrected_volatile_errors",
        "count"
    );
    scalar!(
        out,
        m,
        corrected_persistent_error_count,
        "corrected_persistent_errors",
        "count"
    );
    scalar!(out, m, dirty_shutdown_count, "dirty_shutdown", "count");
    scalar!(
        out,
        m,
        capacity_utilization_percent,
        "capacity_utilization",
        "percent"
    );
    if let Some(cp) = &m.current_period {
        scalar!(
            out,
            cp,
            correctable_ecc_error_count,
            "current_correctable_ecc_errors",
            "count"
        );
        scalar!(
            out,
            cp,
            uncorrectable_ecc_error_count,
            "current_uncorrectable_ecc_errors",
            "count"
        );
        scalar!(
            out,
            cp,
            indeterminate_correctable_error_count,
            "current_indeterminate_correctable_errors",
            "count"
        );
        scalar!(
            out,
            cp,
            indeterminate_uncorrectable_error_count,
            "current_indeterminate_uncorrectable_errors",
            "count"
        );
    }
    if let Some(lt) = &m.life_time {
        scalar!(
            out,
            lt,
            correctable_ecc_error_count,
            "lifetime_correctable_ecc_errors",
            "count"
        );
        scalar!(
            out,
            lt,
            uncorrectable_ecc_error_count,
            "lifetime_uncorrectable_ecc_errors",
            "count"
        );
        scalar!(
            out,
            lt,
            indeterminate_correctable_error_count,
            "lifetime_indeterminate_correctable_errors",
            "count"
        );
        scalar!(
            out,
            lt,
            indeterminate_uncorrectable_error_count,
            "lifetime_indeterminate_uncorrectable_errors",
            "count"
        );
    }
    out
}

fn drive_metric_fields(m: &nv_redfish::schema::drive_metrics::DriveMetrics) -> Vec<MetricField> {
    let mut out = Vec::new();
    scalar!(
        out,
        m,
        correctable_io_read_error_count,
        "correctable_io_read_errors",
        "count"
    );
    scalar!(
        out,
        m,
        correctable_io_write_error_count,
        "correctable_io_write_errors",
        "count"
    );
    scalar!(
        out,
        m,
        uncorrectable_io_read_error_count,
        "uncorrectable_io_read_errors",
        "count"
    );
    scalar!(
        out,
        m,
        uncorrectable_io_write_error_count,
        "uncorrectable_io_write_errors",
        "count"
    );
    scalar!(out, m, bad_block_count, "bad_block", "count");
    scalar!(out, m, power_on_hours, "power_on_hours", "hours");
    scalar!(
        out,
        m,
        native_command_queue_depth,
        "native_command_queue_depth",
        "count"
    );
    scalar!(out, m, read_ioki_bytes, "read_io", "kibibytes");
    scalar!(out, m, write_ioki_bytes, "write_io", "kibibytes");
    out
}

fn power_supply_metric_fields(m: &PowerSupplyMetrics) -> Vec<MetricField> {
    let mut out = Vec::new();
    excerpt!(out, m, input_voltage, "input_voltage", "volts");
    excerpt!(out, m, input_current_amps, "input_current", "amperes");
    excerpt!(out, m, input_power_watts, "input_power", "watts");
    excerpt!(out, m, energyk_wh, "energy", "kilowatt_hours");
    excerpt!(out, m, frequency_hz, "frequency", "hertz");
    excerpt!(out, m, output_power_watts, "output_power", "watts");
    excerpt!(out, m, temperature_celsius, "temperature", "celsius");
    excerpt!(out, m, fan_speed_percent, "fan_speed", "percent");
    out
}

pub struct MetricsCollectorConfig<B: Bmc> {
    pub data_sink: Option<Arc<dyn DataSink>>,
    pub(crate) shared: SharedInventory<B>,
    pub fetch_concurrency: usize,
}

pub struct MetricsCollector<B: Bmc> {
    endpoint: Arc<BmcEndpoint>,
    event_context: EventContext,
    shared: SharedInventory<B>,
    data_sink: Option<Arc<dyn DataSink>>,
    fetch_concurrency: usize,
}

impl<B: Bmc + 'static> PeriodicCollector<B> for MetricsCollector<B> {
    type Config = MetricsCollectorConfig<B>;

    fn new_runner(
        _bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let event_context = EventContext::from_endpoint(endpoint.as_ref(), "metrics_collector");
        Ok(Self {
            endpoint,
            event_context,
            shared: config.shared,
            data_sink: config.data_sink,
            fetch_concurrency: config.fetch_concurrency.max(1),
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        let Some(inventory) = self.shared.load_full() else {
            tracing::debug!(
                bmc_addr = ?self.endpoint.addr,
                "No entity inventory available yet; skipping metrics iteration"
            );
            return Ok(IterationResult {
                refresh_triggered: false,
                entity_count: None,
                fetch_failures: 0,
            });
        };

        tracing::debug!(
            bmc_addr = ?self.endpoint.addr,
            generation = inventory.generation,
            inventory_age_secs = inventory.discovered_at.elapsed().as_secs(),
            entity_count = inventory.entities.len(),
            "Reading entity inventory snapshot for metrics iteration"
        );

        let fetch_failures = AtomicUsize::new(0);
        self.emit_event(CollectorEvent::MetricCollectionStart);

        let this = &*self;
        let failures = &fetch_failures;
        let futures: Vec<_> = inventory
            .entities
            .iter()
            .map(|entity| this.collect_entity(entity, failures))
            .collect();

        let processed: usize = stream::iter(futures)
            .buffer_unordered(self.fetch_concurrency)
            .collect::<Vec<usize>>()
            .await
            .into_iter()
            .sum();

        self.emit_event(CollectorEvent::MetricCollectionEnd);

        Ok(IterationResult {
            refresh_triggered: false,
            entity_count: Some(processed),
            fetch_failures: fetch_failures.load(Ordering::Relaxed),
        })
    }

    fn collector_type(&self) -> &'static str {
        "metrics_collector"
    }

    async fn stop(&mut self) {
        self.emit_event(CollectorEvent::CollectorRemoved);
    }
}

impl<B: Bmc + 'static> MetricsCollector<B> {
    fn emit_event(&self, event: CollectorEvent) {
        if let Some(data_sink) = &self.data_sink {
            data_sink.handle_event(&self.event_context, &event);
        }
    }

    async fn collect_entity(
        &self,
        entity: &DiscoveredEntity<B>,
        fetch_failures: &AtomicUsize,
    ) -> usize {
        let fields = match entity {
            DiscoveredEntity::Processor { entity, .. } => {
                match self.fetch(entity.metrics().await, "processor metrics", fetch_failures) {
                    Some(Some(m)) => processor_metric_fields(&m),
                    _ => return 0,
                }
            }
            DiscoveredEntity::Memory { entity, .. } => {
                match self.fetch(entity.metrics().await, "memory metrics", fetch_failures) {
                    Some(Some(m)) => memory_metric_fields(&m),
                    _ => return 0,
                }
            }
            DiscoveredEntity::Drive { entity, .. } => {
                match self.fetch(entity.metrics().await, "drive metrics", fetch_failures) {
                    Some(Some(m)) => drive_metric_fields(&m),
                    _ => return 0,
                }
            }
            DiscoveredEntity::PowerSupply { entity, .. } => {
                match self.fetch(
                    entity.metrics().await,
                    "power supply metrics",
                    fetch_failures,
                ) {
                    Some(Some(m)) => power_supply_metric_fields(&m),
                    _ => return 0,
                }
            }
            DiscoveredEntity::Chassis { .. } => return 0,
        };

        if fields.is_empty() {
            return 0;
        }

        // The metric_type and unit are encoded in the Prometheus series name
        // (`{prefix}_hw_metric_{metric_type}_{unit}`), so they are not repeated
        // as labels here.
        let mut base = entity.base_attributes();
        base.extend(entity.entity_specific_attributes());

        let entity_key = entity.key();
        let count = fields.len();
        for field in fields {
            self.emit_event(CollectorEvent::Metric(
                MetricSample {
                    key: format!("{entity_key}/{}", field.metric_type),
                    name: "hw_metric".to_string(),
                    metric_type: field.metric_type.to_string(),
                    unit: field.unit.to_string(),
                    value: field.value,
                    labels: base.clone(),
                    context: None,
                }
                .into(),
            ));
        }
        count
    }

    fn fetch<T, E: std::fmt::Debug>(
        &self,
        result: Result<T, E>,
        context: &str,
        fetch_failures: &AtomicUsize,
    ) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                fetch_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(?error, context, bmc_addr = ?self.endpoint.addr, "Failed to fetch metrics resource");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn by_type(fields: &[MetricField]) -> HashMap<String, (&'static str, f64)> {
        fields
            .iter()
            .map(|f| (f.metric_type.to_string(), (f.unit, f.value)))
            .collect()
    }

    #[test]
    fn processor_scalars_and_pcie_errors_are_flattened() {
        let metrics: ProcessorMetrics = serde_json::from_value(json!({
            "@odata.id": "/redfish/v1/Systems/1/Processors/CPU0/ProcessorMetrics",
            "Id": "ProcessorMetrics",
            "Name": "Processor Metrics",
            "BandwidthPercent": 42.5,
            "OperatingSpeedMHz": 3200,
            "CorrectableCoreErrorCount": 7,
            "UncorrectableCoreErrorCount": 0,
            "PCIeErrors": {
                "CorrectableErrorCount": 3,
                "FatalErrorCount": 1
            },
            "PowerLimitThrottleDuration": "PT0S",
            "ThermalLimitThrottleDuration": "PT1M30S"
        }))
        .expect("processor metrics should deserialize");

        let fields = by_type(&processor_metric_fields(&metrics));
        assert_eq!(fields.get("bandwidth"), Some(&("percent", 42.5)));
        assert_eq!(fields.get("operating_speed"), Some(&("mhz", 3200.0)));
        assert_eq!(fields.get("correctable_core_errors"), Some(&("count", 7.0)));
        assert_eq!(
            fields.get("uncorrectable_core_errors"),
            Some(&("count", 0.0))
        );
        assert_eq!(fields.get("pcie_correctable_errors"), Some(&("count", 3.0)));
        assert_eq!(fields.get("pcie_fatal_errors"), Some(&("count", 1.0)));
        // ISO 8601 durations are emitted as seconds.
        assert_eq!(fields.get("power_limit_throttle"), Some(&("seconds", 0.0)));
        assert_eq!(
            fields.get("thermal_limit_throttle"),
            Some(&("seconds", 90.0))
        );
    }

    #[test]
    fn sensor_backed_excerpt_is_skipped_but_inline_excerpt_is_emitted() {
        // CoreVoltage carrying a DataSourceUri is already published as hw_sensor
        // and must NOT be re-emitted here.
        let linked: ProcessorMetrics = serde_json::from_value(json!({
            "@odata.id": "/redfish/v1/Systems/1/Processors/CPU0/ProcessorMetrics",
            "Id": "ProcessorMetrics",
            "Name": "Processor Metrics",
            "CoreVoltage": {
                "DataSourceUri": "/redfish/v1/Chassis/1/Sensors/CPU0_Voltage",
                "Reading": 1.2
            }
        }))
        .expect("deserialize");
        assert!(!by_type(&processor_metric_fields(&linked)).contains_key("core_voltage"));

        // Without a DataSourceUri the inline reading is emitted.
        let inline: ProcessorMetrics = serde_json::from_value(json!({
            "@odata.id": "/redfish/v1/Systems/1/Processors/CPU0/ProcessorMetrics",
            "Id": "ProcessorMetrics",
            "Name": "Processor Metrics",
            "CoreVoltage": { "Reading": 1.05 }
        }))
        .expect("deserialize");
        assert_eq!(
            by_type(&processor_metric_fields(&inline)).get("core_voltage"),
            Some(&("volts", 1.05))
        );
    }

    #[test]
    fn memory_nested_periods_are_flattened_with_prefixes() {
        let metrics: MemoryMetrics = serde_json::from_value(json!({
            "@odata.id": "/redfish/v1/Systems/1/Memory/DIMM0/MemoryMetrics",
            "Id": "MemoryMetrics",
            "Name": "Memory Metrics",
            "CorrectedVolatileErrorCount": 2,
            "CurrentPeriod": { "CorrectableECCErrorCount": 5 },
            "LifeTime": { "UncorrectableECCErrorCount": 9 }
        }))
        .expect("memory metrics should deserialize");

        let fields = by_type(&memory_metric_fields(&metrics));
        assert_eq!(
            fields.get("corrected_volatile_errors"),
            Some(&("count", 2.0))
        );
        assert_eq!(
            fields.get("current_correctable_ecc_errors"),
            Some(&("count", 5.0))
        );
        assert_eq!(
            fields.get("lifetime_uncorrectable_ecc_errors"),
            Some(&("count", 9.0))
        );
    }

    #[test]
    fn drive_io_error_counters_are_emitted() {
        let metrics: nv_redfish::schema::drive_metrics::DriveMetrics =
            serde_json::from_value(json!({
                "@odata.id": "/redfish/v1/Systems/1/Storage/1/Drives/D0/Metrics",
                "Id": "DriveMetrics",
                "Name": "Drive Metrics",
                "BadBlockCount": 4,
                "CorrectableIOReadErrorCount": 11,
                "PowerOnHours": 12345.0
            }))
            .expect("drive metrics should deserialize");

        let fields = by_type(&drive_metric_fields(&metrics));
        assert_eq!(fields.get("bad_block"), Some(&("count", 4.0)));
        assert_eq!(
            fields.get("correctable_io_read_errors"),
            Some(&("count", 11.0))
        );
        assert_eq!(fields.get("power_on_hours"), Some(&("hours", 12345.0)));
    }

    #[test]
    fn power_supply_metrics_skip_sensor_backed_excerpts() {
        let metrics: PowerSupplyMetrics = serde_json::from_value(json!({
            "@odata.id": "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/PSU0/Metrics",
            "Id": "PowerSupplyMetrics",
            "Name": "Power Supply Metrics",
            "InputVoltage": {
                "DataSourceUri": "/redfish/v1/Chassis/1/Sensors/PSU0_Vin",
                "Reading": 230.0
            },
            "OutputPowerWatts": { "Reading": 500.0 }
        }))
        .expect("power supply metrics should deserialize");

        let fields = by_type(&power_supply_metric_fields(&metrics));
        // Sensor-backed input voltage is skipped; inline output power is kept.
        assert!(!fields.contains_key("input_voltage"));
        assert_eq!(fields.get("output_power"), Some(&("watts", 500.0)));
    }
}
