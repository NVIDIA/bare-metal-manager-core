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
                bmc_address = ?self.endpoint.addr,
                "No entity inventory available yet; skipping metrics iteration"
            );
            return Ok(IterationResult {
                refresh_triggered: false,
                entity_count: None,
                fetch_failures: 0,
            });
        };

        tracing::debug!(
            bmc_address = ?self.endpoint.addr,
            generation = inventory.generation,
            inventory_age_seconds = inventory.discovered_at.elapsed().as_secs(),
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
                    Some(Some(m)) => processor_metric_fields(&m.raw()),
                    _ => return 0,
                }
            }
            DiscoveredEntity::Memory { entity, .. } => {
                match self.fetch(entity.metrics().await, "memory metrics", fetch_failures) {
                    Some(Some(m)) => memory_metric_fields(&m.raw()),
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
                tracing::warn!(
                    ?error,
                    context,
                    bmc_address = ?self.endpoint.addr,
                    "Failed to fetch metrics resource"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Mutex as StdMutex;

    use carbide_test_support::Outcome::Yields;
    use carbide_test_support::{Case, Check, check_cases_async, check_values};
    use serde_json::json;

    use super::*;
    use crate::collectors::projection_test_support::{ProjectionFixture, TestBmc, TestEntity};
    use crate::endpoint::test_support::{mac, test_endpoint};

    #[derive(Clone, Copy)]
    enum Projection {
        Processor,
        Memory,
        Drive,
        PowerSupply,
    }

    struct ProjectionCase {
        projection: Projection,
        metrics: serde_json::Value,
    }

    type ProjectedMetric = (String, &'static str, f64);

    fn sort_projected_metrics(mut fields: Vec<ProjectedMetric>) -> Vec<ProjectedMetric> {
        fields.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then(left.1.cmp(right.1))
                .then(left.2.total_cmp(&right.2))
        });
        fields
    }

    fn project(case: ProjectionCase) -> Vec<ProjectedMetric> {
        let fields = match case.projection {
            Projection::Processor => processor_metric_fields(
                &serde_json::from_value(case.metrics)
                    .expect("processor metrics should deserialize"),
            ),
            Projection::Memory => memory_metric_fields(
                &serde_json::from_value(case.metrics).expect("memory metrics should deserialize"),
            ),
            Projection::Drive => drive_metric_fields(
                &serde_json::from_value(case.metrics).expect("drive metrics should deserialize"),
            ),
            Projection::PowerSupply => power_supply_metric_fields(
                &serde_json::from_value(case.metrics)
                    .expect("power supply metrics should deserialize"),
            ),
        };

        sort_projected_metrics(
            fields
                .into_iter()
                .map(|field| (field.metric_type.into_owned(), field.unit, field.value))
                .collect(),
        )
    }

    fn expected(
        fields: impl IntoIterator<Item = (&'static str, &'static str, f64)>,
    ) -> Vec<ProjectedMetric> {
        sort_projected_metrics(
            fields
                .into_iter()
                .map(|(metric_type, unit, value)| (metric_type.to_string(), unit, value))
                .collect(),
        )
    }

    #[test]
    fn child_metric_projection_cases() {
        check_values(
            [
                Check {
                    scenario: "processor scalars, durations, and PCIe errors",
                    input: ProjectionCase {
                        projection: Projection::Processor,
                        metrics: json!({
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
                        }),
                    },
                    expect: expected([
                        ("bandwidth", "percent", 42.5),
                        ("operating_speed", "mhz", 3200.0),
                        ("correctable_core_errors", "count", 7.0),
                        ("uncorrectable_core_errors", "count", 0.0),
                        ("power_limit_throttle", "seconds", 0.0),
                        ("thermal_limit_throttle", "seconds", 90.0),
                        ("pcie_correctable_errors", "count", 3.0),
                        ("pcie_fatal_errors", "count", 1.0),
                    ]),
                },
                Check {
                    scenario: "processor sensor-backed excerpt is ignored",
                    input: ProjectionCase {
                        projection: Projection::Processor,
                        metrics: json!({
                            "@odata.id": "/redfish/v1/Systems/1/Processors/CPU0/ProcessorMetrics",
                            "Id": "ProcessorMetrics",
                            "Name": "Processor Metrics",
                            "CoreVoltage": {
                                "DataSourceUri": "/redfish/v1/Chassis/1/Sensors/CPU0_Voltage",
                                "Reading": 1.2
                            }
                        }),
                    },
                    expect: expected([]),
                },
                Check {
                    scenario: "processor inline excerpt is emitted",
                    input: ProjectionCase {
                        projection: Projection::Processor,
                        metrics: json!({
                            "@odata.id": "/redfish/v1/Systems/1/Processors/CPU0/ProcessorMetrics",
                            "Id": "ProcessorMetrics",
                            "Name": "Processor Metrics",
                            "CoreVoltage": { "Reading": 1.05 }
                        }),
                    },
                    expect: expected([("core_voltage", "volts", 1.05)]),
                },
                Check {
                    scenario: "remaining processor scalars and PCIe counters",
                    input: ProjectionCase {
                        projection: Projection::Processor,
                        metrics: json!({
                            "@odata.id": "/redfish/v1/Systems/1/Processors/CPU0/ProcessorMetrics",
                            "Id": "ProcessorMetrics",
                            "Name": "Processor Metrics",
                            "AverageFrequencyMHz": 2800.5,
                            "ThrottlingCelsius": 95.0,
                            "TemperatureCelsius": 65.0,
                            "ConsumedPowerWatt": 250.0,
                            "FrequencyRatio": 0.75,
                            "LocalMemoryBandwidthBytes": 1000,
                            "RemoteMemoryBandwidthBytes": 2000,
                            "KernelPercent": 4.5,
                            "UserPercent": 10.5,
                            "CorrectableOtherErrorCount": 2,
                            "UncorrectableOtherErrorCount": 3,
                            "PCIeErrors": {
                                "NonFatalErrorCount": 1,
                                "L0ToRecoveryCount": 2,
                                "ReplayCount": 3,
                                "ReplayRolloverCount": 4,
                                "NAKSentCount": 5,
                                "NAKReceivedCount": 6,
                                "UnsupportedRequestCount": 7,
                                "BadTLPCount": 8,
                                "BadDLLPCount": 9,
                                "FlowControlTimeoutErrors": 10
                            }
                        }),
                    },
                    expect: expected([
                        ("average_frequency", "mhz", 2800.5),
                        ("throttling", "celsius", 95.0),
                        ("temperature", "celsius", 65.0),
                        ("consumed_power", "watts", 250.0),
                        ("frequency_ratio", "ratio", 0.75),
                        ("local_memory_bandwidth", "bytes", 1000.0),
                        ("remote_memory_bandwidth", "bytes", 2000.0),
                        ("kernel_time", "percent", 4.5),
                        ("user_time", "percent", 10.5),
                        ("correctable_other_errors", "count", 2.0),
                        ("uncorrectable_other_errors", "count", 3.0),
                        ("pcie_non_fatal_errors", "count", 1.0),
                        ("pcie_l0_to_recovery", "count", 2.0),
                        ("pcie_replay", "count", 3.0),
                        ("pcie_replay_rollover", "count", 4.0),
                        ("pcie_nak_sent", "count", 5.0),
                        ("pcie_nak_received", "count", 6.0),
                        ("pcie_unsupported_request", "count", 7.0),
                        ("pcie_bad_tlp", "count", 8.0),
                        ("pcie_bad_dllp", "count", 9.0),
                        ("pcie_flow_control_timeout", "count", 10.0),
                    ]),
                },
                Check {
                    scenario: "sparse processor metrics",
                    input: ProjectionCase {
                        projection: Projection::Processor,
                        metrics: json!({
                            "@odata.id": "/redfish/v1/Systems/1/Processors/CPU0/ProcessorMetrics",
                            "Id": "ProcessorMetrics",
                            "Name": "Processor Metrics",
                            "BandwidthPercent": null,
                            "PowerLimitThrottleDuration": null
                        }),
                    },
                    expect: expected([]),
                },
                Check {
                    scenario: "memory nested periods use distinct prefixes",
                    input: ProjectionCase {
                        projection: Projection::Memory,
                        metrics: json!({
                            "@odata.id": "/redfish/v1/Systems/1/Memory/DIMM0/MemoryMetrics",
                            "Id": "MemoryMetrics",
                            "Name": "Memory Metrics",
                            "CorrectedVolatileErrorCount": 2,
                            "CurrentPeriod": { "CorrectableECCErrorCount": 5 },
                            "LifeTime": { "UncorrectableECCErrorCount": 9 }
                        }),
                    },
                    expect: expected([
                        ("corrected_volatile_errors", "count", 2.0),
                        ("current_correctable_ecc_errors", "count", 5.0),
                        ("lifetime_uncorrectable_ecc_errors", "count", 9.0),
                    ]),
                },
                Check {
                    scenario: "remaining memory scalars and period counters",
                    input: ProjectionCase {
                        projection: Projection::Memory,
                        metrics: json!({
                            "@odata.id": "/redfish/v1/Systems/1/Memory/DIMM0/MemoryMetrics",
                            "Id": "MemoryMetrics",
                            "Name": "Memory Metrics",
                            "BlockSizeBytes": 4096,
                            "BandwidthPercent": 72.5,
                            "OperatingSpeedMHz": 6400,
                            "CorrectedPersistentErrorCount": 3,
                            "DirtyShutdownCount": 4,
                            "CapacityUtilizationPercent": 81.0,
                            "CurrentPeriod": {
                                "UncorrectableECCErrorCount": 5,
                                "IndeterminateCorrectableErrorCount": 6,
                                "IndeterminateUncorrectableErrorCount": 7
                            },
                            "LifeTime": {
                                "CorrectableECCErrorCount": 8,
                                "IndeterminateCorrectableErrorCount": 9,
                                "IndeterminateUncorrectableErrorCount": 10
                            }
                        }),
                    },
                    expect: expected([
                        ("block_size", "bytes", 4096.0),
                        ("bandwidth", "percent", 72.5),
                        ("operating_speed", "mhz", 6400.0),
                        ("corrected_persistent_errors", "count", 3.0),
                        ("dirty_shutdown", "count", 4.0),
                        ("capacity_utilization", "percent", 81.0),
                        ("current_uncorrectable_ecc_errors", "count", 5.0),
                        ("current_indeterminate_correctable_errors", "count", 6.0),
                        ("current_indeterminate_uncorrectable_errors", "count", 7.0),
                        ("lifetime_correctable_ecc_errors", "count", 8.0),
                        ("lifetime_indeterminate_correctable_errors", "count", 9.0),
                        ("lifetime_indeterminate_uncorrectable_errors", "count", 10.0),
                    ]),
                },
                Check {
                    scenario: "sparse memory metrics",
                    input: ProjectionCase {
                        projection: Projection::Memory,
                        metrics: json!({
                            "@odata.id": "/redfish/v1/Systems/1/Memory/DIMM0/MemoryMetrics",
                            "Id": "MemoryMetrics",
                            "Name": "Memory Metrics"
                        }),
                    },
                    expect: expected([]),
                },
                Check {
                    scenario: "drive error and lifetime counters",
                    input: ProjectionCase {
                        projection: Projection::Drive,
                        metrics: json!({
                            "@odata.id": "/redfish/v1/Systems/1/Storage/1/Drives/D0/Metrics",
                            "Id": "DriveMetrics",
                            "Name": "Drive Metrics",
                            "BadBlockCount": 4,
                            "CorrectableIOReadErrorCount": 11,
                            "PowerOnHours": 12345.0
                        }),
                    },
                    expect: expected([
                        ("correctable_io_read_errors", "count", 11.0),
                        ("bad_block", "count", 4.0),
                        ("power_on_hours", "hours", 12345.0),
                    ]),
                },
                Check {
                    scenario: "remaining drive counters",
                    input: ProjectionCase {
                        projection: Projection::Drive,
                        metrics: json!({
                            "@odata.id": "/redfish/v1/Systems/1/Storage/1/Drives/D0/Metrics",
                            "Id": "DriveMetrics",
                            "Name": "Drive Metrics",
                            "CorrectableIOWriteErrorCount": 1,
                            "UncorrectableIOReadErrorCount": 2,
                            "UncorrectableIOWriteErrorCount": 3,
                            "NativeCommandQueueDepth": 4,
                            "ReadIOKiBytes": 5,
                            "WriteIOKiBytes": 6
                        }),
                    },
                    expect: expected([
                        ("correctable_io_write_errors", "count", 1.0),
                        ("uncorrectable_io_read_errors", "count", 2.0),
                        ("uncorrectable_io_write_errors", "count", 3.0),
                        ("native_command_queue_depth", "count", 4.0),
                        ("read_io", "kibibytes", 5.0),
                        ("write_io", "kibibytes", 6.0),
                    ]),
                },
                Check {
                    scenario: "sparse drive metrics",
                    input: ProjectionCase {
                        projection: Projection::Drive,
                        metrics: json!({
                            "@odata.id": "/redfish/v1/Systems/1/Storage/1/Drives/D0/Metrics",
                            "Id": "DriveMetrics",
                            "Name": "Drive Metrics"
                        }),
                    },
                    expect: expected([]),
                },
                Check {
                    scenario: "power supply ignores sensor-backed and emits inline excerpts",
                    input: ProjectionCase {
                        projection: Projection::PowerSupply,
                        metrics: json!({
                            "@odata.id":
                                "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/PSU0/Metrics",
                            "Id": "PowerSupplyMetrics",
                            "Name": "Power Supply Metrics",
                            "InputVoltage": {
                                "DataSourceUri": "/redfish/v1/Chassis/1/Sensors/PSU0_Vin",
                                "Reading": 230.0
                            },
                            "InputPowerWatts": {
                                "DataSourceUri": null,
                                "Reading": 450.0
                            },
                            "OutputPowerWatts": {
                                "DataSourceUri": null,
                                "Reading": 500.0
                            }
                        }),
                    },
                    expect: expected([
                        ("input_power", "watts", 450.0),
                        ("output_power", "watts", 500.0),
                    ]),
                },
                Check {
                    scenario: "remaining power supply excerpts",
                    input: ProjectionCase {
                        projection: Projection::PowerSupply,
                        metrics: json!({
                            "@odata.id":
                                "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/PSU0/Metrics",
                            "Id": "PowerSupplyMetrics",
                            "Name": "Power Supply Metrics",
                            "InputVoltage": { "Reading": 230.0 },
                            "InputCurrentAmps": {
                                "DataSourceUri": null,
                                "Reading": 2.0
                            },
                            "InputPowerWatts": { "Reading": null },
                            "EnergykWh": {
                                "DataSourceUri": null,
                                "Reading": 2.5
                            },
                            "FrequencyHz": {
                                "DataSourceUri": null,
                                "Reading": 60.0
                            },
                            "TemperatureCelsius": {
                                "DataSourceUri": null,
                                "Reading": 35.0
                            },
                            "FanSpeedPercent": {
                                "DataSourceUri": null,
                                "Reading": 50.0
                            }
                        }),
                    },
                    expect: expected([
                        ("input_voltage", "volts", 230.0),
                        ("input_current", "amperes", 2.0),
                        ("energy", "kilowatt_hours", 2.5),
                        ("frequency", "hertz", 60.0),
                        ("temperature", "celsius", 35.0),
                        ("fan_speed", "percent", 50.0),
                    ]),
                },
            ],
            project,
        );
    }

    #[derive(Clone, Debug, PartialEq)]
    struct ObservedMetric {
        key: String,
        name: String,
        metric_type: String,
        unit: String,
        value: f64,
        labels: Vec<(String, String)>,
        has_context: bool,
    }

    #[derive(Clone, Debug, PartialEq)]
    enum ObservedEvent {
        CollectionStart,
        Metric(ObservedMetric),
        CollectionEnd,
        CollectorRemoved,
        Log,
        Firmware,
        HealthReport,
    }

    #[derive(Default)]
    struct CapturingSink {
        events: StdMutex<Vec<ObservedEvent>>,
    }

    impl DataSink for CapturingSink {
        fn sink_type(&self) -> &'static str {
            "capturing_sink"
        }

        fn try_handle_event(
            &self,
            _context: &EventContext,
            event: &CollectorEvent,
        ) -> Result<(), HealthError> {
            let observed = match event {
                CollectorEvent::MetricCollectionStart => ObservedEvent::CollectionStart,
                CollectorEvent::Metric(sample) => ObservedEvent::Metric(ObservedMetric {
                    key: sample.key.clone(),
                    name: sample.name.clone(),
                    metric_type: sample.metric_type.clone(),
                    unit: sample.unit.clone(),
                    value: sample.value,
                    labels: sample
                        .labels
                        .iter()
                        .map(|(key, value)| (key.to_string(), value.clone()))
                        .collect(),
                    has_context: sample.context.is_some(),
                }),
                CollectorEvent::MetricCollectionEnd => ObservedEvent::CollectionEnd,
                CollectorEvent::CollectorRemoved => ObservedEvent::CollectorRemoved,
                CollectorEvent::Log(_) => ObservedEvent::Log,
                CollectorEvent::Firmware(_) => ObservedEvent::Firmware,
                CollectorEvent::HealthReport(_) => ObservedEvent::HealthReport,
            };
            self.events.lock().unwrap().push(observed);
            Ok(())
        }
    }

    struct CollectionCase {
        bmc: Arc<TestBmc>,
        entity: DiscoveredEntity<TestBmc>,
        with_sink: bool,
    }

    #[derive(Debug, PartialEq)]
    struct ObservedCollection {
        field_count: usize,
        fetch_failures: usize,
        events: Vec<ObservedEvent>,
    }

    async fn collect(case: CollectionCase) -> Result<ObservedCollection, Infallible> {
        let capture = Arc::new(CapturingSink::default());
        let data_sink = case.with_sink.then(|| capture.clone() as Arc<dyn DataSink>);
        let collector = MetricsCollector::new_runner(
            case.bmc,
            Arc::new(test_endpoint(mac("00:11:22:33:44:55"))),
            MetricsCollectorConfig {
                data_sink,
                shared: Arc::new(arc_swap::ArcSwapOption::empty()),
                fetch_concurrency: 1,
            },
        )
        .expect("metrics collector should build");
        let fetch_failures = AtomicUsize::new(0);
        let field_count = collector
            .collect_entity(&case.entity, &fetch_failures)
            .await;
        let events = capture.events.lock().unwrap().clone();

        Ok(ObservedCollection {
            field_count,
            fetch_failures: fetch_failures.load(Ordering::Relaxed),
            events,
        })
    }

    fn metric(
        key: &str,
        metric_type: &str,
        unit: &str,
        value: f64,
        labels: &[(&str, &str)],
    ) -> ObservedEvent {
        ObservedEvent::Metric(ObservedMetric {
            key: key.to_string(),
            name: "hw_metric".to_string(),
            metric_type: metric_type.to_string(),
            unit: unit.to_string(),
            value,
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            has_context: false,
        })
    }

    #[tokio::test]
    async fn collect_entity_cases() {
        let fixture = ProjectionFixture::new().await;

        check_cases_async(
            [
                Case {
                    scenario: "processor metric",
                    input: CollectionCase {
                        bmc: fixture.bmc(),
                        entity: fixture.entity(TestEntity::Processor).await,
                        with_sink: true,
                    },
                    expect: Yields(ObservedCollection {
                        field_count: 1,
                        fetch_failures: 0,
                        events: vec![metric(
                            "/redfish/v1/Systems/SYS0/Processors/CPU0/bandwidth",
                            "bandwidth",
                            "percent",
                            42.0,
                            &[
                                ("processor_id", "CPU0"),
                                ("system_id", "SYS0"),
                                ("processor_type", "cpu"),
                                ("model", "Grace"),
                            ],
                        )],
                    }),
                },
                Case {
                    scenario: "memory metric",
                    input: CollectionCase {
                        bmc: fixture.bmc(),
                        entity: fixture.entity(TestEntity::Memory).await,
                        with_sink: true,
                    },
                    expect: Yields(ObservedCollection {
                        field_count: 1,
                        fetch_failures: 0,
                        events: vec![metric(
                            "/redfish/v1/Systems/SYS0/Memory/DIMM0/block_size",
                            "block_size",
                            "bytes",
                            4096.0,
                            &[
                                ("memory_id", "DIMM0"),
                                ("system_id", "SYS0"),
                                ("device_type", "ddr5"),
                                ("model", "HMCG94AGBRA"),
                            ],
                        )],
                    }),
                },
                Case {
                    scenario: "drive metric",
                    input: CollectionCase {
                        bmc: fixture.bmc(),
                        entity: fixture.entity(TestEntity::Drive).await,
                        with_sink: true,
                    },
                    expect: Yields(ObservedCollection {
                        field_count: 1,
                        fetch_failures: 0,
                        events: vec![metric(
                            "/redfish/v1/Systems/SYS0/Storage/ST0/Drives/D0/bad_block",
                            "bad_block",
                            "count",
                            4.0,
                            &[
                                ("drive_id", "D0"),
                                ("storage_id", "ST0"),
                                ("system_id", "SYS0"),
                                ("model", "NVMe-1"),
                            ],
                        )],
                    }),
                },
                Case {
                    scenario: "power supply metric",
                    input: CollectionCase {
                        bmc: fixture.bmc(),
                        entity: fixture.entity(TestEntity::PowerSupply).await,
                        with_sink: true,
                    },
                    expect: Yields(ObservedCollection {
                        field_count: 1,
                        fetch_failures: 0,
                        events: vec![metric(
                            concat!(
                                "/redfish/v1/Chassis/CH0/PowerSubsystem/PowerSupplies/PS0/",
                                "output_power"
                            ),
                            "output_power",
                            "watts",
                            500.0,
                            &[
                                ("powersupply_id", "PS0"),
                                ("chassis_id", "CH0"),
                                ("model", "PSU-3KW"),
                            ],
                        )],
                    }),
                },
                Case {
                    scenario: "chassis is ignored",
                    input: CollectionCase {
                        bmc: fixture.bmc(),
                        entity: fixture.entity(TestEntity::Chassis).await,
                        with_sink: true,
                    },
                    expect: Yields(ObservedCollection {
                        field_count: 0,
                        fetch_failures: 0,
                        events: vec![],
                    }),
                },
                Case {
                    scenario: "missing metrics link",
                    input: CollectionCase {
                        bmc: fixture.bmc(),
                        entity: fixture.entity(TestEntity::SparseProcessor).await,
                        with_sink: true,
                    },
                    expect: Yields(ObservedCollection {
                        field_count: 0,
                        fetch_failures: 0,
                        events: vec![],
                    }),
                },
                Case {
                    scenario: "empty metrics resource",
                    input: CollectionCase {
                        bmc: fixture.bmc(),
                        entity: fixture.entity(TestEntity::ProcessorWithEmptyMetrics).await,
                        with_sink: true,
                    },
                    expect: Yields(ObservedCollection {
                        field_count: 0,
                        fetch_failures: 0,
                        events: vec![],
                    }),
                },
                Case {
                    scenario: "malformed metrics response",
                    input: CollectionCase {
                        bmc: fixture.bmc(),
                        entity: fixture
                            .entity(TestEntity::ProcessorWithMalformedMetrics)
                            .await,
                        with_sink: true,
                    },
                    expect: Yields(ObservedCollection {
                        field_count: 0,
                        fetch_failures: 1,
                        events: vec![],
                    }),
                },
                Case {
                    scenario: "metric projection without a sink",
                    input: CollectionCase {
                        bmc: fixture.bmc(),
                        entity: fixture.entity(TestEntity::Processor).await,
                        with_sink: false,
                    },
                    expect: Yields(ObservedCollection {
                        field_count: 1,
                        fetch_failures: 0,
                        events: vec![],
                    }),
                },
            ],
            collect,
        )
        .await;
    }
}
