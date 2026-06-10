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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use prometheus::{Histogram, HistogramOpts};

use crate::HealthError;
use crate::bmc::BmcClient;
use crate::collectors::{Collector, LogDowngradeRegistry, SharedInventory};
use crate::config::{
    Config, Configurable, DiscoveryConfig, FirmwareCollectorConfig as FirmwareCollectorOptions,
    LeakDetectorCollectorConfig as LeakDetectorCollectorOptions,
    LogsCollectorConfig as LogsCollectorOptions, MetricsCollectorConfig as MetricsCollectorOptions,
    NmxtCollectorConfig as NmxtCollectorOptions, NvueCollectorConfig as NvueCollectorOptions,
    SensorCollectorConfig as SensorCollectorOptions,
};
use crate::limiter::RateLimiter;
use crate::metrics::{MetricsManager, operation_duration_buckets_seconds};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) enum CollectorKind {
    Discovery,
    Sensor,
    Metrics,
    Logs,
    Firmware,
    LeakDetector,
    Nmxt,
    NvueRest,
    NvueGnmi,
}

impl CollectorKind {
    pub(super) const ALL: [CollectorKind; 9] = [
        CollectorKind::Discovery,
        CollectorKind::Sensor,
        CollectorKind::Metrics,
        CollectorKind::Logs,
        CollectorKind::Firmware,
        CollectorKind::LeakDetector,
        CollectorKind::Nmxt,
        CollectorKind::NvueRest,
        CollectorKind::NvueGnmi,
    ];

    pub(super) fn stop_message(self) -> &'static str {
        match self {
            CollectorKind::Discovery => {
                "Stopping entity discovery collector for removed BMC endpoint"
            }
            CollectorKind::Sensor => "Stopping sensor collector for removed BMC endpoint",
            CollectorKind::Metrics => "Stopping entity metrics collector for removed BMC endpoint",
            CollectorKind::Logs => "Stopping logs collector for removed BMC endpoint",
            CollectorKind::Firmware => "Stopping firmware collector for removed BMC endpoint",
            CollectorKind::LeakDetector => {
                "Stopping leak detector collector for removed BMC endpoint"
            }
            CollectorKind::Nmxt => "Stopping NMX-T collector for removed BMC endpoint",
            CollectorKind::NvueRest => "Stopping NVUE REST collector for removed BMC endpoint",
            CollectorKind::NvueGnmi => {
                "Stopping NVUE gNMI streaming collector for removed switch endpoint"
            }
        }
    }
}

pub(super) struct CollectorState {
    discovery: HashMap<Cow<'static, str>, Collector>,
    sensors: HashMap<Cow<'static, str>, Collector>,
    metrics: HashMap<Cow<'static, str>, Collector>,
    firmware: HashMap<Cow<'static, str>, Collector>,
    leak_detector: HashMap<Cow<'static, str>, Collector>,
    logs: HashMap<Cow<'static, str>, Collector>,
    nmxt: HashMap<Cow<'static, str>, Collector>,
    nvue_rest: HashMap<Cow<'static, str>, Collector>,
    nvue_gnmi: HashMap<Cow<'static, str>, Collector>,
    inventories: HashMap<Cow<'static, str>, SharedInventory<BmcClient>>,
}

impl CollectorState {
    fn new() -> Self {
        Self {
            discovery: HashMap::new(),
            sensors: HashMap::new(),
            metrics: HashMap::new(),
            firmware: HashMap::new(),
            leak_detector: HashMap::new(),
            logs: HashMap::new(),
            nmxt: HashMap::new(),
            nvue_rest: HashMap::new(),
            nvue_gnmi: HashMap::new(),
            inventories: HashMap::new(),
        }
    }

    fn map(&self, kind: CollectorKind) -> &HashMap<Cow<'static, str>, Collector> {
        match kind {
            CollectorKind::Discovery => &self.discovery,
            CollectorKind::Sensor => &self.sensors,
            CollectorKind::Metrics => &self.metrics,
            CollectorKind::Logs => &self.logs,
            CollectorKind::Firmware => &self.firmware,
            CollectorKind::LeakDetector => &self.leak_detector,
            CollectorKind::Nmxt => &self.nmxt,
            CollectorKind::NvueRest => &self.nvue_rest,
            CollectorKind::NvueGnmi => &self.nvue_gnmi,
        }
    }

    pub(super) fn map_mut(
        &mut self,
        kind: CollectorKind,
    ) -> &mut HashMap<Cow<'static, str>, Collector> {
        match kind {
            CollectorKind::Discovery => &mut self.discovery,
            CollectorKind::Sensor => &mut self.sensors,
            CollectorKind::Metrics => &mut self.metrics,
            CollectorKind::Logs => &mut self.logs,
            CollectorKind::Firmware => &mut self.firmware,
            CollectorKind::LeakDetector => &mut self.leak_detector,
            CollectorKind::Nmxt => &mut self.nmxt,
            CollectorKind::NvueRest => &mut self.nvue_rest,
            CollectorKind::NvueGnmi => &mut self.nvue_gnmi,
        }
    }

    pub(super) fn inventory_for(&mut self, key: &str) -> SharedInventory<BmcClient> {
        if let Some(shared) = self.inventories.get(key) {
            return shared.clone();
        }
        let shared = Arc::new(ArcSwapOption::empty());
        self.inventories
            .insert(Cow::Owned(key.to_string()), shared.clone());
        shared
    }

    /// Drop the shared inventory handle for a removed endpoint.
    pub(super) fn remove_inventory(&mut self, key: &str) {
        self.inventories.remove(key);
    }

    pub(super) fn contains(&self, kind: CollectorKind, key: &str) -> bool {
        self.map(kind).contains_key(key)
    }

    pub(super) fn insert(
        &mut self,
        kind: CollectorKind,
        key: Cow<'static, str>,
        collector: Collector,
    ) {
        self.map_mut(kind).insert(key, collector);
    }

    pub(super) fn len(&self, kind: CollectorKind) -> usize {
        self.map(kind).len()
    }

    pub(super) fn removed_keys(
        &self,
        active_keys: &HashSet<Cow<'static, str>>,
    ) -> HashSet<Cow<'static, str>> {
        self.discovery
            .keys()
            .chain(self.sensors.keys())
            .chain(self.metrics.keys())
            .chain(self.logs.keys())
            .chain(self.firmware.keys())
            .chain(self.leak_detector.keys())
            .chain(self.nmxt.keys())
            .chain(self.nvue_rest.keys())
            .chain(self.nvue_gnmi.keys())
            .filter(|key| !active_keys.contains(*key))
            .cloned()
            .collect()
    }

    pub(super) fn prune_finished_logs(&mut self) {
        self.logs.retain(|key, collector| {
            if collector.is_finished() {
                tracing::info!(
                    endpoint_key = %key,
                    "pruning finished logs collector (task exited); discovery will respawn"
                );
                false
            } else {
                true
            }
        });
    }
}

pub struct DiscoveryLoopContext {
    pub(super) collectors: CollectorState,
    pub(crate) discovery_iteration_histogram: Histogram,
    pub(crate) discovery_endpoint_fetch_histogram: Histogram,
    pub(crate) limiter: Arc<dyn RateLimiter>,
    pub(crate) metrics_manager: Arc<MetricsManager>,
    pub(crate) discovery_config: DiscoveryConfig,
    pub(crate) sensors_config: Configurable<SensorCollectorOptions>,
    pub(crate) metrics_config: Configurable<MetricsCollectorOptions>,
    pub(crate) logs_config: Configurable<LogsCollectorOptions>,
    pub(crate) firmware_config: Configurable<FirmwareCollectorOptions>,
    pub(crate) leak_detector_config: Configurable<LeakDetectorCollectorOptions>,
    pub(crate) nmxt_config: Configurable<NmxtCollectorOptions>,
    pub(crate) nvue_config: Configurable<NvueCollectorOptions>,
    pub(crate) log_downgrade_registry: Arc<LogDowngradeRegistry>,
}

impl DiscoveryLoopContext {
    pub fn new(
        limiter: Arc<dyn RateLimiter>,
        metrics_manager: Arc<MetricsManager>,
        config: Arc<Config>,
    ) -> Result<Self, HealthError> {
        let registry = metrics_manager.global_registry();

        let metrics_prefix = &config.metrics.prefix;

        let discovery_iteration_histogram = Histogram::with_opts(
            HistogramOpts::new(
                format!("{metrics_prefix}_discovery_iteration_seconds"),
                "Duration of full discovery loop iteration",
            )
            .buckets(operation_duration_buckets_seconds()),
        )?;
        registry.register(Box::new(discovery_iteration_histogram.clone()))?;

        let discovery_endpoint_fetch_histogram = Histogram::with_opts(
            HistogramOpts::new(
                format!("{metrics_prefix}_discovery_endpoint_fetch_seconds"),
                "Duration of API call to fetch BMC endpoints",
            )
            .buckets(operation_duration_buckets_seconds()),
        )?;
        registry.register(Box::new(discovery_endpoint_fetch_histogram.clone()))?;

        Ok(Self {
            collectors: CollectorState::new(),
            discovery_iteration_histogram,
            discovery_endpoint_fetch_histogram,
            limiter,
            metrics_manager,
            discovery_config: config.collectors.discovery.clone(),
            sensors_config: config.collectors.sensors.clone(),
            metrics_config: config.collectors.metrics.clone(),
            logs_config: config.collectors.logs.clone(),
            firmware_config: config.collectors.firmware.clone(),
            leak_detector_config: config.collectors.leak_detector.clone(),
            nmxt_config: config.collectors.nmxt.clone(),
            nvue_config: config.collectors.nvue.clone(),
            log_downgrade_registry: Arc::new(LogDowngradeRegistry::new()),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::HashSet;

    use super::*;
    use crate::collectors::Collector;

    fn noop_collector() -> Collector {
        Collector::spawn_task(|_| async {})
    }

    #[tokio::test]
    async fn removed_keys_includes_nvue_gnmi_collectors() {
        let mut state = CollectorState::new();
        state.insert(
            CollectorKind::NvueGnmi,
            Cow::Borrowed("removed-gNMI-endpoint"),
            noop_collector(),
        );
        state.insert(
            CollectorKind::NvueRest,
            Cow::Borrowed("active-rest-endpoint"),
            noop_collector(),
        );

        let active = HashSet::from([Cow::Borrowed("active-rest-endpoint")]);
        let removed = state.removed_keys(&active);

        assert!(removed.contains(&Cow::Borrowed("removed-gNMI-endpoint")));
        assert!(!removed.contains(&Cow::Borrowed("active-rest-endpoint")));
    }
}
