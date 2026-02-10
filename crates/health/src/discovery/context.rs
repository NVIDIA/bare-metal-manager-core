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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use nv_redfish_bmc_http::HttpBmc;
use nv_redfish_bmc_http::reqwest::{
    BmcError, Client as ReqwestClient, ClientParams as ReqwestClientParams,
};
use prometheus::{Histogram, HistogramOpts};

use crate::HealthError;
use crate::collectors::Collector;
use crate::config::{
    Config, Configurable, FirmwareCollectorConfig as FirmwareCollectorOptions,
    LogsCollectorConfig as LogsCollectorOptions, NmxtCollectorConfig as NmxtCollectorOptions,
    SensorCollectorConfig as SensorCollectorOptions,
};
use crate::limiter::RateLimiter;
use crate::metrics::{MetricsManager, operation_duration_buckets_seconds};

pub(crate) type BmcClient = HttpBmc<ReqwestClient>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub(super) enum CollectorKind {
    Sensor,
    Logs,
    Firmware,
    Nmxt,
}

impl CollectorKind {
    pub(super) const ALL: [CollectorKind; 4] = [
        CollectorKind::Sensor,
        CollectorKind::Logs,
        CollectorKind::Firmware,
        CollectorKind::Nmxt,
    ];

    pub(super) fn stop_message(self) -> &'static str {
        match self {
            CollectorKind::Sensor => "Stopping sensor collector for removed BMC endpoint",
            CollectorKind::Logs => "Stopping logs collector for removed BMC endpoint",
            CollectorKind::Firmware => "Stopping firmware collector for removed BMC endpoint",
            CollectorKind::Nmxt => "Stopping NMX-T collector for removed BMC endpoint",
        }
    }
}

pub(super) struct CollectorState {
    maps: HashMap<CollectorKind, HashMap<String, Collector>>,
}

impl CollectorState {
    fn new() -> Self {
        let mut maps = HashMap::new();
        for kind in CollectorKind::ALL {
            maps.insert(kind, HashMap::new());
        }
        Self { maps }
    }

    fn map(&self, kind: CollectorKind) -> &HashMap<String, Collector> {
        self.maps
            .get(&kind)
            .expect("collector map should always exist for every kind")
    }

    fn map_mut(&mut self, kind: CollectorKind) -> &mut HashMap<String, Collector> {
        self.maps
            .get_mut(&kind)
            .expect("collector map should always exist for every kind")
    }

    pub(super) fn contains(&self, kind: CollectorKind, key: &str) -> bool {
        self.map(kind).contains_key(key)
    }

    pub(super) fn insert(&mut self, kind: CollectorKind, key: String, collector: Collector) {
        self.map_mut(kind).insert(key, collector);
    }

    pub(super) fn len(&self, kind: CollectorKind) -> usize {
        self.map(kind).len()
    }

    pub(super) fn map_mut_for_kind(
        &mut self,
        kind: CollectorKind,
    ) -> &mut HashMap<String, Collector> {
        self.map_mut(kind)
    }

    pub(super) fn removed_keys(&self, active_keys: &HashSet<String>) -> HashSet<String> {
        self.maps
            .values()
            .flat_map(|map| map.keys())
            .filter(|key| !active_keys.contains(*key))
            .cloned()
            .collect()
    }
}

pub struct DiscoveryLoopContext {
    pub(super) collectors: CollectorState,
    pub(crate) discovery_iteration_histogram: Histogram,
    pub(crate) discovery_endpoint_fetch_histogram: Histogram,
    pub(crate) client: ReqwestClient,
    pub(crate) limiter: Arc<dyn RateLimiter>,
    pub(crate) metrics_manager: Arc<MetricsManager>,
    pub(crate) config: Arc<Config>,
    pub(crate) sensors_config: Configurable<SensorCollectorOptions>,
    pub(crate) logs_config: Configurable<LogsCollectorOptions>,
    pub(crate) firmware_config: Configurable<FirmwareCollectorOptions>,
    pub(crate) nmxt_config: Configurable<NmxtCollectorOptions>,
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

        let client =
            ReqwestClient::with_params(ReqwestClientParams::new().accept_invalid_certs(true))
                .map_err(BmcError::ReqwestError)?;

        let sensors_config = config.collectors.sensors.clone();
        let logs_config = config.collectors.logs.clone();
        let firmware_config = config.collectors.firmware.clone();
        let nmxt_config = config.collectors.nmxt.clone();

        Ok(Self {
            collectors: CollectorState::new(),
            discovery_iteration_histogram,
            discovery_endpoint_fetch_histogram,
            client,
            limiter,
            metrics_manager,
            config,
            sensors_config,
            logs_config,
            firmware_config,
            nmxt_config,
        })
    }
}
