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

use std::sync::Arc;

use nv_redfish::ServiceRoot;
use nv_redfish_core::{Bmc, EntityTypeRef};

use crate::api_client::{BmcEndpoint, EndpointMetadata};
use crate::collector::PeriodicCollector;
use crate::metrics::{CollectorRegistry, GaugeMetrics, GaugeReading};
use crate::{HealthError, collector};

pub struct FirmwareCollectorConfig {
    pub collector_registry: Arc<CollectorRegistry>,
}

pub struct FirmwareCollector<B: Bmc> {
    bmc: Arc<B>,
    hw_firmware_gauge: Arc<GaugeMetrics>,
}

impl<B: Bmc + 'static> PeriodicCollector<B> for FirmwareCollector<B> {
    type Config = FirmwareCollectorConfig;

    fn new_runner(
        bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let (serial, machine_id) = match &endpoint.metadata {
            Some(EndpointMetadata::Machine(m)) => (
                m.machine_serial.clone().unwrap_or_default(),
                m.machine_id.to_string(),
            ),
            _ => (String::new(), String::new()),
        };

        let hw_firmware_gauge = config.collector_registry.create_gauge_metrics(
            format!("firmware_gauge_{}", endpoint.addr.hash_key()),
            "Firmware inventory information",
            vec![
                ("serial_number".to_string(), serial),
                ("machine_id".to_string(), machine_id),
                ("bmc_mac".to_string(), endpoint.addr.mac.clone()),
            ],
        )?;

        Ok(Self {
            bmc,
            hw_firmware_gauge,
        })
    }

    async fn run_iteration(&mut self) -> Result<collector::IterationResult, HealthError> {
        self.run_firmware_iteration().await
    }

    fn collector_type(&self) -> &'static str {
        "firmware_collector"
    }
}

impl<B: Bmc + 'static> FirmwareCollector<B> {
    async fn run_firmware_iteration(&self) -> Result<collector::IterationResult, HealthError> {
        let service_root = ServiceRoot::new(self.bmc.clone()).await?;
        let update_service = service_root.update_service().await?;
        let firmware_inventories = update_service.firmware_inventories().await?;
        self.hw_firmware_gauge.begin_update();

        let mut firmware_count = 0;

        for firmware_item in &firmware_inventories {
            let firmware_data = firmware_item.raw();

            let Some(version) = firmware_data.version.clone().flatten() else {
                tracing::debug!(
                    firmware_id = %firmware_data.base.id,
                    "Skipping firmware with no version"
                );
                continue;
            };

            let firmware_name = &firmware_data.base.name;

            let labels = vec![
                ("firmware_name".to_string(), firmware_name.clone()),
                ("version".to_string(), version.clone()),
            ];

            self.hw_firmware_gauge.record(
                GaugeReading::new(
                    firmware_data.id().to_string(),
                    "hw",
                    "firmware",
                    "info",
                    1.0,
                )
                .with_labels(labels),
            );
            firmware_count += 1;
        }

        self.hw_firmware_gauge.sweep_stale();
        Ok(collector::IterationResult {
            refresh_triggered: true,
            entity_count: Some(firmware_count),
        })
    }
}
