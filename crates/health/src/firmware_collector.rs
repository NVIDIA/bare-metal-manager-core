/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;

use nv_redfish::ServiceRoot;
use nv_redfish_core::{Bmc, EntityTypeRef};

use crate::api_client::BmcEndpoint;
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
        let serial = endpoint
            .machine
            .as_ref()
            .and_then(|m| m.machine_serial.clone())
            .unwrap_or_default();
        let machine_id = endpoint
            .machine
            .as_ref()
            .map(|m| m.machine_id.to_string())
            .unwrap_or_default();

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
