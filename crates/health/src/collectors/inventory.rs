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
use std::time::Instant;

use arc_swap::ArcSwapOption;
use nv_redfish::Resource;
use nv_redfish::chassis::{Chassis, PowerSupply};
use nv_redfish::computer_system::{ComputerSystem, Drive, Memory, Processor, Storage};
use nv_redfish::core::{Bmc, ToSnakeCase};
use nv_redfish::sensor::SensorLink;

use crate::metrics::MetricLabel;

pub(crate) struct DerivedMetric {
    pub(crate) metric_type: &'static str,
    pub(crate) unit: &'static str,
    pub(crate) value: f64,
}

pub(crate) enum DiscoveredEntity<B: Bmc> {
    Processor {
        entity: Arc<Processor<B>>,
        system: Arc<ComputerSystem<B>>,
        sensors: Vec<SensorLink<B>>,
    },
    Memory {
        entity: Arc<Memory<B>>,
        system: Arc<ComputerSystem<B>>,
        sensors: Vec<SensorLink<B>>,
    },
    Drive {
        entity: Arc<Drive<B>>,
        storage: Arc<Storage<B>>,
        system: Arc<ComputerSystem<B>>,
        sensors: Vec<SensorLink<B>>,
    },
    PowerSupply {
        entity: Arc<PowerSupply<B>>,
        chassis: Arc<Chassis<B>>,
        sensors: Vec<SensorLink<B>>,
    },
    Chassis {
        entity: Arc<Chassis<B>>,
        sensors: Vec<SensorLink<B>>,
    },
}

impl<B: Bmc> DiscoveredEntity<B> {
    pub(crate) fn sensors(&self) -> &[SensorLink<B>] {
        match self {
            DiscoveredEntity::Processor { sensors, .. }
            | DiscoveredEntity::Memory { sensors, .. }
            | DiscoveredEntity::Drive { sensors, .. }
            | DiscoveredEntity::PowerSupply { sensors, .. }
            | DiscoveredEntity::Chassis { sensors, .. } => sensors,
        }
    }

    pub(crate) fn entity_type(&self) -> &'static str {
        match self {
            DiscoveredEntity::Processor { .. } => "processor",
            DiscoveredEntity::Memory { .. } => "memory",
            DiscoveredEntity::Drive { .. } => "drive",
            DiscoveredEntity::PowerSupply { .. } => "powersupply",
            DiscoveredEntity::Chassis { .. } => "chassis",
        }
    }

    pub(crate) fn physical_context_fallback(&self) -> &'static str {
        match self {
            DiscoveredEntity::Processor { .. } => "cpu",
            DiscoveredEntity::Memory { .. } => "memory",
            DiscoveredEntity::Drive { .. } => "storage_device",
            DiscoveredEntity::PowerSupply { .. } => "power_supply",
            DiscoveredEntity::Chassis { .. } => "chassis",
        }
    }

    pub(crate) fn base_attributes(&self) -> Vec<MetricLabel> {
        match self {
            DiscoveredEntity::Processor { entity, system, .. } => vec![
                (Cow::Borrowed("processor_id"), entity.raw().base.id.clone()),
                (Cow::Borrowed("system_id"), system.raw().base.id.clone()),
            ],
            DiscoveredEntity::Memory { entity, system, .. } => vec![
                (Cow::Borrowed("memory_id"), entity.raw().base.id.clone()),
                (Cow::Borrowed("system_id"), system.raw().base.id.clone()),
            ],
            DiscoveredEntity::Drive {
                entity,
                system,
                storage,
                ..
            } => vec![
                (Cow::Borrowed("drive_id"), entity.raw().base.id.clone()),
                (Cow::Borrowed("storage_id"), storage.raw().base.id.clone()),
                (Cow::Borrowed("system_id"), system.raw().base.id.clone()),
            ],
            DiscoveredEntity::PowerSupply {
                entity, chassis, ..
            } => vec![
                (
                    Cow::Borrowed("powersupply_id"),
                    entity.raw().base.id.clone(),
                ),
                (Cow::Borrowed("chassis_id"), chassis.raw().base.id.clone()),
            ],
            DiscoveredEntity::Chassis { entity, .. } => {
                vec![(Cow::Borrowed("chassis_id"), entity.raw().base.id.clone())]
            }
        }
    }

    pub(crate) fn entity_specific_attributes(&self) -> Vec<MetricLabel> {
        let mut attrs = Vec::new();
        match self {
            DiscoveredEntity::Processor { entity, .. } => {
                if let Some(processor_type) = entity.raw().processor_type.flatten() {
                    attrs.push((
                        Cow::Borrowed("processor_type"),
                        processor_type.to_snake_case().to_string(),
                    ));
                }
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push((Cow::Borrowed("model"), model));
                }
            }
            DiscoveredEntity::Memory { entity, .. } => {
                if let Some(device_type) = entity.raw().memory_device_type.flatten() {
                    attrs.push((
                        Cow::Borrowed("device_type"),
                        device_type.to_snake_case().to_string(),
                    ));
                }
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push((Cow::Borrowed("model"), model));
                }
            }
            DiscoveredEntity::Drive { entity, .. } => {
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push((Cow::Borrowed("model"), model));
                }
            }
            DiscoveredEntity::PowerSupply { entity, .. } => {
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push((Cow::Borrowed("model"), model));
                }
            }
            DiscoveredEntity::Chassis { entity, .. } => {
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push((Cow::Borrowed("model"), model));
                }
            }
        }
        attrs
    }

    pub(crate) fn key(&self) -> String {
        match self {
            DiscoveredEntity::Processor { entity, .. } => entity.odata_id().to_string(),
            DiscoveredEntity::Memory { entity, .. } => entity.odata_id().to_string(),
            DiscoveredEntity::Drive { entity, .. } => entity.odata_id().to_string(),
            DiscoveredEntity::PowerSupply { entity, .. } => entity.odata_id().to_string(),
            DiscoveredEntity::Chassis { entity, .. } => entity.odata_id().to_string(),
        }
    }

    pub(crate) fn derived_metrics(&self) -> Vec<DerivedMetric> {
        match self {
            DiscoveredEntity::Drive { entity, .. } => entity
                .raw()
                .predicted_media_life_left_percent
                .flatten()
                .map(|value| {
                    vec![DerivedMetric {
                        metric_type: "drive_predicted_media_life_left",
                        unit: "percentage",
                        value,
                    }]
                })
                .unwrap_or_default(),
            DiscoveredEntity::PowerSupply { entity, .. } => entity
                .raw()
                .power_capacity_watts
                .flatten()
                .map(|value| {
                    vec![DerivedMetric {
                        metric_type: "powersupply_capacity",
                        unit: "watts",
                        value,
                    }]
                })
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

pub(crate) struct EntityInventory<B: Bmc> {
    pub(crate) entities: Vec<DiscoveredEntity<B>>,
    pub(crate) discovered_at: Instant,
    pub(crate) generation: u64,
}

pub(crate) type SharedInventory<B> = Arc<ArcSwapOption<EntityInventory<B>>>;
