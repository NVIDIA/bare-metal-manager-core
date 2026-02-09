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
use std::collections::HashMap;

use carbide_uuid::instance_type::InstanceTypeId;
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use health_report::HealthReport;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::bmc_info::BmcInfo;
use crate::controller_outcome::PersistentStateHandlerOutcome;
use crate::hardware_info::{MachineInventory, MachineNvLinkInfo};
use crate::machine::health_override::HealthReportOverrides;
use crate::machine::infiniband::MachineInfinibandStatusObservation;
use crate::machine::network::{MachineNetworkStatusObservation, ManagedHostNetworkConfig};
use crate::machine::nvlink::MachineNvLinkStatusObservation;
use crate::machine::topology::MachineTopology;
use crate::machine::{
    Dpf, FailureDetails, HostReprovisionRequest, Machine, MachineInterfaceSnapshot,
    MachineLastRebootRequested, MachineStateHistory, ManagedHostState, ReprovisionRequest,
    UpgradeDecision,
};
use crate::metadata::Metadata;
use crate::power_manager::PowerOptions;
use crate::sku::SkuStatus;

/// This represents the structure of a machine we get from postgres via the row_to_json or
/// JSONB_AGG functions. Its fields need to match the column names of the machine_snapshots query
/// exactly. It's expected that we read this directly from the JSON returned by the query, and then
/// convert it into a Machine.
#[derive(Serialize, Deserialize)]
pub struct MachineSnapshotPgJson {
    pub id: MachineId,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deployed: Option<DateTime<Utc>>,
    pub agent_reported_inventory: Option<MachineInventory>,
    pub network_config_version: String,
    pub network_config: ManagedHostNetworkConfig,
    pub network_status_observation: Option<MachineNetworkStatusObservation>,
    pub infiniband_status_observation: Option<MachineInfinibandStatusObservation>,
    pub nvlink_status_observation: Option<MachineNvLinkStatusObservation>,
    pub controller_state_version: String,
    pub controller_state: ManagedHostState,
    pub last_discovery_time: Option<DateTime<Utc>>,
    pub last_scout_contact_time: Option<DateTime<Utc>>,
    pub last_reboot_time: Option<DateTime<Utc>>,
    pub last_reboot_requested: Option<MachineLastRebootRequested>,
    pub last_cleanup_time: Option<DateTime<Utc>>,
    pub failure_details: FailureDetails,
    pub reprovisioning_requested: Option<ReprovisionRequest>,
    pub host_reprovisioning_requested: Option<HostReprovisionRequest>,
    pub manual_firmware_upgrade_completed: Option<DateTime<Utc>>,
    pub bios_password_set_time: Option<DateTime<Utc>>,
    pub last_machine_validation_time: Option<DateTime<Utc>>,
    pub discovery_machine_validation_id: Option<uuid::Uuid>,
    pub cleanup_machine_validation_id: Option<uuid::Uuid>,
    pub dpu_agent_health_report: Option<HealthReport>,
    pub dpu_agent_upgrade_requested: Option<UpgradeDecision>,
    pub machine_validation_health_report: HealthReport,
    pub site_explorer_health_report: Option<HealthReport>,
    pub firmware_autoupdate: Option<bool>,
    pub hardware_health_report: Option<HealthReport>,
    pub health_report_overrides: Option<HealthReportOverrides>,
    pub on_demand_machine_validation_id: Option<uuid::Uuid>,
    pub on_demand_machine_validation_request: Option<bool>,
    pub asn: Option<u32>,
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    pub current_machine_validation_id: Option<uuid::Uuid>,
    pub machine_state_model_version: i32,
    pub instance_type_id: Option<InstanceTypeId>,
    pub interfaces: Vec<MachineInterfaceSnapshot>,
    pub topology: Vec<MachineTopology>,
    pub log_parser_health_report: Option<HealthReport>,
    pub labels: HashMap<String, String>,
    pub name: String,
    pub description: String,
    #[serde(default)] // History is only brought in if the search config requested it
    pub history: Vec<MachineStateHistory>,
    pub version: String,
    pub hw_sku: Option<String>,
    pub hw_sku_status: Option<SkuStatus>,
    pub sku_validation_health_report: Option<HealthReport>,
    #[serde(default)] // Power options are valid only for host, not for DPUs.
    pub power_options: Option<PowerOptions>,
    pub hw_sku_device_type: Option<String>,
    pub update_complete: bool,
    pub nvlink_info: Option<MachineNvLinkInfo>,
    pub dpf: Dpf,
}

impl TryFrom<MachineSnapshotPgJson> for Machine {
    type Error = sqlx::Error;

    fn try_from(value: MachineSnapshotPgJson) -> sqlx::Result<Self> {
        let (hardware_info, bmc_info) = value
            .topology
            .into_iter()
            .map(|t| {
                let topology = t.into_topology();
                (
                    Some(topology.discovery_data.info.clone()),
                    topology.bmc_info,
                )
            })
            .next()
            .unwrap_or((None, BmcInfo::default()));

        let metadata = Metadata {
            name: value.name,
            description: value.description,
            labels: value.labels,
        };

        let version: ConfigVersion =
            value
                .version
                .parse()
                .map_err(|e| sqlx::error::Error::ColumnDecode {
                    index: "version".to_string(),
                    source: Box::new(e),
                })?;

        let history = value
            .history
            .into_iter()
            .sorted_by(
                |s1: &crate::machine::MachineStateHistory,
                 s2: &crate::machine::MachineStateHistory| {
                    Ord::cmp(&s1.state_version.timestamp(), &s2.state_version.timestamp())
                },
            )
            .collect();

        Ok(Self {
            id: value.id,
            state: Versioned {
                value: value.controller_state,
                version: value.controller_state_version.parse().map_err(|e| {
                    sqlx::error::Error::ColumnDecode {
                        index: "controller_state_version".to_string(),
                        source: Box::new(e),
                    }
                })?,
            },
            network_config: Versioned {
                value: value.network_config,
                version: value.network_config_version.parse().map_err(|e| {
                    sqlx::error::Error::ColumnDecode {
                        index: "network_config_version".to_string(),
                        source: Box::new(e),
                    }
                })?,
            },
            network_status_observation: value.network_status_observation,
            infiniband_status_observation: value.infiniband_status_observation,
            nvlink_status_observation: value.nvlink_status_observation,
            history,
            interfaces: value.interfaces,
            hardware_info,
            bmc_info,
            last_reboot_time: value.last_reboot_time,
            last_cleanup_time: value.last_cleanup_time,
            last_discovery_time: value.last_discovery_time,
            last_scout_contact_time: value.last_scout_contact_time,
            failure_details: value.failure_details,
            reprovision_requested: value.reprovisioning_requested,
            host_reprovision_requested: value.host_reprovisioning_requested,
            manual_firmware_upgrade_completed: value.manual_firmware_upgrade_completed,
            dpu_agent_upgrade_requested: value.dpu_agent_upgrade_requested,
            dpu_agent_health_report: value.dpu_agent_health_report,
            hardware_health_report: value.hardware_health_report,
            machine_validation_health_report: value.machine_validation_health_report,
            site_explorer_health_report: value.site_explorer_health_report,
            health_report_overrides: value.health_report_overrides.unwrap_or_default(),
            inventory: value.agent_reported_inventory,
            last_reboot_requested: value.last_reboot_requested,
            controller_state_outcome: value.controller_state_outcome,
            bios_password_set_time: value.bios_password_set_time,
            last_machine_validation_time: value.last_machine_validation_time,
            discovery_machine_validation_id: value.discovery_machine_validation_id,
            cleanup_machine_validation_id: value.cleanup_machine_validation_id,
            firmware_autoupdate: value.firmware_autoupdate,
            on_demand_machine_validation_id: value.on_demand_machine_validation_id,
            on_demand_machine_validation_request: value.on_demand_machine_validation_request,
            asn: value.asn,
            metadata,
            instance_type_id: value.instance_type_id,
            log_parser_health_report: value.log_parser_health_report,
            version,
            // Columns for these exist, but are unused in rust code
            // deployed: value.deployed,
            // created: value.created,
            // updated: value.updated,
            hw_sku: value.hw_sku,
            hw_sku_status: value.hw_sku_status,
            sku_validation_health_report: value.sku_validation_health_report,
            power_options: value.power_options,
            hw_sku_device_type: value.hw_sku_device_type,
            update_complete: value.update_complete,
            nvlink_info: value.nvlink_info,
            dpf: value.dpf,
        })
    }
}
