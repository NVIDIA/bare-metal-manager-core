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

use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::sync::Arc;
use std::time::SystemTime;

use byte_unit::UnitType;
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use itertools::Itertools;
use rpc::common::MachineIdList;
// use rpc::forge::forge_server::Forge;
use rpc::forge::{
    BmcInfo, ConnectedDevice, GetSiteExplorationRequest, MachineType, ManagedHostQuarantineState,
    NetworkDevice, NetworkDeviceIdList,
};
use rpc::machine_discovery::MemoryDevice;
use rpc::site_explorer::{EndpointExplorationReport, ExploredEndpoint};
use rpc::{DmiData, DynForge, Machine, Timestamp};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// This represents all the in-memory data needed to render information about a group of managed
/// hosts. This information is expected to be obtained via the API via individual calls, and
/// aggregated here for viewing.
#[derive(Debug)]
pub struct ManagedHostMetadata {
    /// All the machines involved in displaying this output, including hosts and DPUs
    pub machines: Vec<Machine>,
    /// Connected devices (switch connections) of the machines, for showing connection info for the
    /// machines' ports
    pub connected_devices: Vec<ConnectedDevice>,
    /// Network devices (the switches themselves) corresponding to connected_devices, for showing
    /// the actual switch name/description.
    pub network_devices: Vec<NetworkDevice>,
    /// Exploration reports for each endpoint, for showing Redfish data associated with a machine
    pub exploration_reports: Vec<ExploredEndpoint>,
}

impl ManagedHostMetadata {
    /// Given a set of machines to display as managed hosts, hydrate a ManagedHostMetadata struct
    /// via information from the API.
    pub async fn lookup_from_api(
        machines: Vec<Machine>,
        api: Arc<DynForge>,
    ) -> ManagedHostMetadata {
        let request = tonic::Request::new(GetSiteExplorationRequest {});

        let site_exploration_report = api
            .get_site_exploration_report(request)
            .await
            .map(|response| response.into_inner())
            .map_err(|e| {
                warn!("Failed to get site exploration report: {:?}", e);
            })
            .unwrap_or_default();

        // Find connected devices for this machines
        let dpu_id_request = tonic::Request::new(MachineIdList {
            machine_ids: machines
                .iter()
                .flat_map(|m| m.associated_dpu_machine_ids.clone())
                .collect(),
        });
        let connected_devices = api
            .find_connected_devices_by_dpu_machine_ids(dpu_id_request)
            .await
            .map(|response| response.into_inner().connected_devices)
            .unwrap_or_default();

        let network_device_ids = connected_devices
            .iter()
            .filter_map(|d| d.network_device_id.clone())
            .unique()
            .collect();

        let exploration_reports = site_exploration_report.endpoints;

        let network_devices = api
            .find_network_devices_by_device_ids(tonic::Request::new(NetworkDeviceIdList {
                network_device_ids,
            }))
            .await
            .map_or_else(
                |_err| vec![],
                |response| response.into_inner().network_devices,
            );

        ManagedHostMetadata {
            machines,
            connected_devices,
            network_devices,
            exploration_reports,
        }
    }
}

#[derive(Default, Serialize, Deserialize, PartialEq)]
pub struct ManagedHostOutput {
    pub hostname: Option<String>,
    pub machine_id: Option<String>,
    pub state: String,
    pub state_version: String,
    pub state_sla_duration: Option<String>,
    pub time_in_state_above_sla: bool,
    pub time_in_state: String,
    pub state_reason: String,
    pub host_serial_number: Option<String>,
    pub host_bios_version: Option<String>,
    pub host_bmc_ip: Option<String>,
    pub host_bmc_mac: Option<String>,
    pub host_bmc_version: Option<String>,
    pub host_bmc_firmware_version: Option<String>,
    pub host_admin_ip: Option<String>,
    pub host_admin_mac: Option<String>,
    pub host_ib_ifs_count: usize,
    pub host_gpu_count: usize,
    pub host_memory: Option<String>,
    pub maintenance_reference: Option<String>,
    pub maintenance_start_time: Option<String>,
    pub host_last_reboot_time: Option<String>,
    pub host_last_reboot_requested_time_and_mode: Option<String>,
    pub health: health_report::HealthReport,
    pub health_overrides: Vec<String>,
    pub dpus: Vec<ManagedHostAttachedDpu>,
    pub exploration_report: Option<EndpointExplorationReport>,
    pub failure_details: Option<String>,
    pub quarantine_state: Option<ManagedHostQuarantineState>,
    pub instance_type_id: Option<String>,
}

impl From<Machine> for ManagedHostOutput {
    fn from(machine: Machine) -> ManagedHostOutput {
        let primary_interface = machine.interfaces.iter().find(|x| x.primary_interface);
        let (host_admin_ip, host_admin_mac) = primary_interface
            .map(|x| (x.address.first().cloned(), Some(x.mac_address.clone())))
            .unwrap_or((None, None));

        let BmcInfoDisplay {
            ip: host_bmc_ip,
            mac: host_bmc_mac,
            version: host_bmc_version,
            firmware_version: host_bmc_firmware_version,
        } = machine.bmc_info.into();

        let discovery_info = machine.discovery_info;
        let host_gpu_count = discovery_info
            .as_ref()
            .map(|di| di.gpus.len())
            .unwrap_or_default();
        let host_ib_ifs_count = discovery_info
            .as_ref()
            .map(|di| di.infiniband_interfaces.len())
            .unwrap_or_default();
        let host_memory = discovery_info
            .as_ref()
            .and_then(|di| get_memory_details(&di.memory_devices));

        let DmiDataDisplay {
            product_serial: _,
            chassis_serial: host_serial_number,
            bios_version: host_bios_version,
        } = discovery_info.and_then(|di| di.dmi_data).into();

        let health = machine
            .health
            .map(|h| {
                health_report::HealthReport::try_from(h)
                    .unwrap_or_else(health_report::HealthReport::malformed_report)
            })
            .unwrap_or_else(health_report::HealthReport::missing_report);
        let health_overrides = machine
            .health_sources
            .into_iter()
            .map(|o| o.source)
            .collect();

        ManagedHostOutput {
            hostname: primary_interface
                .as_ref()
                .map(|i| i.hostname.clone())
                .and_then(|h| if h.trim().is_empty() { None } else { Some(h) }),
            machine_id: machine.id.as_ref().map(|i| i.to_string()),
            state: machine.state.clone(),
            time_in_state: config_version::since_state_change_humanized(&machine.state_version),
            time_in_state_above_sla: machine
                .state_sla
                .as_ref()
                .map(|sla| sla.time_in_state_above_sla)
                .unwrap_or_default(),
            state_sla_duration: machine
                .state_sla
                .as_ref()
                .and_then(|sla| sla.sla)
                .map(|sla| {
                    config_version::format_duration(
                        chrono::TimeDelta::try_from(sla).unwrap_or(chrono::TimeDelta::MAX),
                    )
                }),
            state_reason: machine
                .state_reason
                .as_ref()
                .and_then(super::reason_to_user_string)
                .unwrap_or_default(),
            host_serial_number,
            host_bios_version,
            host_bmc_ip,
            host_bmc_mac,
            host_bmc_version,
            host_bmc_firmware_version,
            host_admin_ip,
            host_admin_mac,
            host_gpu_count,
            host_ib_ifs_count,
            host_memory,
            failure_details: machine.failure_details.clone(),
            maintenance_reference: machine.maintenance_reference.clone(),
            maintenance_start_time: to_time(machine.maintenance_start_time, machine.id),
            host_last_reboot_time: machine
                .id
                .as_ref()
                .and_then(|id| to_time(machine.last_reboot_time, Some(id))),
            host_last_reboot_requested_time_and_mode: machine.id.as_ref().map(|id| {
                format!(
                    "{}/{}",
                    to_time(machine.last_reboot_requested_time, Some(id))
                        .unwrap_or("Unknown".to_string()),
                    machine.last_reboot_requested_mode.unwrap_or_default()
                )
            }),
            quarantine_state: machine.quarantine_state.clone(),
            instance_type_id: machine.instance_type_id.clone(),
            health,
            health_overrides,
            ..Default::default()
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ManagedHostAttachedDpu {
    pub machine_id: Option<String>,
    pub state: Option<String>,
    pub serial_number: Option<String>,
    pub bios_version: Option<String>,
    pub bmc_ip: Option<String>,
    pub bmc_mac: Option<String>,
    pub bmc_version: Option<String>,
    pub bmc_firmware_version: Option<String>,
    pub oob_ip: Option<String>,
    pub oob_mac: Option<String>,
    pub last_reboot_time: Option<String>,
    pub last_reboot_requested_time_and_mode: Option<String>,
    pub last_observation_time: Option<String>,
    pub switch_connections: Vec<DpuSwitchConnection>,
    pub is_primary: bool,
    pub health: health_report::HealthReport,
    pub exploration_report: Option<EndpointExplorationReport>,
    pub failure_details: Option<String>,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DpuSwitchConnection {
    pub dpu_port: Option<String>,
    pub switch_id: Option<String>,
    pub switch_port: Option<String>,
    pub switch_name: Option<String>,
    pub switch_description: Option<String>,
}

impl DpuSwitchConnection {
    fn from(connected_device: ConnectedDevice, network_device: Option<&NetworkDevice>) -> Self {
        Self {
            dpu_port: Some(connected_device.local_port),
            switch_id: connected_device.network_device_id,
            switch_port: Some(connected_device.remote_port),
            switch_name: network_device.map(|n| n.name.clone()),
            switch_description: network_device.and_then(|n| n.description.clone()),
        }
    }
}

impl ManagedHostAttachedDpu {
    pub fn new_from_dpu_machine(
        dpu_machine: Machine,
        switch_connections: Vec<DpuSwitchConnection>,
        exploration_report: Option<EndpointExplorationReport>,
        is_primary: bool,
    ) -> Self {
        let last_reboot_requested_time_and_mode = Some(format!(
            "{}/{}",
            to_time(dpu_machine.last_reboot_requested_time, dpu_machine.id)
                .unwrap_or("Unknown".to_string()),
            dpu_machine.last_reboot_requested_mode()
        ));

        let (oob_ip, oob_mac) = match dpu_machine
            .interfaces
            .into_iter()
            .find(|x| x.primary_interface)
        {
            Some(primary_interface) => (
                Some(primary_interface.address.join(",")),
                Some(primary_interface.mac_address.to_owned()),
            ),
            None => (None, None),
        };

        let BmcInfoDisplay {
            ip: bmc_ip,
            mac: bmc_mac,
            version: bmc_version,
            firmware_version: bmc_firmware_version,
        } = dpu_machine.bmc_info.into();

        let DmiDataDisplay {
            product_serial: serial_number,
            chassis_serial: _,
            bios_version,
        } = dpu_machine.discovery_info.and_then(|d| d.dmi_data).into();

        ManagedHostAttachedDpu {
            machine_id: dpu_machine.id.map(|i| i.to_string()),
            state: Some(dpu_machine.state),
            serial_number,
            bios_version,
            bmc_ip,
            bmc_mac,
            bmc_version,
            bmc_firmware_version,
            last_reboot_time: to_time(dpu_machine.last_reboot_time, dpu_machine.id),
            exploration_report,
            last_reboot_requested_time_and_mode,
            last_observation_time: to_time(dpu_machine.last_observation_time, dpu_machine.id),
            oob_ip,
            oob_mac,
            switch_connections,
            is_primary,
            health: dpu_machine
                .health
                .map(|h| {
                    health_report::HealthReport::try_from(h)
                        .unwrap_or_else(health_report::HealthReport::malformed_report)
                })
                .unwrap_or_else(health_report::HealthReport::missing_report),
            failure_details: dpu_machine.failure_details,
        }
    }
}

pub fn get_managed_host_output(source: ManagedHostMetadata) -> Vec<ManagedHostOutput> {
    let mut index = IndexedManagedHostMetadata::from(source);
    index
        .managed_hosts
        .into_iter()
        .map(|machine| {
            let primary_dpu_id = machine.interfaces.iter().find_map(|iface| {
                if iface.primary_interface {
                    iface.attached_dpu_machine_id
                } else {
                    None
                }
            });
            let dpu_machine_ids = machine.associated_dpu_machine_ids.clone();

            let mut managed_host_output = ManagedHostOutput::from(machine);
            managed_host_output.exploration_report = managed_host_output
                .host_bmc_ip
                .as_ref()
                .and_then(|address| index.exploration_reports_by_address.remove(address));

            managed_host_output.dpus = dpu_machine_ids
                .into_iter()
                .filter_map(|id| {
                    index
                        .dpus_by_id
                        .remove(&id)
                        .map(|dpu| (id, dpu))
                        .or_else(|| {
                            tracing::warn!("Could not find DPU for associated_dpu_machine_id {id}");
                            None
                        })
                })
                .map(|(dpu_id, dpu)| {
                    let dpu_exploration_report = dpu
                        .bmc_info
                        .as_ref()
                        .and_then(|bmc_info| bmc_info.ip.as_ref())
                        .and_then(|ip| index.exploration_reports_by_address.remove(ip));

                    let switch_connections = index
                        .switch_connections_by_dpu_id
                        .remove(&dpu_id)
                        .unwrap_or_default();

                    ManagedHostAttachedDpu::new_from_dpu_machine(
                        dpu,
                        switch_connections,
                        dpu_exploration_report,
                        Some(dpu_id) == primary_dpu_id,
                    )
                })
                .collect();
            managed_host_output
        })
        .collect()
}

/// Data from ManagedHostMetadata, indexed into HashMaps for easy conversion into ManagedHostOutput
struct IndexedManagedHostMetadata {
    /// The managed hosts (non-dpu)
    managed_hosts: Vec<Machine>,
    /// DPU's indexed by their ID
    dpus_by_id: HashMap<MachineId, Machine>,
    /// Switch connections for each DPU, indexed by the DPU MachineId
    switch_connections_by_dpu_id: HashMap<MachineId, Vec<DpuSwitchConnection>>,
    /// Exploration reports, indexed by the BMC address
    exploration_reports_by_address: HashMap<String, EndpointExplorationReport>,
}

impl From<ManagedHostMetadata> for IndexedManagedHostMetadata {
    fn from(value: ManagedHostMetadata) -> Self {
        let network_devices_by_id: HashMap<String, NetworkDevice> = value
            .network_devices
            .into_iter()
            .map(|n| (n.id.clone(), n))
            .collect();
        let switch_connections_by_dpu_id: HashMap<MachineId, Vec<DpuSwitchConnection>> = value
            .connected_devices
            .into_iter()
            .filter_map(|cd| {
                let dpu_id = cd.id?;
                let network_device = cd
                    .network_device_id
                    .as_ref()
                    .and_then(|nd_id| network_devices_by_id.get(nd_id));
                Some((dpu_id, DpuSwitchConnection::from(cd, network_device)))
            })
            .into_group_map();

        let (dpus, non_dpus): (Vec<Machine>, Vec<Machine>) = value
            .machines
            .into_iter()
            .partition(|m| m.machine_type() == MachineType::Dpu);

        let managed_hosts = non_dpus
            .into_iter()
            .filter(|m| m.machine_type() == MachineType::Host)
            .collect();

        let dpus_by_id: HashMap<MachineId, Machine> = dpus
            .into_iter()
            .filter_map(|m| m.id.map(|i| (i, m)))
            .collect();

        let exploration_reports_by_address: HashMap<String, EndpointExplorationReport> = value
            .exploration_reports
            .into_iter()
            .filter_map(|r| Some((r.address, r.report?)))
            .collect();

        Self {
            managed_hosts,
            dpus_by_id,
            switch_connections_by_dpu_id,
            exploration_reports_by_address,
        }
    }
}

pub fn get_memory_details(memory_devices: &Vec<MemoryDevice>) -> Option<String> {
    let mut breakdown = BTreeMap::default();
    let mut total_size = 0;
    for md in memory_devices {
        let size = byte_unit::Byte::from_f64_with_unit(
            md.size_mb.unwrap_or(0) as f64,
            byte_unit::Unit::MiB,
        )
        .unwrap_or_default();
        total_size += size.as_u64();
        *breakdown.entry(size).or_insert(0u32) += 1;
    }

    let total_size = byte_unit::Byte::from(total_size);

    if memory_devices.len() == 1 {
        Some(
            total_size
                .get_appropriate_unit(UnitType::Binary)
                .to_string(),
        )
    } else if total_size.as_u64() > 0 {
        let mut breakdown_str = String::default();
        for (ind, s) in breakdown.iter().enumerate() {
            if ind != 0 {
                breakdown_str.push_str(", ");
            }
            breakdown_str.push_str(
                format!("{}x{}", s.0.get_appropriate_unit(UnitType::Binary), s.1).as_ref(),
            );
        }
        Some(format!(
            "{} ({})",
            total_size.get_appropriate_unit(UnitType::Binary),
            breakdown_str
        ))
    } else {
        None
    }
}

// Prepare an Option<rpc::Timestamp> for display:
// - Parse the timestamp into a chrono::Time and format as string.
// - Or return empty string
// machine_id is only for logging a more useful error.
pub fn to_time<M: Display>(t: Option<Timestamp>, machine_id: Option<M>) -> Option<String> {
    match t {
        None => None,
        Some(tt) => match SystemTime::try_from(tt) {
            Ok(system_time) => {
                let dt: DateTime<Utc> = DateTime::from(system_time);
                Some(dt.to_string())
            }
            Err(err) => {
                warn!(
                    "get_managed_host_output {}, invalid timestamp: {}",
                    machine_id
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "(no machine ID)".to_string()),
                    err
                );
                None
            }
        },
    }
}

/// Helper to easily turn an Option<BmcInfo> into optional fields for display, without cloning
#[derive(Default)]
struct BmcInfoDisplay {
    ip: Option<String>,
    mac: Option<String>,
    version: Option<String>,
    firmware_version: Option<String>,
}

impl From<Option<BmcInfo>> for BmcInfoDisplay {
    fn from(value: Option<BmcInfo>) -> Self {
        if let Some(bmc_info) = value {
            Self {
                ip: bmc_info.ip.if_non_empty(),
                mac: bmc_info.mac.if_non_empty(),
                version: bmc_info.version.if_non_empty(),
                firmware_version: bmc_info.firmware_version.if_non_empty(),
            }
        } else {
            Self::default()
        }
    }
}

/// Helper to easily turn an Option<DmiData> into optional fields for display, without cloning
#[derive(Default)]
struct DmiDataDisplay {
    product_serial: Option<String>,
    chassis_serial: Option<String>,
    bios_version: Option<String>,
}

impl From<Option<DmiData>> for DmiDataDisplay {
    fn from(value: Option<DmiData>) -> Self {
        if let Some(dmi_data) = value {
            Self {
                product_serial: dmi_data.product_serial.if_non_empty(),
                chassis_serial: dmi_data.chassis_serial.if_non_empty(),
                bios_version: dmi_data.bios_version.if_non_empty(),
            }
        } else {
            Self {
                product_serial: None,
                chassis_serial: None,
                bios_version: None,
            }
        }
    }
}

/// Simple if_non_empty() function to map an empty String (or a Option<String>::None) into None
trait IfNonEmpty {
    type SomeVal;
    fn if_non_empty(self) -> Option<Self::SomeVal>;
}

impl IfNonEmpty for Option<String> {
    type SomeVal = String;
    fn if_non_empty(self) -> Option<Self::SomeVal> {
        if let Some(s) = self
            && !s.is_empty()
        {
            Some(s)
        } else {
            None
        }
    }
}

impl IfNonEmpty for String {
    type SomeVal = String;
    fn if_non_empty(self) -> Option<Self::SomeVal> {
        if !self.is_empty() { Some(self) } else { None }
    }
}
