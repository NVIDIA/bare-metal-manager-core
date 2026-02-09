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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Display;
use std::sync::Arc;
use std::time::SystemTime;

use byte_unit::UnitType;
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use rpc::common::MachineIdList;
// use rpc::forge::forge_server::Forge;
use rpc::forge::{
    ConnectedDevice, GetSiteExplorationRequest, MachineType, ManagedHostQuarantineState,
    NetworkDevice, NetworkDeviceIdList,
};
use rpc::machine_discovery::MemoryDevice;
use rpc::site_explorer::{EndpointExplorationReport, ExploredEndpoint, ExploredManagedHost};
use rpc::{DiscoveryInfo, DynForge, Machine, Timestamp};
use serde::{Deserialize, Serialize};
use tracing::warn;

macro_rules! get_dmi_data_from_machine {
    ($m:ident, $d:ident) => {
        $m.discovery_info
            .as_ref()
            .and_then(|di| di.dmi_data.as_ref())
            .and_then(|dd| {
                if dd.$d.trim().is_empty() {
                    None
                } else {
                    Some(dd.$d.clone())
                }
            })
    };
}

macro_rules! get_bmc_info_from_machine {
    ($m:ident, $d:ident) => {
        $m.bmc_info
            .as_ref()
            .and_then(|bi| bi.$d.as_ref())
            .and_then(|value| {
                if value.trim().is_empty() {
                    None
                } else {
                    Some(value.clone())
                }
            })
    };
}

/// This represents all the in-memory data needed to render information about a group of managed
/// hosts. This information is expected to be obtained via the API via individual calls, and
/// aggregated here for viewing.
#[derive(Debug)]
pub struct ManagedHostMetadata {
    /// All the machines involved in displaying this output, including hosts and DPUs
    pub machines: Vec<Machine>,
    /// Data obtained from site exploration for each managed host
    pub site_explorer_managed_hosts: Vec<ExploredManagedHost>,
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

        let site_explorer_managed_hosts = site_exploration_report.managed_hosts;

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

        let network_device_ids: HashSet<String> = connected_devices
            .iter()
            .filter_map(|d| d.network_device_id.clone())
            .collect();

        let exploration_reports = site_exploration_report.endpoints;

        let network_devices = api
            .find_network_devices_by_device_ids(tonic::Request::new(NetworkDeviceIdList {
                network_device_ids: network_device_ids.iter().map(|id| id.to_owned()).collect(),
            }))
            .await
            .map_or_else(
                |_err| vec![],
                |response| response.into_inner().network_devices,
            );

        ManagedHostMetadata {
            machines,
            site_explorer_managed_hosts,
            connected_devices,
            network_devices,
            exploration_reports,
        }
    }
}

#[derive(Default, Serialize, Deserialize, PartialEq)]
pub struct ManagedHostOutput {
    pub discovery_info: DiscoveryInfo,
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

impl From<&Machine> for ManagedHostOutput {
    fn from(machine: &Machine) -> ManagedHostOutput {
        let primary_interface = machine.interfaces.iter().find(|x| x.primary_interface);
        let (host_admin_ip, host_admin_mac) = primary_interface
            .map(|x| (x.address.first().cloned(), Some(x.mac_address.clone())))
            .unwrap_or((None, None));

        ManagedHostOutput {
            discovery_info: machine.discovery_info.clone().unwrap_or_default(),
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
            host_serial_number: get_dmi_data_from_machine!(machine, chassis_serial),
            host_bios_version: get_dmi_data_from_machine!(machine, bios_version),
            host_bmc_ip: get_bmc_info_from_machine!(machine, ip),
            host_bmc_mac: get_bmc_info_from_machine!(machine, mac),
            host_bmc_version: get_bmc_info_from_machine!(machine, version),
            host_bmc_firmware_version: get_bmc_info_from_machine!(machine, firmware_version),
            host_admin_ip,
            host_admin_mac,
            host_gpu_count: machine
                .discovery_info
                .as_ref()
                .map_or(0, |di| di.gpus.len()),
            host_ib_ifs_count: machine
                .discovery_info
                .as_ref()
                .map_or(0, |di| di.infiniband_interfaces.len()),
            host_memory: machine
                .discovery_info
                .as_ref()
                .and_then(|di| get_memory_details(&di.memory_devices)),
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
                    machine.last_reboot_requested_mode()
                )
            }),
            quarantine_state: machine.quarantine_state.clone(),
            instance_type_id: machine.instance_type_id.clone(),
            ..Default::default()
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ManagedHostAttachedDpu {
    pub discovery_info: DiscoveryInfo,
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
    fn from(connected_device: &ConnectedDevice, network_device: Option<&NetworkDevice>) -> Self {
        Self {
            dpu_port: Some(connected_device.local_port.clone()),
            switch_id: connected_device.network_device_id.clone(),
            switch_port: Some(connected_device.remote_port.clone()),
            switch_name: network_device.map(|n| n.name.clone()),
            switch_description: network_device.and_then(|n| n.description.clone()),
        }
    }
}

impl ManagedHostAttachedDpu {
    pub fn new_from_dpu_machine(
        dpu_machine: &Machine,
        connected_devices: &[ConnectedDevice],
        network_device_map: &HashMap<String, NetworkDevice>,
        is_primary: bool,
        endpoint_exploration_map: HashMap<String, EndpointExplorationReport>,
    ) -> Option<Self> {
        let (oob_ip, oob_mac) = match dpu_machine.interfaces.iter().find(|x| x.primary_interface) {
            Some(primary_interface) => (
                Some(primary_interface.address.join(",")),
                Some(primary_interface.mac_address.to_owned()),
            ),
            None => (None, None),
        };

        let Some(ref dpu_machine_id) = dpu_machine.id else {
            warn!("dpu_machine has no id? {:?}", dpu_machine);
            return None;
        };

        let exploration_map = get_bmc_info_from_machine!(dpu_machine, ip)
            .and_then(|bmc_ip| endpoint_exploration_map.get(&bmc_ip));

        let result = ManagedHostAttachedDpu {
            discovery_info: dpu_machine.discovery_info.clone().unwrap_or_default(),
            machine_id: Some(dpu_machine_id.to_string()),
            state: Some(dpu_machine.state.clone()),
            serial_number: get_dmi_data_from_machine!(dpu_machine, product_serial),
            bios_version: get_dmi_data_from_machine!(dpu_machine, bios_version),
            bmc_ip: get_bmc_info_from_machine!(dpu_machine, ip),
            bmc_mac: get_bmc_info_from_machine!(dpu_machine, mac),
            bmc_version: get_bmc_info_from_machine!(dpu_machine, version),
            bmc_firmware_version: get_bmc_info_from_machine!(dpu_machine, firmware_version),
            last_reboot_time: to_time(dpu_machine.last_reboot_time, Some(dpu_machine_id)),
            exploration_report: exploration_map.cloned(),
            last_reboot_requested_time_and_mode: Some(format!(
                "{}/{}",
                to_time(dpu_machine.last_reboot_requested_time, Some(dpu_machine_id))
                    .unwrap_or("Unknown".to_string()),
                dpu_machine.last_reboot_requested_mode()
            )),
            last_observation_time: to_time(dpu_machine.last_observation_time, Some(dpu_machine_id)),
            oob_ip,
            oob_mac,
            switch_connections: connected_devices
                .iter()
                .map(|d| {
                    DpuSwitchConnection::from(
                        d,
                        d.network_device_id
                            .as_ref()
                            .and_then(|id| network_device_map.get(id)),
                    )
                })
                .collect(),
            is_primary,
            health: dpu_machine
                .health
                .as_ref()
                .map(|h| {
                    health_report::HealthReport::try_from(h.clone())
                        .unwrap_or_else(health_report::HealthReport::malformed_report)
                })
                .unwrap_or_else(health_report::HealthReport::missing_report),
            failure_details: dpu_machine.failure_details.clone(),
        };

        Some(result)
    }
}

pub fn get_managed_host_output(source: ManagedHostMetadata) -> Vec<ManagedHostOutput> {
    let mut result = Vec::default();

    let mut managed_host_map: HashMap<String, String> = HashMap::new();
    let mut exploration_report_map: HashMap<String, EndpointExplorationReport> = HashMap::new();

    for explored_host in source.site_explorer_managed_hosts {
        for dpu in &explored_host.dpus {
            managed_host_map.insert(dpu.bmc_ip.clone(), explored_host.host_bmc_ip.clone());
        }

        for endpoint in source.exploration_reports.iter() {
            if let Some(er) = &endpoint.report {
                if endpoint.address == explored_host.host_bmc_ip {
                    exploration_report_map.insert(explored_host.host_bmc_ip.clone(), er.clone());
                }
                for dpu in &explored_host.dpus {
                    if endpoint.address == dpu.bmc_ip {
                        exploration_report_map.insert(dpu.bmc_ip.clone(), er.clone());
                    }
                }
            }
        }
    }

    let mut connected_device_map = HashMap::<MachineId, Vec<ConnectedDevice>>::new();
    for d in source.connected_devices.iter() {
        let Some(id) = d.id else {
            continue;
        };
        connected_device_map.entry(id).or_default().push(d.clone());
    }
    let network_device_map: HashMap<String, NetworkDevice> = source
        .network_devices
        .iter()
        .map(|n| (n.id.clone(), n.clone()))
        .collect();
    let dpu_map: HashMap<MachineId, &Machine> = source
        .machines
        .iter()
        .filter(|m| m.machine_type() == MachineType::Dpu)
        .filter_map(|m| m.id.map(|i| (i, m)))
        .collect();

    for machine in source
        .machines
        .iter()
        .filter(|m| m.machine_type() == MachineType::Host)
    {
        let mut managed_host_output = ManagedHostOutput::from(machine);
        let mut dpus = Vec::<ManagedHostAttachedDpu>::new();

        // Note: This code is also called by forge-admin-cli to display managed-hosts, which may be
        // operating against an old API server that doesn't support associated_dpu_machine_ids. If
        // so, fall back on getting the DPU ID of the primary interface, which is how we did it in
        // the single-DPU world.
        let dpu_machine_ids = if !machine.associated_dpu_machine_ids.is_empty() {
            machine.associated_dpu_machine_ids.clone()
        } else {
            machine
                .interfaces
                .iter()
                .filter_map(|i| {
                    if i.primary_interface {
                        Some(i.attached_dpu_machine_id)
                    } else {
                        None
                    }
                })
                .collect::<Option<Vec<MachineId>>>()
                .unwrap_or(vec![])
        };

        for dpu_machine_id in dpu_machine_ids {
            let Some(dpu_machine) = dpu_map.get(&dpu_machine_id) else {
                tracing::warn!(
                    "Could not find DPU for associated_dpu_machine_id {}",
                    dpu_machine_id
                );
                continue;
            };

            let is_primary = machine.interfaces.iter().find_map(|x| {
                if let Some(id) = &x.attached_dpu_machine_id {
                    if id == &dpu_machine_id {
                        Some(x.primary_interface)
                    } else {
                        None
                    }
                } else {
                    None
                }
            });

            if let Some(host_bmc_ip) = &managed_host_output.host_bmc_ip {
                managed_host_output.exploration_report =
                    exploration_report_map.get(host_bmc_ip).cloned();
            }

            if let Some(attached_dpu) = ManagedHostAttachedDpu::new_from_dpu_machine(
                dpu_machine,
                connected_device_map.get(&dpu_machine_id).unwrap_or(&vec![]),
                &network_device_map,
                // This should always have value. If no, lets crash to find out why.
                is_primary.expect("Interface type is missing for host."),
                exploration_report_map.clone(),
            ) {
                if let Some(dpu_bmc_ip) = &attached_dpu.bmc_ip {
                    if let Some(host_bmc_ip) = &managed_host_output.host_bmc_ip {
                        if let Some(site_host_bmc_ip) = managed_host_map.get(dpu_bmc_ip)
                            && host_bmc_ip != site_host_bmc_ip
                        {
                            // If somehow these both ips are different, display error.
                            managed_host_output.host_bmc_ip =
                                Some(format!("Error: M-{host_bmc_ip}/S-{site_host_bmc_ip}"));
                        }
                    } else {
                        managed_host_output.host_bmc_ip = managed_host_map.get(dpu_bmc_ip).cloned();
                    }
                }

                dpus.push(attached_dpu);
            }
        }

        managed_host_output.health = machine
            .health
            .as_ref()
            .map(|h| {
                health_report::HealthReport::try_from(h.clone())
                    .unwrap_or_else(health_report::HealthReport::malformed_report)
            })
            .unwrap_or_else(health_report::HealthReport::missing_report);
        managed_host_output.health_overrides = machine
            .health_overrides
            .iter()
            .map(|o| o.source.clone())
            .collect();

        managed_host_output.dpus = dpus;
        result.push(managed_host_output);
    }

    result
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
