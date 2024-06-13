/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    ConnectedDevice, GetSiteExplorationRequest, MachineIdList, MachineType, NetworkDevice,
    NetworkDeviceIdList,
};
use rpc::machine_discovery::MemoryDevice;
use rpc::site_explorer::ExploredManagedHost;
use rpc::{Machine, MachineId, Timestamp};
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
}

impl ManagedHostMetadata {
    /// Given a set of machines to display as managed hosts, hydrate a ManagedHostMetadata struct
    /// via information from the API.
    pub async fn lookup_from_api(
        machines: Vec<Machine>,
        api: Arc<dyn Forge>,
    ) -> ManagedHostMetadata {
        let request = tonic::Request::new(GetSiteExplorationRequest {});
        let site_explorer_managed_hosts = api
            .get_site_exploration_report(request)
            .await
            .map(|response| response.into_inner().managed_hosts)
            .unwrap_or(vec![]);

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
        }
    }
}

#[derive(Default, Serialize, Deserialize, PartialEq)]
pub struct ManagedHostOutput {
    pub hostname: Option<String>,
    pub machine_id: Option<String>,
    pub state: String,
    pub state_version: String,
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
    pub is_network_healthy: bool,
    pub network_err_message: Option<String>,
    pub dpus: Vec<ManagedHostAttachedDpu>,
}

impl From<&Machine> for ManagedHostOutput {
    fn from(machine: &Machine) -> ManagedHostOutput {
        let primary_interface = machine.interfaces.iter().find(|i| i.primary_interface);

        ManagedHostOutput {
            hostname: primary_interface
                .as_ref()
                .map(|i| i.hostname.clone())
                .and_then(|h| if h.trim().is_empty() { None } else { Some(h) }),
            machine_id: machine.id.as_ref().map(|i| i.to_string()),
            state: machine.state.clone(),
            time_in_state: config_version::since_state_change_humanized(&machine.state_version),
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
            host_admin_ip: primary_interface.map(|i| i.address.join(",")),
            host_admin_mac: primary_interface.map(|i| i.mac_address.to_string()),
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
            maintenance_reference: machine.maintenance_reference.clone(),
            maintenance_start_time: machine
                .id
                .as_ref()
                .and_then(|id| to_time(machine.maintenance_start_time.clone(), id)),
            host_last_reboot_time: machine
                .id
                .as_ref()
                .and_then(|id| to_time(machine.last_reboot_time.clone(), id)),
            host_last_reboot_requested_time_and_mode: machine.id.as_ref().map(|id| {
                format!(
                    "{}/{}",
                    to_time(machine.last_reboot_requested_time.clone(), id)
                        .unwrap_or("Unknown".to_string()),
                    machine.last_reboot_requested_mode()
                )
            }),
            ..Default::default()
        }
    }
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ManagedHostAttachedDpu {
    pub machine_id: Option<String>,
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

        let result = ManagedHostAttachedDpu {
            machine_id: Some(dpu_machine_id.to_string()),
            serial_number: get_dmi_data_from_machine!(dpu_machine, chassis_serial),
            bios_version: get_dmi_data_from_machine!(dpu_machine, bios_version),
            bmc_ip: get_bmc_info_from_machine!(dpu_machine, ip),
            bmc_mac: get_bmc_info_from_machine!(dpu_machine, mac),
            bmc_version: get_bmc_info_from_machine!(dpu_machine, version),
            bmc_firmware_version: get_bmc_info_from_machine!(dpu_machine, firmware_version),
            last_reboot_time: to_time(dpu_machine.last_reboot_time.clone(), dpu_machine_id),
            last_reboot_requested_time_and_mode: Some(format!(
                "{}/{}",
                to_time(
                    dpu_machine.last_reboot_requested_time.clone(),
                    dpu_machine_id
                )
                .unwrap_or("Unknown".to_string()),
                dpu_machine.last_reboot_requested_mode()
            )),
            last_observation_time: to_time(
                dpu_machine.last_observation_time.clone(),
                dpu_machine_id,
            ),
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
        };

        Some(result)
    }
}

pub fn get_managed_host_output(source: ManagedHostMetadata) -> Vec<ManagedHostOutput> {
    let mut result = Vec::default();

    let mut managed_host_map: HashMap<String, String> = HashMap::new();

    for explored_host in source.site_explorer_managed_hosts {
        for dpu in &explored_host.dpus {
            managed_host_map.insert(dpu.bmc_ip.clone(), explored_host.host_bmc_ip.clone());
        }
    }

    let mut connected_device_map = HashMap::<String, Vec<ConnectedDevice>>::new();
    for d in source.connected_devices.iter() {
        let Some(id) = d.id.as_ref().map(MachineId::to_string) else {
            continue;
        };
        connected_device_map.entry(id).or_default().push(d.clone());
    }
    let network_device_map: HashMap<String, NetworkDevice> = source
        .network_devices
        .iter()
        .map(|n| (n.id.clone(), n.clone()))
        .collect();
    let dpu_map: HashMap<String, &Machine> = source
        .machines
        .iter()
        .filter(|m| m.machine_type() == MachineType::Dpu)
        .filter_map(|m| m.id.as_ref().map(|i| (i.id.clone(), m)))
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
                        Some(i.attached_dpu_machine_id.clone())
                    } else {
                        None
                    }
                })
                .collect::<Option<Vec<MachineId>>>()
                .unwrap_or(vec![])
        };

        for dpu_machine_id in dpu_machine_ids {
            let Some(dpu_machine) = dpu_map.get(&dpu_machine_id.id) else {
                tracing::warn!(
                    "Could not find DPU for associated_dpu_machine_id {}",
                    dpu_machine_id.id
                );
                continue;
            };

            // Network health is in observation, on DPU, but it relates to
            // the managed host as a whole.
            managed_host_output.is_network_healthy = match &dpu_machine.network_health {
                Some(h) => h.is_healthy,
                None => false,
            };
            managed_host_output.network_err_message = match &dpu_machine.network_health {
                Some(h) => h.message.clone(),
                None => None,
            };

            if let Some(attached_dpu) = ManagedHostAttachedDpu::new_from_dpu_machine(
                dpu_machine,
                connected_device_map
                    .get(&dpu_machine_id.id)
                    .unwrap_or(&vec![]),
                &network_device_map,
            ) {
                if let Some(dpu_bmc_ip) = &attached_dpu.bmc_ip {
                    if let Some(host_bmc_ip) = &managed_host_output.host_bmc_ip {
                        if let Some(site_host_bmc_ip) = managed_host_map.get(dpu_bmc_ip) {
                            if host_bmc_ip != site_host_bmc_ip {
                                // If somehow these both ips are different, display error.
                                managed_host_output.host_bmc_ip = Some(format!(
                                    "Error: M-{}/S-{}",
                                    host_bmc_ip, site_host_bmc_ip
                                ));
                            }
                        }
                    } else {
                        managed_host_output.host_bmc_ip = managed_host_map.get(dpu_bmc_ip).cloned();
                    }
                }

                dpus.push(attached_dpu);
            }
        }

        managed_host_output.dpus = dpus;
        result.push(managed_host_output);
    }

    result
}

fn get_memory_details(memory_devices: &Vec<MemoryDevice>) -> Option<String> {
    let mut breakdown = BTreeMap::default();
    let mut total_size = 0;
    for md in memory_devices {
        let size =
            byte_unit::Byte::from_unit(md.size_mb.unwrap_or(0) as f64, byte_unit::ByteUnit::MiB)
                .unwrap_or_default();
        total_size += size.get_bytes();
        *breakdown.entry(size).or_insert(0u32) += 1;
    }

    let total_size = byte_unit::Byte::from(total_size);

    if memory_devices.len() == 1 {
        Some(total_size.get_appropriate_unit(true).to_string())
    } else if total_size.get_bytes() > 0 {
        let mut breakdown_str = String::default();
        for (ind, s) in breakdown.iter().enumerate() {
            if ind != 0 {
                breakdown_str.push_str(", ");
            }
            breakdown_str.push_str(format!("{}x{}", s.0.get_appropriate_unit(true), s.1).as_ref());
        }
        Some(format!(
            "{} ({})",
            total_size.get_appropriate_unit(true),
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
fn to_time(t: Option<Timestamp>, machine_id: &MachineId) -> Option<String> {
    match t {
        None => None,
        Some(tt) => match SystemTime::try_from(tt) {
            Ok(system_time) => {
                let dt: DateTime<Utc> = DateTime::from(system_time);
                Some(dt.to_string())
            }
            Err(err) => {
                warn!("get_managed_host_output {machine_id}, invalid timestamp: {err}");
                None
            }
        },
    }
}
