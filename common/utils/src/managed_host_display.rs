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

use std::collections::{BTreeMap, HashMap};
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use rpc::forge::{ConnectedDevice, MachineInterface, MachineType, NetworkDevice};
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

#[derive(Default, Serialize, Deserialize, PartialEq)]
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

#[derive(Default, Serialize, Deserialize, PartialEq)]
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

pub fn get_managed_host_output(
    machines: &[Machine],
    site_explorer_managed_host: &[ExploredManagedHost],
    connected_devices: &[ConnectedDevice],
    network_devices: &[NetworkDevice],
) -> Vec<ManagedHostOutput> {
    let mut result = Vec::default();

    let managed_host_map: HashMap<String, String> = site_explorer_managed_host
        .iter()
        .map(|x| (x.dpu_bmc_ip.clone(), x.host_bmc_ip.clone()))
        .collect();
    let mut connected_device_map = HashMap::<String, Vec<ConnectedDevice>>::new();
    for d in connected_devices.iter() {
        let Some(id) = d.id.as_ref().map(MachineId::to_string) else {
            continue;
        };
        connected_device_map.entry(id).or_default().push(d.clone());
    }
    let network_device_map: HashMap<String, NetworkDevice> = network_devices
        .iter()
        .map(|n| (n.id.clone(), n.clone()))
        .collect();

    for machine in machines.iter() {
        let mut managed_host_output = ManagedHostOutput::default();
        if machine.machine_type != MachineType::Host as i32 {
            continue;
        }

        let machine_id = match &machine.id {
            Some(id) => id,
            None => {
                warn!("Machine with no id found.  skipping {:?}", machine);
                continue;
            }
        };

        let machine_interfaces = machine
            .interfaces
            .iter()
            .filter(|x| x.primary_interface)
            .cloned()
            .collect::<Vec<MachineInterface>>();

        if machine_interfaces.is_empty() {
            warn!("No interfaces for machine id {}.  Skipped", machine_id);
            continue;
        }

        if machine_interfaces.len() > 1 {
            warn!(
                "Multiple primary interfaces for machine id {}.  Will only use first",
                machine_id
            );
        }

        let primary_interface = &machine_interfaces[0];

        managed_host_output.hostname = if primary_interface.hostname.trim().is_empty() {
            None
        } else {
            Some(primary_interface.hostname.clone())
        };
        managed_host_output.machine_id = Some(machine_id.to_string());
        managed_host_output.state = machine.state.clone();
        managed_host_output.time_in_state =
            config_version::since_state_change_humanized(&machine.state_version);
        managed_host_output.state_reason = machine
            .state_reason
            .as_ref()
            .and_then(super::reason_to_user_string)
            .unwrap_or_default();
        managed_host_output.host_serial_number =
            get_dmi_data_from_machine!(machine, chassis_serial);
        managed_host_output.host_bios_version = get_dmi_data_from_machine!(machine, bios_version);
        managed_host_output.host_bmc_ip = get_bmc_info_from_machine!(machine, ip);
        managed_host_output.host_bmc_mac = get_bmc_info_from_machine!(machine, mac);
        managed_host_output.host_bmc_version = get_bmc_info_from_machine!(machine, version);
        managed_host_output.host_bmc_firmware_version =
            get_bmc_info_from_machine!(machine, firmware_version);
        managed_host_output.host_admin_ip = Some(primary_interface.address.join(","));
        managed_host_output.host_admin_mac = Some(primary_interface.mac_address.to_string());
        managed_host_output.host_gpu_count = machine
            .discovery_info
            .as_ref()
            .map_or(0, |di| di.gpus.len());
        managed_host_output.host_ib_ifs_count = machine
            .discovery_info
            .as_ref()
            .map_or(0, |di| di.infiniband_interfaces.len());
        managed_host_output.host_memory = machine
            .discovery_info
            .as_ref()
            .and_then(|di| get_memory_details(&di.memory_devices));
        managed_host_output.maintenance_reference = machine.maintenance_reference.clone();
        managed_host_output.maintenance_start_time =
            to_time(machine.maintenance_start_time.clone(), machine_id);
        managed_host_output.host_last_reboot_time =
            to_time(machine.last_reboot_time.clone(), machine_id);
        managed_host_output.host_last_reboot_requested_time_and_mode = Some(format!(
            "{}/{}",
            to_time(machine.last_reboot_requested_time.clone(), machine_id)
                .unwrap_or("Unknown".to_string()),
            machine.last_reboot_requested_mode()
        ));

        if let Some(dpu_machine_id) = primary_interface.attached_dpu_machine_id.as_ref() {
            if dpu_machine_id != machine_id {
                let dpu_machine = machines
                    .iter()
                    .find(|m| m.id.as_ref().map_or(false, |id| id == dpu_machine_id));

                if let Some(dpu_machine) = dpu_machine {
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
                            if let Some(host_bmc_ip) = &attached_dpu.bmc_ip {
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
                                managed_host_output.host_bmc_ip =
                                    managed_host_map.get(dpu_bmc_ip).cloned();
                            }
                        }

                        // Multiple-DPU support is not ready yet, as of now we're emulating it,
                        // with only one DPU possible.
                        managed_host_output.dpus = vec![attached_dpu];
                    }
                };
            }
        };

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
