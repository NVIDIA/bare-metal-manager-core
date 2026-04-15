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

use carbide_uuid::machine::MachineId;
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use db::{machine as db_machine, machine_topology as db_machine_topology, switch as db_switch};
use eyre::{Result, eyre};
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialManager, Credentials,
};
use librms::RmsApi;
use librms::protos::rack_manager as rms;
use model::machine::machine_search_config::MachineSearchConfig;
use model::rack::FirmwareUpgradeDeviceInfo;
use model::rack_firmware::RackFirmware;
use model::rack_type::{RackCapabilitiesSet, RackHardwareClass};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct RackFirmwareInventory {
    pub machine_ids: Vec<MachineId>,
    pub switch_ids: Vec<SwitchId>,
    pub machines: Vec<FirmwareUpgradeDeviceInfo>,
    pub switches: Vec<FirmwareUpgradeDeviceInfo>,
}

#[derive(Debug, Clone)]
pub struct FirmwareUpdateBatchRequest {
    pub display_name: &'static str,
    pub devices: Vec<FirmwareUpgradeDeviceInfo>,
    pub request: rms::UpdateFirmwareByDeviceListRequest,
}

#[derive(Debug, Clone)]
pub struct SubmittedFirmwareBatch {
    pub display_name: &'static str,
    pub devices: Vec<FirmwareUpgradeDeviceInfo>,
    pub response: Result<rms::UpdateFirmwareByDeviceListResponse, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirmwareLookupTable {
    devices: HashMap<String, HashMap<String, FirmwareLookupEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FirmwareLookupEntry {
    filename: String,
    target: String,
    component: String,
    bundle: String,
    firmware_type: String,
    version: Option<String>,
}

pub fn firmware_type_for_capabilities(capabilities: &RackCapabilitiesSet) -> &'static str {
    match capabilities.rack_hardware_class {
        Some(RackHardwareClass::Dev) => "dev",
        Some(RackHardwareClass::Prod) | None => "prod",
    }
}

pub async fn load_rack_firmware_inventory(
    db_pool: &PgPool,
    credential_manager: &dyn CredentialManager,
    rack_id: &RackId,
) -> Result<RackFirmwareInventory> {
    let (machine_ids, machine_topologies, switch_ids, switch_endpoints) = {
        let mut txn = db_pool.begin().await?;

        let machine_ids = db_machine::find_machine_ids(
            txn.as_mut(),
            MachineSearchConfig {
                rack_id: Some(rack_id.clone()),
                ..Default::default()
            },
        )
        .await?;
        let machine_topologies =
            db_machine_topology::find_latest_by_machine_ids(txn.as_mut(), &machine_ids).await?;

        let switch_ids = db_switch::find_ids(
            txn.as_mut(),
            model::switch::SwitchSearchFilter {
                rack_id: Some(rack_id.clone()),
                ..Default::default()
            },
        )
        .await?;
        let switch_endpoints =
            db_switch::find_switch_endpoints_by_ids(txn.as_mut(), &switch_ids).await?;

        txn.commit().await?;
        (
            machine_ids,
            machine_topologies,
            switch_ids,
            switch_endpoints,
        )
    };

    let mut machines = Vec::with_capacity(machine_ids.len());
    for machine_id in &machine_ids {
        let topology = machine_topologies
            .get(machine_id)
            .ok_or_else(|| eyre!("machine {} missing topology", machine_id))?;
        let bmc_mac = topology
            .topology()
            .bmc_info
            .mac
            .ok_or_else(|| eyre!("machine {} missing BMC MAC", machine_id))?;
        let bmc_ip = topology
            .topology()
            .bmc_info
            .ip
            .as_deref()
            .ok_or_else(|| eyre!("machine {} missing BMC IP", machine_id))?;
        let (bmc_username, bmc_password) =
            fetch_bmc_credentials(credential_manager, bmc_mac).await?;
        machines.push(FirmwareUpgradeDeviceInfo {
            node_id: machine_id.to_string(),
            mac: bmc_mac.to_string(),
            bmc_ip: bmc_ip.to_string(),
            bmc_username,
            bmc_password,
            os_mac: None,
            os_ip: None,
            os_username: None,
            os_password: None,
        });
    }

    let mut switches = Vec::with_capacity(switch_endpoints.len());
    for switch in &switch_endpoints {
        let (bmc_username, bmc_password) =
            fetch_bmc_credentials(credential_manager, switch.bmc_mac).await?;
        let nvos_creds = fetch_nvos_credentials(credential_manager, switch.bmc_mac).await;
        switches.push(FirmwareUpgradeDeviceInfo {
            node_id: switch.switch_id.to_string(),
            mac: switch.bmc_mac.to_string(),
            bmc_ip: switch.bmc_ip.to_string(),
            bmc_username,
            bmc_password,
            os_mac: switch.nvos_mac.map(|mac| mac.to_string()),
            os_ip: switch.nvos_ip.map(|ip| ip.to_string()),
            os_username: nvos_creds.as_ref().map(|(username, _)| username.clone()),
            os_password: nvos_creds.map(|(_, password)| password),
        });
    }

    Ok(RackFirmwareInventory {
        machine_ids,
        switch_ids,
        machines,
        switches,
    })
}

pub fn build_firmware_update_batches(
    rack_id: &RackId,
    firmware: &RackFirmware,
    firmware_type: &str,
    inventory: &RackFirmwareInventory,
) -> Result<Vec<FirmwareUpdateBatchRequest>> {
    let parsed_components = firmware
        .parsed_components
        .as_ref()
        .map(|parsed| parsed.0.clone())
        .ok_or_else(|| eyre!("firmware '{}' has no parsed components", firmware.id))?;

    let batch_definitions = [
        (
            "Compute Node",
            rms::NodeType::Compute,
            "Compute Node",
            &inventory.machines,
            true,
        ),
        (
            "Switch Tray",
            rms::NodeType::Switch,
            "Switch",
            &inventory.switches,
            false,
        ),
    ];

    let mut batches = Vec::new();
    for (lookup_key, node_type, display_name, devices, activate) in batch_definitions {
        if devices.is_empty() {
            continue;
        }

        let firmware_targets =
            build_firmware_targets(&parsed_components, lookup_key, firmware_type, &firmware.id)?;
        let node_infos = devices
            .iter()
            .map(|device| build_new_node_info(rack_id, device, node_type))
            .collect();
        let mut target_map = HashMap::new();
        target_map.insert(
            node_type as i32,
            rms::FirmwareTargetList {
                targets: firmware_targets,
            },
        );

        batches.push(FirmwareUpdateBatchRequest {
            display_name,
            devices: devices.clone(),
            request: rms::UpdateFirmwareByDeviceListRequest {
                nodes: Some(rms::NodeSet {
                    devices: node_infos,
                }),
                firmware_targets: target_map,
                activate,
                force_update: true,
                ..Default::default()
            },
        });
    }

    Ok(batches)
}

pub async fn submit_firmware_update_batches(
    rms_client: &dyn RmsApi,
    batches: Vec<FirmwareUpdateBatchRequest>,
) -> Vec<SubmittedFirmwareBatch> {
    let mut submissions = Vec::with_capacity(batches.len());
    for batch in batches {
        let response = rms_client
            .update_firmware_by_device_list(batch.request)
            .await
            .map_err(|err| err.to_string());
        submissions.push(SubmittedFirmwareBatch {
            display_name: batch.display_name,
            devices: batch.devices,
            response,
        });
    }
    submissions
}

async fn fetch_bmc_credentials(
    credential_manager: &dyn CredentialManager,
    bmc_mac: mac_address::MacAddress,
) -> Result<(String, String)> {
    let key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: bmc_mac,
        },
    };

    let creds = match credential_manager.get_credentials(&key).await? {
        Some(creds) => creds,
        None => {
            let sitewide_key = CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::SiteWideRoot,
            };
            credential_manager
                .get_credentials(&sitewide_key)
                .await?
                .ok_or_else(|| eyre!("no BMC credentials found for {} or sitewide", bmc_mac))?
        }
    };

    match creds {
        Credentials::UsernamePassword { username, password } => Ok((username, password)),
    }
}

async fn fetch_nvos_credentials(
    credential_manager: &dyn CredentialManager,
    bmc_mac: mac_address::MacAddress,
) -> Option<(String, String)> {
    let key = CredentialKey::SwitchNvosAdmin {
        bmc_mac_address: bmc_mac,
    };
    match credential_manager.get_credentials(&key).await {
        Ok(Some(Credentials::UsernamePassword { username, password })) => {
            Some((username, password))
        }
        _ => None,
    }
}

fn build_firmware_targets(
    parsed_components: &Value,
    lookup_key: &str,
    firmware_type: &str,
    firmware_id: &str,
) -> Result<Vec<rms::FirmwareTarget>> {
    let mut firmware_components =
        find_firmware_components_for_device(parsed_components, lookup_key, firmware_type)?;
    let flash_order = get_firmware_flash_order(lookup_key);
    firmware_components.sort_by_key(|(_, _, target)| {
        flash_order
            .iter()
            .position(|candidate| candidate == &target.as_str())
            .unwrap_or(usize::MAX)
    });

    if firmware_components.is_empty() {
        return Err(eyre!(
            "no matching firmware found in config for {} ({})",
            lookup_key,
            firmware_type
        ));
    }

    Ok(firmware_components
        .into_iter()
        .map(|(_, filename, target)| rms::FirmwareTarget {
            target,
            filename: format!(
                "/forge-boot-artifacts/blobs/internal/fw/rack_firmware/{}/{}",
                firmware_id, filename
            ),
        })
        .collect())
}

fn build_new_node_info(
    rack_id: &RackId,
    device: &FirmwareUpgradeDeviceInfo,
    node_type: rms::NodeType,
) -> rms::NewNodeInfo {
    let bmc_endpoint = if device.bmc_ip.is_empty() || device.mac.is_empty() {
        None
    } else {
        Some(rms::BmcEndpoint {
            interface: Some(rms::NetworkInterface {
                ip_address: device.bmc_ip.clone(),
                mac_address: device.mac.clone(),
            }),
            port: 443,
            credentials: user_pass_credentials(&device.bmc_username, &device.bmc_password),
        })
    };

    let host_endpoint = if matches!(node_type, rms::NodeType::Switch) {
        Some(rms::HostEndpoint {
            interfaces: build_host_interfaces(device),
            port: 0,
            credentials: user_pass_credentials(
                device.os_username.as_deref().unwrap_or_default(),
                device.os_password.as_deref().unwrap_or_default(),
            ),
        })
    } else {
        None
    };

    rms::NewNodeInfo {
        node_id: device.node_id.clone(),
        rack_id: rack_id.to_string(),
        r#type: Some(node_type as i32),
        bmc_endpoint,
        host_endpoint,
    }
}

fn build_host_interfaces(device: &FirmwareUpgradeDeviceInfo) -> Vec<rms::NetworkInterface> {
    if device.os_ip.is_none() && device.os_mac.is_none() {
        return Vec::new();
    }

    vec![rms::NetworkInterface {
        ip_address: device.os_ip.clone().unwrap_or_default(),
        mac_address: device.os_mac.clone().unwrap_or_default(),
    }]
}

fn user_pass_credentials(username: &str, password: &str) -> Option<rms::Credentials> {
    if username.is_empty() || password.is_empty() {
        return None;
    }

    Some(rms::Credentials {
        auth: Some(rms::credentials::Auth::UserPass(rms::UsernamePassword {
            username: username.to_string(),
            password: password.to_string(),
        })),
    })
}

fn get_firmware_flash_order(device_type_key: &str) -> &'static [&'static str] {
    match device_type_key {
        "Switch Tray" => &["bmc", "fpga", "erot", "bios"],
        "Compute Node" => &["/redfish/v1/Chassis/HGX_Chassis_0", "FW_BMC_0"],
        _ => &[],
    }
}

fn find_firmware_components_for_device(
    parsed_components: &Value,
    hardware_type: &str,
    firmware_type: &str,
) -> Result<Vec<(String, String, String)>> {
    let lookup_table: FirmwareLookupTable = serde_json::from_value(parsed_components.clone())
        .map_err(|err| {
            eyre!(
                "failed to parse firmware lookup table for '{}': {}",
                hardware_type,
                err
            )
        })?;

    let wanted_type = firmware_type.to_lowercase();
    let mut results = Vec::new();
    if let Some(device_components) = lookup_table.devices.get(hardware_type) {
        for (component_key, entry) in device_components {
            if entry.firmware_type.to_lowercase() != wanted_type {
                continue;
            }
            results.push((
                component_key.clone(),
                entry.filename.clone(),
                entry.target.clone(),
            ));
        }
    }

    Ok(results)
}
