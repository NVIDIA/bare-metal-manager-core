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

use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialManager, Credentials,
};
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use db::{machine as db_machine, machine_topology as db_machine_topology, switch as db_switch};
use eyre::{Result, eyre};
use librms::protos::rack_manager as rms;
use model::machine::machine_search_config::MachineSearchConfig;
use model::rack::FirmwareUpgradeDeviceInfo;
use model::rack_type::{RackHardwareClass, RackProfile};
use sqlx::PgPool;

use crate::rms_node_type::is_switch_node_type;

#[derive(Debug, Clone)]
pub struct RackFirmwareInventory {
    pub machine_ids: Vec<carbide_uuid::machine::MachineId>,
    pub machines: Vec<FirmwareUpgradeDeviceInfo>,
    pub switch_ids: Vec<SwitchId>,
    pub switches: Vec<FirmwareUpgradeDeviceInfo>,
}

#[derive(Debug, Clone)]
pub struct RackSwitchFirmwareInventory {
    pub switch_ids: Vec<SwitchId>,
    pub switches: Vec<FirmwareUpgradeDeviceInfo>,
}

pub fn firmware_type_for_profile(profile: &RackProfile) -> &'static str {
    match profile.rack_hardware_class {
        Some(RackHardwareClass::Dev) => "dev",
        Some(RackHardwareClass::Prod) | None => "prod",
    }
}

pub async fn load_rack_firmware_inventory(
    db_pool: &PgPool,
    credential_manager: &dyn CredentialManager,
    rack_id: &RackId,
) -> Result<RackFirmwareInventory> {
    let (machine_ids, machine_topologies) = {
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

        txn.commit().await?;
        (machine_ids, machine_topologies)
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

    let RackSwitchFirmwareInventory {
        switch_ids,
        switches,
    } = load_rack_switch_firmware_inventory(db_pool, credential_manager, rack_id).await?;

    Ok(RackFirmwareInventory {
        machine_ids,
        machines,
        switch_ids,
        switches,
    })
}

pub async fn load_rack_switch_firmware_inventory(
    db_pool: &PgPool,
    credential_manager: &dyn CredentialManager,
    rack_id: &RackId,
) -> Result<RackSwitchFirmwareInventory> {
    let (switch_ids, switch_endpoints) = {
        let mut txn = db_pool.begin().await?;

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
        (switch_ids, switch_endpoints)
    };

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

    Ok(RackSwitchFirmwareInventory {
        switch_ids,
        switches,
    })
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

pub fn build_new_node_info(
    rack_id: &RackId,
    device: &FirmwareUpgradeDeviceInfo,
    node_type: rms::NodeType,
) -> rms::NodeInfo {
    let bmc_endpoint = if device.bmc_ip.is_empty() || device.mac.is_empty() {
        None
    } else {
        Some(rms::Endpoint {
            interface: Some(rms::NetworkInterface {
                ip_address: device.bmc_ip.clone(),
                mac_address: device.mac.clone(),
            }),
            port: 443,
            credentials: user_pass_credentials(&device.bmc_username, &device.bmc_password),
            // TODO: we'll need to remove this from the RMS proto `Endpoint` field. This field
            // should not be set by the caller, and should be owned by the RMS.
            dangerously_accept_invalid_certs: true,
        })
    };

    let host_endpoint = if is_switch_node_type(node_type) {
        Some(rms::Endpoint {
            interface: build_host_interface(device),
            port: 0,
            credentials: user_pass_credentials(
                device.os_username.as_deref().unwrap_or_default(),
                device.os_password.as_deref().unwrap_or_default(),
            ),
            // TODO: we'll need to remove this from the RMS proto `Endpoint` field. This field
            // should not be set by the caller, and should be owned by the RMS.
            dangerously_accept_invalid_certs: true,
        })
    } else {
        None
    };

    rms::NodeInfo {
        node_id: device.node_id.clone(),
        rack_id: rack_id.to_string(),
        r#type: Some(node_type as i32),
        bmc_endpoint,
        host_endpoint,
    }
}

fn build_host_interface(device: &FirmwareUpgradeDeviceInfo) -> Option<rms::NetworkInterface> {
    let (Some(ip_address), Some(mac_address)) = (&device.os_ip, &device.os_mac) else {
        return None;
    };

    Some(rms::NetworkInterface {
        ip_address: ip_address.clone(),
        mac_address: mac_address.clone(),
    })
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
