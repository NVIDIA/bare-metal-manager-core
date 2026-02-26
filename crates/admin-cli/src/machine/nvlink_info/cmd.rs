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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge as forgerpc;

use super::args::{NvlinkInfoArgs, NvlinkInfoPopulateArgs};
use crate::rpc::ApiClient;

pub async fn handle_nvlink_info_show(
    args: NvlinkInfoArgs,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let machine = api_client.get_machine(args.machine_id).await?;

    // Check if this is an MNNVL machine (GB200)
    let is_mnnvl = machine
        .discovery_info
        .as_ref()
        .and_then(|info| info.dmi_data.as_ref())
        .map(|dmi| dmi.product_name.contains("GB200"))
        .unwrap_or(false);

    if !is_mnnvl {
        return Err(CarbideCliError::GenericError(format!(
            "Machine {} is not an MNNVL machine",
            args.machine_id
        )));
    }

    match machine.nvlink_info {
        Some(nvlink_info) => {
            println!("{}", serde_json::to_string_pretty(&nvlink_info)?);
        }
        None => {
            return Err(CarbideCliError::GenericError(format!(
                "Machine {} has no nvlink_info in database",
                args.machine_id
            )));
        }
    }

    Ok(())
}

pub async fn handle_nvlink_info_populate(
    args: NvlinkInfoPopulateArgs,
    _output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let machine = api_client.get_machine(args.machine_id).await?;
    let update_db = args.update_db;

    // Check if this is an MNNVL machine (GB200)
    let is_mnnvl = machine
        .discovery_info
        .as_ref()
        .and_then(|info| info.dmi_data.as_ref())
        .map(|dmi| dmi.product_name.contains("GB200"))
        .unwrap_or(false);

    if !is_mnnvl {
        return Err(CarbideCliError::GenericError(format!(
            "Machine {} is not an MNNVL machine",
            args.machine_id
        )));
    }

    let bmc_ip = machine
        .bmc_info
        .as_ref()
        .and_then(|b| b.ip.clone())
        .ok_or_else(|| CarbideCliError::GenericError("No BMC IP available".to_string()))?;

    // Fetch nmx-m compute nodes and build lookup map by (serial_number, tray_index)
    let nmxm_compute_nodes: HashMap<(String, i32), serde_json::Value> = match api_client
        .0
        .nmxm_browse("nmx/v1/compute-nodes".to_string())
        .await
    {
        Ok(response) => {
            // Check for HTTP error codes
            if response.code < 200 || response.code >= 300 {
                return Err(CarbideCliError::GenericError(format!(
                    "NMX-M compute-nodes request failed with HTTP {}: {}",
                    response.code, response.body
                )));
            }
            if let Ok(nodes) = serde_json::from_str::<Vec<serde_json::Value>>(&response.body) {
                nodes
                    .into_iter()
                    .filter_map(|node| {
                        let location_info = node.get("LocationInfo")?;
                        let serial = location_info
                            .get("ChassisSerialNumber")?
                            .as_str()?
                            .to_string();
                        let tray_idx = location_info.get("TrayIndex")?.as_i64()? as i32;
                        Some(((serial, tray_idx), node))
                    })
                    .collect()
            } else {
                HashMap::new()
            }
        }
        Err(e) => {
            return Err(CarbideCliError::GenericError(format!(
                "Failed to fetch nmx-m compute nodes: {}",
                e
            )));
        }
    };

    // Fetch Redfish data
    let uri = format!("https://{}/redfish/v1/Chassis/CBC_0", bmc_ip);

    let redfish_response = api_client
        .0
        .redfish_browse(uri.clone())
        .await
        .map_err(|e| CarbideCliError::GenericError(format!("Redfish call failed: {}", e)))?;

    let json: serde_json::Value = serde_json::from_str(&redfish_response.text).map_err(|e| {
        CarbideCliError::GenericError(format!("Failed to parse Redfish response: {}", e))
    })?;

    // Extract Oem.Nvidia.ComputeTrayIndex
    let tray_index = json
        .get("Oem")
        .and_then(|oem| oem.get("Nvidia"))
        .and_then(|nvidia| nvidia.get("ComputeTrayIndex"))
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .ok_or_else(|| {
            CarbideCliError::GenericError("No tray_index found in Redfish response".to_string())
        })?;

    // Extract SerialNumber
    let serial_number = json
        .get("SerialNumber")
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            CarbideCliError::GenericError("No SerialNumber found in Redfish response".to_string())
        })?;

    // Look up matching nmx-m compute node
    let nmxm_node = nmxm_compute_nodes
        .get(&(serial_number.clone(), tray_index))
        .ok_or_else(|| {
            CarbideCliError::GenericError(format!(
                "No NMX-M compute node found for serial={}, tray_index={}",
                serial_number, tray_index
            ))
        })?;

    let domain_uuid = nmxm_node
        .get("DomainUUID")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CarbideCliError::GenericError("No DomainUUID found in NMX-M response".to_string())
        })?;

    let gpu_id_list: Vec<String> = nmxm_node
        .get("GpuIDList")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if gpu_id_list.is_empty() {
        return Err(CarbideCliError::GenericError(
            "No GPUs found in NMX-M compute node".to_string(),
        ));
    }

    // Fetch GPU details from nmx-m for each GPU in the list
    let mut gpus: Vec<forgerpc::NvLinkGpu> = Vec::new();
    for gpu_id in &gpu_id_list {
        let gpu_path = format!("nmx/v1/gpus/{}", gpu_id);
        let gpu_response = api_client
            .0
            .nmxm_browse(gpu_path.clone())
            .await
            .map_err(|e| {
                CarbideCliError::GenericError(format!("Failed to fetch GPU {}: {}", gpu_id, e))
            })?;

        // Check for HTTP error codes
        if gpu_response.code < 200 || gpu_response.code >= 300 {
            return Err(CarbideCliError::GenericError(format!(
                "NMX-M GPU {} request failed with HTTP {}: {}",
                gpu_id, gpu_response.code, gpu_response.body
            )));
        }

        let gpu_json: serde_json::Value =
            serde_json::from_str(&gpu_response.body).map_err(|e| {
                CarbideCliError::GenericError(format!(
                    "Failed to parse GPU {} response: {}",
                    gpu_id, e
                ))
            })?;

        let gpu_nmx_m_id = gpu_json
            .get("ID")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let gpu_device_id = gpu_json
            .get("DeviceID")
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        let gpu_device_uid = gpu_json
            .get("DeviceUID")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let gpu_location = gpu_json.get("LocationInfo");
        let gpu_tray_index = gpu_location
            .and_then(|loc| loc.get("TrayIndex"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;
        let gpu_slot_id = gpu_location
            .and_then(|loc| loc.get("SlotID"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0) as i32;

        gpus.push(forgerpc::NvLinkGpu {
            nmx_m_id: gpu_nmx_m_id,
            device_id: gpu_device_id,
            guid: gpu_device_uid,
            tray_index: gpu_tray_index,
            slot_id: gpu_slot_id,
        });
    }

    // Parse domain_uuid as UUID
    let domain_uuid_parsed = uuid::Uuid::parse_str(domain_uuid).map_err(|e| {
        CarbideCliError::GenericError(format!("Failed to parse domain_uuid: {}", e))
    })?;

    // Build the nvlink_info structure for RPC
    let nvlink_info_rpc = forgerpc::MachineNvLinkInfo {
        domain_uuid: Some(carbide_uuid::nvlink::NvLinkDomainId::from(
            domain_uuid_parsed,
        )),
        gpus: gpus.clone(),
    };

    // Build the nvlink_info structure as JSON for display
    let nvlink_info = serde_json::json!({
        "domain_uuid": domain_uuid,
        "gpus": gpus.iter().map(|g| serde_json::json!({
            "nmx_m_id": g.nmx_m_id,
            "device_id": g.device_id,
            "guid": g.guid,
            "tray_index": g.tray_index,
            "slot_id": g.slot_id,
        })).collect::<Vec<_>>(),
    });

    if update_db {
        api_client
            .update_machine_nvlink_info(args.machine_id, nvlink_info_rpc)
            .await?;
        println!("Updated nvlink_info in db with the following nvlink-info:");
    } else {
        println!("\n\n Use --update-db option to apply the following nvlink-info:");
    }

    println!("{}", serde_json::to_string_pretty(&nvlink_info)?);

    Ok(())
}
