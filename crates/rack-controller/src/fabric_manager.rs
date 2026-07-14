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

use std::collections::{HashMap, HashSet};

use carbide_rack::firmware_update::build_new_node_info;
use carbide_rack_controller::config::RmsConfig;
use carbide_utils::none_if_empty::NoneIfEmpty;
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use db::switch as db_switch;
use librms::protos::rack_manager as rms;
use model::rack::FirmwareUpgradeDeviceInfo;
use model::switch::{FabricManagerState, FabricManagerStatus};
use serde::Deserialize;
use sqlx::PgConnection;

use crate as carbide_rack_controller;

pub(super) fn validate_switch_inventory_for_nmx_cluster(
    switches: &[FirmwareUpgradeDeviceInfo],
) -> Result<(), String> {
    for switch in switches {
        if switch.os_ip.as_deref().unwrap_or_default().is_empty() {
            return Err(format!(
                "switch {} is missing an NVOS IP address for ConfigureNmxCluster",
                switch.node_id
            ));
        }
        if switch.os_username.as_deref().unwrap_or_default().is_empty()
            || switch.os_password.as_deref().unwrap_or_default().is_empty()
        {
            return Err(format!(
                "switch {} is missing NVOS credentials for ConfigureNmxCluster",
                switch.node_id
            ));
        }
    }

    Ok(())
}

fn build_scale_up_fabric_services_status_request(
    rack_id: &RackId,
    switches: &[FirmwareUpgradeDeviceInfo],
    node_type: rms::NodeType,
) -> rms::BatchGetScaleUpFabricServiceStatusRequest {
    rms::BatchGetScaleUpFabricServiceStatusRequest {
        nodes: Some(rms::NodeSet {
            nodes: switches
                .iter()
                .map(|switch| build_new_node_info(rack_id, switch, node_type))
                .collect(),
        }),
    }
}

pub(super) async fn batch_get_scale_up_fabric_service_status(
    rms_config: &RmsConfig,
    rack_id: &RackId,
    switches: &[FirmwareUpgradeDeviceInfo],
    node_type: rms::NodeType,
) -> Result<rms::BatchGetScaleUpFabricServiceStatusResponse, String> {
    let Some(url) = rms_config.api_url.as_deref().none_if_empty() else {
        return Err("RMS client not configured".to_string());
    };

    let rms_client_config = librms::client_config::RmsClientConfig::new(
        rms_config.root_ca_path.clone(),
        rms_config.client_cert.clone(),
        rms_config.client_key.clone(),
        rms_config.enforce_tls,
    );
    let rms_api_config = librms::client::RmsApiConfig::new(url, &rms_client_config);
    let rms_client = librms::RackManagerApi::new(&rms_api_config);

    rms_client
        .client
        .batch_get_scale_up_fabric_service_status(build_scale_up_fabric_services_status_request(
            rack_id, switches, node_type,
        ))
        .await
        .map_err(|error| format!("RMS BatchGetScaleUpFabricServiceStatus failed: {}", error))
}

#[derive(Debug, Deserialize)]
struct RmsFabricManagerStatusPayload {
    status: Option<String>,
    #[serde(rename = "addition-info")]
    addition_info: Option<String>,
    reason: Option<String>,
}

fn fabric_manager_status_from_entry(
    node_id: &str,
    entry: &rms::ScaleUpFabricServiceStatusEntry,
) -> FabricManagerStatus {
    if !entry.error_message.trim().is_empty() {
        return FabricManagerStatus {
            fabric_manager_state: FabricManagerState::Unknown,
            addition_info: None,
            reason: None,
            error_message: Some(entry.error_message.clone()),
        };
    }

    if entry.status_json.trim().is_empty() {
        return FabricManagerStatus {
            fabric_manager_state: FabricManagerState::Unknown,
            addition_info: None,
            reason: None,
            error_message: None,
        };
    }

    let status_json =
        match serde_json::from_str::<RmsFabricManagerStatusPayload>(&entry.status_json) {
            Ok(status_json) => status_json,
            Err(error) => {
                tracing::warn!(
                    switch_id = %node_id,
                    %error,
                    status_json = %entry.status_json,
                    "Failed to parse RMS fabric-manager status JSON"
                );
                return FabricManagerStatus {
                    fabric_manager_state: FabricManagerState::Unknown,
                    addition_info: None,
                    reason: None,
                    error_message: None,
                };
            }
        };

    let fabric_manager_state = match status_json.status.as_deref().unwrap_or_default() {
        "ok" => FabricManagerState::Ok,
        "not ok" => FabricManagerState::NotOk,
        _ => FabricManagerState::Unknown,
    };

    FabricManagerStatus {
        fabric_manager_state,
        addition_info: status_json.addition_info,
        reason: status_json.reason,
        error_message: None,
    }
}

pub(super) async fn persist_fabric_manager_statuses(
    txn: &mut PgConnection,
    rack_id: &RackId,
    switches: &[FirmwareUpgradeDeviceInfo],
    response: &rms::BatchGetScaleUpFabricServiceStatusResponse,
) -> Result<(), String> {
    if response.status != rms::ReturnCode::Success as i32 {
        return Err(
            "RMS BatchGetScaleUpFabricServiceStatus returned failure for ConfigureNmxCluster"
                .to_string(),
        );
    }

    for switch in switches {
        let Some(entry) = response.service_statuses.get(switch.node_id.as_str()) else {
            return Err(format!(
                "RMS did not return fabric-manager status for switch {}",
                switch.node_id
            ));
        };
        let switch_id = switch.node_id.parse::<SwitchId>().map_err(|error| {
            format!(
                "invalid switch id {} while persisting fabric-manager status: {}",
                switch.node_id, error
            )
        })?;
        let fabric_manager_status = fabric_manager_status_from_entry(&switch.node_id, entry);

        db_switch::update_fabric_manager_status(txn, switch_id, Some(&fabric_manager_status))
            .await
            .map_err(|error| {
                format!(
                    "failed to persist fabric-manager status for switch {}: {}",
                    switch.node_id, error
                )
            })?;

        tracing::info!(
            rack_id = %rack_id,
            switch_id = %switch.node_id,
            fabric_manager_status = %fabric_manager_status.display_status(),
            raw_fabric_manager_state = ?fabric_manager_status.fabric_manager_state,
            error_message = %fabric_manager_status.error_message.as_deref().unwrap_or_default(),
            "Persisted FabricManager status for switch"
        );
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub(super) struct SwitchPlacement {
    pub(super) device: FirmwareUpgradeDeviceInfo,
    pub(super) tray_index: u32,
    pub(super) slot_number: Option<u32>,
}

pub(super) fn select_primary_switch(
    switches: &[FirmwareUpgradeDeviceInfo],
    response: &rms::BatchGetNodeDeviceInfoResponse,
) -> Result<SwitchPlacement, String> {
    if response.status != rms::ReturnCode::Success as i32 {
        let details = if response.message.trim().is_empty() {
            "no error details provided".to_string()
        } else {
            response.message.clone()
        };
        return Err(format!("RMS BatchGetNodeDeviceInfo failed: {}", details));
    }

    let switches_by_node_id: HashMap<&str, &FirmwareUpgradeDeviceInfo> = switches
        .iter()
        .map(|switch| (switch.node_id.as_str(), switch))
        .collect();
    let mut placements = Vec::with_capacity(response.node_device_details.len());
    let mut seen_node_ids = HashSet::with_capacity(response.node_device_details.len());

    for node_info in &response.node_device_details {
        let Some(device) = switches_by_node_id.get(node_info.node_id.as_str()) else {
            return Err(format!(
                "RMS returned device info for unexpected switch {}",
                node_info.node_id
            ));
        };
        let Some(tray_index) = node_info.tray_index else {
            return Err(format!(
                "RMS did not return tray_index for switch {}",
                node_info.node_id
            ));
        };
        placements.push(SwitchPlacement {
            device: (*device).clone(),
            tray_index,
            slot_number: node_info.slot_number,
        });
        seen_node_ids.insert(node_info.node_id.as_str());
    }

    if placements.is_empty() {
        return Err("RMS returned no switch device info for ConfigureNmxCluster".to_string());
    }

    if placements.len() != switches.len() {
        let missing = switches
            .iter()
            .filter(|switch| !seen_node_ids.contains(switch.node_id.as_str()))
            .map(|switch| switch.node_id.clone())
            .collect::<Vec<_>>();
        return Err(format!(
            "RMS did not return device info for switches: {}",
            missing.join(", ")
        ));
    }

    placements.sort_by_key(|placement| placement.tray_index);

    if let Some(duplicate_tray_index) = placements.windows(2).find_map(|window| {
        let left = &window[0];
        let right = &window[1];
        (left.tray_index == right.tray_index).then_some(left.tray_index)
    }) {
        let duplicate_switches = placements
            .iter()
            .filter(|placement| placement.tray_index == duplicate_tray_index)
            .map(|placement| placement.device.node_id.as_str())
            .collect::<Vec<_>>();
        return Err(format!(
            "RMS returned duplicate tray_index {} for switches: {}",
            duplicate_tray_index,
            duplicate_switches.join(", ")
        ));
    }

    let Some(primary) = placements.into_iter().next() else {
        return Err("RMS returned no switch device info for ConfigureNmxCluster".to_string());
    };

    Ok(primary)
}

pub(super) async fn persist_primary_switch(
    txn: &mut PgConnection,
    rack_id: &RackId,
    primary_switch_node_id: &str,
) -> Result<(), String> {
    let primary_switch_id = primary_switch_node_id
        .parse::<SwitchId>()
        .map_err(|error| {
            format!(
                "selected primary switch '{}' is not a valid SwitchId: {}",
                primary_switch_node_id, error
            )
        })?;

    db_switch::set_primary_switch_for_rack(txn, rack_id, &primary_switch_id)
        .await
        .map_err(|error| {
            format!(
                "failed to persist primary switch '{}' for rack {}: {}",
                primary_switch_node_id, rack_id, error
            )
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use carbide_test_support::{Check, check_values};

    use super::*;

    fn switch(node_id: &str) -> FirmwareUpgradeDeviceInfo {
        FirmwareUpgradeDeviceInfo {
            node_id: node_id.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            bmc_ip: "192.0.2.10".to_string(),
            bmc_username: "admin".to_string(),
            bmc_password: "password".to_string(),
            os_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            os_ip: Some("198.51.100.10".to_string()),
            os_username: Some("nvos".to_string()),
            os_password: Some("password".to_string()),
            os_hostname: None,
        }
    }

    fn node_device_details(
        node_id: &str,
        tray_index: u32,
        slot_number: Option<u32>,
    ) -> rms::NodeDeviceInfo {
        rms::NodeDeviceInfo {
            node_id: node_id.to_string(),
            tray_index: Some(tray_index),
            slot_number,
            ..Default::default()
        }
    }

    #[test]
    fn select_primary_switch_picks_lowest_tray_index() -> Result<(), String> {
        let switches = vec![switch("sw-1"), switch("sw-2"), switch("sw-3")];
        let response = rms::BatchGetNodeDeviceInfoResponse {
            status: rms::ReturnCode::Success as i32,
            node_device_details: vec![
                node_device_details("sw-1", 3, Some(3)),
                node_device_details("sw-2", 1, Some(1)),
                node_device_details("sw-3", 2, Some(2)),
            ],
            ..Default::default()
        };

        let primary = select_primary_switch(&switches, &response)?;

        assert_eq!(primary.device.node_id, "sw-2");
        assert_eq!(primary.tray_index, 1);
        assert_eq!(primary.slot_number, Some(1));

        Ok(())
    }

    #[test]
    fn select_primary_switch_errors_on_duplicate_tray_index() -> Result<(), String> {
        let switches = vec![switch("sw-1"), switch("sw-2")];
        let response = rms::BatchGetNodeDeviceInfoResponse {
            status: rms::ReturnCode::Success as i32,
            node_device_details: vec![
                node_device_details("sw-1", 1, Some(1)),
                node_device_details("sw-2", 1, Some(2)),
            ],
            ..Default::default()
        };

        let Err(error) = select_primary_switch(&switches, &response) else {
            return Err("selection should fail".to_string());
        };

        assert!(error.contains("duplicate tray_index 1"));
        assert!(error.contains("sw-1"));
        assert!(error.contains("sw-2"));

        Ok(())
    }

    fn entry(status_json: &str, error_message: &str) -> rms::ScaleUpFabricServiceStatusEntry {
        rms::ScaleUpFabricServiceStatusEntry {
            status_json: status_json.to_string(),
            error_message: error_message.to_string(),
        }
    }

    /// The full derived status plus its product-facing display string, so a
    /// table row asserts both the parsed fields and the "running"/"not_running"
    /// outcome the caller acts on.
    #[derive(Debug, PartialEq)]
    struct Observed {
        status: FabricManagerStatus,
        display: &'static str,
    }

    fn observe(entry: rms::ScaleUpFabricServiceStatusEntry) -> Observed {
        let status = fabric_manager_status_from_entry("sw-1", &entry);
        let display = status.display_status();
        Observed { status, display }
    }

    #[test]
    fn test_fabric_manager_status_from_entry() {
        check_values(
            [
                Check {
                    scenario: "ok with control-plane configured -> running",
                    input: entry(
                        r#"{"addition-info":"CONTROL_PLANE_STATE_CONFIGURED","reason":"","status":"ok"}"#,
                        "",
                    ),
                    expect: Observed {
                        status: FabricManagerStatus {
                            fabric_manager_state: FabricManagerState::Ok,
                            addition_info: Some("CONTROL_PLANE_STATE_CONFIGURED".to_string()),
                            reason: Some(String::new()),
                            error_message: None,
                        },
                        display: "running",
                    },
                },
                Check {
                    scenario: "not ok -> not_running",
                    input: entry(
                        r#"{"addition-info":"","reason":"stopped by user","status":"not ok"}"#,
                        "",
                    ),
                    expect: Observed {
                        status: FabricManagerStatus {
                            fabric_manager_state: FabricManagerState::NotOk,
                            addition_info: Some(String::new()),
                            reason: Some("stopped by user".to_string()),
                            error_message: None,
                        },
                        display: "not_running",
                    },
                },
                Check {
                    scenario: "empty status json -> unknown, not_running",
                    input: entry("", ""),
                    expect: Observed {
                        status: FabricManagerStatus {
                            fabric_manager_state: FabricManagerState::Unknown,
                            addition_info: None,
                            reason: None,
                            error_message: None,
                        },
                        display: "not_running",
                    },
                },
                Check {
                    scenario: "error message surfaces -> unknown, not_running",
                    input: entry(
                        r#"{"addition-info":"CONTROL_PLANE_STATE_CONFIGURED","status":"ok"}"#,
                        "nmx-controller not started",
                    ),
                    expect: Observed {
                        status: FabricManagerStatus {
                            fabric_manager_state: FabricManagerState::Unknown,
                            addition_info: None,
                            reason: None,
                            error_message: Some("nmx-controller not started".to_string()),
                        },
                        display: "not_running",
                    },
                },
                Check {
                    scenario: "malformed json -> unknown, not_running",
                    input: entry("{not-json", ""),
                    expect: Observed {
                        status: FabricManagerStatus {
                            fabric_manager_state: FabricManagerState::Unknown,
                            addition_info: None,
                            reason: None,
                            error_message: None,
                        },
                        display: "not_running",
                    },
                },
            ],
            observe,
        );
    }
}
