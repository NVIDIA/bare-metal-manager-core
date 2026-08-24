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
use carbide_rack::rms_node_type::RmsNodeIdentity;
use carbide_rack_controller::config::RmsConfig;
use carbide_utils::none_if_empty::NoneIfEmpty;
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use component_manager::nv_switch_manager::{
    ScaleUpFabricResponseStatus, ScaleUpFabricServiceStatuses, ScaleUpFabricStatus,
};
use component_manager::rms::scale_up_fabric_service_statuses_from_rms;
use db::switch as db_switch;
use librms::protos::rack_manager as rms;
use model::rack::FirmwareUpgradeDeviceInfo;
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
    node_identity: &RmsNodeIdentity,
) -> rms::BatchGetScaleUpFabricServiceStatusRequest {
    rms::BatchGetScaleUpFabricServiceStatusRequest {
        nodes: Some(rms::NodeSet {
            nodes: switches
                .iter()
                .map(|switch| build_new_node_info(rack_id, switch, node_identity))
                .collect(),
        }),
    }
}

pub(super) async fn batch_get_scale_up_fabric_service_status(
    rms_config: &RmsConfig,
    rack_id: &RackId,
    switches: &[FirmwareUpgradeDeviceInfo],
    node_identity: &RmsNodeIdentity,
) -> Result<ScaleUpFabricServiceStatuses, String> {
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

    let response =
        rms_client
            .client
            .batch_get_scale_up_fabric_service_status(
                build_scale_up_fabric_services_status_request(rack_id, switches, node_identity),
            )
            .await
            .map_err(|error| format!("RMS BatchGetScaleUpFabricServiceStatus failed: {}", error))?;

    Ok(scale_up_fabric_service_statuses_from_rms(response))
}

pub(super) async fn persist_fabric_manager_statuses(
    txn: &mut PgConnection,
    rack_id: &RackId,
    switches: &[FirmwareUpgradeDeviceInfo],
    response: &ScaleUpFabricServiceStatuses,
) -> Result<(), String> {
    match response.status {
        ScaleUpFabricResponseStatus::Success => {}
        ScaleUpFabricResponseStatus::Failure => {
            return Err(
                "RMS BatchGetScaleUpFabricServiceStatus returned failure for ConfigureNmxCluster"
                    .to_string(),
            );
        }
        ScaleUpFabricResponseStatus::Unknown(code) => {
            return Err(format!(
                "RMS BatchGetScaleUpFabricServiceStatus returned unknown status code {code} for ConfigureNmxCluster"
            ));
        }
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

        db_switch::update_fabric_manager_status(txn, switch_id, Some(entry))
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
            fabric_manager_status = %entry.display_status(),
            raw_fabric_manager_state = ?entry.fabric_manager_state,
            error_message = %entry.error_message.as_deref().unwrap_or_default(),
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

/// Returns the primary switch observed in an RMS ScaleUpFabric status response.
///
/// A valid response must succeed and mark exactly one submitted rack switch as
/// enabled.
///
/// # Errors
///
/// Returns an error when RMS does not report one valid primary.
pub(super) fn observed_primary_switch(
    switches: &[FirmwareUpgradeDeviceInfo],
    response: &ScaleUpFabricStatus,
) -> Result<SwitchId, String> {
    match response.status {
        ScaleUpFabricResponseStatus::Success => {}
        ScaleUpFabricResponseStatus::Failure => {
            let details = if response.error_message.trim().is_empty() {
                "no error details provided"
            } else {
                response.error_message.as_str()
            };

            return Err(format!("RMS GetScaleUpFabricStatus failed: {details}"));
        }
        ScaleUpFabricResponseStatus::Unknown(status) => {
            return Err(format!(
                "RMS GetScaleUpFabricStatus returned invalid status {}",
                status
            ));
        }
    }

    let Some(switch_statuses) = response.switches.as_ref() else {
        return Err("RMS GetScaleUpFabricStatus returned no fabric status".to_string());
    };

    let mut enabled_switches = switch_statuses.iter().filter(|switch| switch.enabled);

    let Some(enabled_switch) = enabled_switches.next() else {
        return Err("RMS GetScaleUpFabricStatus reported no primary switch".to_string());
    };

    if enabled_switches.next().is_some() {
        return Err("RMS GetScaleUpFabricStatus reported multiple primary switches".to_string());
    }

    let observed_primary = enabled_switch
        .node_id
        .parse::<SwitchId>()
        .map_err(|error| {
            format!(
                "RMS returned invalid primary switch ID '{}': {error}",
                enabled_switch.node_id
            )
        })?;

    if !switches
        .iter()
        .any(|switch| switch.node_id == enabled_switch.node_id)
    {
        return Err(format!(
            "RMS returned primary switch {} outside the submitted rack",
            enabled_switch.node_id
        ));
    }

    if !enabled_switch.error_message.trim().is_empty() {
        return Err(format!(
            "RMS failed to inspect primary switch {}: {}",
            enabled_switch.node_id, enabled_switch.error_message
        ));
    }

    Ok(observed_primary)
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
    use carbide_rack::rms_node_type::switch_node_identity_for_profile;
    use carbide_test_support::{Check, check_values};
    use carbide_uuid::switch::{SwitchIdSource, SwitchType};
    use component_manager::nv_switch_manager::ScaleUpFabricSwitchStatus;
    use model::rack_type::{RackProductFamily, RackProfile};

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

    #[test]
    fn fabric_status_request_uses_descriptor_without_node_type() {
        let mut profile = RackProfile {
            product_family: Some(RackProductFamily::Gb300),
            ..Default::default()
        };

        profile.rack_capabilities.switch.vendor = Some("test-switch-vendor".to_string());

        let node_identity = switch_node_identity_for_profile(&profile).unwrap();
        let rack_id = RackId::from("rack-1");
        let switches = [switch("switch-1")];

        let request =
            build_scale_up_fabric_services_status_request(&rack_id, &switches, &node_identity);

        let [node] = request
            .nodes
            .expect("request nodes")
            .nodes
            .try_into()
            .unwrap();

        let descriptor = node.node_descriptor.expect("node descriptor");

        assert_eq!(node.r#type, None);

        assert_eq!(
            descriptor.attributes.get("role").map(String::as_str),
            Some("switch")
        );
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

    #[test]
    fn observed_primary_switch_requires_one_submitted_rack_switch() {
        let first_id = SwitchId::new(SwitchIdSource::Tpm, [1; 32], SwitchType::NvLink).to_string();
        let second_id = SwitchId::new(SwitchIdSource::Tpm, [2; 32], SwitchType::NvLink).to_string();
        let expected_switches = vec![switch(&first_id), switch(&second_id)];

        let switch_status = |node_id: &str, enabled| ScaleUpFabricSwitchStatus {
            node_id: node_id.to_string(),
            enabled,
            error_message: String::new(),
        };

        let response = |status, switches| ScaleUpFabricStatus {
            status,
            switches,
            error_message: String::new(),
        };

        check_values(
            [
                Check {
                    scenario: "one enabled submitted switch",
                    input: response(
                        ScaleUpFabricResponseStatus::Success,
                        Some(vec![
                            switch_status(&first_id, false),
                            switch_status(&second_id, true),
                        ]),
                    ),
                    expect: Some(second_id.clone()),
                },
                Check {
                    scenario: "RMS failure",
                    input: response(ScaleUpFabricResponseStatus::Failure, Some(Vec::new())),
                    expect: None,
                },
                Check {
                    scenario: "unknown response status",
                    input: response(ScaleUpFabricResponseStatus::Unknown(17), Some(Vec::new())),
                    expect: None,
                },
                Check {
                    scenario: "missing fabric status",
                    input: response(ScaleUpFabricResponseStatus::Success, None),
                    expect: None,
                },
                Check {
                    scenario: "no enabled switch",
                    input: response(
                        ScaleUpFabricResponseStatus::Success,
                        Some(vec![switch_status(&first_id, false)]),
                    ),
                    expect: None,
                },
                Check {
                    scenario: "multiple enabled switches",
                    input: response(
                        ScaleUpFabricResponseStatus::Success,
                        Some(vec![
                            switch_status(&first_id, true),
                            switch_status(&second_id, true),
                        ]),
                    ),
                    expect: None,
                },
                Check {
                    scenario: "enabled switch outside submitted rack",
                    input: response(
                        ScaleUpFabricResponseStatus::Success,
                        Some(vec![switch_status(
                            &SwitchId::new(SwitchIdSource::Tpm, [3; 32], SwitchType::NvLink)
                                .to_string(),
                            true,
                        )]),
                    ),
                    expect: None,
                },
            ],
            |response| {
                observed_primary_switch(&expected_switches, &response)
                    .ok()
                    .map(|primary| primary.to_string())
            },
        );
    }
}
