/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::borrow::Cow;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::{Json, Path, Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use serde_json::json;

use crate::json::JsonExt;
use crate::mock_machine_router::{MockWrapperError, MockWrapperState, fallback_to_inner_router};
use crate::{MockPowerState, POWER_CYCLE_DELAY, PowerControl, redfish};

pub fn collection() -> redfish::Collection<'static> {
    redfish::Collection {
        odata_id: Cow::Borrowed("/redfish/v1/Systems"),
        odata_type: Cow::Borrowed("#ComputerSystemCollection.ComputerSystemCollection"),
        name: Cow::Borrowed("Computer System Collection"),
    }
}

pub fn resource<'a>(system_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("/redfish/v1/Systems/{system_id}");
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#ComputerSystem.v1_20_1.ComputerSystem"),
        id: Cow::Borrowed(system_id),
        name: Cow::Borrowed("System"),
    }
}

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    const SYSTEM_ID: &str = "{system_id}";
    const ETH_ID: &str = "{eth_id}";
    r.route(&collection().odata_id, get(get_system_collection))
        .route(
            &resource(SYSTEM_ID).odata_id,
            get(get_system).patch(patch_system),
        )
        .route(
            "/redfish/v1/Systems/{system_id}/Actions/ComputerSystem.Reset",
            post(post_reset_system),
        )
        .route(
            "/redfish/v1/Systems/Bluefield/Settings",
            patch(patch_dpu_settings).get(fallback_to_inner_router),
        )
        .route(
            &redfish::ethernet_interface::system_resource(SYSTEM_ID, ETH_ID).odata_id,
            get(get_ethernet_interface),
        )
        .route(
            &redfish::ethernet_interface::system_collection(SYSTEM_ID).odata_id,
            get(get_ethernet_interface_collection),
        )
}

pub struct SingleSystemConfig {
    pub id: Cow<'static, str>,
    pub eth_interfaces: Vec<redfish::ethernet_interface::EthernetInterface>,
    pub serial_number: String,
    pub pcie_dpu_count: usize,
    pub boot_order_mode: BootOrderMode,
    pub power_control: Option<Arc<dyn PowerControl>>,
}

pub struct SystemConfig {
    pub systems: Vec<SingleSystemConfig>,
}

pub struct SystemState {
    systems: Vec<SingleSystemState>,
}

pub struct SingleSystemState {
    config: SingleSystemConfig,
    boot_order_override: Mutex<Option<Vec<String>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootOrderMode {
    DellOem,
    Generic,
}

impl SystemState {
    pub fn from_config(config: SystemConfig) -> Self {
        Self::from_configs(config.systems)
    }

    pub fn systems(&self) -> &[SingleSystemState] {
        &self.systems
    }

    pub fn find(&self, system_id: &str) -> Option<&SingleSystemState> {
        self.systems
            .iter()
            .find(|system| system.config.id.as_ref() == system_id)
    }

    pub fn boot_order_override(&self, system_id: &str) -> Option<Vec<String>> {
        self.find(system_id)
            .and_then(|system| system.boot_order_override())
    }

    fn from_configs(configs: Vec<SingleSystemConfig>) -> Self {
        let systems = configs.into_iter().map(SingleSystemState::new).collect();
        Self { systems }
    }
}

impl SingleSystemState {
    fn new(config: SingleSystemConfig) -> Self {
        Self {
            config,
            boot_order_override: Mutex::new(None),
        }
    }

    fn set_boot_order_override(&self, boot_order: Vec<String>) {
        *self.boot_order_override.lock().unwrap() = Some(boot_order);
    }

    fn boot_order_override(&self) -> Option<Vec<String>> {
        self.boot_order_override.lock().unwrap().clone()
    }
}

async fn get_system_collection(State(state): State<MockWrapperState>) -> Response {
    let members = state
        .bmc_state
        .system_state
        .systems()
        .iter()
        .map(|system| resource(&system.config.id).entity_ref())
        .collect::<Vec<_>>();
    collection().with_members(&members).into_ok_response()
}

async fn get_system(
    State(mut state): State<MockWrapperState>,
    Path(system_id): Path<String>,
    request: Request<Body>,
) -> Response {
    let json = match state.call_inner_router(request).await {
        Ok(json) => json,
        Err(err) => return err.into_response(),
    };
    let Some(system_state) = state.bmc_state.system_state.find(&system_id) else {
        return not_found();
    };

    let json = if let Some(state) = system_state
        .config
        .power_control
        .as_ref()
        .map(|control| control.get_power_state())
    {
        let power_state = match state {
            MockPowerState::On => "On",
            MockPowerState::Off => "Off",
            MockPowerState::PowerCycling { since } => {
                if since.elapsed() < POWER_CYCLE_DELAY {
                    "Off"
                } else {
                    "On"
                }
            }
        };
        json.patch(json!({ "PowerState": power_state }))
    } else {
        json
    };
    let json = json
        .patch(
            redfish::ethernet_interface::system_collection(&system_id)
                .nav_property("EthernetInterfaces"),
        )
        .patch(json!({ "SerialNumber": &system_state.config.serial_number }));

    let mut json = if let Some(boot_order) = system_state.boot_order_override() {
        json.patch(json!({"Boot": {"BootOrder": boot_order}}))
    } else {
        json
    };

    if system_id != "System.Embedded.1" {
        return json.into_ok_response();
    }

    let dpu_count = system_state.config.pcie_dpu_count;
    if dpu_count == 0 {
        return json.into_ok_response();
    }

    // Modify the Pcie Device List
    // 1) Include a new entry for every mocked DPU in the host
    // 2) Remove all unmocked DPU entries from the list
    // (1): Create a new pcie device for the mocked DPUs in this host
    let mut pcie_devices = Vec::new();
    for index in 1..=dpu_count {
        pcie_devices
            .push(redfish::chassis::gen_dpu_pcie_device_resource(&system_id, index).entity_ref());
    }

    // (2) Remove any Pcie devices from the host's original list that refer to unmocked DPUs
    let Some(devices) = json
        .as_object_mut()
        .and_then(|v| v.remove("PCIeDevices"))
        .and_then(|mut v| v.as_array_mut().map(std::mem::take))
    else {
        return json.into_ok_response();
    };
    for device in devices {
        let Some(odata_id) = device.get("@odata.id").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(upstream_json) = state
            .call_inner_router(
                Request::builder()
                    .method(Method::GET)
                    .uri(odata_id)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
        else {
            continue;
        };
        // Keep all default PCIE devices. Just remove any of the DPU entries
        if upstream_json
            .get("Manufacturer")
            .and_then(|v| v.as_str())
            .is_some_and(|v| v != "Mellanox Technologies")
        {
            pcie_devices.push(device);
        }
    }

    json.patch(json!({"PCIeDevices": pcie_devices}))
        .into_ok_response()
}

async fn get_ethernet_interface(
    State(state): State<MockWrapperState>,
    Path((system_id, interface_id)): Path<(String, String)>,
) -> Response {
    let Some(system_state) = state.bmc_state.system_state.find(&system_id) else {
        return not_found();
    };
    system_state
        .config
        .eth_interfaces
        .iter()
        .find(|eth| eth.id == interface_id)
        .map(|eth| eth.to_json().into_ok_response())
        .unwrap_or_else(not_found)
}

async fn get_ethernet_interface_collection(
    State(state): State<MockWrapperState>,
    Path(system_id): Path<String>,
) -> Response {
    let Some(system_state) = state.bmc_state.system_state.find(&system_id) else {
        return not_found();
    };
    let members = system_state
        .config
        .eth_interfaces
        .iter()
        .map(|eth| redfish::ethernet_interface::system_resource(&system_id, &eth.id).entity_ref())
        .collect::<Vec<_>>();
    redfish::ethernet_interface::system_collection(&system_id)
        .with_members(&members)
        .into_ok_response()
}

async fn patch_dpu_settings() -> Response {
    json!({}).into_ok_response()
}

async fn patch_system(
    State(state): State<MockWrapperState>,
    Path(system_id): Path<String>,
    Json(patch_system): Json<serde_json::Value>,
) -> Response {
    let Some(system_state) = state.bmc_state.system_state.find(&system_id) else {
        return not_found();
    };
    if let Some(new_boot_order) = patch_system
        .get("Boot")
        .and_then(|obj| obj.get("BootOrder"))
        .and_then(serde_json::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
    {
        system_state.set_boot_order_override(new_boot_order);
        match system_state.config.boot_order_mode {
            BootOrderMode::DellOem => redfish::oem::dell::idrac::create_job_with_location(state),
            BootOrderMode::Generic => json!({}).into_ok_response(),
        }
    } else {
        json!({}).into_ok_response()
    }
}

async fn post_reset_system(
    State(mut state): State<MockWrapperState>,
    Path(system_id): Path<String>,
    Json(mut power_request): Json<serde_json::Value>,
) -> Response {
    // Dell specific call back after a reset -- sets the job status for all scheduled BIOS jobs to "Completed"
    state.bmc_state.complete_all_bios_jobs();

    let Some(system_state) = state.bmc_state.system_state.find(&system_id) else {
        return not_found();
    };
    let Some(power_control) = system_state.config.power_control.as_ref() else {
        return not_found();
    };
    let Some(reset_type) = power_request
        .get_mut("ResetType")
        .map(std::mem::take)
        .and_then(|v| serde_json::from_value(v).ok())
    else {
        return json!("Valid ResetType is expected field in Reset action")
            .into_response(StatusCode::BAD_REQUEST);
    };

    // Reply with a failure if the power request is invalid for the current state.
    // Note: This logic is duplicated with that in machine-a-tron's MachineStateMachine, because
    // we don't want to block waiting for the power control implementation to reply. Doing so may
    // introduce a deadlock if the API server holds a lock on the row for this machine
    // while issuing a redfish call, and MachineStateMachine is blocked waiting for the row lock
    // to be released.
    power_control
        .set_power_state(reset_type)
        .map_err(MockWrapperError::from)
        .into_response()
}

fn not_found() -> Response {
    json!("").into_response(StatusCode::NOT_FOUND)
}
