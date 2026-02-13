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

use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::{JsonExt, JsonPatch, json_patch};
use crate::redfish::Builder;
use crate::{
    LogServices, MockPowerState, POWER_CYCLE_DELAY, PowerControl, SetSystemPowerError, http,
    redfish,
};

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

pub fn reset_target(system_id: &str) -> String {
    format!(
        "{}/Actions/ComputerSystem.Reset",
        resource(system_id).odata_id
    )
}

pub fn add_routes(r: Router<BmcState>, bmc_vendor: redfish::oem::BmcVendor) -> Router<BmcState> {
    const SYSTEM_ID: &str = "{system_id}";
    const ETH_ID: &str = "{eth_id}";
    const BOOT_OPTION_ID: &str = "{boot_option_id}";
    const LOG_SERVICE_ID: &str = "{log_service_id}";
    let bios = redfish::bios::resource(SYSTEM_ID);
    r.route(&collection().odata_id, get(get_system_collection))
        .route(
            &resource(SYSTEM_ID).odata_id,
            get(get_system).patch(patch_system),
        )
        .route(&reset_target(SYSTEM_ID), post(post_reset_system))
        .route(
            &bmc_vendor.make_settings_odata_id(&resource(SYSTEM_ID)),
            patch(patch_settings),
        )
        .route(
            &redfish::ethernet_interface::system_resource(SYSTEM_ID, ETH_ID).odata_id,
            get(get_ethernet_interface),
        )
        .route(
            &redfish::ethernet_interface::system_collection(SYSTEM_ID).odata_id,
            get(get_ethernet_interface_collection),
        )
        .route(
            &redfish::secure_boot::resource(SYSTEM_ID).odata_id,
            get(get_secure_boot).patch(patch_secure_boot),
        )
        .route(
            &redfish::boot_option::collection(SYSTEM_ID).odata_id,
            get(get_boot_options_collection),
        )
        .route(
            &redfish::boot_option::resource(SYSTEM_ID, BOOT_OPTION_ID).odata_id,
            get(get_boot_option),
        )
        .route(&bios.odata_id, get(get_bios))
        .route(
            &redfish::log_service::system_collection(SYSTEM_ID).odata_id,
            get(get_log_services_collection),
        )
        .route(
            &redfish::log_service::system_resource(SYSTEM_ID, LOG_SERVICE_ID).odata_id,
            get(get_log_service),
        )
        .route(
            &redfish::log_service::system_entries_collection(SYSTEM_ID, LOG_SERVICE_ID).odata_id,
            get(get_log_service_entries),
        )
        .route(
            &bmc_vendor.make_settings_odata_id(&bios),
            patch(patch_bios_settings),
        )
        .route(
            &redfish::bios::change_password_target(&bios),
            post(change_bios_password_action),
        )
}

pub struct SingleSystemConfig {
    pub id: Cow<'static, str>,
    pub eth_interfaces: Option<Vec<redfish::ethernet_interface::EthernetInterface>>,
    pub serial_number: Option<Cow<'static, str>>,
    pub manufacturer: Option<Cow<'static, str>>,
    pub model: Option<Cow<'static, str>>,
    pub boot_order_mode: BootOrderMode,
    pub power_control: Option<Arc<dyn PowerControl>>,
    pub chassis: Vec<Cow<'static, str>>,
    pub boot_options: Option<Vec<redfish::boot_option::BootOption>>,
    pub bios_mode: BiosMode,
    pub base_bios: Option<serde_json::Value>,
    pub log_services: Option<Arc<dyn LogServices>>,
    pub oem: Oem,
}

pub struct Config {
    pub systems: Vec<SingleSystemConfig>,
}

pub struct SystemState {
    systems: Vec<SingleSystemState>,
}

pub struct SingleSystemState {
    config: SingleSystemConfig,
    boot_order_override: Mutex<Option<Vec<String>>>,
    secure_boot_enabled: Arc<AtomicBool>,
    bios_overrides: Arc<Mutex<serde_json::Value>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootOrderMode {
    DellOem,
    Generic,
    ViaSettings, // Set boot order using /Settings resource
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BiosMode {
    DellOem,
    Generic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Oem {
    NvidiaBluefield,
    Generic,
}

impl SystemState {
    pub fn from_config(config: Config) -> Self {
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
            secure_boot_enabled: Arc::new(AtomicBool::new(false)),
            bios_overrides: Arc::new(Mutex::new(serde_json::json!({}))),
        }
    }

    pub fn find_boot_option(&self, option_id: &str) -> Option<&redfish::boot_option::BootOption> {
        self.config
            .boot_options
            .iter()
            .flatten()
            .find(|v| v.id == option_id)
    }

    fn set_boot_order_override(&self, boot_order: Vec<String>) {
        *self.boot_order_override.lock().unwrap() = Some(boot_order);
    }

    fn boot_order_override(&self) -> Option<Vec<String>> {
        self.boot_order_override.lock().unwrap().clone()
    }
}

async fn get_system_collection(State(state): State<BmcState>) -> Response {
    let members = state
        .system_state
        .systems()
        .iter()
        .map(|system| resource(&system.config.id).entity_ref())
        .collect::<Vec<_>>();
    collection().with_members(&members).into_ok_response()
}

async fn get_system(State(state): State<BmcState>, Path(system_id): Path<String>) -> Response {
    let Some(system_state) = state.system_state.find(&system_id) else {
        return http::not_found();
    };

    let mut b = builder(&resource(&system_id))
        .ethernet_interfaces(redfish::ethernet_interface::system_collection(&system_id))
        .boot_options(&redfish::boot_option::collection(&system_id))
        .bios(&redfish::bios::resource(&system_id))
        .secure_boot(&redfish::secure_boot::resource(&system_id))
        .link_chassis(&system_state.config.chassis);

    let config = &system_state.config;

    if let Some(state) = config
        .power_control
        .as_ref()
        .map(|control| control.get_power_state())
    {
        b = b.power_state(state)
    }

    if let Some(boot_order) = system_state.boot_order_override() {
        b = b.boot_order(&boot_order.iter().map(String::as_str).collect::<Vec<_>>());
    } else {
        b = b.boot_order(
            &config
                .boot_options
                .iter()
                .flatten()
                .map(|v| v.id.as_ref())
                .collect::<Vec<_>>(),
        );
    }

    b = match config.oem {
        Oem::Generic => b,
        Oem::NvidiaBluefield => b.oem_nvidia(&redfish::oem::nvidia::bluefield::resource()),
    };

    let pcie_devices = config
        .chassis
        .iter()
        .flat_map(|chassis_id| state.chassis_state.find(chassis_id))
        .flat_map(|chassis| chassis.pcie_devices_resources().into_iter())
        .collect::<Vec<_>>();

    let log_services = config
        .log_services
        .is_some()
        .then_some(redfish::log_service::system_collection(&system_id));

    b.maybe_with(SystemBuilder::serial_number, &config.serial_number)
        .maybe_with(SystemBuilder::manufacturer, &config.manufacturer)
        .maybe_with(SystemBuilder::model, &config.model)
        .maybe_with(SystemBuilder::log_services, &log_services)
        .pcie_devices(&pcie_devices)
        .build()
        .into_ok_response()
}

async fn get_ethernet_interface(
    State(state): State<BmcState>,
    Path((system_id, interface_id)): Path<(String, String)>,
) -> Response {
    let Some(system_state) = state.system_state.find(&system_id) else {
        return http::not_found();
    };
    system_state
        .config
        .eth_interfaces
        .iter()
        .flatten()
        .find(|eth| eth.id == interface_id)
        .map(|eth| eth.to_json().into_ok_response())
        .unwrap_or_else(http::not_found)
}

async fn get_ethernet_interface_collection(
    State(state): State<BmcState>,
    Path(system_id): Path<String>,
) -> Response {
    let Some(system_state) = state.system_state.find(&system_id) else {
        return http::not_found();
    };
    let members = system_state
        .config
        .eth_interfaces
        .iter()
        .flatten()
        .map(|eth| redfish::ethernet_interface::system_resource(&system_id, &eth.id).entity_ref())
        .collect::<Vec<_>>();
    redfish::ethernet_interface::system_collection(&system_id)
        .with_members(&members)
        .into_ok_response()
}

async fn patch_settings(
    State(state): State<BmcState>,
    Path(system_id): Path<String>,
    Json(patch_settings): Json<serde_json::Value>,
) -> Response {
    let Some(system_state) = state.system_state.find(&system_id) else {
        return http::not_found();
    };
    if let Some(new_boot_order) = patch_settings
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
        match system_state.config.boot_order_mode {
            BootOrderMode::ViaSettings => {
                system_state.set_boot_order_override(new_boot_order);
                json!({}).into_ok_response()
            }
            _ => json!("Boot order setup must use ComputerSystem resource")
                .into_response(StatusCode::BAD_REQUEST),
        }
    } else {
        json!({}).into_ok_response()
    }
}

async fn patch_system(
    State(state): State<BmcState>,
    Path(system_id): Path<String>,
    Json(patch_system): Json<serde_json::Value>,
) -> Response {
    let Some(system_state) = state.system_state.find(&system_id) else {
        return http::not_found();
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
        match system_state.config.boot_order_mode {
            BootOrderMode::DellOem => {
                system_state.set_boot_order_override(new_boot_order);
                redfish::oem::dell::idrac::create_job_with_location(state)
            }
            BootOrderMode::ViaSettings => json!("Boot order setup must use Settings resource")
                .into_response(StatusCode::BAD_REQUEST),
            BootOrderMode::Generic => {
                system_state.set_boot_order_override(new_boot_order);
                json!({}).into_ok_response()
            }
        }
    } else {
        json!({}).into_ok_response()
    }
}

async fn post_reset_system(
    State(state): State<BmcState>,
    Path(system_id): Path<String>,
    Json(mut power_request): Json<serde_json::Value>,
) -> Response {
    state.complete_all_bios_jobs();

    let Some(system_state) = state.system_state.find(&system_id) else {
        return http::not_found();
    };
    let Some(power_control) = system_state.config.power_control.as_ref() else {
        return http::not_found();
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
    match power_control.set_power_state(reset_type) {
        Ok(_) => json!({}).into_ok_response(),
        Err(SetSystemPowerError::BadRequest(_)) => StatusCode::BAD_REQUEST.into_response(),
        Err(SetSystemPowerError::CommandSendError(_)) => {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn get_secure_boot(State(state): State<BmcState>, Path(system_id): Path<String>) -> Response {
    let Some(system_state) = state.system_state.find(&system_id) else {
        return http::not_found();
    };
    let secure_boot_enabled = system_state.secure_boot_enabled.load(Ordering::Relaxed);
    redfish::secure_boot::builder(&redfish::secure_boot::resource(&system_id))
        .secure_boot_enable(secure_boot_enabled)
        .secure_boot_current_boot(secure_boot_enabled)
        .build()
        .into_ok_response()
}

async fn patch_secure_boot(
    State(state): State<BmcState>,
    Path(system_id): Path<String>,
    Json(secure_boot_request): Json<serde_json::Value>,
) -> Response {
    let Some(system_state) = state.system_state.find(&system_id) else {
        return http::not_found();
    };
    if let Some(v) = secure_boot_request
        .get("SecureBootEnable")
        .and_then(serde_json::Value::as_bool)
    {
        system_state.secure_boot_enabled.store(v, Ordering::Relaxed);
    }
    json!({}).into_ok_response()
}

async fn get_boot_options_collection(
    State(state): State<BmcState>,
    Path(system_id): Path<String>,
) -> Response {
    let Some(system_state) = state.system_state.find(&system_id) else {
        return http::not_found();
    };
    let Some(boot_options) = &system_state.config.boot_options else {
        return http::not_found();
    };
    let boot_options_order = match system_state.config.boot_order_mode {
        BootOrderMode::DellOem => {
            // Carbide relies that Dell sorts boot options in according to boot
            // order. Code below simulates the same.
            if let Some(boot_order) = system_state.boot_order_override() {
                let mut indices = (0..boot_options.len()).collect::<Vec<_>>();
                indices.sort_by_key(|&i| {
                    boot_order
                        .iter()
                        .enumerate()
                        .find(|(_, id)| *id == &boot_options[i].id)
                        .map(|(idx, _)| idx)
                        .unwrap_or(boot_options.len())
                });
                indices
            } else {
                (0..boot_options.len()).collect::<Vec<_>>()
            }
        }
        BootOrderMode::Generic | BootOrderMode::ViaSettings => (0..boot_options.len()).collect(),
    };
    let members = boot_options_order
        .into_iter()
        .map(|idx| redfish::boot_option::resource(&system_id, &boot_options[idx].id).entity_ref())
        .collect::<Vec<_>>();
    redfish::boot_option::collection(&system_id)
        .with_members(&members)
        .into_ok_response()
}

async fn get_boot_option(
    State(state): State<BmcState>,
    Path((system_id, boot_option_id)): Path<(String, String)>,
) -> Response {
    state
        .system_state
        .find(&system_id)
        .and_then(|system_state| system_state.find_boot_option(&boot_option_id))
        .map(|boot_option| boot_option.to_json().into_ok_response())
        .unwrap_or_else(http::not_found)
}

async fn get_log_services_collection(
    State(state): State<BmcState>,
    Path(system_id): Path<String>,
) -> Response {
    state
        .system_state
        .find(&system_id)
        .and_then(|system_state| system_state.config.log_services.as_ref())
        .map(|log_services| {
            let members = log_services
                .services()
                .into_iter()
                .map(|service| {
                    redfish::log_service::system_resource(&system_id, service.id()).entity_ref()
                })
                .collect::<Vec<_>>();
            redfish::boot_option::collection(&system_id)
                .with_members(&members)
                .into_ok_response()
        })
        .unwrap_or_else(http::not_found)
}

async fn get_log_service(
    State(state): State<BmcState>,
    Path((system_id, log_service_id)): Path<(String, String)>,
) -> Response {
    state
        .system_state
        .find(&system_id)
        .and_then(|system_state| system_state.config.log_services.as_ref())
        .and_then(|log_services| log_services.find(&log_service_id))
        .map(|_log_service| {
            redfish::log_service::builder(&redfish::log_service::system_resource(
                &system_id,
                &log_service_id,
            ))
            .entries(&redfish::log_service::system_entries_collection(
                &system_id,
                &log_service_id,
            ))
            .build()
            .into_ok_response()
        })
        .unwrap_or_else(http::not_found)
}

async fn get_log_service_entries(
    State(state): State<BmcState>,
    Path((system_id, log_service_id)): Path<(String, String)>,
) -> Response {
    state
        .system_state
        .find(&system_id)
        .and_then(|system_state| system_state.config.log_services.as_ref())
        .and_then(|log_services| log_services.find(&log_service_id))
        .map(|log_service| {
            let collection =
                redfish::log_service::system_entries_collection(&system_id, &log_service_id);
            let members = log_service.entries(&collection);
            collection
                .with_members(&members)
                .patch(json!({"Description": "Log services collection"})) // Required by libredfish
                .into_ok_response()
        })
        .unwrap_or_else(http::not_found)
}

async fn get_bios(State(state): State<BmcState>, Path(system_id): Path<String>) -> Response {
    state
        .system_state
        .find(&system_id)
        .and_then(|system_state| {
            system_state.config.base_bios.as_ref().map(|base_bios| {
                let overrides = system_state
                    .bios_overrides
                    .lock()
                    .expect("mutex is poisoned");
                base_bios
                    .clone()
                    .patch(overrides.clone())
                    .into_ok_response()
            })
        })
        .unwrap_or_else(http::not_found)
}

async fn patch_bios_settings(
    State(state): State<BmcState>,
    Path(system_id): Path<String>,
    Json(patch_bios_request): Json<serde_json::Value>,
) -> Response {
    let Some(system_state) = state.system_state.find(&system_id) else {
        return http::not_found();
    };
    match system_state.config.bios_mode {
        BiosMode::DellOem => {
            // Clear is transformed to Enabled state after reboot. Check if we
            // need to apply this logic here.
            const TPM2_HIERARCHY: &str = "Tpm2Hierarchy";
            const ATTRIBUTES: &str = "Attributes";
            let tpm2_clear_to_enabled = patch_bios_request
                .as_object()
                .and_then(|obj| obj.get(ATTRIBUTES))
                .and_then(|v| v.as_object())
                .and_then(|obj| obj.get(TPM2_HIERARCHY))
                .and_then(|v| v.as_str())
                .is_some_and(|v| v == "Clear");
            let patch_bios_request = if tpm2_clear_to_enabled {
                patch_bios_request.patch(json!({ATTRIBUTES: {
                    TPM2_HIERARCHY: "Enabled"
                }}))
            } else {
                patch_bios_request
            };
            json_patch(
                &mut system_state.bios_overrides.lock().expect("mutex poisoned"),
                patch_bios_request,
            );
            redfish::oem::dell::idrac::create_job_with_location(state)
        }
        BiosMode::Generic => {
            json_patch(
                &mut system_state.bios_overrides.lock().expect("mutex poisoned"),
                patch_bios_request,
            );
            json!({}).into_ok_response()
        }
    }
}

async fn change_bios_password_action(Path(_system_id): Path<String>) -> Response {
    json!({}).into_ok_response()
}

pub fn builder(resource: &redfish::Resource) -> SystemBuilder {
    SystemBuilder {
        value: resource.json_patch(),
    }
}

pub struct SystemBuilder {
    value: serde_json::Value,
}

impl Builder for SystemBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
        }
    }
}

impl SystemBuilder {
    pub fn serial_number(self, v: &str) -> Self {
        self.add_str_field("SerialNumber", v)
    }

    pub fn manufacturer(self, v: &str) -> Self {
        self.add_str_field("Manufacturer", v)
    }

    pub fn model(self, v: &str) -> Self {
        self.add_str_field("Model", v)
    }

    pub fn ethernet_interfaces(self, v: redfish::Collection<'_>) -> Self {
        self.apply_patch(v.nav_property("EthernetInterfaces"))
    }

    pub fn boot_order(self, boot_order: &[&str]) -> Self {
        self.apply_patch(json!({"Boot": {"BootOrder": boot_order}}))
    }

    pub fn boot_options(self, boot_options: &redfish::Collection<'_>) -> Self {
        self.apply_patch(json!({"Boot": boot_options.nav_property("BootOptions")}))
    }

    pub fn secure_boot(self, secure_boot: &redfish::Resource<'_>) -> Self {
        self.apply_patch(secure_boot.nav_property("SecureBoot"))
    }

    pub fn pcie_devices(self, devices: &[redfish::Resource<'_>]) -> Self {
        let devices = devices.iter().map(|r| r.entity_ref()).collect::<Vec<_>>();
        self.apply_patch(json!({"PCIeDevices": devices}))
    }

    pub fn bios(self, resource: &redfish::Resource<'_>) -> Self {
        self.apply_patch(resource.nav_property("Bios"))
    }

    pub fn power_state(self, state: MockPowerState) -> Self {
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
        self.add_str_field("PowerState", power_state)
    }

    pub fn log_services(self, log_services: &redfish::Collection<'_>) -> Self {
        self.apply_patch(log_services.nav_property("LogServices"))
    }

    pub fn link_chassis(self, ids: &[Cow<'static, str>]) -> Self {
        let chassis = ids
            .iter()
            .map(|id| redfish::chassis::resource(id).entity_ref())
            .collect::<Vec<_>>();
        self.apply_patch(json!({"Links": {"Chassis": chassis}}))
    }

    pub fn oem_nvidia(self, resource: &redfish::Resource<'_>) -> Self {
        self.apply_patch(json!({"Oem": {"Nvidia": resource.entity_ref()}}))
    }

    pub fn build(self) -> serde_json::Value {
        self.value
    }
}
