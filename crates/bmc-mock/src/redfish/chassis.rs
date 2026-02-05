/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::get;
use serde_json::json;

use crate::bmc_state::BmcState;
use crate::json::{JsonExt, JsonPatch};
use crate::{http, redfish};

pub fn resource<'a>(chassis_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("{}/{chassis_id}", collection().odata_id);
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#Chassis.v1_23_0.Chassis"),
        id: Cow::Borrowed(chassis_id),
        name: Cow::Borrowed("Chassis"),
    }
}

pub fn collection() -> redfish::Collection<'static> {
    redfish::Collection {
        odata_id: Cow::Borrowed("/redfish/v1/Chassis"),
        odata_type: Cow::Borrowed("#ChassisCollection.ChassisCollection"),
        name: Cow::Borrowed("Chassis Collection"),
    }
}

pub fn builder(resource: &redfish::Resource) -> ChassisBuilder {
    ChassisBuilder {
        value: resource.json_patch(),
    }
}

pub fn add_routes(r: Router<BmcState>) -> Router<BmcState> {
    const CHASSIS_ID: &str = "{chassis_id}";
    const NET_ADAPTER_ID: &str = "{network_adapter_id}";
    const NET_FUNC_ID: &str = "{function_id}";
    const PCIE_DEVICE_ID: &str = "{pcie_device_id}";
    r.route(&collection().odata_id, get(get_chassis_collection))
        .route(&resource(CHASSIS_ID).odata_id, get(get_chassis))
        .route(
            &redfish::network_adapter::chassis_collection(CHASSIS_ID).odata_id,
            get(get_chassis_network_adapters),
        )
        .route(
            &redfish::network_adapter::chassis_resource(CHASSIS_ID, NET_ADAPTER_ID).odata_id,
            get(get_chassis_network_adapter),
        )
        .route(
            &redfish::network_device_function::chassis_collection(CHASSIS_ID, NET_ADAPTER_ID)
                .odata_id,
            get(get_chassis_network_adapters_network_device_functions_list),
        )
        .route(
            &redfish::network_device_function::chassis_resource(
                CHASSIS_ID,
                NET_ADAPTER_ID,
                NET_FUNC_ID,
            )
            .odata_id,
            get(get_chassis_network_adapters_network_device_function),
        )
        .route(
            &redfish::pcie_device::chassis_collection(CHASSIS_ID).odata_id,
            get(get_chassis_pcie_devices),
        )
        .route(
            &redfish::pcie_device::chassis_resource(CHASSIS_ID, PCIE_DEVICE_ID).odata_id,
            get(get_pcie_device),
        )
}

pub struct SingleChassisConfig {
    pub id: Cow<'static, str>,
    pub serial_number: Option<Cow<'static, str>>,
    pub manufacturer: Option<Cow<'static, str>>,
    pub model: Option<Cow<'static, str>>,
    pub part_number: Option<Cow<'static, str>>,
    pub network_adapters: Option<Vec<redfish::network_adapter::NetworkAdapter>>,
    pub pcie_devices: Option<Vec<redfish::pcie_device::PCIeDevice>>,
}

pub struct ChassisConfig {
    pub chassis: Vec<SingleChassisConfig>,
}

pub struct ChassisState {
    chassis: Vec<SingleChassisState>,
}

impl ChassisState {
    pub fn from_config(config: ChassisConfig) -> Self {
        let chassis = config
            .chassis
            .into_iter()
            .map(SingleChassisState::new)
            .collect();
        Self { chassis }
    }

    pub fn find(&self, chassis_id: &str) -> Option<&SingleChassisState> {
        self.chassis
            .iter()
            .find(|c| c.config.id.as_ref() == chassis_id)
    }
}

pub struct SingleChassisState {
    pub config: SingleChassisConfig,
}

impl SingleChassisState {
    fn new(config: SingleChassisConfig) -> Self {
        Self { config }
    }

    pub fn pcie_devices_resources(&self) -> Vec<redfish::Resource<'static>> {
        self.config
            .pcie_devices
            .iter()
            .flat_map(|v| v.iter())
            .map(|dev| redfish::pcie_device::chassis_resource(&self.config.id, &dev.id))
            .collect::<Vec<_>>()
    }

    fn find_network_adapter(&self, id: &str) -> Option<&redfish::network_adapter::NetworkAdapter> {
        self.config
            .network_adapters
            .as_ref()
            .and_then(|adapters| adapters.iter().find(|na| na.id == id))
    }

    fn find_pcie_device(&self, id: &str) -> Option<&redfish::pcie_device::PCIeDevice> {
        self.config
            .pcie_devices
            .as_ref()
            .and_then(|devs| devs.iter().find(|v| v.id == id))
    }
}

async fn get_chassis_collection(State(state): State<BmcState>) -> Response {
    let members = state
        .chassis_state
        .chassis
        .iter()
        .map(|chassis| resource(&chassis.config.id).entity_ref())
        .collect::<Vec<_>>();
    collection().with_members(&members).into_ok_response()
}

async fn get_chassis(State(state): State<BmcState>, Path(chassis_id): Path<String>) -> Response {
    let Some(chassis_state) = state.chassis_state.find(&chassis_id) else {
        return http::not_found();
    };
    let config = &chassis_state.config;
    let b = builder(&resource(&chassis_id));
    let b = if config.pcie_devices.is_some() {
        b.pcie_devices(redfish::pcie_device::chassis_collection(&chassis_id))
    } else {
        b
    };
    let b = if config.network_adapters.is_some() {
        b.network_adapters(redfish::network_adapter::chassis_collection(&chassis_id))
    } else {
        b
    };
    b.maybe_with(ChassisBuilder::serial_number, &config.serial_number)
        .maybe_with(ChassisBuilder::manufacturer, &config.manufacturer)
        .maybe_with(ChassisBuilder::part_number, &config.part_number)
        .maybe_with(ChassisBuilder::model, &config.model)
        .build()
        .into_ok_response()
}

async fn get_chassis_network_adapters(
    State(state): State<BmcState>,
    Path(chassis_id): Path<String>,
) -> Response {
    state
        .chassis_state
        .find(&chassis_id)
        .and_then(|chassis_state| chassis_state.config.network_adapters.as_ref())
        .map(|network_adapters| {
            network_adapters
                .iter()
                .map(|na| {
                    redfish::network_adapter::chassis_resource(&chassis_id, &na.id).entity_ref()
                })
                .collect::<Vec<_>>()
        })
        .map(|members| {
            redfish::network_adapter::chassis_collection(&chassis_id)
                .with_members(&members)
                .into_ok_response()
        })
        .unwrap_or_else(http::not_found)
}

async fn get_chassis_network_adapter(
    State(state): State<BmcState>,
    Path((chassis_id, network_adapter_id)): Path<(String, String)>,
) -> Response {
    let Some(chassis_state) = state.chassis_state.find(&chassis_id) else {
        return http::not_found();
    };
    if let Some(helper) = state.injected_bugs.all_dpu_lost_on_host() {
        return helper
            .network_adapter(&chassis_id, &network_adapter_id)
            .into_ok_response();
    }
    chassis_state
        .find_network_adapter(&network_adapter_id)
        .map(|eth| eth.to_json().into_ok_response())
        .unwrap_or_else(http::not_found)
}

async fn get_chassis_network_adapters_network_device_functions_list(
    State(state): State<BmcState>,
    Path((chassis_id, network_adapter_id)): Path<(String, String)>,
) -> Response {
    state
        .chassis_state
        .find(&chassis_id)
        .and_then(|chassis_state| chassis_state.find_network_adapter(&network_adapter_id))
        .map(|network_adapter| {
            let members = network_adapter
                .functions
                .iter()
                .map(|f| {
                    redfish::network_device_function::chassis_resource(
                        &chassis_id,
                        &network_adapter_id,
                        &f.id,
                    )
                    .entity_ref()
                })
                .collect::<Vec<_>>();
            redfish::network_device_function::chassis_collection(&chassis_id, &network_adapter_id)
                .with_members(&members)
                .into_ok_response()
        })
        .unwrap_or_else(http::not_found)
}

async fn get_chassis_network_adapters_network_device_function(
    State(state): State<BmcState>,
    Path((chassis_id, network_adapter_id, function_id)): Path<(String, String, String)>,
) -> Response {
    state
        .chassis_state
        .find(&chassis_id)
        .and_then(|chassis_state| chassis_state.find_network_adapter(&network_adapter_id))
        .and_then(|network_adapter| network_adapter.find_function(&function_id))
        .map(|function| function.to_json().into_ok_response())
        .unwrap_or_else(http::not_found)
}

async fn get_pcie_device(
    State(state): State<BmcState>,
    Path((chassis_id, pcie_device_id)): Path<(String, String)>,
) -> Response {
    state
        .chassis_state
        .find(&chassis_id)
        .and_then(|chassis_state| chassis_state.find_pcie_device(&pcie_device_id))
        .map(|pcie_device| {
            if pcie_device.is_mat_dpu && state.injected_bugs.all_dpu_lost_on_host().is_some() {
                json!("All DPU lost bug injected").into_response(StatusCode::NOT_FOUND)
            } else {
                pcie_device.to_json().into_ok_response()
            }
        })
        .unwrap_or_else(http::not_found)
}

async fn get_chassis_pcie_devices(
    State(state): State<BmcState>,
    Path(chassis_id): Path<String>,
) -> Response {
    state
        .chassis_state
        .find(&chassis_id)
        .and_then(|chassis_state| chassis_state.config.pcie_devices.as_ref())
        .map(|pcie_devices| {
            pcie_devices
                .iter()
                .map(|v| redfish::pcie_device::chassis_resource(&chassis_id, &v.id).entity_ref())
                .collect::<Vec<_>>()
        })
        .map(|members| {
            redfish::pcie_device::chassis_collection(&chassis_id)
                .with_members(&members)
                .into_ok_response()
        })
        .unwrap_or_else(http::not_found)
}

pub struct ChassisBuilder {
    value: serde_json::Value,
}

impl ChassisBuilder {
    pub fn maybe_with<T, V>(self, f: fn(Self, &V) -> Self, v: &Option<T>) -> Self
    where
        T: AsRef<V>,
        V: ?Sized,
    {
        if let Some(v) = v {
            f(self, v.as_ref())
        } else {
            self
        }
    }

    pub fn serial_number(self, v: &str) -> Self {
        self.add_str_field("SerialNumber", v)
    }

    pub fn manufacturer(self, v: &str) -> Self {
        self.add_str_field("Manufacturer", v)
    }

    pub fn part_number(self, v: &str) -> Self {
        self.add_str_field("PartNumber", v)
    }

    pub fn model(self, v: &str) -> Self {
        self.add_str_field("Model", v)
    }

    pub fn network_adapters(self, v: redfish::Collection<'_>) -> Self {
        self.apply_patch(v.nav_property("NetworkAdapters"))
    }

    pub fn pcie_devices(self, v: redfish::Collection<'_>) -> Self {
        self.apply_patch(v.nav_property("PCIeDevices"))
    }

    pub fn build(self) -> serde_json::Value {
        self.value
    }

    fn add_str_field(self, name: &str, value: &str) -> Self {
        self.apply_patch(json!({ name: value }))
    }

    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
        }
    }
}
