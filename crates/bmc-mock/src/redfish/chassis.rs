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

use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

use crate::json::JsonExt;
use crate::mock_machine_router::MockWrapperState;
use crate::{MachineInfo, redfish};

pub fn add_routes(r: Router<MockWrapperState>) -> Router<MockWrapperState> {
    const CHASSIS_ID: &str = "{chassis_id}";
    const NET_ADAPTER_ID: &str = "{network_adapter_id}";
    const NET_FUNC_ID: &str = "{function_id}";
    const PCIE_DEVICE_ID: &str = "{pcie_device_id}";
    r.route("/redfish/v1/Chassis/{chassis_id}", get(get_chassis))
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

const MAT_DPU_PCIE_DEVICE_PREFIX: &str = "mat_dpu";

pub fn gen_dpu_pcie_device_resource(chassis_id: &str, index: usize) -> redfish::Resource<'static> {
    let device_id = format!("{MAT_DPU_PCIE_DEVICE_PREFIX}_{index}");
    redfish::pcie_device::chassis_resource(chassis_id, &device_id)
}

async fn get_chassis(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> Response {
    state
        .call_inner_router(request)
        .await
        .map(|body| {
            body.patch(json!({"SerialNumber": state.machine_info.chassis_serial()}))
                .into_ok_response()
        })
        .unwrap_or_else(|err| err.into_response())
}

async fn get_chassis_network_adapters(
    State(mut state): State<MockWrapperState>,
    Path(chassis_id): Path<String>,
    request: Request<Body>,
) -> Response {
    if chassis_id != "System.Embedded.1" {
        return state.proxy_inner(request).await;
    }
    let MachineInfo::Host(host) = state.machine_info else {
        return state.proxy_inner(request).await;
    };

    // Add stock adapters, embedded and integrated
    let mut members = vec![
        redfish::network_adapter::chassis_resource(&chassis_id, "NIC.Embedded.1").entity_ref(),
        redfish::network_adapter::chassis_resource(&chassis_id, "NIC.Integrated.1").entity_ref(),
    ];

    // Add a network adapter for every DPU, or if there are no DPUs, mock a single non-DPU NIC.
    let count = if host.dpus.is_empty() {
        1
    } else {
        host.dpus.len()
    };
    for index in 1..=count {
        members.push(
            redfish::network_adapter::chassis_resource(&chassis_id, &format!("NIC.Slot.{}", index))
                .entity_ref(),
        )
    }

    redfish::network_adapter::chassis_collection(&chassis_id)
        .with_members(&members)
        .into_ok_response()
}

async fn get_chassis_network_adapter(
    State(mut state): State<MockWrapperState>,
    Path((chassis_id, network_adapter_id)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let MachineInfo::Host(host) = &state.machine_info else {
        return state.proxy_inner(request).await;
    };

    if !network_adapter_id.starts_with("NIC.Slot.") {
        return state.proxy_inner(request).await;
    }

    if host.dpus.is_empty() {
        let Some(mac) = host.non_dpu_mac_address else {
            tracing::error!(
                "Request for NIC ID {}, but machine has no NICs (zero DPUs and no non_dpu_mac_address set.) This is a bug.",
                network_adapter_id
            );
            return state.proxy_inner(request).await;
        };
        let serial = mac.to_string().replace(':', "");

        // Build a non-DPU NetworkAdapter
        let resource = redfish::network_adapter::chassis_resource(&chassis_id, &network_adapter_id);
        redfish::network_adapter::builder(&resource)
            .manufacturer("Rooftop Technologies")
            .model("Rooftop 10 Kilobit Ethernet Adapter")
            .part_number("31337")
            .serial_number(&serial)
            .status(redfish::resource::Status::Ok)
            .build()
            .into_ok_response()
    } else {
        let Some(dpu) = state.find_dpu(&network_adapter_id) else {
            return state.proxy_inner(request).await;
        };

        if let Some(helper) = state.bmc_state.injected_bugs.all_dpu_lost_on_host() {
            return helper
                .network_adapter(&chassis_id, &network_adapter_id)
                .into_ok_response();
        }

        // Build a NetworkAdapter from our mock DPU info (mainly just the serial number)
        let resource = redfish::network_adapter::chassis_resource(&chassis_id, &network_adapter_id);
        redfish::network_adapter::builder(&resource)
            .manufacturer("Mellanox Technologies")
            .model("BlueField-2 SmartNIC Main Card")
            .part_number("MBF2H5")
            .serial_number(&dpu.serial)
            .network_device_functions(&redfish::network_device_function::chassis_collection(
                &chassis_id,
                &network_adapter_id,
            ))
            .status(redfish::resource::Status::Ok)
            .build()
            .into_ok_response()
    }
}

async fn get_chassis_network_adapters_network_device_functions_list(
    State(mut state): State<MockWrapperState>,
    Path((chassis_id, network_adapter_id)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let Some(_dpu) = state.find_dpu(&network_adapter_id) else {
        return state.proxy_inner(request).await;
    };

    let function_id = format!("{network_adapter_id}-1");
    let resource = redfish::network_device_function::chassis_resource(
        &chassis_id,
        &network_adapter_id,
        &function_id,
    );
    redfish::network_device_function::chassis_collection(&chassis_id, &network_adapter_id)
        .with_members(std::slice::from_ref(&resource.entity_ref()))
        .into_ok_response()
}

async fn get_chassis_network_adapters_network_device_function(
    State(mut state): State<MockWrapperState>,
    Path((chassis_id, network_adapter_id, function_id)): Path<(String, String, String)>,
    request: Request<Body>,
) -> Response {
    let Some(dpu) = state.find_dpu(&network_adapter_id) else {
        return state.proxy_inner(request).await;
    };

    let resource = redfish::network_device_function::chassis_resource(
        &chassis_id,
        &network_adapter_id,
        &function_id,
    );
    redfish::network_device_function::builder(&resource)
        .ethernet(json!({
            "MACAddress": &dpu.host_mac_address,
        }))
        .oem(redfish::oem::dell::network_device_function::dpu_dell_nic_info(&function_id, &dpu))
        .build()
        .into_ok_response()
}

async fn get_pcie_device(
    State(mut state): State<MockWrapperState>,
    Path((chassis_id, pcie_device_id)): Path<(String, String)>,
    request: Request<Body>,
) -> Response {
    let MachineInfo::Host(host) = &state.machine_info else {
        return state.proxy_inner(request).await;
    };

    if !pcie_device_id.starts_with(MAT_DPU_PCIE_DEVICE_PREFIX) {
        return state.proxy_inner(request).await;
    }

    if state
        .bmc_state
        .injected_bugs
        .all_dpu_lost_on_host()
        .is_some()
    {
        return json!("All DPU lost bug injected").into_response(StatusCode::NOT_FOUND);
    }

    let Some(dpu_index) = pcie_device_id
        .chars()
        .last()
        .and_then(|c| c.to_digit(10))
        .map(|i| i as usize)
    else {
        tracing::error!("Invalid Pcie Device ID: {}", pcie_device_id);
        return state.proxy_inner(request).await;
    };

    let Some(dpu) = host.dpus.get(dpu_index - 1) else {
        tracing::error!(
            "Request for Pcie Device ID {}, which we don't have a DPU for (we have {} DPUs), not rewriting request",
            pcie_device_id,
            host.dpus.len()
        );
        return state.proxy_inner(request).await;
    };

    // Mock a BF3 for all mocked DPUs. Response modeled from a real Dell in dev (10.217.132.202)

    // Set the BF3 Part Number based on whether the DPU is supposed to be in NIC mode or not
    // Use a BF3 SuperNIC OPN if the DPU is supposed to be in NIC mode. Otherwise, use
    // a BF3 DPU OPN. Site explorer assumes that BF3 SuperNICs must be in NIC mode and that
    // BF3 DPUs must be in DPU mode. It will not ingest a host if any of the BF3 DPUs in the host
    // are in NIC mode or if any of the BF3 SuperNICs in the host are in DPU mode.
    // OPNs taken from: https://docs.nvidia.com/networking/display/bf3dpu
    let part_number = match dpu.nic_mode {
        true => "900-9D3B4-00CC-EA0",
        false => "900-9D3B6-00CV-AA0",
    };

    let resource = redfish::pcie_device::chassis_resource(&chassis_id, &pcie_device_id)
        .with_name("MT43244 BlueField-3 integrated ConnectX-7 network controller");

    redfish::pcie_device::builder(&resource)
        .description("MT43244 BlueField-3 integrated ConnectX-7 network controller")
        .firmware_version("32.41.1000")
        .manufacturer("Mellanox Technologies")
        .part_number(part_number)
        .serial_number(&dpu.serial)
        .status(redfish::resource::Status::Ok)
        .build()
        .into_ok_response()
}

async fn get_chassis_pcie_devices(
    State(mut state): State<MockWrapperState>,
    Path(chassis_id): Path<String>,
    request: Request<Body>,
) -> Response {
    let is_host_with_dpus = matches!(state.machine_info, MachineInfo::Host(_));
    let dpu_count = if let MachineInfo::Host(ref host) = state.machine_info {
        host.dpus.len()
    } else {
        0
    };

    if !is_host_with_dpus {
        return state.proxy_inner(request).await;
    }

    let mut collection = match state.call_inner_router(request).await {
        Ok(json) => json,
        Err(err) => return err.into_response(),
    };

    let mut members = Vec::new();
    if let Some(existing_members) = collection
        .get_mut("Members")
        .and_then(serde_json::Value::as_array_mut)
        .map(std::mem::take)
    {
        for member in existing_members {
            let Some(odata_id) = member["@odata.id"].as_str() else {
                continue;
            };
            let valid_entry = state
                .call_inner_router(
                    Request::builder()
                        .method(Method::GET)
                        .uri(odata_id)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .ok()
                .and_then(|mut pcie_dev| pcie_dev.get_mut("Manufacturer").map(std::mem::take))
                .is_some_and(|m| m.as_str().is_some_and(|v| v != "Mellanox Technologies"));

            // Keep all default PCIE devices. Just remove any of the DPU entries
            if valid_entry {
                members.push(member);
            }
        }
    }

    for index in 1..=dpu_count {
        members.push(gen_dpu_pcie_device_resource(&chassis_id, index).entity_ref());
    }

    redfish::pcie_device::chassis_collection(&chassis_id)
        .with_members(&members)
        .into_ok_response()
}
