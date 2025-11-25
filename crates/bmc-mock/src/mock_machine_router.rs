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
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use http_body_util::BodyExt;
use lazy_static::lazy_static;
use libredfish::model::software_inventory::SoftwareInventory;
use libredfish::model::{
    BootOption, ComputerSystem, ODataId, ResourceHealth, ResourceState, ResourceStatus,
};
use libredfish::{Chassis, NetworkAdapter, OData, PCIeDevice};
use mac_address::MacAddress;
use regex::{Captures, Regex};
use tokio::sync::{mpsc, oneshot};

use crate::bmc_state::BmcState;
use crate::{
    DpuMachineInfo, MachineInfo, MockPowerState, POWER_CYCLE_DELAY, PowerStateQuerying,
    SetSystemPowerReq, call_router_with_new_request, rf,
};

lazy_static! {
    static ref UEFI_DEVICE_PATH_MAC_ADDRESS_REGEX: Regex =
        Regex::new(r"(?<prefix>.*MAC\()(?<mac>[[:alnum:]]+)(?<suffix>,.*)$").unwrap();
}

const MAT_DPU_PCIE_DEVICE_PREFIX: &str = "mat_dpu";

#[derive(Debug, Clone)]
struct MockWrapperState {
    machine_info: MachineInfo,
    inner_router: Router,
    command_channel: Option<mpsc::UnboundedSender<BmcCommand>>,
    bmc_state: BmcState,
    mock_power_state: Arc<dyn PowerStateQuerying>,
}

#[derive(Debug)]
pub enum BmcCommand {
    SetSystemPower {
        request: SetSystemPowerReq,
        reply: Option<oneshot::Sender<SetSystemPowerResult>>,
    },
}

pub type SetSystemPowerResult = Result<(), SetSystemPowerError>;

#[derive(Debug, thiserror::Error)]
pub enum SetSystemPowerError {
    #[error("Mock BMC reported bad request when setting system power: {0}")]
    BadRequest(String),
}

/// Return an axum::Router that mocks various redfish calls to match the provided MachineInfo.
/// Any redfish calls not explicitly mocked will be delegated to inner_router (typically a tar_router.)
///
// TODO: This router is now more and more coupled to a particular tar_router (dell_poweredge_r750.tar.gz).
// At this point this module no longer can be said to wrap any old tar router, but instead only works with
// the Dell router. At the very least we may want to rename this module.
pub fn wrap_router_with_mock_machine(
    inner_router: Router,
    machine_info: MachineInfo,
    command_channel: Option<mpsc::UnboundedSender<BmcCommand>>,
    mock_power_state: Arc<dyn PowerStateQuerying>,
) -> Router {
    Router::new()
        .route(
            rf!("Managers/{manager_id}/EthernetInterfaces/{interface_id}"),
            get(get_managers_ethernet_interface),
        )
        .route(
            rf!("Systems/{system_id}/EthernetInterfaces/{nic}"),
            get(get_systems_ethernet_interface),
        )
        .route(rf!("Chassis/{chassis_id}"), get(get_chassis))
        .route(
            rf!("Chassis/{chassis_id}/NetworkAdapters"),
            get(get_chassis_network_adapters),
        )
        .route(
            rf!("Chassis/{chassis_id}/NetworkAdapters/{network_adapter_id}"),
            get(get_chassis_network_adapter),
        )
        .route(
            rf!("Chassis/{chassis_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions"),
            get(get_chassis_network_adapters_network_device_functions_list),
        )
        .route(
            rf!("Chassis/{chassis_id}/NetworkAdapters/{network_adapter_id}/NetworkDeviceFunctions/{function_id}"),
            get(get_chassis_network_adapters_network_device_function),
        )
        .route(
            rf!("Chassis/{chassis_id}/PCIeDevices"),
            get(get_chassis_pcie_devices),
        )
        .route(
            rf!("Chassis/{chassis_id}/PCIeDevices/{pcie_device_id}"),
            get(get_pcie_device),
        )
        .route(rf!("Systems/{system_id}"), get(get_system))
        .route(
            rf!("Systems/Bluefield/BootOptions/{boot_option_id}"),
            get(get_dpu_boot_options),
        )
        .route(
            rf!("UpdateService/FirmwareInventory/DPU_SYS_IMAGE"),
            get(get_dpu_sys_image),
        )
        .route(
            rf!("Systems/Bluefield/Bios"),
            get(get_dpu_bios),
        )
        .route(
            rf!("Systems/{system_id}/Actions/ComputerSystem.Reset"),
            post(post_reset_system),
        )
        .route(
            rf!("Systems/System.Embedded.1/Bios/Settings"),
            patch(patch_bios_settings),
        )
        .route(
            rf!("Systems/System.Embedded.1"),
        patch(patch_dell_system).get(get_dell_system),
        )
        .route(
            rf!("Systems/Bluefield/SecureBoot"),
            get(get_dpu_secure_boot),
        )
        .route(
            rf!("Systems/Bluefield/SecureBoot"),
            patch(patch_dpu_secure_boot),
        )
        .route(
            rf!("Systems/1/Bios/Actions/Bios.ChangePassword"),
            post(post_password_change),
        )
        .route(rf!("Managers/{manager_id}/Oem/Dell/DellJobService/Actions/DellJobService.DeleteJobQueue"),
               post(post_delete_job_queue),
        )
        .route(rf!("Systems/Bluefield/Settings"),
               patch(patch_dpu_settings).get(fallback_to_inner_router),
        )
        .route(rf!("Managers/iDRAC.Embedded.1/Jobs"),
               post(post_dell_create_bios_job),
        )
        .route(rf!("Managers/iDRAC.Embedded.1/Jobs/{job_id}"),get(get_dell_job),
        )
        .route(rf!("TaskService/Tasks/{task_id}"), get(get_task))
        .route(rf!("UpdateService/Actions/UpdateService.SimpleUpdate"), post(update_firmware_simple_update))
        .route(rf!("UpdateService/FirmwareInventory/BMC_Firmware"), get(get_dpu_bmc_firmware))
        .route(rf!("UpdateService/FirmwareInventory/Bluefield_FW_ERoT"), get(get_dpu_erot_firmware))
        .route(rf!("UpdateService/FirmwareInventory/DPU_UEFI"), get(get_dpu_uefi_firmware))
        .route(rf!("UpdateService/FirmwareInventory/DPU_NIC"), get(get_dpu_nic_firmware))
        .route(rf!("Systems/Bluefield/Oem/Nvidia"), get(get_oem_nvidia))
        .fallback(fallback_to_inner_router)
        .with_state(MockWrapperState {
            machine_info,
            command_channel,
            inner_router,
            mock_power_state,
            bmc_state: BmcState{
                jobs: Arc::new(Mutex::new(HashMap::new())),
                secure_boot_enabled: Arc::new(AtomicBool::new(false)),
            },
        })
}

impl MockWrapperState {
    /// See docs in `call_router_with_new_request`
    async fn call_inner_router(&mut self, request: Request<Body>) -> MockWrapperResult {
        let (method, uri) = (request.method().clone(), request.uri().clone());
        let response = call_router_with_new_request(&mut self.inner_router, request).await;
        let status = response.status();
        let response_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
        if !status.is_success() {
            return Err(MockWrapperError::InnerRequest(
                method,
                uri,
                status,
                String::from_utf8_lossy(&response_bytes).to_string(),
            ));
        }

        Ok(response_bytes)
    }

    /// Given an identifier like NIC.Slot.1, get the DPU corresponding to it
    fn find_dpu(&self, identifier: &str) -> Option<DpuMachineInfo> {
        let MachineInfo::Host(host) = &self.machine_info else {
            return None;
        };
        if !identifier.starts_with("NIC.Slot.") {
            return None;
        }
        let Some(dpu_index) = identifier
            .chars()
            .last()
            .and_then(|c| c.to_digit(10))
            .map(|i| i as usize)
        else {
            tracing::error!("Invalid NIC slot: {}", identifier);
            return None;
        };

        let Some(dpu) = host.dpus.get(dpu_index - 1) else {
            tracing::error!(
                "Request for NIC ID {}, which we don't have a DPU for (we have {} DPUs), not rewriting request",
                identifier,
                host.dpus.len()
            );
            return None;
        };

        Some(dpu.clone())
    }
}

type MockWrapperResult = Result<Bytes, MockWrapperError>;

#[derive(thiserror::Error, Debug)]
enum MockWrapperError {
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Axum error on inner request: {0}")]
    Axum(#[from] axum::Error),
    #[error("Infallible error: {0}")]
    Infallible(#[from] Infallible),
    #[error("Inner request {0} {1} failed with HTTP error {2}: {3}")]
    InnerRequest(Method, Uri, StatusCode, String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    SetSystemPower(#[from] SetSystemPowerError),
    #[error("Error sending to BMC command channel: {0}")]
    BmcCommandSendError(#[from] mpsc::error::SendError<BmcCommand>),
    #[error("Error receiving from BMC command channel: {0}")]
    BmcCommandReceiveError(#[from] oneshot::error::RecvError),
}

impl IntoResponse for MockWrapperError {
    fn into_response(self) -> axum::response::Response {
        // Don't log errors if the upstream request was the one that failed
        if !matches!(self, MockWrapperError::InnerRequest(_, _, _, _)) {
            tracing::error!("Mock machine router failure: {}", self.to_string());
        }

        match self {
            MockWrapperError::InnerRequest(_, _, status_code, body_bytes) => {
                // Use the error's status code instead of INTERNAL_SERVER_ERROR
                (status_code, body_bytes).into_response()
            }
            MockWrapperError::NotFound(reason) => (StatusCode::NOT_FOUND, reason).into_response(),
            MockWrapperError::SetSystemPower(e) => {
                (StatusCode::BAD_REQUEST, e.to_string()).into_response()
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response(),
        }
    }
}

// MARK: - axum Request handlers

async fn fallback_to_inner_router(
    mut state: State<MockWrapperState>,
    _path: Path<()>,
    request: Request<Body>,
) -> MockWrapperResult {
    state.call_inner_router(request).await
}

async fn get_managers_ethernet_interface(
    State(mut state): State<MockWrapperState>,
    Path((manager_id, _interface_id)): Path<(String, String)>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    let mut iface = serde_json::from_slice::<serde_json::Value>(&inner_response)?;
    match state.machine_info {
        MachineInfo::Dpu(dpu) => {
            if manager_id.eq("Bluefield_BMC") && redfish_resource_id(&iface) == Some("eth0") {
                json_patch(&mut iface, mac_address_patch(dpu.bmc_mac_address));
            }
        }
        MachineInfo::Host(host) => {
            json_patch(&mut iface, mac_address_patch(host.bmc_mac_address));
        }
    }
    Ok(Bytes::from(iface.to_string()))
}

async fn get_systems_ethernet_interface(
    State(mut state): State<MockWrapperState>,
    Path((system_id, _interface_id)): Path<(String, String)>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    let mut iface = serde_json::from_slice::<serde_json::Value>(&inner_response)?;

    match state.machine_info {
        MachineInfo::Dpu(dpu) => {
            if system_id.eq("Bluefield") {
                json_patch(&mut iface, mac_address_patch(dpu.host_mac_address));
            }
        }
        MachineInfo::Host(host) => {
            if let Some(m) = host.system_mac_address() {
                json_patch(&mut iface, mac_address_patch(m));
            }
        }
    }
    Ok(Bytes::from(iface.to_string()))
}

async fn get_chassis(
    State(mut state): State<MockWrapperState>,
    Path(_chassis_id): Path<String>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    let mut chassis = serde_json::from_slice::<Chassis>(&inner_response)?;
    chassis.serial_number = state.machine_info.chassis_serial();
    Ok(Bytes::from(serde_json::to_string(&chassis)?))
}

async fn get_chassis_network_adapters(
    State(mut state): State<MockWrapperState>,
    Path(chassis_id): Path<String>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    let MachineInfo::Host(host) = state.machine_info else {
        return Ok(inner_response);
    };
    let mut body: HashMap<String, serde_json::Value> = serde_json::from_slice(&inner_response)?;

    // Discard the "members" array from the upstream request, build our own.
    body.remove("Members");

    // Add stock adapters, embedded and integrated
    let mut members = Vec::<ODataId>::from(&[
        ODataId {
            odata_id: format!(
                "/redfish/v1/Chassis/{}/NetworkAdapters/NIC.Embedded.1",
                &chassis_id,
            ),
        },
        ODataId {
            odata_id: format!(
                "/redfish/v1/Chassis/{}/NetworkAdapters/NIC.Integrated.1",
                &chassis_id,
            ),
        },
    ]);

    // Add a network adapter for every DPU, or if there are no DPUs, mock a single non-DPU NIC.
    let count = if host.dpus.is_empty() {
        1
    } else {
        host.dpus.len()
    };
    for index in 1..=count {
        members.push(ODataId {
            odata_id: format!(
                "/redfish/v1/Chassis/{}/NetworkAdapters/NIC.Slot.{}",
                &chassis_id, index
            ),
        })
    }
    let members_len = members.len();
    body.insert("Members".to_string(), serde_json::to_value(members)?);

    body.remove("Members@odata.count");
    body.insert(
        "Members@odata.count".to_string(),
        serde_json::to_value(members_len)?,
    );
    Ok(Bytes::from(serde_json::to_string(&body)?))
}

async fn get_chassis_network_adapter(
    State(mut state): State<MockWrapperState>,
    Path((chassis_id, network_adapter_id)): Path<(String, String)>,
    request: Request<Body>,
) -> MockWrapperResult {
    let MachineInfo::Host(host) = &state.machine_info else {
        return state.call_inner_router(request).await;
    };

    if !network_adapter_id.starts_with("NIC.Slot.") {
        return state.call_inner_router(request).await;
    }
    if host.dpus.is_empty() {
        let Some(mac) = host.non_dpu_mac_address else {
            tracing::error!(
                "Request for NIC ID {}, but machine has no NICs (zero DPUs and no non_dpu_mac_address set.) This is a bug.",
                network_adapter_id
            );
            return state.call_inner_router(request).await;
        };
        let serial = mac.to_string().replace(':', "");

        // Build a non-DPU NetworkAdapter
        let adapter = NetworkAdapter {
            id: network_adapter_id,
            manufacturer: Some("Rooftop Technologies".to_string()),
            model: Some("Rooftop 10 Kilobit Ethernet Adapter".to_string()),
            part_number: Some("31337".to_string()),
            serial_number: Some(serial),
            odata: libredfish::OData {
                odata_id: "odata_id".to_string(),
                odata_type: "odata_type".to_string(),
                odata_etag: None,
                odata_context: None,
            },
            ports: None,
            network_device_functions: None,
            name: Some("Network Adapter".into()),
            status: Some(resource_status_ok()),
            controllers: None,
        };
        Ok(Bytes::from(serde_json::to_string(&adapter)?))
    } else {
        let Some(dpu) = state.find_dpu(&network_adapter_id) else {
            return state.call_inner_router(request).await;
        };

        // Build a NetworkAdapter from our mock DPU info (mainly just the serial number)
        let adapter = NetworkAdapter {
            id: network_adapter_id.clone(),
            manufacturer: Some("Mellanox Technologies".to_string()),
            model: Some("BlueField-2 SmartNIC Main Card".to_string()),
            part_number: Some("MBF2H5".to_string()),
            serial_number: Some(dpu.serial),
            odata: libredfish::OData {
                odata_id: format!(
                    "/redfish/v1/Chassis/{}/NetworkAdapters/{}",
                    &chassis_id, network_adapter_id
                ),
                odata_type: "#NetworkAdapter.v1_7_0.NetworkAdapter".to_string(),
                odata_etag: None,
                odata_context: None,
            },
            ports: None,
            network_device_functions: Some(ODataId {
                odata_id: format!(
                    "/redfish/v1/Chassis/{}/NetworkAdapters/{}/NetworkDeviceFunctions",
                    &chassis_id, network_adapter_id
                ),
            }),
            name: Some("Network Adapter".into()),
            status: Some(resource_status_ok()),
            controllers: None,
        };
        Ok(Bytes::from(serde_json::to_string(&adapter)?))
    }
}

async fn get_chassis_network_adapters_network_device_functions_list(
    State(mut state): State<MockWrapperState>,
    Path((system_id, network_adapter_id)): Path<(String, String)>,
    request: Request<Body>,
) -> MockWrapperResult {
    let Some(_dpu) = state.find_dpu(&network_adapter_id) else {
        return state.call_inner_router(request).await;
    };

    Ok(Bytes::from(serde_json::to_string(&serde_json::json!(
            {
      "@odata.context": "/redfish/v1/$metadata#NetworkDeviceFunctionCollection.NetworkDeviceFunctionCollection",
      "@odata.id": format!("/redfish/v1/Chassis/{}/NetworkAdapters/{}/NetworkDeviceFunctions", system_id, network_adapter_id),
      "@odata.type": "#NetworkDeviceFunctionCollection.NetworkDeviceFunctionCollection",
      "Description": "Collection Of Network Device Function entities",
      "Members": [
        {
          "@odata.id": format!("/redfish/v1/Chassis/{}/NetworkAdapters/{}/NetworkDeviceFunctions/{}-1", system_id, network_adapter_id, network_adapter_id),
        }
      ],
      "Members@odata.count": 1,
      "Name": "Network Device Function Collection"
    }
        ))?))
}

async fn get_chassis_network_adapters_network_device_function(
    State(mut state): State<MockWrapperState>,
    Path((system_id, network_adapter_id, _network_device_function_id)): Path<(
        String,
        String,
        String,
    )>,
    request: Request<Body>,
) -> MockWrapperResult {
    let Some(dpu) = state.find_dpu(&network_adapter_id) else {
        return state.call_inner_router(request).await;
    };

    // Base our response on what we know exists in the upstream tar file (it has a DPU in NIC.Slot.5-1)
    let upstream_response = state.call_inner_router(Request::builder()
        .method(Method::GET)
        .uri("/redfish/v1/Chassis/System.Embedded.1/NetworkAdapters/NIC.Slot.5/NetworkDeviceFunctions/NIC.Slot.5-1")
        .body(Body::empty()).unwrap()).await?;

    let json = String::from_utf8_lossy(upstream_response.as_ref())
        .to_string()
        .replace("System.Embedded.1", &system_id)
        .replace("NIC.Slot.5", &network_adapter_id)
        // NOTE: if the tar changes, this will likely change too.
        .replace("B8:3F:D2:90:97:C4", &dpu.host_mac_address.to_string())
        .replace("MT2242XZ00QA", &dpu.serial.to_string());
    Ok(Bytes::from(json))
}

async fn get_pcie_device(
    State(mut state): State<MockWrapperState>,
    Path((chassis_id, pcie_device_id)): Path<(String, String)>,
    request: Request<Body>,
) -> MockWrapperResult {
    let MachineInfo::Host(host) = &state.machine_info else {
        return state.call_inner_router(request).await;
    };

    if !pcie_device_id.starts_with(MAT_DPU_PCIE_DEVICE_PREFIX) {
        return state.call_inner_router(request).await;
    }

    let Some(dpu_index) = pcie_device_id
        .chars()
        .last()
        .and_then(|c| c.to_digit(10))
        .map(|i| i as usize)
    else {
        tracing::error!("Invalid Pcie Device ID: {}", pcie_device_id);
        return state.call_inner_router(request).await;
    };

    let Some(dpu) = host.dpus.get(dpu_index - 1) else {
        tracing::error!(
            "Request for Pcie Device ID {}, which we don't have a DPU for (we have {} DPUs), not rewriting request",
            pcie_device_id,
            host.dpus.len()
        );
        return state.call_inner_router(request).await;
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

    let pcie_device = PCIeDevice {
        odata: OData {
            odata_id: format!("/redfish/v1/Chassis/{chassis_id}/PCIeDevices/{pcie_device_id}"),
            odata_type: "#PCIeDevice.v1_5_0.PCIeDevice".to_string(),
            odata_etag: None,
            odata_context: Some("/redfish/v1/$metadata#PCIeDevice.PCIeDevice".to_string()),
        },
        description: Some(
            "MT43244 BlueField-3 integrated ConnectX-7 network controller".to_string(),
        ),
        firmware_version: Some("32.41.1000".to_string()),
        id: Some(pcie_device_id.to_string()),
        manufacturer: Some("Mellanox Technologies".to_string()),
        gpu_vendor: None,
        name: Some("MT43244 BlueField-3 integrated ConnectX-7 network controller".to_string()),
        part_number: Some(part_number.to_string()),
        serial_number: Some(dpu.serial.clone()),
        status: Some(libredfish::model::SystemStatus {
            health: Some("OK".to_string()),
            health_rollup: Some("OK".to_string()),
            state: Some("Enabled".to_string()),
        }),
        slot: None,
        pcie_functions: None,
    };

    Ok(Bytes::from(serde_json::to_string(&pcie_device)?))
}

async fn get_chassis_pcie_devices(
    State(mut state): State<MockWrapperState>,
    Path(chassis_id): Path<String>,
    request: Request<Body>,
) -> MockWrapperResult {
    let is_host_with_dpus = matches!(state.machine_info, MachineInfo::Host(_));
    let dpu_count = if let MachineInfo::Host(ref host) = state.machine_info {
        host.dpus.len()
    } else {
        0
    };

    if !is_host_with_dpus {
        return state.call_inner_router(request).await;
    }

    let inner_response = state.call_inner_router(request).await?;
    let mut collection: serde_json::Value = serde_json::from_slice(&inner_response)?;

    let mut members = Vec::new();

    if let Some(existing_members) = collection["Members"].as_array() {
        for member in existing_members {
            if let Some(odata_id) = member["@odata.id"].as_str() {
                let device_response = state
                    .call_inner_router(
                        Request::builder()
                            .method(Method::GET)
                            .uri(odata_id)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await;

                // Keep all default PCIE devices. Just remove any of the DPU entries
                if let Ok(device_bytes) = device_response
                    && let Ok(pcie_device) = serde_json::from_slice::<PCIeDevice>(&device_bytes)
                    && pcie_device
                        .manufacturer
                        .is_some_and(|manufacturer| manufacturer != "Mellanox Technologies")
                {
                    members.push(member.clone());
                }
            }
        }
    }

    for index in 1..=dpu_count {
        members.push(serde_json::json!({
            "@odata.id": format!(
                "/redfish/v1/Chassis/{}/PCIeDevices/{}_{}",
                chassis_id, MAT_DPU_PCIE_DEVICE_PREFIX, index
            )
        }));
    }

    collection["Members"] = serde_json::Value::Array(members);
    collection["Members@odata.count"] = serde_json::Value::Number(serde_json::Number::from(
        collection["Members"].as_array().unwrap().len(),
    ));

    Ok(Bytes::from(serde_json::to_string(&collection)?))
}

async fn get_dell_system(
    State(state): State<MockWrapperState>,
    _path: Path<()>,
    request: Request<Body>,
) -> MockWrapperResult {
    get_system(State(state), Path("System.Embedded.1".to_string()), request).await
}

async fn get_system(
    State(mut state): State<MockWrapperState>,
    Path(system_id): Path<String>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    let inner_json = serde_json::from_slice::<serde_json::Value>(&inner_response)?;
    let name = ResourceName::new(&inner_json);
    let bios = inner_json.get("Bios").cloned();
    let oem = inner_json.get("Oem").cloned();
    let secure_boot = inner_json.get("SecureBoot").cloned();
    let mut system = serde_json::from_value::<ComputerSystem>(inner_json)?;
    system.serial_number = state.machine_info.product_serial();
    system.power_state = state.mock_power_state.get_power_state().into();

    let MachineInfo::Host(host) = state.machine_info.clone() else {
        // Append required 'Name' field to the json. It is not part of the
        // libredfish model but must present in all Redfish resources.
        let json = serde_json::to_value(&system)?;
        let mut json = name.add_to_json(json);
        if let Some(bios) = bios {
            json_patch(&mut json, serde_json::json!({"Bios": bios}));
        }
        if let Some(oem) = oem {
            json_patch(&mut json, serde_json::json!({"Oem": oem}));
        }
        if let Some(secure_boot) = secure_boot {
            json_patch(&mut json, serde_json::json!({"SecureBoot": secure_boot}));
        }
        return Ok(Bytes::from(json.to_string()));
    };

    // Modify the Pcie Device List
    // 1) Include a new entry for every mocked DPU in the host
    // 2) Remove all unmocked DPU entries from the list

    // (1): Create a new pcie device for the mocked DPUs in this host
    let mut pcie_devices = Vec::new();
    for index in 1..=host.dpus.len() {
        pcie_devices.push(ODataId {
            odata_id: format!(
                "/redfish/v1/Chassis/{}/PCIeDevices/{}_{}",
                &system_id, MAT_DPU_PCIE_DEVICE_PREFIX, index
            ),
        });
    }

    // (2) Remove any Pcie devices from the host's original list that refer to unmocked DPUs
    for device in system.pcie_devices {
        let upstream_response = state
            .call_inner_router(
                Request::builder()
                    .method(Method::GET)
                    .uri(device.odata_id.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await?;

        let pcie_device: PCIeDevice = serde_json::from_slice(&upstream_response)?;
        // Keep all default PCIE devices. Just remove any of the DPU entries
        if pcie_device
            .manufacturer
            .is_some_and(|manufacturer| manufacturer != *"Mellanox Technologies".to_string())
        {
            pcie_devices.push(device);
        }
    }

    system.pcie_devices = pcie_devices;

    let json = serde_json::to_value(&system)?;
    let mut json = name.add_to_json(json);
    if let Some(bios) = bios {
        json_patch(&mut json, serde_json::json!({"Bios": bios}));
    }
    if let Some(oem) = oem {
        json_patch(&mut json, serde_json::json!({"Oem": oem}));
    }
    if let Some(secure_boot) = secure_boot {
        json_patch(&mut json, serde_json::json!({"SecureBoot": secure_boot}));
    }
    Ok(Bytes::from(json.to_string()))
}

async fn get_dpu_boot_options(
    State(mut state): State<MockWrapperState>,
    Path(_boot_option_id): Path<String>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    // We only rewrite this line if it's a DPU we're mocking
    let MachineInfo::Dpu(dpu) = state.machine_info else {
        return Ok(inner_response);
    };
    let mut boot_option = serde_json::from_slice::<BootOption>(&inner_response)?;
    let Some(uefi_device_path) = boot_option.uefi_device_path else {
        return Ok(inner_response);
    };
    let mocked_mac_no_colons = dpu
        .oob_mac_address
        .to_string()
        .replace(':', "")
        .to_ascii_uppercase();
    let updated_uefi_device_path =
        UEFI_DEVICE_PATH_MAC_ADDRESS_REGEX.replace(&uefi_device_path, |captures: &Captures| {
            [
                &captures["prefix"],
                &mocked_mac_no_colons,
                &captures["suffix"],
            ]
            .join("")
        });
    boot_option.uefi_device_path = Some(updated_uefi_device_path.to_string());
    Ok(Bytes::from(serde_json::to_string(&boot_option)?))
}

async fn get_dpu_sys_image(
    State(mut state): State<MockWrapperState>,
    _path: Path<()>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    // We only rewrite this line if it's a DPU we're mocking
    let MachineInfo::Dpu(dpu) = state.machine_info else {
        return Ok(inner_response);
    };

    let inner_json = serde_json::from_slice::<serde_json::Value>(&inner_response)?;
    let name = ResourceName::new(&inner_json);
    let mut inventory = serde_json::from_value::<SoftwareInventory>(inner_json)?;
    // Version string is the mac address with extra padding in the middle to reach 64 bits, and
    // colons after every 16 bits instead of 8. Carbide will reverse this, removing the middle
    // padding and rearranging the colons to form a mac address.
    // example: 12:34:56:ab:cd:ef -> 1234:5600:00ab:cdef
    let base_mac = dpu.host_mac_address.to_string().replace(':', "");
    inventory.version = Some(format!(
        "{}:{}00:00{}:{}",
        &base_mac[0..4],
        &base_mac[4..6],
        &base_mac[6..8],
        &base_mac[8..12]
    ));

    let json = serde_json::to_value(&inventory)?;
    let json = name.add_to_json(json);
    Ok(Bytes::from(json.to_string()))
}

async fn get_dpu_bios(
    State(mut state): State<MockWrapperState>,
    _path: Path<()>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    // We only rewrite this line if it's a DPU we're mocking
    let MachineInfo::Dpu(dpu) = state.machine_info else {
        return Ok(inner_response);
    };

    // For DPUs in NicMode, rewrite the BIOS attributes to reflect as such
    if dpu.nic_mode {
        let serde_json::Value::Object(mut bios) = serde_json::from_slice(inner_response.as_ref())?
        else {
            tracing::error!(
                "Invalid JSON response, expected object, got {:?}",
                inner_response
            );
            return Ok(inner_response);
        };

        let Some(serde_json::Value::Object(attributes)) = bios.get_mut("Attributes") else {
            tracing::error!(
                "Invalid Attributes, expected object, got {:?}",
                inner_response
            );
            return Ok(inner_response);
        };

        if attributes.get("NicMode").is_none() {
            tracing::warn!(
                "DPU BIOS Attributes.NicMode is not present: {:?}",
                inner_response
            )
        }

        attributes.insert(
            "NicMode".to_string(),
            serde_json::Value::String("NicMode".to_string()),
        );
        Ok(Bytes::from(serde_json::to_string(&bios)?))
    } else {
        Ok(inner_response)
    }
}

async fn patch_dell_system(
    State(mut state): State<MockWrapperState>,
    _path: Path<()>,
    _request: Request<Body>,
) -> impl IntoResponse {
    // Dell password change, needs a job ID to be returned in the Location: header
    match state.bmc_state.add_job() {
        Ok(job_id) => Response::builder()
            .status(StatusCode::OK)
            .header(
                "location",
                format!("/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/{job_id}"),
            )
            .body(Body::from(""))
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(e.to_string()))
            .unwrap(),
    }
}

async fn patch_bios_settings(
    State(_state): State<MockWrapperState>,
    _path: Path<()>,
    _request: Request<Body>,
) -> impl IntoResponse {
    // Dell password change, needs a job ID to be returned in the Location: header
    Response::builder()
        .status(StatusCode::OK)
        .header(
            "Location",
            "/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/JID_00000000001",
        )
        .body(Body::from(""))
        .unwrap()
}

async fn post_dell_create_bios_job(
    State(mut state): State<MockWrapperState>,
    _path: Path<()>,
    _request: Request<Body>,
) -> impl IntoResponse {
    match state.bmc_state.add_job() {
        Ok(job_id) => Response::builder()
            .status(StatusCode::OK)
            .header(
                "location",
                format!("/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/{job_id}"),
            )
            .body(Body::from(""))
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(e.to_string()))
            .unwrap(),
    }
}

async fn get_task(
    State(_state): State<MockWrapperState>,
    _path: Path<()>,
    _request: Request<Body>,
) -> MockWrapperResult {
    Ok(Bytes::from(serde_json::to_string(&serde_json::json!(
        {
    "@odata.id": "/redfish/v1/TaskService/Tasks/0",
    "@odata.type": "#Task.v1_4_3.Task",
    "Id": "0",
    "PercentComplete": 100,
    "StartTime": "2024-01-30T09:00:52+00:00",
    "TaskMonitor": "/redfish/v1/TaskService/Tasks/0/Monitor",
    "TaskState": "Completed",
    "TaskStatus": "OK"
    }
    ))?))
}

async fn update_firmware_simple_update(
    State(_state): State<MockWrapperState>,
    _path: Path<()>,
    _request: Request<Body>,
) -> MockWrapperResult {
    Ok(Bytes::from(serde_json::to_string(&serde_json::json!(
        {
    "@odata.id": "/redfish/v1/TaskService/Tasks/0",
    "@odata.type": "#Task.v1_4_3.Task",
    "Id": "0"
    }
    ))?))
}

async fn patch_dpu_secure_boot(
    State(mut state): State<MockWrapperState>,
    _path: Path<()>,
    _request: Request<Body>,
) -> impl IntoResponse {
    state.bmc_state.set_secure_boot_enabled(true);
    Response::builder()
        .status(StatusCode::OK)
        .header("Location", "/redfish/v1/Systems/Bluefield/SecureBoot")
        .body(Body::from(""))
        .unwrap()
}

async fn get_dpu_secure_boot(
    State(state): State<MockWrapperState>,
    _path: Path<()>,
    _request: Request<Body>,
) -> MockWrapperResult {
    let secure_boot_enabled = state.bmc_state.secure_boot_enabled.load(Ordering::Relaxed);
    Ok(Bytes::from(serde_json::to_string(&serde_json::json!(
        {
            "@odata.context": "/redfish/v1/$metadata#SecureBoot.SecureBoot",
            "@odata.id": "/redfish/v1/Systems/Bluefield/SecureBoot",
            "@odata.type": "#SecureBoot.v1_6_0.SecureBoot",
            "Id": "SecureBoot",
            "Name": "UEFI Secure Boot",
            "SecureBootEnable": secure_boot_enabled,
            "SecureBootMode": "UserMode",
            "SecureBootCurrentBoot": if secure_boot_enabled {
                "Enabled"
            } else {
                "Disabled"
            },
        }
    ))?))
}

async fn get_dell_job(
    State(state): State<MockWrapperState>,
    Path(job_id): Path<String>,
    _request: Request<Body>,
) -> MockWrapperResult {
    let job = state
        .bmc_state
        .get_job(&job_id)
        .ok_or(MockWrapperError::NotFound(format!(
            "could not find iDRAC job: {job_id}"
        )))?;

    // TODO (spyda): move this to libredfish
    let job_state = match job.job_state {
        libredfish::JobState::Scheduled => "Scheduled".to_string(),
        libredfish::JobState::Completed => "Completed".to_string(),
        _ => "Unknown".to_string(),
    };

    Ok(Bytes::from(serde_json::to_string(&serde_json::json!(
          {
    "@odata.context": "/redfish/v1/$metadata#DellJob.DellJob",
    "@odata.id": format!("/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/Jobs/{job_id}"),
    "@odata.type": "#DellJob.v1_5_0.DellJob",
    "ActualRunningStartTime": format!("{}", job.start_time),
    "ActualRunningStopTime": null,
    "CompletionTime": null,
    "Description": "Job Instance",
    "EndTime": "TIME_NA",
    "Id": job_id,
    "JobState": job_state,
    "JobType": job.job_type,
    "Message": job_state,
    "MessageArgs": [],
    "MessageArgs@odata.count": 0,
    "MessageId": "PR19",
    "Name": job.job_type,
    "PercentComplete": job.percent_complete(),
    "StartTime": format!("{}", job.start_time),
    "TargetSettingsURI": null
        }
      ))?))
}

async fn get_dpu_firmware(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
    fw_name: &str,
    version: impl FnOnce(&DpuMachineInfo) -> Option<&String>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    let MachineInfo::Dpu(dpu_machine) = state.machine_info else {
        return Ok(inner_response);
    };
    let inner_json = serde_json::from_slice::<serde_json::Value>(&inner_response)?;
    let name = ResourceName::new(&inner_json);
    let mut inventory: SoftwareInventory = serde_json::from_value(inner_json)?;
    let Some(desired_version) = version(&dpu_machine) else {
        tracing::debug!(
            "Unknown desired {fw_name} firmware version for {}, not rewriting response",
            dpu_machine.serial
        );
        return Ok(inner_response);
    };
    inventory.version = Some(desired_version.to_string());

    let json = serde_json::to_value(&inventory)?;
    let json = name.add_to_json(json);
    Ok(Bytes::from(json.to_string()))
}

async fn get_dpu_bmc_firmware(
    state: State<MockWrapperState>,
    request: Request<Body>,
) -> MockWrapperResult {
    get_dpu_firmware(state, request, "BMC", |m| m.firmware_versions.bmc.as_ref()).await
}

async fn get_dpu_erot_firmware(
    state: State<MockWrapperState>,
    request: Request<Body>,
) -> MockWrapperResult {
    get_dpu_firmware(state, request, "CEC", |m| m.firmware_versions.cec.as_ref()).await
}

async fn get_dpu_uefi_firmware(
    state: State<MockWrapperState>,
    request: Request<Body>,
) -> MockWrapperResult {
    get_dpu_firmware(state, request, "UEFI", |m| {
        m.firmware_versions.uefi.as_ref()
    })
    .await
}

async fn get_dpu_nic_firmware(
    state: State<MockWrapperState>,
    request: Request<Body>,
) -> MockWrapperResult {
    get_dpu_firmware(state, request, "NIC", |m| m.firmware_versions.nic.as_ref()).await
}

async fn get_oem_nvidia(
    State(mut state): State<MockWrapperState>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    let MachineInfo::Dpu(dpu_machine) = state.machine_info else {
        return Ok(inner_response);
    };

    let mut system: serde_json::Value = serde_json::from_slice(&inner_response)?;
    json_patch(
        &mut system,
        serde_json::json!(
        {
            "@odata.id": "/redfish/v1/Systems/Bluefield/Oem/Nvidia",
            "@odata.type": "#NvidiaComputerSystem.v1_0_0.NvidiaComputerSystem",
            "Mode": if dpu_machine.nic_mode {
                "NicMode"
            } else {
                "DpuMode"
            }
        }),
    );
    Ok(Bytes::from(serde_json::to_string(&system)?))
}

async fn patch_dpu_settings(
    State(_state): State<MockWrapperState>,
    _path: Path<()>,
    _request: Request<Body>,
) -> impl IntoResponse {
    StatusCode::OK
}

async fn post_password_change(
    State(_state): State<MockWrapperState>,
    _path: Path<()>,
    _request: Request<Body>,
) -> impl IntoResponse {
    StatusCode::OK
}

async fn post_delete_job_queue(
    State(_state): State<MockWrapperState>,
    _path: Path<()>,
    _request: Request<Body>,
) -> impl IntoResponse {
    StatusCode::OK
}

async fn post_reset_system(
    State(mut state): State<MockWrapperState>,
    Path(_system_id): Path<String>,
    request: Request<Body>,
) -> MockWrapperResult {
    // Dell specific call back after a reset -- sets the job status for all scheduled BIOS jobs to "Completed"
    state.bmc_state.complete_all_bios_jobs();

    if let Some(command_channel) = &state.command_channel {
        let body = request.into_body().collect().await?.to_bytes();
        let power_request: SetSystemPowerReq = serde_json::from_slice(&body)?;
        use crate::SystemPowerControl;

        // Reply with a failure if the power request is invalid for the current state.
        // Note: This logic is duplicated with that in machine-a-tron's MachineStateMachine, because
        // we don't want to block waiting for the BMC command_channel to reply. Doing so may
        // introduce a deadlock if the API server holds a lock on the row for this machine
        // while issuing a redfish call, and MachineStateMachine is blocked waiting for the row lock
        // to be released.
        match (
            power_request.reset_type,
            state.mock_power_state.get_power_state(),
        ) {
            (
                SystemPowerControl::GracefulShutdown
                | SystemPowerControl::ForceOff
                | SystemPowerControl::GracefulRestart
                | SystemPowerControl::ForceRestart,
                MockPowerState::Off,
            ) => {
                return Err(MockWrapperError::SetSystemPower(
                    SetSystemPowerError::BadRequest(
                        "bmc-mock: cannot power off machine, it is already off".to_string(),
                    ),
                ));
            }
            (SystemPowerControl::On | SystemPowerControl::ForceOn, MockPowerState::On) => {
                return Err(MockWrapperError::SetSystemPower(
                    SetSystemPowerError::BadRequest(
                        "bmc-mock: cannot power on machine, it is already on".to_string(),
                    ),
                ));
            }
            (_, MockPowerState::PowerCycling { since }) if since.elapsed() < POWER_CYCLE_DELAY => {
                return Err(MockWrapperError::SetSystemPower(
                    SetSystemPowerError::BadRequest(format!(
                        "bmc-mock: cannot reset machine, it is in the middle of power cycling since {:?} ago",
                        since.elapsed()
                    )),
                ));
            }
            _ => {}
        }
        command_channel.send(BmcCommand::SetSystemPower {
            request: power_request,
            reply: None,
        })?;
        Ok("".into())
    } else {
        state.call_inner_router(request).await?;
        Ok("".into())
    }
}

struct ResourceName {
    name: Option<serde_json::Value>,
}

impl ResourceName {
    pub fn new(v: &serde_json::Value) -> Self {
        Self {
            name: v.as_object().and_then(|obj| obj.get("Name").cloned()),
        }
    }
    pub fn add_to_json(self, v: serde_json::Value) -> serde_json::Value {
        // Append required 'Name' field to the json. It is not part of the
        // libredfish model but must present in all Redfish resources.
        if let Some(name) = self.name {
            match v {
                serde_json::Value::Object(mut map) => {
                    map.insert("Name".into(), name);
                    serde_json::Value::Object(map)
                }
                other => other,
            }
        } else {
            v
        }
    }
}

fn redfish_resource_id(json: &serde_json::Value) -> Option<&str> {
    json.as_object()
        .and_then(|obj| obj.get("Id"))
        .and_then(serde_json::Value::as_str)
}

fn mac_address_patch(m: MacAddress) -> serde_json::Value {
    serde_json::json!({
        "MACAddress": m.to_string()
    })
}

fn json_patch(target: &mut serde_json::Value, patch: serde_json::Value) {
    match (target, patch) {
        (serde_json::Value::Object(target_obj), serde_json::Value::Object(patch_obj)) => {
            for (k, v_patch) in patch_obj {
                match target_obj.get_mut(&k) {
                    Some(v_target) => json_patch(v_target, v_patch),
                    None => {
                        target_obj.insert(k, v_patch);
                    }
                }
            }
        }
        (target_slot, v_patch) => *target_slot = v_patch,
    }
}

fn resource_status_ok() -> ResourceStatus {
    ResourceStatus {
        health: Some(ResourceHealth::Ok),
        health_rollup: None,
        state: Some(ResourceState::Enabled),
    }
}
