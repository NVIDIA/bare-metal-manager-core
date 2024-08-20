use crate::{call_router_with_new_request, rf, MachineInfo};
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{Method, Request, Response, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use axum::Router;
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use libredfish::model::software_inventory::SoftwareInventory;
use libredfish::model::{BootOption, ComputerSystem, ODataId};
use libredfish::{Chassis, EthernetInterface, NetworkAdapter};
use regex::{Captures, Regex};
use std::collections::HashMap;
use std::convert::Infallible;
use tokio::sync::mpsc;

lazy_static! {
    static ref UEFI_DEVICE_PATH_MAC_ADDRESS_REGEX: Regex =
        Regex::new(r"(?<prefix>.*MAC\()(?<mac>[[:alnum:]]+)(?<suffix>,.*)$").unwrap();
}

#[derive(Debug, Clone)]
struct MockWrapperState {
    machine_info: MachineInfo,
    inner_router: Router,
    command_channel: Option<mpsc::UnboundedSender<BmcCommand>>,
}

#[derive(Debug, Clone)]
pub enum BmcCommand {
    Reboot(DateTime<Utc>),
}

/// Return an axum::Router that mocks various redfish calls to match the provided MachineInfo.
/// Any redfish calls not explicitly mocked will be delegated to inner_router (typically a tar_router.)
pub fn wrap_router_with_mock_machine(
    inner_router: Router,
    machine_info: MachineInfo,
    command_channel: Option<mpsc::UnboundedSender<BmcCommand>>,
) -> Router {
    Router::new()
        .route(
            rf!("Managers/:manager_id/EthernetInterfaces/:interface_id"),
            get(get_managers_ethernet_interface),
        )
        .route(
            rf!("Systems/:system_id/EthernetInterfaces/:nic"),
            get(get_systems_ethernet_interface),
        )
        .route(rf!("Chassis/:chassis_id"), get(get_chassis))
        .route(
            rf!("Chassis/:chassis_id/NetworkAdapters"),
            get(get_chassis_network_adapters),
        )
        .route(
            rf!("Chassis/:chassis_id/NetworkAdapters/:network_adapter_id"),
            get(get_chassis_network_adapter),
        )
        .route(rf!("Systems/:system_id"), get(get_system))
        .route(
            rf!("Systems/Bluefield/BootOptions/:boot_option_id"),
            get(get_dpu_boot_options),
        )
        .route(
            rf!("UpdateService/FirmwareInventory/DPU_SYS_IMAGE"),
            get(get_dpu_sys_image),
        )
        .route(
            rf!("Systems/:system_id/Actions/ComputerSystem.Reset"),
            post(post_reset_system),
        )
        .route(
            rf!("Systems/System.Embedded.1/Bios/Settings"),
            patch(patch_bios_settings),
        )
        .route(
            rf!("Systems/1/Bios/Actions/Bios.ChangePassword"),
            post(post_password_change),
        )
        .route(rf!("Managers/:manager_id/Oem/Dell/DellJobService/Actions/DellJobService.DeleteJobQueue"),
               post(post_delete_job_queue),
        )
        .fallback(fallback_to_inner_router)
        .with_state(MockWrapperState {
            machine_info,
            command_channel,
            inner_router,
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
    #[error("{0} {1} failed with HTTP error {2}: {3}")]
    Generic(Method, Uri, StatusCode, String),
}

impl MockWrapperError {
    fn generic(request: Request<Body>, status_code: StatusCode, message: String) -> Self {
        let (head, _body) = request.into_parts();
        Self::Generic(head.method, head.uri, status_code, message)
    }
}

impl IntoResponse for MockWrapperError {
    fn into_response(self) -> axum::response::Response {
        // Don't log errors if the upstream request was the one that failed
        if !matches!(self, MockWrapperError::InnerRequest(_, _, _, _)) {
            tracing::error!("Mock machine router failure: {}", self.to_string());
        }

        match self {
            MockWrapperError::Generic(_, _, status_code, body_bytes)
            | MockWrapperError::InnerRequest(_, _, status_code, body_bytes) => {
                // Use the error's status code instead of INTERNAL_SERVER_ERROR
                (status_code, body_bytes).into_response()
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
    let mut iface = serde_json::from_slice::<EthernetInterface>(&inner_response)?;

    match state.machine_info {
        MachineInfo::Dpu(dpu) => {
            if manager_id.eq("Bluefield_BMC")
                && iface
                    .id
                    .as_ref()
                    .map(|name| name.eq("eth0"))
                    .unwrap_or(false)
            {
                iface.mac_address = Some(dpu.bmc_mac_address.to_string());
            }
        }
        MachineInfo::Host(host) => {
            iface.mac_address = Some(host.bmc_mac_address.to_string());
        }
    }
    Ok(Bytes::from(serde_json::to_string(&iface)?))
}

async fn get_systems_ethernet_interface(
    State(mut state): State<MockWrapperState>,
    Path((system_id, _interface_id)): Path<(String, String)>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    let mut iface = serde_json::from_slice::<EthernetInterface>(&inner_response)?;

    match state.machine_info {
        MachineInfo::Dpu(dpu) => {
            if system_id.eq("Bluefield") {
                iface.mac_address = Some(dpu.host_mac_address.to_string());
            }
        }
        MachineInfo::Host(host) => {
            iface.mac_address = host.system_mac_address().map(|m| m.to_string());
        }
    }
    Ok(Bytes::from(serde_json::to_string(&iface)?))
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

    // Add a network adapter for every DPU
    for (index, _dpu) in host.dpus.iter().enumerate() {
        members.push(ODataId {
            odata_id: format!(
                "/redfish/v1/Chassis/{}/NetworkAdapters/NIC.Slot.{}",
                &chassis_id,
                index + 1
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
    Path((_chassis_id, network_adapter_id)): Path<(String, String)>,
    request: Request<Body>,
) -> MockWrapperResult {
    let MachineInfo::Host(host) = &state.machine_info else {
        return state.call_inner_router(request).await;
    };
    if !network_adapter_id.starts_with("NIC.Slot.") {
        return state.call_inner_router(request).await;
    }
    let Some(dpu_index) = network_adapter_id
        .chars()
        .last()
        .and_then(|c| c.to_digit(10))
        .map(|i| i as usize)
    else {
        return Err(MockWrapperError::generic(
            request,
            StatusCode::NOT_FOUND,
            format!("Invalid NIC slot: {}", network_adapter_id),
        ));
    };
    let Some(dpu) = host.dpus.get(dpu_index - 1) else {
        tracing::error!("Request for NIC ID {}, which we don't have a DPU for (we have {} DPUs), not rewriting request", network_adapter_id, host.dpus.len());
        return Err(MockWrapperError::generic(
            request,
            StatusCode::NOT_FOUND,
            format!(
                "Request for NIC ID {}, which we don't have a DPU for (we have {} DPUs)",
                network_adapter_id,
                host.dpus.len()
            ),
        ));
    };

    // Build a NetworkAdapter from our mock DPU info (mainly just the serial number)
    let adapter = NetworkAdapter {
        id: network_adapter_id,
        manufacturer: Some("Mellanox Technologies".to_string()),
        model: Some("BlueField-2 SmartNIC Main Card".to_string()),
        part_number: Some("MBF2H5".to_string()),
        serial_number: Some(dpu.serial.clone()),
        odata: libredfish::OData {
            odata_id: "odata_id".to_string(),
            odata_type: "odata_type".to_string(),
            odata_etag: None,
            odata_context: None,
        },
        ports: None,
        network_device_functions: None,
        name: None,
        status: None,
        controllers: None,
    };
    Ok(Bytes::from(serde_json::to_string(&adapter)?))
}

async fn get_system(
    State(mut state): State<MockWrapperState>,
    Path(_system_id): Path<String>,
    request: Request<Body>,
) -> MockWrapperResult {
    let inner_response = state.call_inner_router(request).await?;
    let mut system = serde_json::from_slice::<ComputerSystem>(&inner_response)?;
    system.serial_number = state.machine_info.product_serial();
    Ok(Bytes::from(serde_json::to_string(&system)?))
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

    let mut inventory = serde_json::from_slice::<SoftwareInventory>(&inner_response)?;
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

    Ok(Bytes::from(serde_json::to_string(&inventory)?))
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
) -> impl IntoResponse {
    if let Some(command_channel) = &state.command_channel {
        _ = command_channel.send(BmcCommand::Reboot(Utc::now()))
    }
    state.call_inner_router(request).await
}
