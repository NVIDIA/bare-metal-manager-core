use crate::bmc_state::BmcState;
use crate::{call_router_with_new_request, rf, DpuMachineInfo, MachineInfo};
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
use std::sync::{Arc, Mutex};
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
    bmc_state: BmcState,
}

#[derive(Debug, Clone)]
pub enum BmcCommand {
    Reboot(DateTime<Utc>),
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
        .route(
            rf!("Chassis/:chassis_id/NetworkAdapters/:network_adapter_id/NetworkDeviceFunctions"),
            get(get_chassis_network_adapters_network_device_functions_list),
        )
        .route(
            rf!("Chassis/:chassis_id/NetworkAdapters/:network_adapter_id/NetworkDeviceFunctions/:function_id"),
            get(get_chassis_network_adapters_network_device_function),
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
            rf!("Systems/Bluefield/Bios"),
            get(get_dpu_bios),
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
        .route(rf!("Systems/Bluefield/Settings"),
               patch(patch_dpu_settings).get(fallback_to_inner_router),
        )
        .route(rf!("Managers/iDRAC.Embedded.1/Jobs"),
               post(post_dell_create_bios_job),
        )
        .route(rf!("Managers/iDRAC.Embedded.1/Jobs/:job_id"),get(get_dell_job),
        )
        .fallback(fallback_to_inner_router)
        .with_state(MockWrapperState {
            machine_info,
            command_channel,
            inner_router,
            bmc_state: BmcState{
                jobs: Arc::new(Mutex::new(HashMap::new())),
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
            tracing::error!("Request for NIC ID {}, which we don't have a DPU for (we have {} DPUs), not rewriting request", identifier, host.dpus.len());
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
            tracing::error!("Request for NIC ID {}, but machine has no NICs (zero DPUs and no non_dpu_mac_address set.) This is a bug.", network_adapter_id);
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
            name: None,
            status: None,
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
            serial_number: Some(dpu.serial.clone()),
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
            name: None,
            status: None,
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

        let Some(serde_json::Value::Object(ref mut attributes)) = bios.get_mut("Attributes") else {
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
    match state.bmc_state.add_job(true) {
        Ok(job_id) => Response::builder()
            .status(StatusCode::OK)
            .header(
                "location",
                format!("/redfish/v1/Managers/iDRAC.Embedded.1/Jobs/{}", job_id),
            )
            .body(Body::from(""))
            .unwrap(),
        Err(e) => Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(e.to_string()))
            .unwrap(),
    }
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
) -> impl IntoResponse {
    if let Some(command_channel) = &state.command_channel {
        _ = command_channel.send(BmcCommand::Reboot(Utc::now()))
    }

    // Dell specific call back after a reset -- sets the job status for all scheduled BIOS jobs to "Completed"
    state.bmc_state.complete_all_bios_jobs();
    state.call_inner_router(request).await
}
