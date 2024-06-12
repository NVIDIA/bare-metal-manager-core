/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use axum::body::Body;
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;

use std::path::Path;
use std::pin::Pin;
use std::process::Command;

use axum::body::HttpBody;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use axum::Json;
use axum::Router;
use axum::ServiceExt;
use axum_server::tls_rustls::RustlsConfig;
use tower::Service;

use tracing::{debug, error, info};

mod tar;
pub use tar::tar_router;

#[macro_export]
macro_rules! rf {
    ($url:literal) => {
        &format!("/{}/{}", libredfish::REDFISH_ENDPOINT, $url)
    };
}

#[derive(Clone)]
pub struct BmcState {
    pub use_qemu: bool,
}

#[derive(thiserror::Error, Debug)]
pub enum BmcMockError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("BMC Mock Configuration error: {0}")]
    Config(String),
}

pub fn default_router(state: BmcState) -> Router {
    Router::new()
        .route(rf!(""), get(get_root))
        .route(rf!("Managers/"), get(get_manager_id))
        .route(rf!("Managers/:manager_id"), get(get_manager))
        .route(
            rf!("Managers/:manager_id/Attributes"), // no slash at end
            patch(update_manager_attributes),
        )
        .route(
            rf!("Managers/:manager_id/EthernetInterfaces"),
            get(get_manager_ethernet_interface_ids),
        )
        .route(
            rf!("Managers/:manager_id/EthernetInterfaces/:id"),
            get(get_manager_ethernet_interface),
        )
        .route(rf!("Managers/:manager_id/Oem/Dell/DellAttributes/:manager_id"),
            patch(update_manager_attributes_long),
        )
        .route(rf!("Managers/:manager_id/Oem/Dell/DellAttributes/:manager_id"),
            get(get_manager_attributes),
        )
        .route(rf!("Managers/:manager_id/Oem/Dell/DellJobService/Actions/DellJobService.DeleteJobQueue"),
            post(delete_job_queue),
        )
        .route(rf!("Systems/"), get(get_system_id))
        .route(rf!("Systems/:manager_id"), get(get_system))
        .route(rf!("Systems/:manager_id/"), get(get_system))
        .route(
            rf!("Systems/:manager_id/Bios/Settings/"),
            patch(set_bios_attribute),
        )
        .route(
            rf!("Systems/:manager_id/Actions/ComputerSystem.Reset"),
            post(set_system_power),
        )
        .route(rf!("Systems/:manager_id/Bios"), get(get_bios))
        .route(
            rf!("Systems/:manager_id/EthernetInterfaces"),
            get(get_system_ethernet_interface_ids),
        )
        .route(
            rf!("Systems/:manager_id/EthernetInterfaces/:id"),
            get(get_system_ethernet_interface),
        )
        .route(rf!("Chassis/"), get(get_chassis_id))
        .route(rf!("Chassis/:id"), get(get_chassis))
        .route(rf!("Chassis/:id/NetworkAdapters"), get(get_chassis_network_adapter_ids))
        .route(rf!("Chassis/:id/NetworkAdapters/:nic_id"), get(get_chassis_network_adapter))
        .route(rf!("UpdateService/FirmwareInventory"), get(firmware_inventory))
        .route(rf!("UpdateService/FirmwareInventory/:id"), get(firmware_inventory_item))
        .with_state(state)
}

pub async fn run(
    routers: HashMap<String, Router>,
    cert_path: Option<String>,
    listen_addr: Option<SocketAddr>,
) -> Result<(), BmcMockError> {
    let cert_path = match cert_path.as_ref() {
        Some(cert_path) => Path::new(cert_path),
        None => {
            let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
            match manifest_dir.try_exists() {
                Ok(true) => manifest_dir,
                Ok(false) => Path::new("/opt/carbide"),
                Err(error) => {
                    return Err(BmcMockError::Config(format!(
                        "Could not determine if CARGO_MANIFEST_DIR exists: {}",
                        error
                    )));
                }
            }
        }
    };

    let addr = listen_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 1266)));

    let cert_file = cert_path.join("tls.crt");
    let key_file = cert_path.join("tls.key");
    info!("Loading {:?} and {:?}", cert_file, key_file);
    let config = RustlsConfig::from_pem_file(cert_file, key_file)
        .await
        .unwrap();

    debug!("Listening on {}", addr);

    let bmc_service = BmcService { routers };

    axum_server::bind_rustls(addr, config)
        .serve(bmc_service.into_make_service())
        .await
        .inspect_err(|e| tracing::error!("BMC mock could not listen on address {}: {}", addr, e))?;
    Ok(())
}

#[derive(Clone)]
struct BmcService {
    routers: HashMap<String, Router>,
}

impl Service<axum::http::Request<Body>> for BmcService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let mac_address = request
            .headers()
            .get("x-really-to-mac")
            .map(|v| v.to_str().unwrap())
            .unwrap_or("");

        let Some(router) = self.routers.get_mut(mac_address) else {
            let err = format!("no BMC mock configured for mac: {mac_address}");
            tracing::info!(err);
            return Box::pin(async {
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from(err))
                    .unwrap())
            });
        };

        let call_fut = router.call(request);

        let fut = async move {
            let mut response = match call_fut.await {
                Ok(r) => r,
                Err(e) => {
                    let err = format!("error calling BMC mock: {e}");
                    tracing::error!(err);
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from(err))
                        .unwrap());
                }
            };

            let (status, body) = match response.data().await {
                // Mirror the status we get from bmc mock
                Some(Ok(bytes)) => (response.status(), Body::from(bytes)),
                // If we got an error calling it, render an internal server error
                Some(Err(e)) => {
                    let err = format!("error calling BMC mock: {e}");
                    tracing::info!(err);
                    (StatusCode::INTERNAL_SERVER_ERROR, Body::from(err))
                }
                // Not clear when the data would be None, but map it to an empty body and relay the status code
                None => {
                    let err = "empty response from BMC mock";
                    tracing::error!(err);
                    (response.status(), Body::empty())
                }
            };
            Ok(Response::builder().status(status).body(body).unwrap())
        };

        Box::pin(fut)
    }
}

async fn get_root() -> impl IntoResponse {
    let mut out = HashMap::new();
    out.insert("Vendor", "Dell");
    out.insert("RedfishVersion", "1.13.1");
    (StatusCode::OK, Json(out))
}

async fn get_system_id() -> impl IntoResponse {
    let odata = libredfish::model::ODataLinks {
        odata_context: Some("odata_context".to_string()),
        odata_id: "123".to_string(),
        odata_type: "odata_type".to_string(),
        links: None,
    };
    let systems = libredfish::Systems {
        odata,
        description: Some("BMC Mock systems for Forge".to_string()),
        members: vec![libredfish::model::ODataId {
            odata_id: "123".to_string(),
        }],
        name: "BMC Mock systems".to_string(),
    };

    (StatusCode::OK, Json(systems))
}

async fn get_manager_id() -> impl IntoResponse {
    let odata = libredfish::model::ODataLinks {
        odata_context: Some("odata_context".to_string()),
        odata_id: "123".to_string(),
        odata_type: "odata_type".to_string(),
        links: None,
    };
    let managers = libredfish::model::Systems {
        odata,
        description: Some("BMC Mock managers for Forge".to_string()),
        members: vec![libredfish::model::ODataId {
            odata_id: "123".to_string(),
        }],
        name: "BMC Mock managers".to_string(),
    };

    (StatusCode::OK, Json(managers))
}

async fn get_manager() -> impl IntoResponse {
    let out = include_str!("../manager.json");
    out
}

async fn get_system() -> impl IntoResponse {
    let out = include_str!("../system.json");
    out
}

async fn update_manager_attributes(
    AxumPath(manager_id): AxumPath<String>,
    body: String,
) -> impl IntoResponse {
    debug!("update_manager_attributes {manager_id}, body: {body}");
    StatusCode::OK
}

async fn update_manager_attributes_long(
    AxumPath((manager_id, _)): AxumPath<(String, String)>,
    body: String,
) -> impl IntoResponse {
    debug!("update_manager_attributes_long {manager_id}, body: {body}");
    StatusCode::OK
}

async fn get_manager_attributes() -> impl IntoResponse {
    let out = include_str!("../manager-attributes.json");
    out
}

async fn delete_job_queue(
    AxumPath(manager_id): AxumPath<String>,
    body: String,
) -> impl IntoResponse {
    debug!("delete_job_queue {manager_id}, body: {body}");
    StatusCode::OK
}

async fn set_bios_attribute(
    AxumPath(manager_id): AxumPath<String>,
    body: String,
) -> impl IntoResponse {
    debug!("set_bios_attribute {manager_id}, body: {body}");
    StatusCode::OK
}

async fn get_bios() -> impl IntoResponse {
    let odata = libredfish::model::ODataLinks {
        odata_context: Some("/redfish/v1/$metadata#Bios.Bios".to_string()),
        odata_id: "/redfish/v1/Systems/System.Embedded.1/Bios".to_string(),
        odata_type: "#Bios.v1_2_1.Bios".to_string(),
        links: None,
    };

    (StatusCode::OK, Json(odata))
}

async fn set_system_power(
    AxumState(state): AxumState<BmcState>,
    AxumPath(manager_id): AxumPath<String>,
    body: String,
) -> impl IntoResponse {
    debug!("set_system_power {manager_id}, body: {body}");

    if !state.use_qemu {
        return StatusCode::ACCEPTED;
    }

    let reboot_output = match Command::new("virsh")
        .arg("reboot")
        .arg("ManagedHost")
        .output()
    {
        Ok(o) => o,
        Err(err) if matches!(err.kind(), ErrorKind::NotFound) => {
            info!("`virsh` not found. Cannot reboot QEMU host.");
            return StatusCode::ACCEPTED;
        }
        Err(err) => {
            error!("Error trying to run 'virsh reboot ManagedHost'. {}", err);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    match reboot_output.status.code() {
        Some(0) => {
            debug!("Rebooting managed host...");
            StatusCode::OK
        }
        Some(exit_code) => {
            error!("Reboot command 'virsh reboot ManagedHost' failed with exit code {exit_code}.");
            info!("STDOUT: {}", String::from_utf8_lossy(&reboot_output.stdout));
            info!("STDERR: {}", String::from_utf8_lossy(&reboot_output.stderr));
            StatusCode::INTERNAL_SERVER_ERROR
        }
        None => {
            error!("Reboot command killed by signal");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn get_chassis_id() -> impl IntoResponse {
    let data = r##"
    {
        "@odata.context": "/redfish/v1/$metadata#ChassisCollection.ChassisCollection",
        "@odata.id": "/redfish/v1/Chassis",
        "@odata.type": "#ChassisCollection.ChassisCollection",
        "Description": "Collection of Chassis",
        "Members": [
            {
                "@odata.id": "/redfish/v1/Chassis/System.Embedded.1"
            }
        ],
        "Members@odata.count": 1,
        "Name": "Chassis Collection"
    }
    "##;
    let headers = [(axum::http::header::CONTENT_TYPE, "application/json")];
    (headers, data)
}

async fn firmware_inventory() -> impl IntoResponse {
    let out = include_str!("../firmware_inventory.json");
    out
}

async fn firmware_inventory_item() -> impl IntoResponse {
    let out = include_str!("../firmware_nic_dpu.json");
    out
}

async fn get_manager_ethernet_interface_ids() -> impl IntoResponse {
    let data = r##"
{
    "@odata.context": "/redfish/v1/$metadata#EthernetInterfaceCollection.EthernetInterfaceCollection",
    "@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1/EthernetInterfaces",
    "@odata.type": "#EthernetInterfaceCollection.EthernetInterfaceCollection",
    "Description": "Collection of EthernetInterfaces for this Manager",
    "Members": [
        {
            "@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1/EthernetInterfaces/NIC.1"
        }
    ],
    "Members@odata.count": 1,
    "Name": "Ethernet Network Interface Collection"
}
    "##;
    let headers = [(axum::http::header::CONTENT_TYPE, "application/json")];
    (headers, data)
}

async fn get_system_ethernet_interface_ids() -> impl IntoResponse {
    let data = r##"
{
    "@odata.context": "/redfish/v1/$metadata#EthernetInterfaceCollection.EthernetInterfaceCollection",
    "@odata.id": "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces",
    "@odata.type": "#EthernetInterfaceCollection.EthernetInterfaceCollection",
    "Description": "Collection of Ethernet Interfaces for this System",
    "Members": [
        {
            "@odata.id": "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.Slot.5-1"
        }
    ],
    "Members@odata.count": 1,
    "Name": "System Ethernet Interface Collection"
}
    "##;
    let headers = [(axum::http::header::CONTENT_TYPE, "application/json")];
    (headers, data)
}

async fn get_manager_ethernet_interface() -> impl IntoResponse {
    let out = include_str!("../manager_eth_nic1.json");
    out
}

async fn get_system_ethernet_interface() -> impl IntoResponse {
    let out = include_str!("../system_eth_dpu.json");
    out
}

async fn get_chassis() -> impl IntoResponse {
    let out = include_str!("../chassis.json");
    out
}

async fn get_chassis_network_adapter_ids() -> impl IntoResponse {
    let data = r##"
{
    "@odata.context": "/redfish/v1/$metadata#NetworkAdapterCollection.NetworkAdapterCollection",
    "@odata.id": "/redfish/v1/Chassis/System.Embedded.1/NetworkAdapters",
    "@odata.type": "#NetworkAdapterCollection.NetworkAdapterCollection",
    "Description": "Collection Of Network Adapter",
    "Members": [
        {
            "@odata.id": "/redfish/v1/Chassis/System.Embedded.1/NetworkAdapters/NIC.Slot.5"
        }
    ],
    "Members@odata.count": 1,
    "Name": "Network Adapter Collection"
}
"##;
    let headers = [(axum::http::header::CONTENT_TYPE, "application/json")];
    (headers, data)
}

async fn get_chassis_network_adapter() -> impl IntoResponse {
    let out = include_str!("../chassis_eth_dpu.json");
    out
}
