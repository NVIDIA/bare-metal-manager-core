use std::io::ErrorKind;
///
/// bmc-mock behaves like a Redfish BMC server
/// Run: 'cargo run'
/// Try it:
///  - start docker-compose things
///  - `cargo make bootstrap-forge-docker`
///  - `grpcurl -d '{"machine_id": {"value": "71363261-a95a-4964-9eb1-8dd98b870746"}}' -plaintext
///  127.0.0.1:1079 forge.Forge/CleanupMachineCompleted`
///  where that UUID is a host machine in DB.
///
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;

use axum::body::Body;
use axum::extract::Path as AxumPath;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{any, get, patch, post};
use axum::Json;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use libredfish::common::{ODataId, ODataLinks};
use libredfish::system::Systems;
use tracing::{debug, error, info};

#[tokio::main]
async fn main() {
    std::env::set_var("RUST_LOG", "debug");
    tracing_subscriber::fmt::init();

    let app = Router::new()
        .route("/", any(handler))
        .route("/redfish/v1/Systems/", get(get_system_id))
        .route("/redfish/v1/Managers/", get(get_manager_id))
        .route(
            "/redfish/v1/Managers/:manager_id/Attributes",
            patch(update_manager_attributes),
        )
        .route(
            "/redfish/v1/Systems/:manager_id/Bios/Settings/",
            patch(set_bios_attribute),
        )
        .route(
            "/redfish/v1/Systems/:manager_id/Actions/ComputerSystem.Reset",
            post(set_system_power),
        );

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let config = RustlsConfig::from_pem_file(root.join("cert.pem"), root.join("key.pem"))
        .await
        .unwrap();

    let addr = SocketAddr::from(([0, 0, 0, 0], 1266));
    debug!("Listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn handler(request: Request<Body>) -> &'static str {
    debug!("general handler: {:?}", request);
    "OK"
}

async fn get_system_id() -> impl IntoResponse {
    let odata = ODataLinks {
        odata_context: "odata_context".to_string(),
        odata_id: "123".to_string(),
        odata_type: "odata_type".to_string(),
        links: None,
    };
    let systems = Systems {
        odata,
        description: "BMC Mock systems for Forge".to_string(),
        members: vec![ODataId {
            odata_id: "123".to_string(),
        }],
        name: "BMC Mock systems".to_string(),
    };

    (StatusCode::OK, Json(systems))
}

async fn get_manager_id() -> impl IntoResponse {
    let odata = ODataLinks {
        odata_context: "odata_context".to_string(),
        odata_id: "123".to_string(),
        odata_type: "odata_type".to_string(),
        links: None,
    };
    let managers = Systems {
        odata,
        description: "BMC Mock managers for Forge".to_string(),
        members: vec![ODataId {
            odata_id: "123".to_string(),
        }],
        name: "BMC Mock managers".to_string(),
    };

    (StatusCode::OK, Json(managers))
}

async fn update_manager_attributes(
    AxumPath(manager_id): AxumPath<String>,
    body: String,
) -> impl IntoResponse {
    debug!("update_manager_attributes {manager_id}, body: {body}");
    StatusCode::OK
}

async fn set_bios_attribute(
    AxumPath(manager_id): AxumPath<String>,
    body: String,
) -> impl IntoResponse {
    debug!("set_bios_attribute {manager_id}, body: {body}");
    StatusCode::OK
}

async fn set_system_power(
    AxumPath(manager_id): AxumPath<String>,
    body: String,
) -> impl IntoResponse {
    debug!("set_system_power {manager_id}, body: {body}");

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
