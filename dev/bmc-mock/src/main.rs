use std::collections::HashMap;
use std::io::ErrorKind;
///
/// bmc-mock behaves like a Redfish BMC server
/// Run: 'cargo run'
/// Try it:
///  - start docker-compose things
///  - `cargo make bootstrap-forge-docker`
///  - `grpcurl -d '{"machine_id": {"value": "71363261-a95a-4964-9eb1-8dd98b870746"}}' -insecure
///  127.0.0.1:1079 forge.Forge/CleanupMachineCompleted`
///  where that UUID is a host machine in DB.
///
mod command_line;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, patch, post};
use axum::Json;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use tracing::{debug, error, info};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt::Layer;
use tracing_subscriber::prelude::*;

macro_rules! rf {
    ($url:literal) => {
        &format!("/{}/{}", libredfish::REDFISH_ENDPOINT, $url)
    };
}

#[tokio::main]
async fn main() {
    let env_filter = EnvFilter::from_default_env()
        .add_directive(LevelFilter::DEBUG.into())
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(Layer::default().compact())
        .with(env_filter)
        .init();

    let state = command_line::parse_args();
    info!("Using qemu: {}", state.use_qemu);

    let app = Router::new()
        .route(rf!(""), get(get_root))
        .route(rf!("Managers/"), get(get_manager_id))
        .route(
            rf!("Managers/:manager_id/Attributes"), // no slash at end
            patch(update_manager_attributes),
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
        .route(
            rf!("Systems/:manager_id/Bios/Settings/"),
            patch(set_bios_attribute),
        )
        .route(
            rf!("Systems/:manager_id/Actions/ComputerSystem.Reset"),
            post(set_system_power),
        )
        .with_state(state);

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));

    let root = match manifest_dir.try_exists() {
        Ok(false) => Path::new("/opt/carbide"),
        Err(error) => panic!(
            "Could not determine if CARGO_MANIFEST_DIR exists: {}",
            error
        ),
        Ok(true) => manifest_dir,
    };

    let cert_file = root.join("cert.pem");
    let key_file = root.join("key.pem");
    info!("Loading {:?} and {:?}", cert_file, key_file);
    let config = RustlsConfig::from_pem_file(cert_file, key_file)
        .await
        .unwrap();

    let addr = SocketAddr::from(([0, 0, 0, 0], 1266));
    debug!("Listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

/*
async fn handler(request: Request<Body>) -> &'static str {
    debug!("general handler: {:?}", request);
    "OK"
}
*/

async fn get_root() -> impl IntoResponse {
    let mut out = HashMap::new();
    out.insert("Vendor", "Dell");
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
        description: "BMC Mock systems for Forge".to_string(),
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
        description: "BMC Mock managers for Forge".to_string(),
        members: vec![libredfish::model::ODataId {
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

async fn set_system_power(
    State(state): State<command_line::Args>,
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
