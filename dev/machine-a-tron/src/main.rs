pub mod api_client;
pub mod config;
pub mod dhcp_relay;
pub mod dpu_machine;
pub mod host_machine;
pub mod machine_a_tron;
pub mod machine_utils;
pub mod tui;

use std::net::SocketAddr;
use std::sync::Arc;
use std::{collections::HashMap, error::Error, path::Path};

use axum::http::Uri;
use axum::{http::StatusCode, response::IntoResponse, routing::get, Json, Router};

use clap::Parser;
use figment::providers::{Format, Toml};
use figment::Figment;
use forge_tls::client_config::{
    get_carbide_api_url, get_client_cert_info, get_config_from_file, get_forge_root_ca_path,
    get_proxy_info,
};
use machine_a_tron::MachineATron;
use rpc::forge_tls_client::ForgeClientConfig;

use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*, registry};

use crate::config::{MachineATronArgs, MachineATronConfig, MachineATronContext};
use crate::dhcp_relay::DhcpRelayService;

fn init_log(filename: &Option<String>) -> Result<(), Box<dyn Error>> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    match filename {
        Some(filename) => {
            let log_file = std::sync::Arc::new(std::fs::File::create(filename)?);
            registry()
                .with(fmt::Layer::default().compact().with_writer(log_file))
                .with(env_filter)
                .try_init()
                .unwrap();
        }
        None => {
            registry()
                .with(fmt::Layer::default().compact().with_writer(std::io::stdout))
                .with(env_filter)
                .try_init()
                .unwrap();
        }
    }
    Ok(())
}

#[derive(Clone, Default)]
struct MatBmcState {
    response_map: Arc<Mutex<HashMap<String, String>>>,
}

async fn get_response(
    filename: &str,
    response_file: &mut tokio::fs::File,
) -> (StatusCode, Json<Value>) {
    let mut buf = [0u8; 10240];
    match response_file.read(&mut buf).await {
        Ok(data_size) => {
            let data = String::from_utf8_lossy(&buf[..data_size]).trim().to_owned();
            match serde_json::from_str::<Value>(&data) {
                Ok(value) => (StatusCode::OK, Json(value)),
                Err(e) => {
                    let err_str = format!("Could not pase response data {data}: {e}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(err_str.as_str().into()),
                    )
                }
            }
        }
        Err(e) => {
            let err_str = format!("Could not read response file {filename}: {e}");
            tracing::info!(err_str);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(err_str.as_str().into()),
            )
        }
    }
}

async fn get_not_found_response(response_path: &str) -> (StatusCode, Json<Value>) {
    let filename: String = format!("{}/not_found.json", response_path);

    match tokio::fs::OpenOptions::new()
        .read(true)
        .open(&filename)
        .await
    {
        Ok(mut response_file) => {
            let mut buf = [0u8; 10240];
            match response_file.read(&mut buf).await {
                Ok(data_size) => {
                    let data = String::from_utf8_lossy(&buf[..data_size]).trim().to_owned();
                    match serde_json::from_str::<Value>(&data) {
                        Ok(value) => (StatusCode::NOT_FOUND, Json(value)),
                        Err(e) => {
                            let err_str = format!("Could not parse response data {data}: {e}");
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(err_str.as_str().into()),
                            )
                        }
                    }
                }
                Err(e) => {
                    let err_str = format!("Could not read response file {filename}: {e}");
                    tracing::info!(err_str);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(err_str.as_str().into()),
                    )
                }
            }
        }
        Err(e) => {
            let err_str = format!("Could not open not found response file {filename}: {e}");
            tracing::info!(err_str);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(err_str.as_str().into()),
            )
        }
    }
}

async fn handle_request(
    uri: Uri,
    axum::extract::State(state): axum::extract::State<MatBmcState>,
) -> impl IntoResponse {
    tracing::trace!("bmc request path: {uri}");
    if let Some(host) = uri.host() {
        let response_map = state.response_map.lock().await;
        if let Some(response_path) = response_map.get(host) {
            // TODO: replace any URL encoding or special characters
            let filename = uri.path().trim_matches('/').replace('/', "_");
            let filename: String = format!("{}/{}.json", response_path, filename);
            match tokio::fs::OpenOptions::new()
                .read(true)
                .open(&filename)
                .await
            {
                Ok(mut response_file) => get_response(&filename, &mut response_file).await,
                Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                    tracing::error!("curl -k -x socks5://localhost:8888/  \"https://${{USER}}:${{PASS}}@${{BMC_IP}}{}\" > {}", uri.path(), filename);
                    get_not_found_response(response_path).await
                }
                Err(e) => {
                    let err_str = format!("Could not open response file {filename}: {e}");
                    tracing::info!(err_str);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(err_str.as_str().into()),
                    )
                }
            }
        } else {
            tracing::info!("No response found for host: {host}");
            (
                StatusCode::NOT_FOUND,
                Json("Failed to find response for host".into()),
            )
        }
    } else {
        tracing::info!("No host in request uri: {:?}", uri);
        (
            StatusCode::NOT_FOUND,
            Json("Failed to find response for host".into()),
        )
    }
}

fn bmc_router(state: MatBmcState) -> Router {
    Router::new()
        .fallback(get(handle_request))
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = MachineATronArgs::parse();

    let fig = Figment::new().merge(Toml::file(args.config_file.as_str()));
    let mut app_config: MachineATronConfig = fig.extract().unwrap();
    init_log(&app_config.log_file).unwrap();

    let file_config = get_config_from_file();
    let carbide_api_url =
        get_carbide_api_url(app_config.carbide_api_url.clone(), file_config.as_ref());
    app_config.carbide_api_url = Some(carbide_api_url);

    let forge_root_ca_path = get_forge_root_ca_path(args.forge_root_ca_path, file_config.as_ref());
    let forge_client_cert = get_client_cert_info(
        args.client_cert_path,
        args.client_key_path,
        file_config.as_ref(),
    );
    let proxy = get_proxy_info().expect("Failed to get proxy info");

    let mut forge_client_config =
        ForgeClientConfig::new(forge_root_ca_path.clone(), Some(forge_client_cert));
    forge_client_config.socks_proxy(proxy);

    let cert_path = Path::new(&forge_root_ca_path)
        .parent()
        .expect("Could not get cert path from root ca path")
        .to_owned()
        .to_str()
        .map(|p| p.to_owned());

    let mat_bmc_state = MatBmcState::default();

    let mut app_context = MachineATronContext {
        app_config,
        forge_client_config,
        circuit_id: None,
        bmc_response_map: mat_bmc_state.response_map.clone(),
    };

    let (mut dhcp_client, mut dhcp_service) =
        DhcpRelayService::new(app_context.clone(), app_context.app_config.clone());
    let dhcp_handle = tokio::spawn(async move {
        dhcp_service.run().await;
    });

    let segments = api_client::find_network_segments(&app_context)
        .await
        .unwrap();

    for s in segments.network_segments.iter() {
        tracing::info!("segment: {:?}", s);
    }

    let circuit_id = segments
        .network_segments
        .iter()
        .find_map(|s| s.prefixes.iter().find_map(|p| p.circuit_id.clone()));
    app_context.circuit_id = circuit_id;

    let info = api_client::version(&app_context).await.unwrap();
    tracing::info!("version: {}", info.build_version);

    let listen_addr = app_context
        .app_config
        .bmc_port
        .map(|p| SocketAddr::from(([0, 0, 0, 0], p)));

    tracing::info!("Starting bmc mock on {:?}", listen_addr);

    let bmc_mock_handle = tokio::spawn(bmc_mock::run(
        bmc_router(mat_bmc_state),
        cert_path,
        listen_addr,
    ));

    let mut mat = MachineATron::new(app_context, dhcp_client.clone());
    mat.run().await;

    bmc_mock_handle.abort();
    dhcp_client.stop_service().await;
    dhcp_handle.await.unwrap();
    Ok(())
}
