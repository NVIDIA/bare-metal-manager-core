use std::{collections::HashMap, net::SocketAddr};

use axum::{
    http::{StatusCode, Uri},
    response::IntoResponse,
    Json, Router,
};
use bmc_mock::BmcMockError;
use serde_json::Value;
use tokio::{io::AsyncReadExt, task::JoinHandle};

use crate::host_machine::MachineStateError;

#[derive(Clone)]
pub struct MatBmcState {
    pub response_path: String,
}

#[derive(Debug)]
pub struct Bmc {
    listen_ip: String,
    listen_port: u16,
    response_path: String,
    cert_path: String,
    join_handle: Option<JoinHandle<Result<(), BmcMockError>>>,
}

impl Bmc {
    pub fn new(
        listen_ip: String,
        listen_port: u16,
        response_path: String,
        cert_path: String,
    ) -> Self {
        Bmc {
            listen_ip,
            listen_port,
            response_path,
            cert_path,
            join_handle: None,
        }
    }

    pub fn start(&mut self) -> Result<(), MachineStateError> {
        // let cert_path = PathBuf::from(app_context.forge_client_config.root_ca_path.clone())
        //     .parent()
        //     .map(|p| p.to_string_lossy().into_owned());
        let bmc_state = MatBmcState {
            response_path: self.response_path.clone(),
        };
        let listen_addr_str = format!("{}:{}", self.listen_ip, self.listen_port);
        let listen_addr = listen_addr_str.parse::<SocketAddr>().map_err(|e| {
            MachineStateError::InvalidAddress(format!(
                "Invalid listen IP address {} when configuring mock BMC: {}",
                listen_addr_str, e
            ))
        })?;

        tracing::info!("Starting bmc mock on {:?}", listen_addr);

        let cert_path = self.cert_path.clone();
        self.join_handle = Some(tokio::spawn(async move {
            let mut routers = HashMap::default();
            routers.insert("".to_owned(), crate::bmc::bmc_router(bmc_state));

            bmc_mock::run(routers, Some(cert_path), Some(listen_addr))
                .await
                .inspect_err(|e| tracing::error!("{}", e))
        }));
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(join_handle) = self.join_handle.as_ref() {
            join_handle.abort();
        }
    }
}
const MAX_RESPONSE_FILE_SIZE: usize = 102400;

async fn get_response(
    filename: &str,
    response_file: &mut tokio::fs::File,
) -> (StatusCode, Json<Value>) {
    let mut buf = [0u8; MAX_RESPONSE_FILE_SIZE];
    if response_file
        .metadata()
        .await
        .is_ok_and(|m| m.len() > MAX_RESPONSE_FILE_SIZE as u64)
    {
        tracing::warn!(r#"response file "{}" is too big"#, filename);
    }
    match response_file.read(&mut buf).await {
        Ok(data_size) => {
            let data = String::from_utf8_lossy(&buf[..data_size]).trim().to_owned();
            match serde_json::from_str::<Value>(&data) {
                Ok(value) => (StatusCode::OK, Json(value)),
                Err(e) => {
                    let err_str = format!("Could not pase response data {data}: {e}");
                    tracing::warn!(err_str);
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
    tracing::info!("bmc request path: {uri}");
    let filename = uri.path().trim_matches('/').replace('/', "_");
    let filename: String = format!("{}/{}.json", state.response_path, filename);
    match tokio::fs::OpenOptions::new()
        .read(true)
        .open(&filename)
        .await
    {
        Ok(mut response_file) => get_response(&filename, &mut response_file).await,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::error!("curl -k -x socks5://localhost:8888/  \"https://${{BMC_USER}}:${{BMC_PASS}}@${{BMC_IP}}{}\" | jq . > {}", uri.path(), filename);
            get_not_found_response(&state.response_path).await
        }
        Err(e) => {
            let err_str = format!("Could not open response file {filename}: {e}");
            tracing::warn!(err_str);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(err_str.as_str().into()),
            )
        }
    }
}

pub fn bmc_router(state: MatBmcState) -> Router {
    Router::new().fallback(handle_request).with_state(state)
}
