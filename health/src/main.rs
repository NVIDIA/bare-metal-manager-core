/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use color_eyre::eyre::Result;
use prometheus::{Encoder, TextEncoder};
use std::convert::Infallible;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ::rpc::forge::{self as rpc};
use ::rpc::forge_tls_client::{self, ForgeClientCert, ForgeClientT, ForgeTlsConfig};
use ::rpc::MachineId;

use http::header::CONTENT_LENGTH;
use hyper::{
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server,
};
use opentelemetry_sdk::metrics::MeterProvider;
use prometheus::Registry;
use tracing::error;

mod metrics;
use crate::metrics::scrape_machine_health;

#[derive(thiserror::Error, Debug)]
pub enum HealthError {
    #[error("Unable to connect to carbide API: {0}")]
    ApiConnectFailed(String),

    #[error("The API call to the Forge API server returned {0}")]
    ApiInvocationError(tonic::Status),

    #[error("Generic Error: {0}")]
    GenericError(String),

    #[error("Error while handling json: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Error in redfish call: {0}")]
    RedfishError(#[from] libredfish::RedfishError),

    #[error("Tokio Task Join Error {0}")]
    TokioJoinError(#[from] tokio::task::JoinError),

    #[error("Opentelemetry error: {0}")]
    OpentelemetryError(#[from] opentelemetry::metrics::MetricsError),

    #[error("No results returned")]
    Empty,
}

fn get_client_cert_info(
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
) -> ForgeClientCert {
    if let (Some(client_key_path), Some(client_cert_path)) = (client_key_path, client_cert_path) {
        return ForgeClientCert {
            cert_path: client_cert_path,
            key_path: client_key_path,
        };
    }
    // this is the location for most k8s pods
    if Path::new("/var/run/secrets/spiffe.io/tls.crt").exists()
        && Path::new("/var/run/secrets/spiffe.io/tls.key").exists()
    {
        return ForgeClientCert {
            cert_path: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            key_path: "/var/run/secrets/spiffe.io/tls.key".to_string(),
        };
    }
    // if you make it here, you'll just have to tell me where the client cert is.
    panic!(
        r###"Unknown client cert location. Set (will be read in same sequence.)
           1. --client-cert-path and --client-key-path flag or
           2. environment variables CLIENT_KEY_PATH and CLIENT_CERT_PATH or
           3. a file existing at "/var/run/secrets/spiffe.io/tls.crt" and "/var/run/secrets/spiffe.io/tls.key".
           4. a file existing at "/opt/forge/machine_cert.pem" and "/opt/forge/machine_cert.key".
           5. a file existing at "$REPO_ROOT/dev/certs/server_identity.pem" and "$REPO_ROOT/dev/certs/server_identity.key."###
    )
}

fn get_forge_root_ca_path(forge_root_ca_path: Option<String>) -> String {
    // First from command line, second env var.
    if let Some(forge_root_ca_path) = forge_root_ca_path {
        return forge_root_ca_path;
    }
    // this is the location for most k8s pods
    if Path::new("/var/run/secrets/spiffe.io/ca.crt").exists() {
        return "/var/run/secrets/spiffe.io/ca.crt".to_string();
    }
    // if you make it here, you'll just have to tell me where the root CA is.
    panic!(
        r###"Unknown FORGE_ROOT_CA_PATH. Set (will be read in same sequence.)
           1. --forge-root-ca-path flag or
           2. environment variable FORGE_ROOT_CA_PATH or
           3. a file existing at "/var/run/secrets/spiffe.io/ca.crt".
           4. a file existing at "/opt/forge/forge_root.pem".
           5. a file existing at "$REPO_ROOT/dev/certs/forge_developer_local_only_root_cert_pem"."###
    )
}

async fn create_forge_client(
    root_ca: String,
    client_cert: String,
    client_key: String,
    api_url: String,
) -> Result<ForgeClientT, HealthError> {
    let forge_tls_config = ForgeTlsConfig {
        root_ca_path: root_ca,
        client_cert: Some(ForgeClientCert {
            cert_path: client_cert,
            key_path: client_key,
        }),
    };
    let client = forge_tls_client::ForgeTlsClient::new(forge_tls_config)
        .connect(&api_url)
        .await
        .map_err(|err| HealthError::ApiConnectFailed(err.to_string()))?;
    Ok(client)
}

pub async fn get_machines(client: &mut ForgeClientT) -> Result<rpc::MachineList, HealthError> {
    let request = tonic::Request::new(rpc::MachineSearchQuery {
        id: None,
        fqdn: None,
        search_config: Some(rpc::MachineSearchConfig {
            include_dpus: false,
            include_history: false,
            include_predicted_host: false,
            only_maintenance: false,
        }),
    });
    let machines = client
        .find_machines(request)
        .await
        .map(|response| response.into_inner())
        .map_err(HealthError::ApiInvocationError)?;

    Ok(machines)
}

pub async fn get_machine(
    client: &mut ForgeClientT,
    id: MachineId,
) -> Result<libredfish::Endpoint, HealthError> {
    let request = tonic::Request::new(rpc::BmcMetaDataGetRequest {
        machine_id: Some(id.clone()),
        role: rpc::UserRoles::Administrator.into(),
        request_type: rpc::BmcRequestType::Ipmi.into(),
    });
    let response = client
        .get_bmc_meta_data(request)
        .await
        .map(|response| response.into_inner())
        .map_err(HealthError::ApiInvocationError)?;
    let endpoint = libredfish::Endpoint {
        host: response.ip,
        port: None,
        user: Some(response.user),
        password: Some(response.password),
    };
    Ok(endpoint)
}

pub struct HealthMetricsState {
    registry: Registry,
}

pub async fn serve_metrics(
    req: Request<Body>,
    state: Arc<HealthMetricsState>,
) -> Result<Response<Body>, hyper::Error> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = state.registry.gather();
            encoder.encode(&metric_families, &mut buffer).unwrap();

            Response::builder()
                .status(200)
                .header(CONTENT_TYPE, encoder.format_type())
                .header(CONTENT_LENGTH, buffer.len())
                .body(Body::from(buffer))
                .unwrap()
        }
        (&Method::GET, "/") => Response::builder()
            .status(200)
            .body(Body::from("/metrics"))
            .unwrap(),
        _ => Response::builder()
            .status(404)
            .body(Body::from("Invalid URL"))
            .unwrap(),
    };

    Ok(response)
}

// setup the /metrics prometheus endpoint, adapted from:
// https://github.com/open-telemetry/opentelemetry-rust/blob/main/opentelemetry-prometheus/examples/hyper.rs
// and carbide/api/src/logging/metrics_endpoint.rs
pub async fn metrics_listener(state: Arc<HealthMetricsState>) -> Result<(), hyper::Error> {
    let make_svc = make_service_fn(move |_conn| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(service_fn(move |req| serve_metrics(req, state.clone()))) }
    });
    // port seems to be either 5558, 8082,8083,8084,8085 or 9001 in forged
    let listen_address = ([0, 0, 0, 0], 9009).into();
    let server = Server::bind(&listen_address).serve(make_svc);
    println!("Starting metrics listening server");
    server.await?;
    Ok(())
}

pub async fn scrape_machines_health(provider: MeterProvider) -> Result<(), HealthError> {
    // we may eventually want a config for this service with these items:
    // cert paths, api server url, metrics listener address, bmcs polling interval
    let root_ca = get_forge_root_ca_path(None);
    let client_certs = get_client_cert_info(None, None);
    let mut grpc_client = create_forge_client(
        root_ca,
        client_certs.cert_path,
        client_certs.key_path,
        "https://carbide-api.forge-system.svc.cluster.local".to_string(),
    )
    .await?;

    loop {
        let machines: rpc::MachineList = get_machines(&mut grpc_client).await?;

        println!("Got {} machines from api server", machines.machines.len());
        let mut machine_count = 0;
        for machine in machines.machines.iter() {
            if machine.id.is_none() {
                continue;
            }
            let id = machine.id.clone().unwrap().clone();
            let endpoint = match get_machine(&mut grpc_client, id.clone()).await {
                Ok(x) => x,
                Err(e) => {
                    // some hosts bmc data may error out at times due to creds missing in vault
                    error!("grpc error getting machine bmc metadata {}", e.to_string());
                    continue;
                }
            };
            match scrape_machine_health(provider.clone(), endpoint, id.id.clone()).await {
                Ok(_x) => {
                    machine_count += 1;
                }
                Err(e) => {
                    error!(
                        "failed to scrape metrics for {}\n{}",
                        id.id.clone(),
                        e.to_string()
                    );
                }
            }
        }

        println!("Exported {} machines metrics", machine_count);
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), HealthError> {
    let registry = Registry::new();
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()?;
    let provider = MeterProvider::builder().with_reader(exporter).build();
    let state = Arc::new(HealthMetricsState { registry });

    let join_listener = tokio::spawn(async move { metrics_listener(state).await });

    let join_scraper = tokio::spawn(async move { scrape_machines_health(provider).await });

    let _ = join_scraper.await?;
    let _ = join_listener.await?;

    Ok(())
}
