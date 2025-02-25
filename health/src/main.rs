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
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ::rpc::common::MachineId;
use ::rpc::forge::{self as rpc};
use ::rpc::forge_tls_client::{self, ApiConfig, ForgeClientConfig, ForgeClientT};
use cfg::Options;
use chrono::{DateTime, Utc};
use eyre::Result;
use forge_tls::client_config::ClientCert;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{
    body,
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    service::service_fn,
    Method, Request, Response,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;

use opentelemetry::logs::{Logger, LoggerProvider};
use opentelemetry::metrics::{Histogram, MeterProvider};
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::logs::{LogError, SdkLoggerProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, TextEncoder};
use rpc::Machine;
use tokio::net::TcpListener;
use tracing::error;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

mod cfg;
mod metrics;
use crate::metrics::{scrape_machine_health, HealthHashData};

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
    OpentelemetryError(#[from] opentelemetry_sdk::metrics::MetricError),

    #[error("Generic error: {0}")]
    LogErr(#[from] LogError),

    #[error("No results returned")]
    Empty,
}

fn get_client_cert_info(
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
) -> ClientCert {
    if let (Some(client_key_path), Some(client_cert_path)) = (client_key_path, client_cert_path) {
        return ClientCert {
            cert_path: client_cert_path,
            key_path: client_key_path,
        };
    }
    // this is the location for most k8s pods
    if Path::new("/var/run/secrets/spiffe.io/tls.crt").exists()
        && Path::new("/var/run/secrets/spiffe.io/tls.key").exists()
    {
        return ClientCert {
            cert_path: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            key_path: "/var/run/secrets/spiffe.io/tls.key".to_string(),
        };
    }
    // if you make it here, you'll just have to tell me where the client cert is.
    panic!(
        r###"Unknown client cert location. Set (will be read in same sequence.)
           1. --client-cert-path and --client-key-path flag or
           2. a file existing at "/var/run/secrets/spiffe.io/tls.crt" and "/var/run/secrets/spiffe.io/tls.key"."###
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
           2. a file existing at "/var/run/secrets/spiffe.io/ca.crt"."###
    )
}

async fn create_forge_client(
    root_ca: String,
    client_cert: String,
    client_key: String,
    api_url: String,
) -> Result<ForgeClientT, HealthError> {
    let client_config = ForgeClientConfig::new(
        root_ca,
        Some(ClientCert {
            cert_path: client_cert,
            key_path: client_key,
        }),
    );
    let api_config = ApiConfig::new(&api_url, &client_config);

    let client = forge_tls_client::ForgeTlsClient::retry_build(&api_config)
        .await
        .map_err(|err| HealthError::ApiConnectFailed(err.to_string()))?;
    Ok(client)
}

pub async fn get_machines(client: &mut ForgeClientT) -> Result<rpc::MachineList, HealthError> {
    let request = tonic::Request::new(rpc::MachineSearchConfig {
        include_dpus: false,
        include_history: false,
        include_predicted_host: false,
        only_maintenance: false,
        exclude_hosts: false,
    });
    let machine_ids = client
        .find_machine_ids(request)
        .await
        .map(|response| response.into_inner())
        .map_err(HealthError::ApiInvocationError)?;
    let mut all_machines = rpc::MachineList {
        machines: Vec::with_capacity(machine_ids.machine_ids.len()),
    };
    for ids_chunk in machine_ids.machine_ids.chunks(100) {
        let request = tonic::Request::new(::rpc::forge::MachinesByIdsRequest {
            machine_ids: Vec::from(ids_chunk),
            ..Default::default()
        });
        let machines = client
            .find_machines_by_ids(request)
            .await
            .map(|response| response.into_inner())
            .map_err(HealthError::ApiInvocationError)?;
        all_machines.machines.extend(machines.machines);
    }

    Ok(all_machines)
}

pub async fn get_machine_bmc_data(
    client: &mut ForgeClientT,
    id: &MachineId,
    histogram: &Histogram<f64>,
) -> Result<libredfish::Endpoint, HealthError> {
    let request = tonic::Request::new(rpc::BmcMetaDataGetRequest {
        machine_id: Some(id.clone()),
        bmc_endpoint_request: None,
        role: rpc::UserRoles::Administrator.into(),
        request_type: rpc::BmcRequestType::Ipmi.into(),
    });
    let start_time = std::time::Instant::now();
    let response = client
        .get_bmc_meta_data(request)
        .await
        .map(|response| response.into_inner())
        .map_err(HealthError::ApiInvocationError);
    histogram.record(1000.0 * start_time.elapsed().as_secs_f64(), &[]);
    let response = response?;

    let endpoint = libredfish::Endpoint {
        host: response.ip,
        port: response.port.map(|p| p as u16),
        user: Some(response.user),
        password: Some(response.password),
    };
    Ok(endpoint)
}

pub struct HealthMetricsState {
    registry: prometheus::Registry,
    //logger: Logger,
}

pub async fn serve_metrics(
    req: Request<Incoming>,
    state: Arc<HealthMetricsState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = state.registry.gather();
            match encoder.encode(&metric_families, &mut buffer) {
                Ok(_) => Response::builder()
                    .status(200)
                    .header(CONTENT_TYPE, encoder.format_type())
                    .header(CONTENT_LENGTH, buffer.len())
                    .body(buffer.into()),
                Err(e) => Response::builder()
                    .status(500)
                    .body(format!("Encoding error: {e}").into()),
            }
        }
        (&Method::GET, "/") => Response::builder().status(200).body("/metrics".into()),
        _ => Response::builder().status(404).body("Invalid URL".into()),
    };

    Ok(response.expect("BUG: Response::builder error"))
}

// setup the /metrics prometheus endpoint, adapted from:
// https://github.com/open-telemetry/opentelemetry-rust/blob/main/opentelemetry-prometheus/examples/hyper.rs
// and carbide/api/src/logging/metrics_endpoint.rs
pub async fn metrics_listener(state: Arc<HealthMetricsState>) -> Result<(), io::Error> {
    // using port 9009, configured for scraping by prometheus
    let listen_address = SocketAddr::from(([0, 0, 0, 0], 9009));
    let listener = TcpListener::bind(listen_address).await?;

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::task::spawn(async move {
            let state = state.clone();
            auto::Builder::new(TokioExecutor::new())
                .serve_connection(
                    io,
                    service_fn(move |req: Request<body::Incoming>| {
                        serve_metrics(req, state.clone())
                    }),
                )
                .await
        });
    }
}

pub async fn scrape_machines_health(
    provider: SdkMeterProvider,
    logger: Arc<dyn Logger<LogRecord = opentelemetry_sdk::logs::SdkLogRecord> + Send + Sync>,
    config: Options,
) -> Result<(), HealthError> {
    // we may eventually want a config for this service with these items:
    // metrics listener address, bmcs polling interval
    let root_ca = get_forge_root_ca_path(Some(config.root_ca));
    let client_certs = get_client_cert_info(Some(config.client_cert), Some(config.client_key));
    let mut grpc_client = create_forge_client(
        root_ca,
        client_certs.cert_path,
        client_certs.key_path,
        config.api,
    )
    .await?;

    let mut machines_hash: HashMap<String, HealthHashData> = HashMap::new();

    // build a meter for carbide api response time
    let api_meter = provider.meter("api-server-client");

    let find_machines_latency_histogram = api_meter
        .f64_histogram("forge_hardware_health_findmachines_latency")
        .with_description("api server response time for FindMachines")
        .with_unit("ms")
        .build();

    let get_bmc_metadata_latency_histogram = api_meter
        .f64_histogram("forge_hardware_health_getbmcmetadata_latency")
        .with_description("api server response time for GetBMCMetaData")
        .with_unit("ms")
        .build();

    let iteration_latency_histogram = api_meter
        .f64_histogram("forge_hardware_health_iteration_latency")
        .with_description("The time it took to perform one hardware health monitor iteration")
        .with_unit("ms")
        .build();

    loop {
        let loop_start = std::time::Instant::now();
        let get_machines_result = get_machines(&mut grpc_client).await;
        find_machines_latency_histogram.record(1000.0 * loop_start.elapsed().as_secs_f64(), &[]);
        let machines = match get_machines_result {
            Ok(machines) => machines,
            Err(e) => {
                tracing::error!("Failed to fetch Machine list: {e}");
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                continue;
            }
        };

        // Only keep active machines in machines_hash
        let active_ids: HashSet<String> = machines
            .machines
            .iter()
            .filter_map(|m| m.id.as_ref().map(|machine_id| machine_id.id.clone()))
            .collect();
        machines_hash.retain(|id, _| active_ids.contains(id));

        for machine in machines.machines {
            let Some(id) = machine.id.as_ref() else {
                continue;
            };
            let machine_id = id.id.as_str();
            let health_data = machines_hash.entry(machine_id.to_owned()).or_insert_with(||
                // insert into hash on first enumeration of the machine
                HealthHashData {
                    description: "".to_string(),
                    firmware_digest: "".to_string(),
                    sel_count: 0,
                    last_polled_ts: 0,
                    last_recorded_ts: 0,
                    last_host_error_ts: 0,
                    last_dpu_error_ts: 0,
                    host_error_count: 0,
                    dpu_error_count: 0,
                    host: "".to_string(),
                    dpu: "".to_string(),
                    port: 0,
                    dpu_port: 0,
                    user: "".to_string(),
                    dpu_user: "".to_string(),
                    password: "".to_string(),
                    dpu_password: "".to_string(),
            });

            let mut scrape_machine = true;
            // check if a host had errors and back off querying appropriately
            if health_data.host_error_count > 0 {
                let now: DateTime<Utc> = Utc::now();
                if health_data.host_error_count < 24 {
                    // try every 30 minutes for 12 hours
                    if (now.timestamp() - health_data.last_host_error_ts) < (30 * 60) {
                        scrape_machine = false;
                    }
                } else if health_data.host_error_count < 36 {
                    // try every 60 minutes for next 12 hours
                    if (now.timestamp() - health_data.last_host_error_ts) < (60 * 60) {
                        scrape_machine = false;
                    }
                } else {
                    // try once a day
                    if (now.timestamp() - health_data.last_host_error_ts) < (24 * 60 * 60) {
                        scrape_machine = false;
                    }
                }
            }
            if !scrape_machine {
                continue;
            }

            if health_data.host.is_empty() {
                // initial empty hash, get host bmc creds from api-server
                let endpoint = match get_machine_bmc_data(
                    &mut grpc_client,
                    id,
                    &get_bmc_metadata_latency_histogram,
                )
                .await
                {
                    Ok(x) => {
                        health_data.last_host_error_ts = 0;
                        health_data.host_error_count = 0;
                        x
                    }
                    Err(e) => {
                        // some hosts bmc data may error out at times due to creds missing in vault
                        error!(error=%e, %machine_id, "grpc error getting machine bmc metadata");
                        // back off for grpc / vault errors for a host
                        let now: DateTime<Utc> = Utc::now();
                        health_data.last_host_error_ts = now.timestamp();
                        health_data.host_error_count += 1;
                        continue;
                    }
                };
                if let Some(dmi_data) = machine
                    .discovery_info
                    .as_ref()
                    .and_then(|i| i.dmi_data.as_ref())
                {
                    health_data.description = format!(
                        "{} {} SN: {}",
                        dmi_data.sys_vendor, dmi_data.product_name, dmi_data.product_serial
                    )
                    .to_string();
                }
                health_data.host = endpoint.host;
                health_data.port = endpoint.port.unwrap_or(0);
                health_data.user = endpoint.user.unwrap_or("".to_string());
                health_data.password = endpoint.password.unwrap_or("".to_string());
            }

            if health_data.dpu.is_empty() {
                // dpu bmc creds
                let now: DateTime<Utc> = Utc::now();
                let mut scrape_dpu = true;
                if health_data.dpu_error_count < 24 {
                    // try every 30 minutes for 12 hours
                    if (now.timestamp() - health_data.last_dpu_error_ts) < (30 * 60) {
                        scrape_dpu = false;
                    }
                } else if health_data.dpu_error_count < 36 {
                    // try every 60 minutes for next 12 hours
                    if (now.timestamp() - health_data.last_dpu_error_ts) < (60 * 60) {
                        scrape_dpu = false;
                    }
                } else {
                    // try once a day
                    if (now.timestamp() - health_data.last_dpu_error_ts) < (24 * 60 * 60) {
                        scrape_dpu = false;
                    }
                }
                if let (Some(dpu_id), true) = (
                    attached_dpu_machine_id_for_primary_interface(&machine),
                    scrape_dpu,
                ) {
                    let dpu_endpoint = match get_machine_bmc_data(
                        &mut grpc_client,
                        dpu_id,
                        &get_bmc_metadata_latency_histogram,
                    )
                    .await
                    {
                        Ok(x) => {
                            health_data.last_dpu_error_ts = 0;
                            health_data.dpu_error_count = 0;
                            Some(x)
                        }
                        Err(e) => {
                            error!(error=%e, %dpu_id, "grpc error getting dpu bmc metadata");
                            let now: DateTime<Utc> = Utc::now();
                            health_data.last_dpu_error_ts = now.timestamp();
                            health_data.dpu_error_count += 1;
                            None
                        }
                    };
                    if let Some(dpu_endpoint) = dpu_endpoint {
                        health_data.dpu = dpu_endpoint.host.clone();
                        health_data.dpu_port = dpu_endpoint.port.unwrap_or(0);
                        health_data.dpu_user = dpu_endpoint.user.clone().unwrap_or("".to_string());
                        health_data.dpu_password =
                            dpu_endpoint.password.clone().unwrap_or("".to_string());
                    }
                }
            }

            match scrape_machine_health(
                &mut grpc_client,
                provider.clone(),
                logger.clone(),
                machine_id,
                health_data,
            )
            .await
            {
                Ok((
                    firmware_digest,
                    sel_count,
                    last_polled_ts,
                    last_recorded_ts,
                    dpu_reachable,
                    dpu_attempted,
                )) => {
                    if !firmware_digest.is_empty() {
                        health_data.firmware_digest = firmware_digest.to_string();
                    }
                    if sel_count > 0 {
                        health_data.sel_count = sel_count;
                    }
                    if last_polled_ts > 0 {
                        health_data.last_polled_ts = last_polled_ts;
                    }
                    if last_recorded_ts > 0 {
                        health_data.last_recorded_ts = last_recorded_ts;
                    }
                    if dpu_reachable {
                        health_data.last_dpu_error_ts = 0;
                        health_data.dpu_error_count = 0;
                    } else if dpu_attempted {
                        let now: DateTime<Utc> = Utc::now();
                        health_data.last_dpu_error_ts = now.timestamp();
                        health_data.dpu_error_count += 1;
                    }
                    health_data.last_host_error_ts = 0;
                    health_data.host_error_count = 0;
                }
                Err(e) => {
                    error!(error=%e, %machine_id, "failed to scrape metrics");
                    let now: DateTime<Utc> = Utc::now();
                    health_data.last_host_error_ts = now.timestamp();
                    health_data.host_error_count += 1;
                    continue;
                }
            };
        }

        let elapsed = loop_start.elapsed();
        iteration_latency_histogram.record(1000.0 * elapsed.as_secs_f64(), &[]);

        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

fn init_logging() -> Result<
    Arc<dyn Logger<LogRecord = opentelemetry_sdk::logs::SdkLogRecord> + Send + Sync>,
    LogError,
> {
    let provider = SdkLoggerProvider::builder()
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_attributes(vec![opentelemetry::KeyValue::new(
                    "carbide-hardware-health",
                    "machine-logs",
                )])
                .build(),
        )
        .with_batch_exporter(
            LogExporter::builder()
                .with_tonic()
                .with_endpoint("http://opentelemetry-collector.otel.svc.cluster.local:4317")
                .build()?,
        )
        .build();
    Ok(Arc::new(provider.logger("health")))
}

#[tokio::main]
async fn main() -> Result<(), HealthError> {
    let config = Options::load();
    if config.version {
        println!("{}", forge_version::version!());
        return Ok(());
    }

    let registry = prometheus::Registry::new();
    let exporter = opentelemetry_prometheus::exporter()
        .with_registry(registry.clone())
        .build()?;

    let provider = SdkMeterProvider::builder().with_reader(exporter).build();

    // logger only for pushing bmc / machine scraped events and data, not this service's logs
    let logger_provider = init_logging()?;

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::Layer::default().compact())
        .with(env_filter)
        .init();

    let state = Arc::new(HealthMetricsState { registry });

    tracing::info!(
        version = forge_version::v!(build_version),
        "Started forge-hw-health"
    );
    let join_listener = tokio::spawn(async move { metrics_listener(state).await });

    let join_scraper =
        tokio::spawn(
            async move { scrape_machines_health(provider, logger_provider, config).await },
        );

    let _ = join_scraper.await?;
    let _ = join_listener.await?;

    tracing::info!(
        version = forge_version::v!(build_version),
        "Stopped forge-hw-health"
    );

    Ok(())
}

fn attached_dpu_machine_id_for_primary_interface(machine: &Machine) -> Option<&MachineId> {
    let machine_id = machine
        .id
        .as_ref()
        .map(|id| id.id.as_str())
        .unwrap_or("<unknown>");
    let Some(primary_interface) = machine.interfaces.iter().find(|i| i.primary_interface) else {
        tracing::warn!(%machine_id, interfaces = ?machine.interfaces, "machine has no primary interface, health data will not include DPU info.");
        return None;
    };

    let Some(dpu_id) = primary_interface.attached_dpu_machine_id.as_ref() else {
        tracing::warn!(%machine_id, interfaces = ?machine.interfaces, "machine's primary interface is not a DPU, health data will not include DPU info.");
        return None;
    };

    Some(dpu_id)
}
