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
use std::option::Option;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ::rpc::forge::{self as rpc};
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use cfg::{ConcurrencyOption, Options};
use chrono::{DateTime, Utc};
use eyre::Result;
use forge_tls::client_config::ClientCert;
use forge_uuid::machine::MachineId;
use futures::future;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{
    Method, Request, Response, body,
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;

use ::rpc::forge_api_client::ForgeApiClient;
use opentelemetry::logs::{Logger, LoggerProvider};
use opentelemetry::metrics::{Histogram, MeterProvider};
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::logs::{LogError, SdkLoggerProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, TextEncoder};
use rpc::Machine;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, MutexGuard};
use tracing::error;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod cfg;
mod metrics;
use crate::metrics::{HealthHashData, scrape_machine_health};

const DEFAULT_CONCURRENCY: usize = 32;

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
) -> Result<ForgeApiClient, HealthError> {
    let client_config = ForgeClientConfig::new(
        root_ca,
        Some(ClientCert {
            cert_path: client_cert,
            key_path: client_key,
        }),
    );
    let api_config = ApiConfig::new(&api_url, &client_config);

    let client = ForgeApiClient::new(&api_config);
    // Test the connection now, so that we don't do it N times in N different workers.
    client
        .connection()
        .await
        .map_err(|err| HealthError::ApiConnectFailed(err.to_string()))?;
    Ok(client)
}

pub async fn get_machines(client: &ForgeApiClient) -> Result<rpc::MachineList, HealthError> {
    let machine_ids = client
        .find_machine_ids(rpc::MachineSearchConfig::default())
        .await
        .map_err(HealthError::ApiInvocationError)?;
    let mut all_machines = rpc::MachineList {
        machines: Vec::with_capacity(machine_ids.machine_ids.len()),
    };
    for ids_chunk in machine_ids.machine_ids.chunks(100) {
        let request = ::rpc::forge::MachinesByIdsRequest {
            machine_ids: Vec::from(ids_chunk),
            ..Default::default()
        };
        let machines = client
            .find_machines_by_ids(request)
            .await
            .map_err(HealthError::ApiInvocationError)?;
        all_machines.machines.extend(machines.machines);
    }

    Ok(all_machines)
}

pub async fn get_machine_bmc_data(
    client: ForgeApiClient,
    id: &MachineId,
    histogram: Histogram<f64>,
) -> Result<libredfish::Endpoint, HealthError> {
    let request = rpc::BmcMetaDataGetRequest {
        machine_id: Some(*id),
        bmc_endpoint_request: None,
        role: rpc::UserRoles::Administrator.into(),
        request_type: rpc::BmcRequestType::Ipmi.into(),
    };
    let start_time = std::time::Instant::now();
    let response = client
        .get_bmc_meta_data(request)
        .await
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

pub async fn scrape_single_machine(
    machine: &Machine,
    mut health_data: MutexGuard<'_, HealthHashData>,
    grpc_client: ForgeApiClient,
    get_bmc_metadata_latency_histogram: Histogram<f64>,
    provider: SdkMeterProvider,
    logger: Arc<dyn Logger<LogRecord = opentelemetry_sdk::logs::SdkLogRecord> + Send + Sync>,
) {
    let Some(machine_id) = machine.id.as_ref() else {
        return;
    };

    let machine_serial = machine
        .discovery_info
        .as_ref()
        .and_then(|d| d.dmi_data.as_ref())
        .map(|dmi| dmi.chassis_serial.clone());

    let mut scrape_machine = true;
    // check if a host had errors and back off querying appropriately
    if health_data.host_error_count > 0 {
        let now: DateTime<Utc> = Utc::now();
        if health_data.host_error_count < 24 {
            // try every 5 minutes for 2 hours
            if (now.timestamp() - health_data.last_host_error_ts) < (5 * 60) {
                scrape_machine = false;
            }
        } else {
            // try every 15 minutes
            if (now.timestamp() - health_data.last_host_error_ts) < (15 * 60) {
                scrape_machine = false;
            }
        }
    }
    if !scrape_machine {
        return;
    }

    if health_data.host.is_empty() {
        // initial empty hash, get host bmc creds from api-server
        let endpoint = match get_machine_bmc_data(
            grpc_client.clone(),
            machine_id,
            get_bmc_metadata_latency_histogram.clone(),
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
                return;
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
            );
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
            attached_dpu_machine_id_for_primary_interface(machine),
            scrape_dpu,
        ) {
            let dpu_endpoint = match get_machine_bmc_data(
                grpc_client.clone(),
                dpu_id,
                get_bmc_metadata_latency_histogram.clone(),
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
                health_data.dpu_password = dpu_endpoint.password.unwrap_or("".to_string());
            }
        }
    }

    match scrape_machine_health(
        grpc_client.clone(),
        provider.clone(),
        logger,
        machine_id,
        machine_serial,
        &health_data,
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
                health_data.firmware_digest = firmware_digest;
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
        }
    };
}

async fn scrape_machines_concurrent(
    machines: Arc<Mutex<Vec<Machine>>>,
    machines_map: Arc<Mutex<HashMap<MachineId, Arc<Mutex<HealthHashData>>>>>,
    mut grpc_clients: Vec<ForgeApiClient>,
    get_bmc_metadata_latency_histogram: Histogram<f64>,
    provider: SdkMeterProvider,
    logger: Arc<dyn Logger<LogRecord = opentelemetry_sdk::logs::SdkLogRecord> + Send + Sync>,
) {
    let workers: Vec<_> = grpc_clients
        .iter_mut()
        .map(|client| {
            let work_items = machines.clone();
            let map = machines_map.clone();
            let client = client.clone();
            let logger = logger.clone();
            let provider = provider.clone();
            let histogram = get_bmc_metadata_latency_histogram.clone();

            tokio::spawn(async move {
                loop {
                    let machine = {
                        let mut guard = work_items.lock().await;
                        guard.pop()
                    };

                    match machine {
                        Some(machine) => {
                            let Some(machine_id) = machine.id else {
                                continue;
                            };
                            let pending_health_data =
                                map.lock().await.entry(machine_id).or_default().clone();
                            scrape_single_machine(
                                &machine,
                                pending_health_data.lock().await,
                                client.clone(),
                                histogram.clone(),
                                provider.clone(),
                                logger.clone(),
                            )
                            .await;
                        }
                        None => break,
                    }
                }
            })
        })
        .collect();

    let results: Vec<_> = future::join_all(workers).await;

    for result in results {
        if let Err(e) = result {
            tracing::error!("Concurrent scrape failed with error: {}", e);
        }
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
    let grpc_client = create_forge_client(
        root_ca.to_string(),
        client_certs.cert_path.to_string(),
        client_certs.key_path.to_string(),
        config.api.to_string(),
    )
    .await?;

    let concurrency = match config.concurrency {
        ConcurrencyOption::Default => DEFAULT_CONCURRENCY,
        ConcurrencyOption::MachineCount => 0,
        ConcurrencyOption::Custom(n) => n,
    };

    let mut grpc_clients: Vec<ForgeApiClient> =
        (0..concurrency).map(|_| grpc_client.clone()).collect();

    let machines_map: Arc<Mutex<HashMap<MachineId, Arc<Mutex<HealthHashData>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

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
        .with_unit("s")
        .with_boundaries(vec![
            0.0, 5.0, 10.0, 15.0, 20.0, 30.0, 40.0, 50.0, 60.0, 90.0, 120.0, 180.0, 300.0, 600.0,
            1800.0,
        ])
        .build();

    loop {
        let loop_start = std::time::Instant::now();
        let get_machines_result = get_machines(&grpc_client).await;
        find_machines_latency_histogram.record(1000.0 * loop_start.elapsed().as_secs_f64(), &[]);
        let machines = match get_machines_result {
            Ok(machines) => machines,
            Err(e) => {
                tracing::error!("Failed to fetch Machine list: {e}");
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                continue;
            }
        };

        if let ConcurrencyOption::MachineCount = config.concurrency {
            while grpc_clients.len() < machines.machines.len() {
                grpc_clients.push(grpc_client.clone());
            }
        }

        // Only keep active machines in machines_map
        let active_ids: HashSet<&MachineId> = machines
            .machines
            .iter()
            .filter_map(|m| m.id.as_ref())
            .collect();

        {
            let mut map_guard = machines_map.lock().await;
            map_guard.retain(|id, _| active_ids.contains(id));
        }

        scrape_machines_concurrent(
            Arc::new(Mutex::new(machines.machines)),
            machines_map.clone(),
            grpc_clients.clone(),
            get_bmc_metadata_latency_histogram.clone(),
            provider.clone(),
            logger.clone(),
        )
        .await;

        let elapsed = loop_start.elapsed();
        iteration_latency_histogram.record(elapsed.as_secs_f64(), &[]);

        // If it took less than a minute to scrape all the machines, sleep the remainder of the
        // minute, or 5 seconds minimum.
        let remaining_sleep_time = Duration::from_secs(60).saturating_sub(elapsed);
        let sleep_time = remaining_sleep_time.max(Duration::from_secs(5));
        tokio::time::sleep(sleep_time).await;
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
        .map(|id| id.to_string())
        .unwrap_or_else(|| "<unknown>".to_string());
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
