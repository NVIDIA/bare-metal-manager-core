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
use cfg::Options;
use chrono::{DateTime, Utc};
use eyre::Result;
use prometheus::{Encoder, TextEncoder};
use std::collections::HashMap;
use std::convert::Infallible;
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ::rpc::forge::{self as rpc};
use ::rpc::forge_tls_client::{self, ForgeClientCert, ForgeClientConfig, ForgeClientT};
use ::rpc::MachineId;

use http::header::CONTENT_LENGTH;
use hyper::{
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server,
};
use opentelemetry::global::{logger_provider, GlobalLoggerProvider, ObjectSafeLoggerProvider};
use opentelemetry::logs::LogError;
use opentelemetry::metrics::ObservableGauge;
use opentelemetry::metrics::{MeterProvider as _, Unit};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::MeterProvider;

use tracing::error;

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
    OpentelemetryError(#[from] opentelemetry::metrics::MetricsError),

    #[error("Generic error: {0}")]
    LogErr(#[from] LogError),

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
    let forge_client_config = ForgeClientConfig::new(
        root_ca,
        Some(ForgeClientCert {
            cert_path: client_cert,
            key_path: client_key,
        }),
    );

    let client = forge_tls_client::ForgeTlsClient::new(forge_client_config)
        .connect(&api_url)
        .await
        .map_err(|err| HealthError::ApiConnectFailed(err.to_string()))?;
    Ok(client)
}

pub async fn get_machines(
    client: &mut ForgeClientT,
    gauge: &ObservableGauge<i64>,
) -> Result<rpc::MachineList, HealthError> {
    let request = tonic::Request::new(rpc::MachineSearchQuery {
        id: None,
        fqdn: None,
        search_config: Some(rpc::MachineSearchConfig {
            include_dpus: false,
            include_history: false,
            include_predicted_host: false,
            only_maintenance: false,
            include_associated_machine_id: false,
        }),
    });
    let begin_ts: DateTime<Utc> = Utc::now();
    let machines = client
        .find_machines(request)
        .await
        .map(|response| response.into_inner())
        .map_err(HealthError::ApiInvocationError)?;
    let end_ts: DateTime<Utc> = Utc::now();
    let elapsed = end_ts.timestamp_micros() - begin_ts.timestamp_micros();
    gauge.observe(elapsed, &[]);

    Ok(machines)
}

pub async fn get_machine(
    client: &mut ForgeClientT,
    id: &MachineId,
    gauge: &ObservableGauge<i64>,
) -> Result<libredfish::Endpoint, HealthError> {
    let request = tonic::Request::new(rpc::BmcMetaDataGetRequest {
        machine_id: Some(id.clone()),
        role: rpc::UserRoles::Administrator.into(),
        request_type: rpc::BmcRequestType::Ipmi.into(),
    });
    let begin_ts: DateTime<Utc> = Utc::now();
    let response = client
        .get_bmc_meta_data(request)
        .await
        .map(|response| response.into_inner())
        .map_err(HealthError::ApiInvocationError)?;
    let end_ts: DateTime<Utc> = Utc::now();
    let elapsed = end_ts.timestamp_micros() - begin_ts.timestamp_micros();
    gauge.observe(elapsed, &[]);

    let endpoint = libredfish::Endpoint {
        host: response.ip,
        port: None,
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
    // using port 9009, configured for scraping by prometheus
    let listen_address = ([0, 0, 0, 0], 9009).into();
    let server = Server::bind(&listen_address).serve(make_svc);
    server.await?;
    Ok(())
}

pub async fn scrape_machines_health(
    provider: MeterProvider,
    logger: GlobalLoggerProvider,
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

    let box_logger = Arc::new(logger.boxed_logger(Arc::new(Default::default())));

    let mut machines_hash: HashMap<String, HealthHashData> = HashMap::new();

    // build a meter for carbide api response time
    let api_meter = provider.meter("api-server-client".to_string());
    let api_gauge_1 = api_meter
        .i64_observable_gauge("api.findmachines.latency")
        .with_description("api server response time for FindMachines")
        .with_unit(Unit::new("microseconds"))
        .init();
    let api_gauge_2 = api_meter
        .i64_observable_gauge("api.getbmcmetadata.latency")
        .with_description("api server response time for GetBMCMetaData")
        .with_unit(Unit::new("microseconds"))
        .init();

    loop {
        let machines: rpc::MachineList = get_machines(&mut grpc_client, &api_gauge_1).await?;
        for machine in machines.machines.iter() {
            if machine.id.is_none() {
                continue;
            }
            let id = machine.id.clone().unwrap();
            let machine_id: Box<String> = Box::from(id.clone().id);
            if machine.interfaces.is_empty() {
                continue;
            }

            let dpu_id = machine.interfaces[0]
                .attached_dpu_machine_id
                .clone()
                .unwrap();

            let mut last_updated = match machines_hash.get_mut(machine_id.as_str()) {
                Some(x) => x.deref().to_owned(),
                None => {
                    let initial_hash = HealthHashData {
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
                    };

                    // insert into hash on first enumeration of the machine
                    let _ = machines_hash.insert(machine_id.to_string(), initial_hash.clone());
                    initial_hash
                }
            };

            let mut scrape_machine = true;
            // check if a host had errors and back off querying appropriately
            if last_updated.host_error_count > 0 {
                let now: DateTime<Utc> = Utc::now();
                if last_updated.host_error_count < 24 {
                    // try every 30 minutes for 12 hours
                    if (now.timestamp() - last_updated.last_host_error_ts) < (30 * 60) {
                        scrape_machine = false;
                    }
                } else if last_updated.host_error_count < 36 {
                    // try every 60 minutes for next 12 hours
                    if (now.timestamp() - last_updated.last_host_error_ts) < (60 * 60) {
                        scrape_machine = false;
                    }
                } else {
                    // try once a day
                    if (now.timestamp() - last_updated.last_host_error_ts) < (24 * 60 * 60) {
                        scrape_machine = false;
                    }
                }
            }
            if !scrape_machine {
                continue;
            }

            if last_updated.host.is_empty() {
                // initial empty hash, get host bmc creds from api-server
                let endpoint = match get_machine(&mut grpc_client, &id, &api_gauge_2).await {
                    Ok(x) => {
                        machines_hash
                            .get_mut(machine_id.as_str())
                            .unwrap()
                            .last_host_error_ts = 0;
                        machines_hash
                            .get_mut(machine_id.as_str())
                            .unwrap()
                            .host_error_count = 0;
                        x
                    }
                    Err(e) => {
                        // some hosts bmc data may error out at times due to creds missing in vault
                        error!(error=%e, %machine_id, "grpc error getting machine bmc metadata");
                        // back off for grpc / vault errors for a host
                        let now: DateTime<Utc> = Utc::now();
                        machines_hash
                            .get_mut(machine_id.as_str())
                            .unwrap()
                            .last_host_error_ts = now.timestamp();
                        machines_hash
                            .get_mut(machine_id.as_str())
                            .unwrap()
                            .host_error_count += 1;
                        continue;
                    }
                };
                let mut description = String::new();
                if machine.discovery_info.is_some()
                    && machine.discovery_info.clone().unwrap().dmi_data.is_some()
                {
                    description = format!(
                        "{} {} SN: {}",
                        machine
                            .discovery_info
                            .clone()
                            .unwrap()
                            .dmi_data
                            .unwrap()
                            .sys_vendor,
                        machine
                            .discovery_info
                            .clone()
                            .unwrap()
                            .dmi_data
                            .unwrap()
                            .product_name,
                        machine
                            .discovery_info
                            .clone()
                            .unwrap()
                            .dmi_data
                            .unwrap()
                            .product_serial
                    )
                    .to_string();
                }
                last_updated.description = description;
                last_updated.host = endpoint.host;
                last_updated.port = endpoint.port.unwrap_or(0);
                last_updated.user = endpoint.user.unwrap_or("".to_string());
                last_updated.password = endpoint.password.unwrap_or("".to_string());
            }

            if last_updated.dpu.is_empty() {
                // dpu bmc creds
                let now: DateTime<Utc> = Utc::now();
                let mut scrape_dpu = true;
                if last_updated.dpu_error_count < 24 {
                    // try every 30 minutes for 12 hours
                    if (now.timestamp() - last_updated.last_dpu_error_ts) < (30 * 60) {
                        scrape_dpu = false;
                    }
                } else if last_updated.dpu_error_count < 36 {
                    // try every 60 minutes for next 12 hours
                    if (now.timestamp() - last_updated.last_dpu_error_ts) < (60 * 60) {
                        scrape_dpu = false;
                    }
                } else {
                    // try once a day
                    if (now.timestamp() - last_updated.last_dpu_error_ts) < (24 * 60 * 60) {
                        scrape_dpu = false;
                    }
                }
                if scrape_dpu {
                    let dpu_endpoint =
                        match get_machine(&mut grpc_client, &dpu_id, &api_gauge_2).await {
                            Ok(x) => {
                                last_updated.last_dpu_error_ts = 0;
                                last_updated.dpu_error_count = 0;
                                Some(x)
                            }
                            Err(e) => {
                                error!(error=%e, %dpu_id, "grpc error getting dpu bmc metadata");
                                let now: DateTime<Utc> = Utc::now();
                                last_updated.last_dpu_error_ts = now.timestamp();
                                last_updated.dpu_error_count += 1;
                                None
                            }
                        };
                    if dpu_endpoint.is_some() {
                        last_updated.dpu = dpu_endpoint.clone().unwrap().host;
                        last_updated.dpu_port = dpu_endpoint.clone().unwrap().port.unwrap_or(0);
                        last_updated.dpu_user =
                            dpu_endpoint.clone().unwrap().user.unwrap_or("".to_string());
                        last_updated.dpu_password = dpu_endpoint
                            .clone()
                            .unwrap()
                            .password
                            .unwrap_or("".to_string());
                    }
                }
            }

            match scrape_machine_health(
                provider.clone(),
                box_logger.clone(),
                machine_id.as_str(),
                last_updated,
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
                    let update_hash = machines_hash.get_mut(machine_id.as_str()).unwrap();
                    if !firmware_digest.is_empty() {
                        update_hash.firmware_digest = firmware_digest.to_string();
                    }
                    if sel_count > 0 {
                        update_hash.sel_count = sel_count;
                    }
                    if last_polled_ts > 0 {
                        update_hash.last_polled_ts = last_polled_ts;
                    }
                    if last_recorded_ts > 0 {
                        update_hash.last_recorded_ts = last_recorded_ts;
                    }
                    if dpu_reachable {
                        update_hash.last_dpu_error_ts = 0;
                        update_hash.dpu_error_count = 0;
                    } else if dpu_attempted {
                        let now: DateTime<Utc> = Utc::now();
                        update_hash.last_dpu_error_ts = now.timestamp();
                        update_hash.dpu_error_count += 1;
                    }
                    update_hash.last_host_error_ts = 0;
                    update_hash.host_error_count = 0;
                }
                Err(e) => {
                    error!(error=%e, %machine_id, "failed to scrape metrics");
                    let update_hash = machines_hash.get_mut(machine_id.as_str()).unwrap();
                    let now: DateTime<Utc> = Utc::now();
                    update_hash.last_host_error_ts = now.timestamp();
                    update_hash.host_error_count += 1;
                    continue;
                }
            };
        }

        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

fn init_logging() -> Result<opentelemetry_sdk::logs::Logger, LogError> {
    opentelemetry_otlp::new_pipeline()
        .logging()
        .with_log_config(opentelemetry_sdk::logs::Config::default().with_resource(
            opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new(
                "carbide-hardware-health",
                "machine-logs",
            )]),
        ))
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint("http://opentelemetry-collector.otel.svc.cluster.local:4317"),
        )
        .install_batch(opentelemetry_sdk::runtime::Tokio)
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
    let provider = MeterProvider::builder().with_reader(exporter).build();
    // logger only for pushing bmc / machine scraped events and data, not this service's logs
    let _logger = init_logging()?;
    let logger_provider = logger_provider();

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
