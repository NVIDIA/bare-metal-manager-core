/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::sync::Arc;

use clap::Parser;
use fmds::cfg::Options;
use fmds::grpc_server::FmdsGrpcServer;
use fmds::rest_server::get_fmds_router;
use fmds::state::FmdsState;
use fmds::{http_request_metrics, nic_init};
use forge_tls::client_config::ClientCert;
use rpc::fmds::fmds_config_service_server::FmdsConfigServiceServer;
use rpc::forge_tls_client::ForgeClientConfig;
use tracing::metadata::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

pub fn subscriber() -> impl SubscriberInitExt {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("sqlx=info".parse().unwrap())
        .add_directive("tokio_util::codec=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap())
        .add_directive("hickory_resolver::error=info".parse().unwrap())
        .add_directive("hickory_proto::xfer=info".parse().unwrap())
        .add_directive("hickory_resolver::name_server=info".parse().unwrap())
        .add_directive("hickory_proto=info".parse().unwrap())
        .add_directive("netlink_proto=warn".parse().unwrap());
    let stdout_formatter = logfmt::layer()
        .with_event_fields([logfmt::EventField::with_default("component", "nico-fmds")]);
    let log_events = carbide_instrument::LogEventsMetric::new("nico-fmds");
    Box::new(
        tracing_subscriber::registry()
            .with(log_events.layer().with_filter(env_filter.clone()))
            .with(stdout_formatter.with_filter(env_filter)),
    )
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let subscriber = subscriber();
    subscriber
        .try_init()
        .expect("tracing_subscriber setup failed");
    tracing::error!("Starting fmds...");
    let options = Options::parse();

    if options.version {
        println!("{}", carbide_version::version!());
        return Ok(());
    }

    tracing::info!(
        version = carbide_version::version!(),
        "Starting carbide-fmds"
    );

    nic_init::assign_address(&options.interface_name, options.interface_cidr).await?;
    nic_init::setup_metadata_routing(&options.interface_name, options.interface_cidr).await?;

    // Build ForgeClientConfig for phone_home if cert paths are provided
    let forge_client_config = match (&options.root_ca, &options.client_cert, &options.client_key) {
        (Some(root_ca), Some(client_cert), Some(client_key)) => {
            Some(Arc::new(ForgeClientConfig::new(
                root_ca.clone(),
                Some(ClientCert {
                    cert_path: client_cert.clone(),
                    key_path: client_key.clone(),
                }),
            )))
        }
        _ => {
            tracing::warn!(
                "No TLS credentials provided; phone_home to carbide-api will be unavailable"
            );
            None
        }
    };

    let state = Arc::new(
        FmdsState::try_new(options.forge_api.clone(), forge_client_config)
            .map_err(|e| eyre::eyre!("failed to initialize FMDS state: {e}"))?,
    );

    let (prometheus_registry, http_request_metrics_state) = http_request_metrics::init()?;
    // init() installed the global meter provider, so the log-event counter can register now.
    carbide_instrument::log_events::register(&opentelemetry::global::meter("carbide-instrument"));
    let http_request_metrics_state = Arc::new(http_request_metrics_state);

    let metrics_address = options.metrics_address;
    let registry_for_metrics = prometheus_registry.clone();
    tokio::spawn(async move {
        let config = metrics_endpoint::MetricsEndpointConfig {
            address: metrics_address,
            registry: registry_for_metrics,
            health_controller: None,
            additional_prefix: None,
        };
        if let Err(err) = metrics_endpoint::run_metrics_endpoint(&config).await {
            tracing::error!(error = %err, "Prometheus metrics server error");
        }
    });

    // Start REST server for tenant metadata queries
    let rest_state = state.clone();
    let rest_address = options.rest_address;
    let rest_http_metrics = http_request_metrics_state.clone();
    tokio::spawn(async move {
        // We serve metadata under both /latest and /2009-04-04 for
        // compatibility with cloud-init, which uses the AWS EC2 instance
        // metadata API versioned path format.
        let router = axum::Router::new()
            .nest("/latest", get_fmds_router(rest_state.clone()))
            .nest("/2009-04-04", get_fmds_router(rest_state));
        let router = http_request_metrics::with_http_request_trace_layer(router, rest_http_metrics);

        let server = axum_server::Server::bind(rest_address);

        tracing::info!(%rest_address, "REST server listening");
        if let Err(err) = server.serve(router.into_make_service()).await {
            tracing::error!(error = %err, "REST server error");
        }
    });

    // Start gRPC server for receiving config updates from agent
    let grpc_server = FmdsGrpcServer::new(state);

    tracing::info!(%options.grpc_address, "gRPC server listening");
    tonic::transport::Server::builder()
        .add_service(FmdsConfigServiceServer::new(grpc_server))
        .serve(options.grpc_address)
        .await?;

    Ok(())
}
