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
use fmds::nic_init;
use fmds::rest_server::get_fmds_router;
use fmds::state::FmdsState;
use forge_tls::client_config::ClientCert;
use rpc::fmds::fmds_config_service_server::FmdsConfigServiceServer;
use rpc::forge_tls_client::ForgeClientConfig;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let options = Options::parse();

    if options.version {
        println!("{}", carbide_version::version!());
        return Ok(());
    }

    tracing::info!(
        version = carbide_version::version!(),
        "Starting carbide-fmds"
    );

    let interface_cidr: ipnetwork::IpNetwork = options.interface_cidr.parse()?;
    nic_init::assign_address(&options.interface_name, interface_cidr).await?;

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

    let state = Arc::new(FmdsState::new(
        options.forge_api.clone(),
        forge_client_config,
    ));

    // Start REST server for tenant metadata queries
    let rest_state = state.clone();
    let rest_address = options.rest_address.clone();
    tokio::spawn(async move {
        // We serve metadata under both /latest and /2009-04-04 for
        // compatibility with cloud-init, which uses the AWS EC2 instance
        // metadata API versioned path format.
        let router = axum::Router::new()
            .nest("/latest", get_fmds_router(rest_state.clone()))
            .nest("/2009-04-04", get_fmds_router(rest_state));

        let addr: std::net::SocketAddr = rest_address.parse().expect("invalid REST address");
        let server = axum_server::Server::bind(addr);

        tracing::info!(%addr, "REST server listening");
        if let Err(err) = server.serve(router.into_make_service()).await {
            tracing::error!("REST server error: {err}");
        }
    });

    // Start gRPC server for receiving config updates from agent
    let grpc_address: std::net::SocketAddr =
        options.grpc_address.parse().expect("invalid gRPC address");

    let grpc_server = FmdsGrpcServer::new(state);

    tracing::info!(%grpc_address, "gRPC server listening");
    tonic::transport::Server::builder()
        .add_service(FmdsConfigServiceServer::new(grpc_server))
        .serve(grpc_address)
        .await?;

    Ok(())
}
