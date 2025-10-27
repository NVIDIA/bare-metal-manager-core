/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;

use axum::Router;

use crate::instance_metadata_endpoint::{InstanceMetadataRouterStateImpl, get_fmds_router};
use crate::instrumentation::{
    AgentMetricsState, WithTracingLayer, get_metrics_router, get_prometheus_registry,
};

pub fn spawn_metadata_service(
    metadata_service_address: String,
    metrics_address: String,
    metrics_state: Arc<AgentMetricsState>,
    state: Arc<InstanceMetadataRouterStateImpl>,
) -> Result<(), Box<dyn std::error::Error>> {
    let instance_metadata_state = state;

    let prometheus_registry = get_prometheus_registry();
    // let meter = get_dpu_agent_meter();
    // let metrics_state = create_metrics(meter);

    start_server(
        metadata_service_address,
        Router::new()
            .nest(
                "/latest",
                get_fmds_router(instance_metadata_state.clone())
                    .with_tracing_layer(metrics_state.clone()),
            )
            .nest(
                "/2009-04-04",
                get_fmds_router(instance_metadata_state).with_tracing_layer(metrics_state),
            ),
    )
    .expect("metadata server panicked");

    start_server(
        metrics_address,
        Router::new().nest("/metrics", get_metrics_router(prometheus_registry)),
    )
}

/// Spawns a background task to run an axum server listening on given socket, and returns.
fn start_server(address: String, router: Router) -> Result<(), Box<dyn std::error::Error>> {
    let addr: std::net::SocketAddr = address.parse()?;
    let server = axum_server::Server::bind(addr);

    tokio::spawn(async move {
        if let Err(err) = server.serve(router.into_make_service()).await {
            eprintln!("Error while serving: {err}");
        }
    });

    Ok(())
}
