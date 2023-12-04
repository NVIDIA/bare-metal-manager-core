/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use arc_swap::ArcSwap;
use tracing::{error, trace, warn};

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ForgeClientConfig};

pub struct NetworkConfigReader {
    state: Arc<NetworkConfigFetcherState>,
}

impl NetworkConfigReader {
    /// Reads the latest desired network configuration obtained from the Forge
    /// Site controller
    pub fn read(&self) -> Arc<Option<rpc::ManagedHostNetworkConfigResponse>> {
        self.state.current.load_full()
    }
}

struct NetworkConfigFetcherState {
    current: ArcSwap<Option<rpc::ManagedHostNetworkConfigResponse>>,
    config: NetworkConfigFetcherConfig,
    is_cancelled: AtomicBool,
}

/// Fetches the desired network configuration for a managed host in regular intervals
pub struct NetworkConfigFetcher {
    state: Arc<NetworkConfigFetcherState>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for NetworkConfigFetcher {
    fn drop(&mut self) {
        // Signal the background task and wait for it to shut down
        // TODO: Might be nicer if it would be interrupted during waiting for 30s,
        self.state
            .is_cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(jh) = self.join_handle.take() {
            // In main.rs we have a shutdown_timeout on the runtime
            // so this should get to run.
            tokio::spawn(async move {
                jh.await.unwrap();
            });
        }
    }
}

impl NetworkConfigFetcher {
    pub async fn new(config: NetworkConfigFetcherConfig) -> Self {
        let forge_client_config = config.forge_client_config.clone();
        let state = Arc::new(NetworkConfigFetcherState {
            current: ArcSwap::default(),
            config,
            is_cancelled: AtomicBool::new(false),
        });

        // Do an initial synchronous fetch so that caller has data to use
        // This gets a DPU on the network immediately
        single_fetch(forge_client_config.clone(), state.clone()).await;

        let task_state = state.clone();
        let join_handle = tokio::spawn(async move {
            while single_fetch(forge_client_config.clone(), task_state.clone()).await {
                tokio::time::sleep(task_state.config.config_fetch_interval).await;
            }
        });

        Self {
            state,
            join_handle: Some(join_handle),
        }
    }

    /// Returns a reader for fetching the latest retrieved network config
    pub fn reader(&self) -> Box<NetworkConfigReader> {
        Box::new(NetworkConfigReader {
            state: self.state.clone(),
        })
    }
}

pub struct NetworkConfigFetcherConfig {
    /// The interval in which the config is fetched
    pub config_fetch_interval: Duration,
    pub machine_id: String,
    pub forge_api: String,
    pub forge_client_config: ForgeClientConfig,
}

async fn single_fetch(
    forge_client_config: ForgeClientConfig,
    state: Arc<NetworkConfigFetcherState>,
) -> bool {
    if state
        .is_cancelled
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        trace!("NetworkConfigReader was dropped. Stopping config reading");
        return false; // exit fetching thread
    }

    trace!(
        "Fetching managed host network configuration for Machine {}",
        state.config.machine_id
    );

    match fetch(
        &state.config.machine_id,
        &state.config.forge_api,
        forge_client_config,
    )
    .await
    {
        Ok(config) => {
            state.current.store(Arc::new(Some(config)));
        }
        Err(err) => match err.downcast_ref::<tonic::Status>() {
            Some(grpc_status) if grpc_status.code() == tonic::Code::NotFound => {
                warn!("DPU not found: {}", state.config.machine_id);
                state.current.store(Arc::new(None));
            }
            _ => {
                error!(
                    "Failed to fetch the latest configuration. Will retry in {:?}. {err:#?}",
                    state.config.config_fetch_interval
                );
            }
        },
    };

    true
}

/// Make the network request to get network config
pub async fn fetch(
    dpu_machine_id: &str,
    forge_api: &str,
    forge_client_config: ForgeClientConfig,
) -> Result<rpc::ManagedHostNetworkConfigResponse, eyre::Report> {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_client_config)
        .connect(forge_api)
        .await
    {
        Ok(client) => client,
        Err(err) => {
            return Err(err.wrap_err(format!(
                "Could not connect to Forge API server at {forge_api}"
            )));
        }
    };
    let request = tonic::Request::new(rpc::ManagedHostNetworkConfigRequest {
        dpu_machine_id: Some(rpc::MachineId {
            id: dpu_machine_id.to_string(),
        }),
    });

    let config = match client.get_managed_host_network_config(request).await {
        Ok(config) => config.into_inner(),
        Err(err) => {
            return Err(eyre::Report::new(err)
                .wrap_err("Error while executing the GetManagedHostNetworkConfig gRPC call"));
        }
    };

    Ok(config)
}
