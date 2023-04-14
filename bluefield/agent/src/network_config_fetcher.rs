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
    thread::sleep,
    time::Duration,
};

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client;
use arc_swap::ArcSwap;
use tracing::{error, trace};

/// The desired DPU configuration for a ManagedHost - as fetched from the
/// Forge Site Controller
#[derive(Debug)]
pub struct NetworkConfig {
    pub config: rpc::ManagedHostNetworkConfig,
    pub config_version: String,
}

/// An interface for reading the latest received network configuration for
/// a Forge host
pub trait NetworkConfigReader {
    fn read(&self) -> Arc<Option<NetworkConfig>>;
}

struct NetworkConfigReaderImpl {
    state: Arc<NetworkConfigFetcherState>,
}

impl NetworkConfigReader for NetworkConfigReaderImpl {
    /// Reads the latest desired network configuration obtained from the Forge
    /// Site controller
    fn read(&self) -> Arc<Option<NetworkConfig>> {
        self.state.current.load_full()
    }
}

struct NetworkConfigFetcherState {
    current: ArcSwap<Option<NetworkConfig>>,
    config: NetworkConfigFetcherConfig,
    is_cancelled: AtomicBool,
}

/// Fetches the desired network configuration for a managed host in regular intervals
pub struct NetworkConfigFetcher {
    state: Arc<NetworkConfigFetcherState>,
    join_handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for NetworkConfigFetcher {
    fn drop(&mut self) {
        // Signal the background task and wait for it to shut down
        // TODO: Might be nicer if it would be interrupted during waiting for 30s,
        self.state
            .is_cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(jh) = self.join_handle.take() {
            jh.join().unwrap();
        }
    }
}

impl NetworkConfigFetcher {
    pub fn new(config: NetworkConfigFetcherConfig) -> Self {
        let root_ca = config.root_ca.clone();
        let state = Arc::new(NetworkConfigFetcherState {
            current: ArcSwap::default(),
            config,
            is_cancelled: AtomicBool::new(false),
        });

        let task_state = state.clone();
        let join_handle = std::thread::spawn(|| {
            run_network_config_fetcher(root_ca, task_state);
        });

        Self {
            state,
            join_handle: Some(join_handle),
        }
    }

    /// Returns a reader for fetching the latest retrieved network config
    pub fn reader(&self) -> Box<dyn NetworkConfigReader> {
        Box::new(NetworkConfigReaderImpl {
            state: self.state.clone(),
        })
    }
}

pub struct NetworkConfigFetcherConfig {
    /// The interval in which the config is fetched
    pub config_fetch_interval: Duration,
    pub machine_id: String,
    pub forge_api: String,
    pub root_ca: String,
    pub runtime: tokio::runtime::Handle,
}

fn run_network_config_fetcher(root_ca: String, state: Arc<NetworkConfigFetcherState>) {
    loop {
        if state
            .is_cancelled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            trace!("NetworkConfigReader was dropped. Stopping config reading");
            return;
        }

        trace!(
            "Fetching managed host network configuration for Machine {}",
            state.config.machine_id
        );

        match state
            .config
            .runtime
            .block_on(async { fetch_latest_network_config(root_ca.clone(), &state).await })
        {
            Ok(config) => {
                state.current.store(Arc::new(Some(config)));
            }
            Err(err) => {
                error!(
                    "Failed to fetch the latest configuration: {err}.\n Will retry in {:?}",
                    state.config.config_fetch_interval
                );
            }
        };

        sleep(state.config.config_fetch_interval);
    }
}

async fn fetch_latest_network_config(
    root_ca: String,
    state: &NetworkConfigFetcherState,
) -> Result<NetworkConfig, eyre::Error> {
    let mut client = match forge_tls_client::ForgeTlsClient::new(root_ca)
        .connect(state.config.forge_api.clone())
        .await
    {
        Ok(client) => client,
        Err(err) => {
            return Err(eyre::eyre!(
                "Could not connect to Forge API server at {}: {err}",
                state.config.forge_api
            ));
        }
    };
    let request = tonic::Request::new(rpc::ManagedHostNetworkConfigRequest {
        machine_id: Some(rpc::MachineId {
            id: state.config.machine_id.clone(),
        }),
    });

    let config = match client.get_managed_host_network_config(request).await {
        Ok(config) => config.into_inner(),
        Err(err) => {
            return Err(eyre::eyre!(
                "Error while executing the GetManagedHostNetworkConfig gRPC call: {}",
                err.to_string()
            ));
        }
    };

    let managed_host_config = match config.managed_host_config {
        Some(config) => config,
        None => {
            return Err(eyre::eyre!(
                "managed_host_config field is missing in GetManagedHostNetworkConfig call"
            ));
        }
    };

    Ok(NetworkConfig {
        config: managed_host_config,
        config_version: config.managed_host_config_version,
    })
}
