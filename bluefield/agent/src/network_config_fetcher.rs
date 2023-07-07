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

use arc_swap::ArcSwap;
use tracing::{error, trace};

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ForgeTlsConfig};

/// An interface for reading the latest received network configuration for
/// a Forge host
pub trait NetworkConfigReader {
    fn read(&self) -> Arc<Option<rpc::ManagedHostNetworkConfigResponse>>;
}

struct NetworkConfigReaderImpl {
    state: Arc<NetworkConfigFetcherState>,
}

impl NetworkConfigReader for NetworkConfigReaderImpl {
    /// Reads the latest desired network configuration obtained from the Forge
    /// Site controller
    fn read(&self) -> Arc<Option<rpc::ManagedHostNetworkConfigResponse>> {
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
        let forge_tls_config = config.forge_tls_config.clone();
        let state = Arc::new(NetworkConfigFetcherState {
            current: ArcSwap::default(),
            config,
            is_cancelled: AtomicBool::new(false),
        });

        let task_state = state.clone();
        let join_handle = std::thread::spawn(|| {
            run_network_config_fetcher(forge_tls_config, task_state);
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
    pub forge_tls_config: ForgeTlsConfig,
    pub runtime: tokio::runtime::Handle,
}

fn run_network_config_fetcher(
    forge_tls_config: ForgeTlsConfig,
    state: Arc<NetworkConfigFetcherState>,
) {
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

        match state.config.runtime.block_on(async {
            fetch(
                &state.config.machine_id,
                &state.config.forge_api,
                forge_tls_config.clone(),
            )
            .await
        }) {
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

/// Make the network request to get network config
pub async fn fetch(
    dpu_machine_id: &str,
    forge_api: &str,
    forge_tls_config: ForgeTlsConfig,
) -> Result<rpc::ManagedHostNetworkConfigResponse, eyre::Error> {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_tls_config)
        .connect(forge_api)
        .await
    {
        Ok(client) => client,
        Err(err) => {
            return Err(eyre::eyre!(
                "Could not connect to Forge API server at {forge_api}: {err}"
            ));
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
            return Err(eyre::eyre!(
                "Error while executing the GetManagedHostNetworkConfig gRPC call: {}",
                err.to_string()
            ));
        }
    };

    Ok(config)
}
