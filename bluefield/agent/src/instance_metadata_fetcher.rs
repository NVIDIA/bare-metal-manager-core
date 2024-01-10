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
use mockall::*;
use tracing::{error, trace};

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ForgeClientConfig};

/// The instance metadata - as fetched from the
/// Forge Site Controller
#[derive(Clone, Debug)]
pub struct InstanceMetadata {
    pub address: String,
    pub hostname: String,
    pub user_data: String,
}

/// An interface for reading the latest received network configuration for
/// a Forge host
#[automock]
pub trait InstanceMetadataReader: Sync + Send {
    fn read(&self) -> Arc<Option<InstanceMetadata>>;
}

struct InstanceMetadataReaderImpl {
    state: Arc<InstanceMetadataFetcherState>,
}

impl InstanceMetadataReader for InstanceMetadataReaderImpl {
    /// Reads the latest desired instance metadata obtained from the Forge
    /// Site controller
    fn read(&self) -> Arc<Option<InstanceMetadata>> {
        self.state.current.load_full()
    }
}

struct InstanceMetadataFetcherState {
    current: ArcSwap<Option<InstanceMetadata>>,
    config: InstanceMetadataFetcherConfig,
    is_cancelled: AtomicBool,
}

/// Fetches the desired network configuration for a managed host in regular intervals
pub struct InstanceMetadataFetcher {
    state: Arc<InstanceMetadataFetcherState>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for InstanceMetadataFetcher {
    fn drop(&mut self) {
        // Signal the background task and wait for it to shut down
        // TODO: Might be nicer if it would be interrupted during waiting for 30s
        self.state
            .is_cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(jh) = self.join_handle.take() {
            tokio::spawn(async move {
                jh.await.unwrap();
            });
        }
    }
}

impl InstanceMetadataFetcher {
    pub fn new(config: InstanceMetadataFetcherConfig) -> Self {
        let forge_client_config = config.forge_client_config.clone();
        let state = Arc::new(InstanceMetadataFetcherState {
            current: ArcSwap::default(),
            config,
            is_cancelled: AtomicBool::new(false),
        });

        let task_state = state.clone();
        let join_handle = tokio::spawn(async move {
            run_instance_metadata_fetcher(forge_client_config, task_state).await;
        });

        Self {
            state,
            join_handle: Some(join_handle),
        }
    }

    /// Returns a reader for fetching the latest retrieved instance metadata
    pub fn reader(&self) -> Arc<dyn InstanceMetadataReader> {
        Arc::new(InstanceMetadataReaderImpl {
            state: self.state.clone(),
        })
    }
}

pub struct InstanceMetadataFetcherConfig {
    /// The interval in which the config is fetched
    pub config_fetch_interval: Duration,
    pub machine_id: String,
    pub forge_api: String,
    pub forge_client_config: ForgeClientConfig,
}

async fn run_instance_metadata_fetcher(
    forge_client_config: ForgeClientConfig,
    state: Arc<InstanceMetadataFetcherState>,
) {
    loop {
        if state
            .is_cancelled
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            trace!("Instance metadata fetcher was dropped. Stopping config reading");
            return;
        }

        trace!(
            "Fetching managed host network configuration for Machine {}",
            state.config.machine_id
        );

        match fetch_latest_ip_addresses(forge_client_config.clone(), &state).await {
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

        tokio::time::sleep(state.config.config_fetch_interval).await;
    }
}

async fn fetch_latest_ip_addresses(
    forge_client_config: ForgeClientConfig,
    state: &InstanceMetadataFetcherState,
) -> Result<InstanceMetadata, eyre::Error> {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_client_config)
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
    let request = tonic::Request::new(rpc::MachineId {
        id: state.config.machine_id.clone(),
    });

    let instances = match client.find_instance_by_machine_id(request).await {
        Ok(response) => response.into_inner().instances,
        Err(err) => {
            return Err(eyre::eyre!(
                "Error while executing the FindInstanceByMachineId gRPC call: {}",
                err.to_string()
            ));
        }
    };

    let first_instance = instances
        .first()
        .ok_or_else(|| eyre::eyre!("instances array is empty in response"))?;
    let hostname = first_instance.id.clone().unwrap().to_string();
    let pf_address = first_instance
        .status
        .as_ref()
        .and_then(|status| status.network.as_ref())
        .and_then(|network| {
            network
                .interfaces
                .iter()
                .find(|interface| interface.virtual_function_id.is_none()) // We only want an IP address of a physical function
                .and_then(|interface| interface.addresses.first().cloned())
        })
        .ok_or_else(|| eyre::eyre!("No suitable address found"))?;
    let user_data = first_instance
        .config
        .as_ref()
        .and_then(|config| config.tenant.as_ref())
        .and_then(|tenant_config| tenant_config.user_data.clone())
        .ok_or_else(|| eyre::eyre!("user data is not present in tenant config"))?;

    Ok(InstanceMetadata {
        address: pf_address,
        hostname,
        user_data,
    })
}
