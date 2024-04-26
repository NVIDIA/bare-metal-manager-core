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
use tracing::{error, trace};

use ::rpc::forge_tls_client::ForgeClientConfig;
use ::rpc::Instance;
use ::rpc::Uuid as uuid;

use crate::util::{create_forge_client, get_instance};

/// The instance metadata - as fetched from the
/// Forge Site Controller
#[derive(Clone, Debug)]
pub struct InstanceMetadata {
    pub address: String,
    pub hostname: String,
    pub user_data: String,
    pub ib_devices: Option<Vec<IBDeviceConfig>>,
}

#[derive(Clone, Debug)]
pub struct IBDeviceConfig {
    pub pf_guid: String,
    pub instances: Vec<IBInstanceConfig>,
}

#[derive(Clone, Debug)]
pub struct IBInstanceConfig {
    pub ib_partition_id: Option<uuid>,
    pub ib_guid: Option<String>,
    pub lid: u32,
}

pub struct InstanceMetadataFetcherState {
    current: ArcSwap<Option<InstanceMetadata>>,
    config: InstanceMetadataFetcherConfig,
    is_cancelled: AtomicBool,
}

impl InstanceMetadataFetcherState {
    pub fn read(&self) -> Arc<Option<InstanceMetadata>> {
        self.current.load_full()
    }
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
    pub fn reader(&self) -> Arc<InstanceMetadataFetcherState> {
        self.state.clone()
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
    client_config: ForgeClientConfig,
    state: &InstanceMetadataFetcherState,
) -> Result<InstanceMetadata, eyre::Error> {
    let mut client = create_forge_client(&state.config.forge_api, client_config).await?;
    let instance = get_instance(&mut client, state.config.machine_id.clone()).await?;

    let hostname = match instance.id.clone() {
        Some(name) => name.to_string(),
        None => return Err(eyre::eyre!("host name is not present in tenant config")),
    };

    let pf_address = instance
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
    let user_data = instance
        .config
        .as_ref()
        .and_then(|config| config.tenant.as_ref())
        .and_then(|tenant_config| tenant_config.user_data.clone())
        .ok_or_else(|| eyre::eyre!("user data is not present in tenant config"))?;

    let devices = match extract_instance_ib_config(&instance) {
        Ok(value) => Some(value),
        Err(e) => {
            trace!("Failed to fetch IB config: {}", e.to_string());
            None
        }
    };

    Ok(InstanceMetadata {
        address: pf_address,
        hostname,
        user_data,
        ib_devices: devices,
    })
}

fn extract_instance_ib_config(instance: &Instance) -> Result<Vec<IBDeviceConfig>, eyre::Error> {
    let ib_config = instance
        .config
        .as_ref()
        .and_then(|config| config.infiniband.as_ref())
        .ok_or_else(|| eyre::eyre!("No infiniband interfaces found"))?;

    let ib_interface_configs = &ib_config.ib_interfaces;

    let ib_status = instance
        .status
        .as_ref()
        .and_then(|status| status.infiniband.as_ref())
        .ok_or_else(|| eyre::eyre!("No infiniband interfaces found"))?;

    let ib_interface_statuses = &ib_status.ib_interfaces;

    let mut devices: Vec<IBDeviceConfig> = Vec::new();

    for (index, config) in ib_interface_configs.iter().enumerate() {
        let status = &ib_interface_statuses[index];

        let instance: IBInstanceConfig = IBInstanceConfig {
            ib_partition_id: config.ib_partition_id.clone(),
            ib_guid: status.guid.clone(),
            lid: status.lid,
        };

        if let Some(pf_guid) = &status.pf_guid {
            match devices.iter_mut().find(|dev| &(dev.pf_guid) == pf_guid) {
                Some(device) => device.instances.push(instance),
                None => devices.push(IBDeviceConfig {
                    pf_guid: pf_guid.clone(),
                    instances: vec![instance],
                }),
            }
        } else {
            continue;
        }
    }

    if devices.is_empty() {
        return Err(eyre::eyre!("No infiniband devices found"));
    }

    Ok(devices)
}
