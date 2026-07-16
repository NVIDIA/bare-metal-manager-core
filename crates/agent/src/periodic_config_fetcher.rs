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
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use ::rpc::forge_tls_client::ForgeClientConfig;
use ::rpc::{Instance, forge as rpc};
use arc_swap::ArcSwapOption;
use carbide_instrument::{Outcome, emit};
use carbide_uuid::infiniband::IBPartitionId;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use config_version::ConfigVersion;
use eyre::Context;
use forge_dpu_agent_utils::utils::create_forge_client;
use tracing::{error, trace, warn};

use crate::instrumentation::{ReportLoop, ReportLoopCompleted};
use crate::util::{get_periodic_dpu_config, get_sitename};

pub struct PeriodicFetcherState {
    config: PeriodicConfigFetcherConfig,
    netconf: ArcSwapOption<rpc::ManagedHostNetworkConfigResponse>,
    instmeta: ArcSwapOption<InstanceMetadata>,
    is_cancelled: AtomicBool,
    sitename: Option<String>,
}

/// Fetches the desired network configuration for a managed host in regular intervals
pub struct PeriodicConfigFetcher {
    state: Arc<PeriodicFetcherState>,
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

pub struct PeriodicConfigFetcherReader {
    state: Arc<PeriodicFetcherState>,
}
/// The instance metadata - as fetched from the
/// Forge Site Controller
#[derive(Clone, Debug)]
pub struct InstanceMetadata {
    pub address: String,
    pub hostname: String,
    pub sitename: Option<String>,
    pub instance_id: Option<InstanceId>,
    pub machine_id: Option<MachineId>,
    pub user_data: String,
    pub ib_devices: Option<Vec<IBDeviceConfig>>,
    pub config_version: ConfigVersion,
    pub network_config_version: ConfigVersion,
    pub extension_service_version: ConfigVersion,
}

#[derive(Clone, Debug)]
pub struct IBDeviceConfig {
    pub pf_guid: String,
    pub instances: Vec<IBInstanceConfig>,
}

#[derive(Clone, Debug)]
pub struct IBInstanceConfig {
    pub ib_partition_id: Option<IBPartitionId>,
    pub ib_guid: Option<String>,
    pub lid: u32,
}

impl PeriodicConfigFetcherReader {
    pub fn net_conf_read(&self) -> Option<Arc<rpc::ManagedHostNetworkConfigResponse>> {
        self.state.netconf.load_full()
    }

    pub fn meta_data_conf_reader(&self) -> Option<Arc<InstanceMetadata>> {
        self.state.instmeta.load_full()
    }
}

impl Drop for PeriodicConfigFetcher {
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

impl PeriodicConfigFetcher {
    pub async fn new(config: PeriodicConfigFetcherConfig) -> Self {
        let forge_client_config = Arc::clone(&config.forge_client_config);
        // Fetch the sitename from Carbide at the start and keep it in State
        // so that it can be made available as instance metadata.
        let sitename = match fetch_sitename(&forge_client_config, &config.forge_api).await {
            Ok(sn) => sn,
            Err(e) => {
                warn!(error = %e, "Unable to fetch sitename");
                None
            }
        };

        let state = Arc::new(PeriodicFetcherState {
            netconf: ArcSwapOption::default(),
            instmeta: ArcSwapOption::default(),
            sitename,
            config,
            is_cancelled: AtomicBool::new(false),
        });

        // Do an initial synchronous fetch so that caller has data to use
        // This gets a DPU on the network immediately
        single_fetch(&forge_client_config, state.clone()).await;

        let task_state = state.clone();
        let join_handle = tokio::spawn(async move {
            while single_fetch(&forge_client_config, task_state.clone()).await {
                tokio::time::sleep(task_state.config.config_fetch_interval).await;
            }
        });

        Self {
            state,
            join_handle: Some(join_handle),
        }
    }

    pub fn reader(&self) -> Box<PeriodicConfigFetcherReader> {
        Box::new(PeriodicConfigFetcherReader {
            state: self.state.clone(),
        })
    }

    pub fn get_host_machine_interface_id(&self) -> Option<MachineInterfaceId> {
        self.state
            .netconf
            .load()
            .as_ref()
            .and_then(|netconf| netconf.host_interface_id.as_ref())
            .and_then(|id| id.parse().ok())
    }
}

pub struct PeriodicConfigFetcherConfig {
    /// The interval in which the config is fetched
    pub config_fetch_interval: Duration,
    pub machine_id: MachineId,
    pub forge_api: String,
    pub forge_client_config: Arc<ForgeClientConfig>,
}

// Use the version grpc call to carbide to get
// the sitename. This will be made visible to tenant OS
// at an FMDS endpoint
async fn fetch_sitename(
    forge_client_config: &ForgeClientConfig,
    forge_api: &str,
) -> Result<Option<String>, eyre::Report> {
    let mut client = create_forge_client(forge_api, forge_client_config).await?;

    get_sitename(&mut client).await
}

async fn single_fetch(
    forge_client_config: &ForgeClientConfig,
    state: Arc<PeriodicFetcherState>,
) -> bool {
    if state
        .is_cancelled
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        trace!("Periodic fetcher was dropped. Stopping config reading");
        return false;
    }

    trace!(
        machine_id = %state.config.machine_id,
        "Fetching periodic configuration"
    );

    let result = fetch(
        &state.config.machine_id,
        &state.config.forge_api,
        forge_client_config,
    )
    .await;
    // The outcome covers the whole fetch: a successful RPC whose instance
    // metadata fails to convert is still a failed configuration fetch.
    let outcome = match result {
        Ok(resp) => {
            state.netconf.store(Some(Arc::new(resp.clone())));

            match instance_metadata_from_instance(resp.instance, state.sitename.clone()) {
                Ok(Some(config)) => {
                    state.instmeta.store(Some(Arc::new(config)));
                    Outcome::Ok
                }
                Ok(None) => {
                    state.instmeta.store(None);
                    Outcome::Ok
                }
                Err(err) => {
                    error!(
                        error = %err,
                        retry_interval_seconds = state.config.config_fetch_interval.as_secs_f64(),
                        "Failed to fetch the latest configuration. Will retry"
                    );
                    Outcome::Error
                }
            }
        }
        Err(err) => match err.downcast_ref::<tonic::Status>() {
            Some(grpc_status) if grpc_status.code() == tonic::Code::NotFound => {
                warn!(machine_id = %state.config.machine_id, "DPU not found");
                state.netconf.store(None);
                state.instmeta.store(None);
                Outcome::Error
            }
            _ => {
                error!(
                    retry_interval_seconds = state.config.config_fetch_interval.as_secs_f64(),
                    error = ?err,
                    "Failed to fetch the latest configuration. Will retry"
                );
                Outcome::Error
            }
        },
    };
    emit(ReportLoopCompleted {
        report_loop: ReportLoop::ConfigFetch,
        outcome,
    });

    true
}

/// Make the network request to get network config
pub async fn fetch(
    dpu_machine_id: &MachineId,
    forge_api: &str,
    client_config: &ForgeClientConfig,
) -> Result<rpc::ManagedHostNetworkConfigResponse, eyre::Report> {
    let mut client = create_forge_client(forge_api, client_config).await?;

    get_periodic_dpu_config(&mut client, dpu_machine_id).await
}

pub fn instance_metadata_from_instance(
    instance: Option<Instance>,
    sitename: Option<String>,
) -> Result<Option<InstanceMetadata>, eyre::Error> {
    let instance = match instance {
        Some(instance) => instance,
        None => return Ok(None),
    };

    let hostname = match instance.id {
        Some(name) => name.to_string(),
        None => return Err(eyre::eyre!("host name is not present in tenant config")),
    };

    let machine_id = instance.machine_id;

    let instance_id = instance.id;

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
        .unwrap_or_default();

    let user_data = instance
        .config
        .as_ref()
        .and_then(|config| config.os.as_ref())
        .and_then(|os_config| os_config.user_data.clone())
        .unwrap_or_default();

    let devices = match extract_instance_ib_config(&instance) {
        Ok(value) => Some(value),
        Err(e) => {
            trace!(error = %e, "Failed to fetch IB config");
            None
        }
    };

    Ok(Some(InstanceMetadata {
        address: pf_address,
        hostname,
        sitename,
        instance_id,
        machine_id,
        user_data,
        ib_devices: devices,
        config_version: instance
            .config_version
            .parse()
            .wrap_err("failed to parse instance config_version")?,
        network_config_version: instance
            .network_config_version
            .parse()
            .wrap_err("failed to parse instance network_config_version")?,
        extension_service_version: instance
            .dpu_extension_service_version
            .parse()
            .wrap_err("failed to parse instance extension_service_version")?,
    }))
}

fn extract_instance_ib_config(instance: &Instance) -> Result<Vec<IBDeviceConfig>, eyre::Error> {
    let ib_config = instance
        .config
        .as_ref()
        .and_then(|config| config.infiniband.as_ref())
        .ok_or_else(|| eyre::eyre!("no infiniband interfaces found"))?;

    let ib_interface_configs = &ib_config.ib_interfaces;

    let ib_status = instance
        .status
        .as_ref()
        .and_then(|status| status.infiniband.as_ref())
        .ok_or_else(|| eyre::eyre!("no infiniband interfaces found"))?;

    let ib_interface_statuses = &ib_status.ib_interfaces;

    let mut devices: Vec<IBDeviceConfig> = Vec::new();

    for (index, config) in ib_interface_configs.iter().enumerate() {
        let status = &ib_interface_statuses[index];

        let instance: IBInstanceConfig = IBInstanceConfig {
            ib_partition_id: config.ib_partition_id,
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
        return Err(eyre::eyre!("no infiniband devices found"));
    }

    Ok(devices)
}
