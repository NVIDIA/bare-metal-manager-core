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

use std::collections::HashMap;

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::nvlink::{NvLinkDomainId, NvLinkLogicalPartitionId};
use config_version::Versioned;
use rpc::forge as rpc;
use serde::{Deserialize, Serialize};

use crate::instance::config::nvlink::InstanceNvLinkConfig;
use crate::instance::status::SyncState;
use crate::machine::nvlink::MachineNvLinkStatusObservation;

#[derive(Clone, Debug)]
pub struct InstanceNvLinkStatus {
    /// each entry here maps to the corresponding entry in the config Vec<InstanceNvLinkConfig>
    pub nvlink_gpus: Vec<InstanceNvLinkGpuStatus>,
    /// similar to InstanceNetworkStatus
    pub configs_synced: SyncState,
}

impl TryFrom<InstanceNvLinkStatus> for rpc::InstanceNvLinkStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: InstanceNvLinkStatus) -> Result<Self, Self::Error> {
        let mut gpu_statuses: Vec<rpc::InstanceNvLinkGpuStatus> = Vec::new();
        for gpu in status.nvlink_gpus.iter() {
            let g = rpc::InstanceNvLinkGpuStatus::try_from(gpu.clone())?;
            gpu_statuses.push(g);
        }
        Ok(Self {
            gpu_statuses,
            configs_synced: rpc::SyncState::try_from(status.configs_synced)? as i32,
        })
    }
}

impl InstanceNvLinkStatus {
    pub fn from_config_and_observation(
        config: Versioned<&InstanceNvLinkConfig>,
        observations: Option<&MachineNvLinkStatusObservation>,
    ) -> Self {
        if config.gpu_configs.is_empty() {
            return Self {
                nvlink_gpus: Vec::new(),
                configs_synced: SyncState::Synced,
            };
        }

        let Some(observations) = observations else {
            return Self::unsynchronized_for_config(&config);
        };

        if config.gpu_configs.len() != observations.nvlink_gpus.len() {
            return Self::unsynchronized_for_config(&config);
        }

        let mut configs_synced = SyncState::Synced;

        let mut nvlink_gpus: Vec<InstanceNvLinkGpuStatus> =
            Vec::with_capacity(config.gpu_configs.len());
        let obs_by_device_instance: HashMap<_, _> = observations
            .nvlink_gpus
            .iter()
            .map(|obs| (obs.device_instance, obs))
            .collect();
        for cfg in &config.gpu_configs {
            let status = match obs_by_device_instance.get(&cfg.device_instance) {
                Some(obs) => {
                    if cfg.logical_partition_id != obs.logical_partition_id {
                        configs_synced = SyncState::Pending;
                    }
                    InstanceNvLinkGpuStatus {
                        logical_partition_id: obs.logical_partition_id,
                        domain_id: obs.domain_id,
                        gpu_guid: obs.guid.to_string(), // This is the DeviceUID field returned from NMX-M, which I think matches nvidia-smi GUID
                    }
                }
                None => {
                    tracing::error!(
                        "could not find matching status gpu {:?}",
                        cfg.device_instance
                    );
                    configs_synced = SyncState::Pending;
                    InstanceNvLinkGpuStatus {
                        logical_partition_id: None,
                        domain_id: NvLinkDomainId::default(),
                        gpu_guid: "".to_string(), // just an empty string as status is not ready yet
                    }
                }
            };
            nvlink_gpus.push(status);
        }
        Self {
            nvlink_gpus,
            configs_synced,
        }
    }

    fn unsynchronized_for_config(config: &InstanceNvLinkConfig) -> Self {
        Self {
            nvlink_gpus: config
                .gpu_configs
                .iter()
                .map(|cfg| InstanceNvLinkGpuStatus {
                    logical_partition_id: None,
                    domain_id: NvLinkDomainId::default(),
                    gpu_guid: cfg.device_instance.to_string(), // just fill it with the index as status is not ready.
                })
                .collect(),
            configs_synced: SyncState::Pending,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceNvLinkGpuStatus {
    pub gpu_guid: String,
    pub domain_id: NvLinkDomainId,
    pub logical_partition_id: Option<NvLinkLogicalPartitionId>,
}

impl TryFrom<InstanceNvLinkGpuStatus> for rpc::InstanceNvLinkGpuStatus {
    type Error = RpcDataConversionError;
    fn try_from(status: InstanceNvLinkGpuStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            logical_partition_id: status.logical_partition_id,
            gpu_guid: Some(status.gpu_guid.clone()),
            domain_id: Some(status.domain_id),
        })
    }
}

impl TryFrom<rpc::InstanceNvLinkGpuStatus> for InstanceNvLinkGpuStatus {
    type Error = RpcDataConversionError;
    fn try_from(status: rpc::InstanceNvLinkGpuStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            logical_partition_id: status.logical_partition_id,
            gpu_guid: status.gpu_guid.unwrap_or_default(),
            domain_id: status.domain_id.unwrap_or_default(),
        })
    }
}
