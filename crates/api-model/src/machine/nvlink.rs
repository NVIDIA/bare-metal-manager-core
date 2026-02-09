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

use carbide_uuid::nvlink::{NvLinkDomainId, NvLinkLogicalPartitionId, NvLinkPartitionId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::StatusValidationError;
use crate::instance::config::nvlink::InstanceNvLinkConfig;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MachineNvLinkStatusObservation {
    /// Observed status for each configured interface
    #[serde(default)]
    pub nvlink_gpus: Vec<MachineNvLinkGpuStatusObservation>,

    /// When this status was observed
    pub observed_at: DateTime<Utc>,
}

impl MachineNvLinkStatusObservation {
    pub fn validate(&self) -> Result<(), StatusValidationError> {
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineNvLinkGpuStatusObservation {
    pub gpu_id: String,
    pub partition_id: Option<NvLinkPartitionId>,
    pub logical_partition_id: Option<NvLinkLogicalPartitionId>,
    pub device_instance: u32,
    pub domain_id: NvLinkDomainId,
    pub guid: u64,
}

impl From<MachineNvLinkStatusObservation> for rpc::forge::MachineNvLinkStatusObservation {
    fn from(value: MachineNvLinkStatusObservation) -> Self {
        rpc::forge::MachineNvLinkStatusObservation {
            gpu_status: value
                .nvlink_gpus
                .into_iter()
                .map(rpc::forge::MachineNvLinkGpuStatusObservation::from)
                .collect(),
        }
    }
}

impl From<MachineNvLinkGpuStatusObservation> for rpc::forge::MachineNvLinkGpuStatusObservation {
    fn from(value: MachineNvLinkGpuStatusObservation) -> Self {
        rpc::forge::MachineNvLinkGpuStatusObservation {
            gpu_id: value.gpu_id,
            partition_id: value.partition_id,
            logical_partition_id: value.logical_partition_id,
            device_instance: value.device_instance,
            domain_id: Some(value.domain_id),
            guid: value.guid,
        }
    }
}

impl Default for MachineNvLinkGpuStatusObservation {
    fn default() -> Self {
        Self {
            gpu_id: "".to_string(),
            partition_id: None,
            logical_partition_id: None,
            device_instance: 0,
            domain_id: NvLinkDomainId::default(),
            guid: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NvLinkConfigNotSyncedReason(pub String);

pub fn nvlink_config_synced(
    observation: Option<&MachineNvLinkStatusObservation>,
    config: Option<&InstanceNvLinkConfig>,
) -> Result<(), NvLinkConfigNotSyncedReason> {
    let Some(config) = config.as_ref() else {
        return Ok(());
    };
    if config.gpu_configs.is_empty() {
        return Ok(());
    }

    let Some(observation) = observation.as_ref() else {
        return Err(NvLinkConfigNotSyncedReason("Due to missing NvLink status observation, it can't be verified whether the NvLink config is applied to NMX-M".to_string()));
    };
    if config.gpu_configs.len() != observation.nvlink_gpus.len() {
        return Err(NvLinkConfigNotSyncedReason(
            "the number of configured GPUs does not match the number of observed GPUs".to_string(),
        ));
    }

    for gpu_config in config.gpu_configs.iter() {
        let Some(gpu_observation) = observation
            .nvlink_gpus
            .iter()
            .find(|gpu| gpu.device_instance == gpu_config.device_instance)
        else {
            tracing::error!(
                "could not find matching status gpu {:?}",
                gpu_config.device_instance
            );
            return Err(NvLinkConfigNotSyncedReason(
                "No matching NvLink status observation found for GPU in config".to_string(),
            ));
        };
        if gpu_config.logical_partition_id != gpu_observation.logical_partition_id {
            return Err(NvLinkConfigNotSyncedReason(
                "Logical partition ID mismatch between config and observation".to_string(),
            ));
        }
        if gpu_config.logical_partition_id.is_some() && gpu_observation.partition_id.is_none() {
            return Err(NvLinkConfigNotSyncedReason(
                "GPU part of logical partition but not part of physical partition".to_string(),
            ));
        }
    }
    Ok(())
}
