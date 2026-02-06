/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//use std::collections::HashSet;

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::nvlink::NvLinkLogicalPartitionId;
use rpc::forge as rpc;
use serde::{Deserialize, Serialize};

use crate::ConfigValidationError;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceNvLinkConfig {
    /// Configures how GPUs are set up
    pub gpu_configs: Vec<InstanceNvLinkGpuConfig>,
}

impl InstanceNvLinkConfig {
    /// Validates the nvlink configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        Ok(())
    }

    pub fn verify_update_allowed_to(&self, new_config: &Self) -> Result<(), ConfigValidationError> {
        // If the new config specifies a logical partition ID, it must be the same as the current config if the current config specifies a logical partition ID.
        for gpu in new_config.gpu_configs.iter() {
            let current_partition_id = self
                .gpu_configs
                .iter()
                .find(|g| g.device_instance == gpu.device_instance)
                .and_then(|g| g.logical_partition_id);

            if gpu.logical_partition_id.is_some()
                && current_partition_id.is_some()
                && gpu.logical_partition_id != current_partition_id
            {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "GPU {} is already part of a logical partition. Please remove it from the logical partition before adding it to a new one.",
                    gpu.device_instance
                )));
            }
        }
        Ok(())
    }

    pub fn is_nvlink_config_update_requested(&self, new_config: &Self) -> bool {
        self != new_config
    }
}

impl TryFrom<rpc::InstanceNvLinkConfig> for InstanceNvLinkConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::InstanceNvLinkConfig) -> Result<Self, Self::Error> {
        let mut gpu_configs = Vec::with_capacity(config.gpu_configs.len());
        for gpu in config.gpu_configs.into_iter() {
            gpu_configs.push(InstanceNvLinkGpuConfig {
                logical_partition_id: gpu.logical_partition_id,
                device_instance: gpu.device_instance,
            });
        }

        Ok(Self { gpu_configs })
    }
}

impl TryFrom<InstanceNvLinkConfig> for rpc::InstanceNvLinkConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: InstanceNvLinkConfig) -> Result<rpc::InstanceNvLinkConfig, Self::Error> {
        let mut gpu_configs = Vec::with_capacity(config.gpu_configs.len());
        for gpu in config.gpu_configs.into_iter() {
            gpu_configs.push(rpc::InstanceNvLinkGpuConfig {
                device_instance: gpu.device_instance,
                logical_partition_id: gpu.logical_partition_id,
            });
        }

        Ok(rpc::InstanceNvLinkConfig { gpu_configs })
    }
}

/// The configuration that a customer desires for an instances gpus
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceNvLinkGpuConfig {
    // The logical nvlink partition this gpu is attached to
    pub logical_partition_id: Option<NvLinkLogicalPartitionId>,
    /// gpu module id
    pub device_instance: u32,
}
