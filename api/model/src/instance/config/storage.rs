/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 *
 * implement storage volumes configuration for an instance
 */

use std::convert::TryFrom;

use ::rpc::errors::RpcDataConversionError;
use rpc::forge as rpc;
use serde::{Deserialize, Serialize};

use crate::ConfigValidationError;
use crate::storage::StorageVolumeAttributes;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InstanceStorageConfig {
    pub volumes: Vec<StorageVolumeAttributes>,
}

impl InstanceStorageConfig {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        // ensure only upto 8 volumes specified
        if self.volumes.len() > 8 {
            return Err(ConfigValidationError::StorageVolumeCountExceeded(
                self.volumes.len(),
            ));
        }
        if self.volumes.len() < 2 {
            return Ok(());
        }
        // ensure same cluster used for all volumes
        let cluster_id = self.volumes[0].cluster_id;
        for vol in self.volumes.iter() {
            if vol.cluster_id != cluster_id {
                return Err(ConfigValidationError::StorageClusterInvalid);
            }
        }

        Ok(())
    }
}

impl TryFrom<rpc::InstanceStorageConfig> for InstanceStorageConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::InstanceStorageConfig) -> Result<Self, Self::Error> {
        let mut volumes: Vec<StorageVolumeAttributes> = Vec::new();
        for vol in config.volumes.iter() {
            let v = StorageVolumeAttributes::try_from(vol.clone())?;
            volumes.push(v);
        }
        Ok(Self { volumes })
    }
}

impl TryFrom<InstanceStorageConfig> for rpc::InstanceStorageConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: InstanceStorageConfig) -> Result<rpc::InstanceStorageConfig, Self::Error> {
        let mut volumes: Vec<rpc::StorageVolumeAttributes> = Vec::new();
        for vol in config.volumes.iter() {
            let v = rpc::StorageVolumeAttributes::try_from(vol.clone())?;
            volumes.push(v);
        }
        Ok(Self { volumes })
    }
}
