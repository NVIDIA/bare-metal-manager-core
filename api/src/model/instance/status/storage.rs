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
 */

use crate::model::instance::config::storage::InstanceStorageConfig;
use crate::model::instance::status::SyncState;
use crate::model::storage::{StorageVolume, StorageVolumeHealth, StorageVolumeStatus};
use crate::model::{RpcDataConversionError, StatusValidationError};
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct InstanceStorageStatus {
    /// each volume here maps to the corresponding entry in the config Vec<StorageVolumeAttributes>
    pub volumes: Vec<StorageVolume>,
    /// similar to InstanceNetworkStatus whether InstanceStorageConfig
    pub configs_synced: SyncState,
}

impl TryFrom<InstanceStorageStatus> for rpc::forge::InstanceStorageStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: InstanceStorageStatus) -> Result<Self, Self::Error> {
        let mut volumes: Vec<rpc::forge::StorageVolume> = Vec::new();
        for vol in status.volumes.iter() {
            let v = rpc::forge::StorageVolume::try_from(vol.clone())?;
            volumes.push(v);
        }
        Ok(Self {
            volumes,
            configs_synced: rpc::SyncState::try_from(status.configs_synced)? as i32,
        })
    }
}

impl InstanceStorageStatus {
    pub fn from_config_and_observation(
        config: Versioned<&InstanceStorageConfig>,
        observations: Option<&InstanceStorageStatusObservation>,
    ) -> Self {
        let observations = match observations {
            Some(observations) => observations,
            None => return Self::unsynchronized_for_config(&config),
        };
        if observations.config_version != config.version {
            return Self::unsynchronized_for_config(&config);
        }
        if config.volumes.len() != observations.volumes.len() {
            return Self::unsynchronized_for_config(&config);
        }

        // the configured volumes list is an ordered list, items in nth position MUST correspond
        // with items in the nth position in the status list
        let mut volumes: Vec<StorageVolume> = Vec::with_capacity(config.volumes.len());
        let volumes_zip = config.volumes.iter().zip(observations.volumes.iter());
        for (attrs, volume) in volumes_zip {
            if *attrs != volume.attributes || (volume.attributes.id.as_u64_pair() != (0, 0)) {
                tracing::error!(
                    "volume attributes {:?} did not match expected {:?} or volume id is invalid",
                    volume.attributes,
                    attrs,
                );
            }
            volumes.push(volume.clone());
        }
        Self {
            volumes,
            configs_synced: SyncState::Synced,
        }
    }

    fn unsynchronized_for_config(config: &InstanceStorageConfig) -> Self {
        Self {
            volumes: config
                .volumes
                .iter()
                .map(|attrs| StorageVolume {
                    nvmesh_uuid: Default::default(),
                    attributes: attrs.clone(),
                    status: StorageVolumeStatus {
                        health: StorageVolumeHealth::Initializing,
                        attached: false,
                        status_message: None,
                    },
                    instance_id: vec![],
                    dpu_machine_id: vec![],
                    created_at: None,
                    modified_at: None,
                })
                .collect(),
            configs_synced: SyncState::Pending,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstanceStorageStatusObservation {
    pub config_version: ConfigVersion,
    /// Observed status for each configured interface
    #[serde(default)]
    pub volumes: Vec<StorageVolume>,

    /// When this status was observed
    pub observed_at: DateTime<Utc>,
}

impl TryFrom<rpc::forge::InstanceStorageStatusObservation> for InstanceStorageStatusObservation {
    type Error = RpcDataConversionError;

    fn try_from(
        observation: rpc::forge::InstanceStorageStatusObservation,
    ) -> Result<Self, Self::Error> {
        let observed_at = match observation.observed_at {
            Some(timestamp) => {
                let system_time = std::time::SystemTime::try_from(timestamp.clone())
                    .map_err(|_| RpcDataConversionError::InvalidTimestamp(timestamp.to_string()))?;
                DateTime::from(system_time)
            }
            None => Utc::now(),
        };
        let mut volumes: Vec<StorageVolume> = Vec::new();
        for vol in observation.volumes.iter() {
            let v = StorageVolume::try_from(vol.clone())?;
            volumes.push(v);
        }
        Ok(Self {
            config_version: observation.config_version.parse().map_err(|_| {
                RpcDataConversionError::InvalidConfigVersion(observation.config_version)
            })?,
            volumes,
            observed_at,
        })
    }
}

impl InstanceStorageStatusObservation {
    pub fn validate(&self) -> Result<(), StatusValidationError> {
        Ok(())
    }
}
