/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::model::{
    config_version::{ConfigVersion, Versioned},
    instance::{
        config::InstanceConfig,
        status::{InstanceStatus, InstanceStatusObservations},
    },
};
use serde::{Deserialize, Serialize};

/// Represents a snapshot view of an `Instance`
///
/// This snapshot will be transmitted to SiteControllers users as part of
/// `InstanceInfo`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceSnapshot {
    /// Instance ID
    pub instance_id: uuid::Uuid,
    /// Machine ID
    pub machine_id: uuid::Uuid,

    /// Instance configuration. This represents the desired status of the Instance
    /// The Instance might not yet be in that state, but work would be underway
    /// to get the Instance into this state
    pub config: InstanceConfig,
    /// Current version of the networking configuration that is stored as part
    /// of [InstanceConfig::network]
    pub network_config_version: ConfigVersion,

    /// Observed status of the instance
    pub observations: InstanceStatusObservations,
}

impl InstanceSnapshot {
    /// Derives the tenant and site-admin facing [`InstanceStatus`] from the
    /// snapshot information about the instance
    pub fn derive_status(&self) -> InstanceStatus {
        InstanceStatus::from_config_and_observation(
            Versioned::new(&self.config.network, self.network_config_version),
            &self.observations,
        )
    }
}
