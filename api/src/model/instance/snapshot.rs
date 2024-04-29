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

use config_version::{ConfigVersion, Versioned};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::model::{
    instance::{
        config::InstanceConfig,
        status::{InstanceStatus, InstanceStatusObservations},
    },
    machine::{machine_id::MachineId, ManagedHostState},
    RpcDataConversionError,
};

/// Represents a snapshot view of an `Instance`
///
/// This snapshot will be transmitted to SiteControllers users as part of
/// `InstanceInfo`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceSnapshot {
    /// Instance ID
    pub instance_id: uuid::Uuid,
    /// Machine ID
    pub machine_id: MachineId,

    /// Machine State
    pub machine_state: ManagedHostState,

    /// Instance configuration. This represents the desired status of the Instance
    /// The Instance might not yet be in that state, but work would be underway
    /// to get the Instance into this state
    pub config: InstanceConfig,
    /// Current version of the networking configuration that is stored as part
    /// of [InstanceConfig::network]
    pub network_config_version: ConfigVersion,

    /// Current version of the infiniband configuration that is stored as part
    /// of [InstanceConfig::infiniband]
    pub ib_config_version: ConfigVersion,

    /// Observed status of the instance
    pub observations: InstanceStatusObservations,

    /// Is delete requested
    pub delete_requested: bool,

    pub name: String,
    /// optional user-defined resource description                    
    pub description: String,
    /// optional user-defined key/ value pairs             
    pub labels: HashMap<String, String>,
}

impl TryFrom<InstanceSnapshot> for rpc::Instance {
    type Error = RpcDataConversionError;

    fn try_from(snapshot: InstanceSnapshot) -> Result<Self, Self::Error> {
        let status = snapshot.derive_status()?;

        Ok(rpc::Instance {
            id: Some(snapshot.instance_id.into()),
            machine_id: Some(snapshot.machine_id.to_string().into()),
            config: Some(snapshot.config.try_into()?),
            status: Some(status.try_into()?),
            network_config_version: snapshot.network_config_version.version_string(),
            ib_config_version: snapshot.ib_config_version.version_string(),
            metadata: {
                Some(rpc::Metadata {
                    name: snapshot.name,
                    description: snapshot.description,
                    labels: snapshot
                        .labels
                        .iter()
                        .map(|(key, value)| rpc::forge::Label {
                            key: key.clone(),
                            value: if value.clone().is_empty() {
                                None
                            } else {
                                Some(value.clone())
                            },
                        })
                        .collect(),
                })
            },
        })
    }
}

impl InstanceSnapshot {
    /// Derives the tenant and site-admin facing [`InstanceStatus`] from the
    /// snapshot information about the instance
    pub fn derive_status(&self) -> Result<InstanceStatus, RpcDataConversionError> {
        InstanceStatus::from_config_and_observation(
            Versioned::new(&self.config.network, self.network_config_version),
            Versioned::new(&self.config.infiniband, self.ib_config_version),
            &self.observations,
            self.machine_state.clone(),
            self.delete_requested,
            self.config
                .tenant
                .as_ref()
                .map_or(false, |tenant| tenant.phone_home_enabled),
        )
    }
}
