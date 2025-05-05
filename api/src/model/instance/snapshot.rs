/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::model::{
    instance::{
        config::InstanceConfig,
        status::{InstanceStatus, InstanceStatusObservations},
    },
    machine::infiniband::MachineInfinibandStatusObservation,
    machine::{ManagedHostState, ReprovisionRequest},
    metadata::Metadata,
};
use ::rpc::errors::RpcDataConversionError;
use forge_uuid::{instance::InstanceId, instance_type::InstanceTypeId, machine::MachineId};

use super::config::network::InstanceNetworkConfigUpdate;

/// Represents a snapshot view of an `Instance`
///
/// This snapshot is a state-in-time representation of everything that
/// carbide knows about an instance.
/// In order to provide a tenant accurate state of an instance, the state of the
/// host that is hosting the instance also needs to be known.
#[derive(Debug, Clone)]
pub struct InstanceSnapshot {
    /// Instance ID
    pub id: InstanceId,
    /// Machine ID
    pub machine_id: MachineId,

    /// InstanceType ID
    pub instance_type_id: Option<InstanceTypeId>,

    /// Instance Metadata
    pub metadata: Metadata,

    /// Instance configuration. This represents the desired status of the Instance
    /// The Instance might not yet be in that state, but work would be underway
    /// to get the Instance into this state
    pub config: InstanceConfig,
    /// Current version of all instance configurations except the networking related ones
    pub config_version: ConfigVersion,

    /// Current version of the networking configuration that is stored as part
    /// of [InstanceConfig::network]
    pub network_config_version: ConfigVersion,

    /// Current version of the infiniband configuration that is stored as part
    /// of [InstanceConfig::infiniband]
    pub ib_config_version: ConfigVersion,

    pub storage_config_version: ConfigVersion,

    /// Observed status of the instance
    pub observations: InstanceStatusObservations,

    /// Whether the next boot attempt should run the tenants iPXE script
    pub use_custom_pxe_on_boot: bool,

    /// The timestamp when deletion for this instance was requested
    pub deleted: Option<chrono::DateTime<chrono::Utc>>,

    /// Update instance network config request.
    pub update_network_config_request: Option<InstanceNetworkConfigUpdate>,
    // There are columns for these but they're unused as of today.
    // pub(crate) requested: chrono::DateTime<chrono::Utc>,
    // pub(crate) started: chrono::DateTime<chrono::Utc>,
    // pub(crate) finished: Option<chrono::DateTime<chrono::Utc>>,
}

impl InstanceSnapshot {
    /// Derives the tenant and site-admin facing [`InstanceStatus`] from the
    /// snapshot information about the instance
    pub fn derive_status(
        &self,
        managed_host_state: ManagedHostState,
        reprovision_request: Option<ReprovisionRequest>,
        ib_status: Option<&MachineInfinibandStatusObservation>,
    ) -> Result<InstanceStatus, RpcDataConversionError> {
        InstanceStatus::from_config_and_observation(
            Versioned::new(&self.config, self.config_version),
            Versioned::new(&self.config.network, self.network_config_version),
            Versioned::new(&self.config.infiniband, self.ib_config_version),
            Versioned::new(&self.config.storage, self.storage_config_version),
            &self.observations,
            managed_host_state,
            self.deleted.is_some(),
            reprovision_request,
            ib_status,
            self.update_network_config_request.is_some(),
        )
    }
}
