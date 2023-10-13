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

use serde::{Deserialize, Serialize};

use crate::model::{
    config_version::Versioned,
    instance::config::{infiniband::InstanceInfinibandConfig, network::InstanceNetworkConfig},
    machine::{InstanceState, ManagedHostState},
    RpcDataConversionError,
};

pub mod infiniband;
pub mod network;
pub mod tenant;

/// Instance status
///
/// This represents the actual status of an Instance
#[derive(Debug, Clone)]
pub struct InstanceStatus {
    /// Status that is related to the tenant of the instance.
    /// In case no tenant has been assigned to this instance, the field would be absent.
    pub tenant: Option<tenant::InstanceTenantStatus>,

    /// Status of the networking subsystem of an instance
    pub network: network::InstanceNetworkStatus,

    /// Status of the infiniband subsystem of an instance
    pub infiniband: infiniband::InstanceInfinibandStatus,

    /// Whether all configurations related to an instance are in-sync.
    /// This is a logical AND for the settings of all sub-configurations.
    /// At this time it equals `InstanceNetworkStatus::configs_synced`,
    /// but might in the future also include readiness for other subsystems.
    pub configs_synced: SyncState,
}

impl TryFrom<InstanceStatus> for rpc::InstanceStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: InstanceStatus) -> Result<Self, Self::Error> {
        Ok(rpc::InstanceStatus {
            tenant: status.tenant.map(|status| status.try_into()).transpose()?,
            network: Some(status.network.try_into()?),
            infiniband: Some(status.infiniband.try_into()?),
            configs_synced: rpc::SyncState::try_from(status.configs_synced)? as i32,
        })
    }
}

impl InstanceStatus {
    /// Tries to convert Machine state to tenant state.
    fn tenant_state(
        machine_state: ManagedHostState,
    ) -> Result<tenant::TenantState, RpcDataConversionError> {
        // At this point, we are sure that instance is created.
        // If machine state is still ready, means state mahcine has not processed this instance
        // yet.

        let tenant_state = match machine_state {
            ManagedHostState::Ready => tenant::TenantState::Provisioning,
            ManagedHostState::Assigned { instance_state } => match instance_state {
                InstanceState::Init | InstanceState::WaitingForNetworkConfig => {
                    tenant::TenantState::Provisioning
                }
                InstanceState::Ready => tenant::TenantState::Ready,
                InstanceState::SwitchToAdminNetwork
                | InstanceState::BootingWithDiscoveryImage
                | InstanceState::WaitingForNetworkReconfig => tenant::TenantState::Terminating,
                InstanceState::DPUReprovision { .. } => tenant::TenantState::DpuReprovisioning,
            },
            _ => {
                tracing::error!(%machine_state, "Invalid state during state handling");
                return Err(RpcDataConversionError::InvalidMachineState(
                    machine_state.to_string(),
                ));
            }
        };

        Ok(tenant_state)
    }

    /// Derives an Instances network status from the users desired config
    /// and status that we observed from the networking subsystem.
    ///
    /// This mechanism guarantees that the status we return to the user always
    /// matches the latest `Config` set by the user. We can not directly
    /// forwarding the last observed status without taking `Config` into account,
    /// because the observation might have been related to a different config,
    /// and the interfaces therefore won't match.
    pub fn from_config_and_observation(
        network_config: Versioned<&InstanceNetworkConfig>,
        ib_config: Versioned<&InstanceInfinibandConfig>,
        observations: &InstanceStatusObservations,
        machine_state: ManagedHostState,
    ) -> Result<Self, RpcDataConversionError> {
        let network = network::InstanceNetworkStatus::from_config_and_observation(
            network_config,
            observations.network.as_ref(),
        );
        let infiniband = infiniband::InstanceInfinibandStatus::from_config_and_observation(
            ib_config,
            observations.infiniband.as_ref(),
        );

        // If additional configs are added, they need to be incorporated here
        let configs_synced = match (network.configs_synced, infiniband.configs_synced) {
            (SyncState::Synced, SyncState::Synced) => SyncState::Synced,
            _ => SyncState::Pending,
        };

        let tenant = tenant::InstanceTenantStatus {
            state: match configs_synced {
                SyncState::Synced => InstanceStatus::tenant_state(machine_state)?,
                SyncState::Pending => tenant::TenantState::Provisioning,
            },
            state_details: String::new(),
        };

        Ok(Self {
            tenant: Some(tenant),
            network,
            infiniband,
            configs_synced,
        })
    }
}

/// Whether user configurations have been applied
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SyncState {
    /// All configuration changes that users requested have been applied
    Synced,
    // At least one configuration change to an active instance has not yet been processed
    Pending,
}

impl TryFrom<SyncState> for rpc::SyncState {
    type Error = RpcDataConversionError;

    fn try_from(state: SyncState) -> Result<Self, Self::Error> {
        Ok(match state {
            SyncState::Synced => rpc::SyncState::Synced,
            SyncState::Pending => rpc::SyncState::Pending,
        })
    }
}

/// Contains all reports we have about the current instances state
///
/// We combine these with the desired config to derive instance state that we
/// signal to customers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceStatusObservations {
    /// Observed status of the networking subsystem
    pub network: Option<network::InstanceNetworkStatusObservation>,

    /// Observed status of the infiniband subsystem
    pub infiniband: Option<infiniband::InstanceInfinibandStatusObservation>,
}
