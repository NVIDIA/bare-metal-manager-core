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

use serde::{Deserialize, Serialize};

use crate::model::{
    config_version::Versioned, instance::config::network::InstanceNetworkConfig,
    RpcDataConversionError,
};

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
            configs_synced: rpc::SyncState::try_from(status.configs_synced)? as i32,
        })
    }
}

impl InstanceStatus {
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
        observations: &InstanceStatusObservations,
    ) -> Self {
        let network = network::InstanceNetworkStatus::from_config_and_observation(
            network_config,
            observations.network.as_ref(),
        );
        // If additional configs are added, they need to be incorporated here
        let configs_synced = network.configs_synced;

        // TODO: Implement tenant state properly
        //
        // The current implementation is an approximation, and only works because
        // the only time the network status changes is after the managed resource
        // becomes ready. This is the only time we observe the network status,
        // and can therefore get from `Provisioning` to `Ready`.
        // If we would observe the state more often, using the same logic could
        // however make us go back from a `Ready` state to a `Provisioning` state.
        // This would be wrong - it needs to be `Configuring` instead. To fix this,
        // we need an additional persisted flag that tracks whether the instance
        // has ever been `Ready`. We don't have this yet, so we can't provide the
        // better implementation.
        let tenant = tenant::InstanceTenantStatus {
            state: match configs_synced {
                SyncState::Synced => tenant::TenantState::Ready,
                SyncState::Pending => tenant::TenantState::Provisioning,
            },
            state_details: String::new(),
        };

        Self {
            tenant: Some(tenant),
            network,
            configs_synced,
        }
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
}
