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
    config_version::Versioned,
    instance::config::network::InstanceNetworkConfig
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
        // TODO: Implement tenant state properly
        //
        // While we currently know whether the tenants desired config has been met
        // or not (`configs_synced`), and could switch the state to `Provisioning`
        // or `Configuring` based on that, we don't know yet whether the instance
        // ever was ready and therefore not which of those 2 states we are in.
        // Therefore we just always return `Ready` for the moment, which makes
        // us at least not go back from `Ready` to `Provisioning`
        let tenant = tenant::InstanceTenantStatus {
            state: tenant::TenantState::Ready,
            state_details: String::new(),
        };

        let network = network::InstanceNetworkStatus::from_config_and_observation(
            network_config,
            observations.network.as_ref(),
        );
        // If additional configs are added, they need to be incorporated here
        let configs_synced = network.configs_synced;

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

/// Contains all reports we have about the current instances state
///
/// We combine these with the desired config to derive instance state that we
/// signal to customers
#[derive(Debug, Clone)]
pub struct InstanceStatusObservations {
    /// Observed status of the networking subsystem
    pub network: Option<network::InstanceNetworkStatusObservation>,
}
