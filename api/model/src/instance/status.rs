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

use std::collections::HashMap;

use ::rpc::errors::RpcDataConversionError;
use config_version::Versioned;
use forge_uuid::machine::MachineId;
use serde::{Deserialize, Serialize};

use crate::instance::config::InstanceConfig;
use crate::instance::config::infiniband::InstanceInfinibandConfig;
use crate::instance::config::network::InstanceNetworkConfig;
use crate::instance::config::storage::InstanceStorageConfig;
use crate::machine::infiniband::MachineInfinibandStatusObservation;
use crate::machine::{InstanceState, ManagedHostState, ReprovisionRequest};

pub mod infiniband;
pub mod network;
pub mod storage;
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

    pub storage: storage::InstanceStorageStatus,

    /// Whether all configurations related to an instance are in-sync.
    /// This is a logical AND for the settings of all sub-configurations.
    /// At this time it equals `InstanceNetworkStatus::configs_synced`,
    /// but might in the future also include readiness for other subsystems.
    pub configs_synced: SyncState,

    /// Whether there is one reprovision request on the underlying Machine
    /// TODO: This might be multiple. and potentially it it should be
    /// `InstanceUpdateStatus` instead of `ReprovisionRequest`
    pub reprovision_request: Option<ReprovisionRequest>,
}

impl TryFrom<InstanceStatus> for rpc::InstanceStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: InstanceStatus) -> Result<Self, Self::Error> {
        Ok(rpc::InstanceStatus {
            tenant: status.tenant.map(|status| status.try_into()).transpose()?,
            network: Some(status.network.try_into()?),
            infiniband: Some(status.infiniband.try_into()?),
            storage: Some(status.storage.try_into()?),
            configs_synced: rpc::SyncState::try_from(status.configs_synced)? as i32,
            update: status.reprovision_request.map(|request| request.into()),
        })
    }
}

impl InstanceStatus {
    /// Tries to convert Machine state to tenant state.
    pub fn tenant_state(
        machine_state: ManagedHostState,
        configs_synced: SyncState,
        phone_home_enrolled: bool,
        phone_home_last_contact: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<tenant::TenantState, RpcDataConversionError> {
        // At this point, we are sure that instance is created.
        // If machine state is still ready, means state machine has not processed this instance
        // yet.

        let tenant_state = match machine_state {
            ManagedHostState::Ready => tenant::TenantState::Provisioning,
            ManagedHostState::Assigned { instance_state } => match instance_state {
                InstanceState::Init
                | InstanceState::WaitingForNetworkSegmentToBeReady
                | InstanceState::WaitingForNetworkConfig
                | InstanceState::WaitingForStorageConfig
                | InstanceState::WaitingForRebootToReady => tenant::TenantState::Provisioning,
                InstanceState::NetworkConfigUpdate { .. } => tenant::TenantState::Configuring,
                InstanceState::Ready => {
                    let phone_home_pending =
                        phone_home_enrolled && phone_home_last_contact.is_none();

                    // TODO phone_home_last_contact window? e.g. must have been received in last 10 minutes

                    match (phone_home_pending, configs_synced) {
                        // If there is no pending phone-home, but configs are
                        // not synced, configs must have changed after provisioning finished
                        // since we entered Ready state.
                        (false, SyncState::Pending) => tenant::TenantState::Configuring,

                        // If there is no pending phone-home,
                        // return Ready (this was the default before phone_home)
                        (false, SyncState::Synced) => tenant::TenantState::Ready,

                        // If there is a pending phone-home, we're still
                        // provisioning.
                        (true, _) => tenant::TenantState::Provisioning,
                    }
                }
                // If termination had been requested (i.e., if the `deleted` column
                // of the instance record in the DB is non-null), then things would
                // have short-circuited to Terminating before ever even getting to
                // this tenant_state function.
                InstanceState::SwitchToAdminNetwork
                | InstanceState::WaitingForNetworkReconfig
                | InstanceState::WaitingForDpusToUp => tenant::TenantState::Terminating,
                // We're deprecating TenantState::DpuReprovisioning and
                // TenantState::HostReprovisioning in favor of TenantState::Updating.
                // Because forge-cloud already translates DpuReprovisioning to Updating,
                // we can use that while we prepare it to accept TenantState::Updating.
                // TODO: Replace TenantState::DpuReprovisioning with TenantState::Updating
                // after cloud components for all sites have been updated.
                InstanceState::BootingWithDiscoveryImage { .. }
                | InstanceState::DPUReprovision { .. }
                | InstanceState::HostReprovision { .. } => tenant::TenantState::DpuReprovisioning,
                InstanceState::Failed { .. } => tenant::TenantState::Failed,
            },
            ManagedHostState::ForceDeletion => tenant::TenantState::Terminating,
            _ => {
                tracing::error!(%machine_state, "Invalid state during state handling");
                tenant::TenantState::Invalid
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
    #[allow(clippy::too_many_arguments)]
    pub fn from_config_and_observation(
        dpu_id_to_device_map: HashMap<String, Vec<MachineId>>,
        instance_config: Versioned<&InstanceConfig>,
        network_config: Versioned<&InstanceNetworkConfig>,
        ib_config: Versioned<&InstanceInfinibandConfig>,
        storage_config: Versioned<&InstanceStorageConfig>,
        observations: &InstanceStatusObservations,
        machine_state: ManagedHostState,
        delete_requested: bool,
        reprovision_request: Option<ReprovisionRequest>,
        ib_status: Option<&MachineInfinibandStatusObservation>,
        is_network_config_request_pending: bool,
    ) -> Result<Self, RpcDataConversionError> {
        let mut instance_config_synced = SyncState::Synced;

        for network_obs in observations.network.values() {
            if let Some(version_obs) = network_obs.instance_config_version
                && instance_config.version != version_obs
            {
                instance_config_synced = SyncState::Pending;
                break;
            }
            // TODO(bcavanagh): Switch to SyncState::Pending or
            //                  return Err(RpcDataConversionError::InvalidConfigVersion)
            //                  after all dpu-agents have been updated to support/report the field.
            // If observations.network.instance_config_version was None, then "ignore"
        }

        let network = network::InstanceNetworkStatus::from_config_and_observations(
            dpu_id_to_device_map,
            network_config,
            &observations.network,
            is_network_config_request_pending,
        );

        let infiniband =
            infiniband::InstanceInfinibandStatus::from_config_and_observation(ib_config, ib_status);
        let storage = storage::InstanceStorageStatus::from_config_and_observation(
            storage_config,
            observations.storage.as_ref(),
        );

        let phone_home_last_contact = observations.phone_home_last_contact;

        // If additional configs are added, they need to be incorporated here
        let configs_synced = match (
            network.configs_synced,
            infiniband.configs_synced,
            instance_config_synced,
        ) {
            (SyncState::Synced, SyncState::Synced, SyncState::Synced) => SyncState::Synced,
            _ => SyncState::Pending,
        };

        let tenant = tenant::InstanceTenantStatus {
            state: match delete_requested {
                false => InstanceStatus::tenant_state(
                    machine_state,
                    configs_synced,
                    instance_config.os.phone_home_enabled,
                    phone_home_last_contact,
                )?,
                true => {
                    // If instance deletion was requested, we always confirm the
                    // tenant that the instance is actually in progress of shutting down.
                    // The instance might however still first need to run through
                    // various provisioning steps to become "ready" before starting
                    // to terminate
                    tenant::TenantState::Terminating
                }
            },
            state_details: String::new(),
        };

        Ok(Self {
            tenant: Some(tenant),
            network,
            infiniband,
            storage,
            configs_synced,
            reprovision_request,
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
    pub network: HashMap<MachineId, network::InstanceNetworkStatusObservation>,

    pub storage: Option<storage::InstanceStorageStatusObservation>,

    /// Has the instance phoned home?
    pub phone_home_last_contact: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::machine::{DpuReprovisionStates, ReprovisionState};

    #[test]
    fn test_tenant_state() {
        let machine_id: MachineId =
            MachineId::from_str("fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0")
                .unwrap();

        assert_eq!(
            InstanceStatus::tenant_state(
                ManagedHostState::DPUReprovision {
                    dpu_states: DpuReprovisionStates {
                        states: HashMap::from([(
                            machine_id,
                            ReprovisionState::WaitingForNetworkConfig,
                        )]),
                    },
                },
                SyncState::Synced,
                false,
                None,
            )
            .unwrap(),
            tenant::TenantState::Invalid
        );
    }
}
