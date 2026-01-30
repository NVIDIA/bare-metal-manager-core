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
use carbide_uuid::machine::MachineId;
use config_version::Versioned;
use serde::{Deserialize, Serialize};

use crate::instance::config::InstanceConfig;
use crate::instance::config::extension_services::InstanceExtensionServicesConfig;
use crate::instance::config::infiniband::InstanceInfinibandConfig;
use crate::instance::config::network::InstanceNetworkConfig;
use crate::instance::config::nvlink::InstanceNvLinkConfig;
use crate::machine::infiniband::MachineInfinibandStatusObservation;
use crate::machine::nvlink::MachineNvLinkStatusObservation;
use crate::machine::{InstanceState, ManagedHostState, ReprovisionRequest};

pub mod extension_service;
pub mod infiniband;
pub mod network;
pub mod nvlink;
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

    /// Status of the extension services configured on an instance
    pub extension_services: extension_service::InstanceExtensionServicesStatus,

    /// Status of nvlink subsystem of an instance
    pub nvlink: nvlink::InstanceNvLinkStatus,

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
            dpu_extension_services: Some(status.extension_services.try_into()?),
            nvlink: Some(status.nvlink.try_into()?),
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
        extension_services_ready: bool,
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
                | InstanceState::WaitingForExtensionServicesConfig
                | InstanceState::WaitingForRebootToReady => tenant::TenantState::Provisioning,
                InstanceState::NetworkConfigUpdate { .. } => tenant::TenantState::Configuring,

                InstanceState::Ready => {
                    let phone_home_pending =
                        phone_home_enrolled && phone_home_last_contact.is_none();

                    // TODO phone_home_last_contact window? e.g. must have been received in last 10 minutes
                    match (phone_home_pending, configs_synced, extension_services_ready) {
                        // If there is no pending phone-home, but configs are
                        // not synced, configs must have changed after provisioning finished
                        // since we entered Ready state.
                        (false, SyncState::Pending, _) => tenant::TenantState::Configuring,

                        // If there is no pending phone-home, but extension services are not ready,
                        // then extension services must have changed after provisioning finished
                        // since we entered Ready state.
                        (false, _, false) => tenant::TenantState::Configuring,

                        // If there is no pending phone-home and extension services are ready,
                        // return Ready (this was the default before phone_home)
                        (false, SyncState::Synced, true) => tenant::TenantState::Ready,

                        // If there is a pending phone-home, we're still
                        // provisioning.
                        (true, _, _) => tenant::TenantState::Provisioning,
                    }
                }
                // If termination had been requested (i.e., if the `deleted` column
                // of the instance record in the DB is non-null), then things would
                // have short-circuited to Terminating before ever even getting to
                // this tenant_state function.
                InstanceState::SwitchToAdminNetwork | InstanceState::WaitingForNetworkReconfig => {
                    tenant::TenantState::Terminating
                }
                // When tenants request a custom pxe reboot, the managed hosts
                // will go through HostPlatformConfiguration and WaitingForDpusToUp
                // before going back to Ready
                InstanceState::WaitingForDpusToUp
                | InstanceState::HostPlatformConfiguration { .. } => {
                    tenant::TenantState::Configuring
                }
                InstanceState::BootingWithDiscoveryImage { .. }
                | InstanceState::DPUReprovision { .. }
                | InstanceState::HostReprovision { .. } => tenant::TenantState::Updating,
                InstanceState::DpaProvisioning => tenant::TenantState::Updating,
                InstanceState::WaitingForDpaToBeReady => tenant::TenantState::Updating,
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
        extension_services_config: Versioned<&InstanceExtensionServicesConfig>,
        nvlink_config: Versioned<&InstanceNvLinkConfig>,
        observations: &InstanceStatusObservations,
        machine_state: ManagedHostState,
        delete_requested: bool,
        reprovision_request: Option<ReprovisionRequest>,
        ib_status: Option<&MachineInfinibandStatusObservation>,
        nvlink_status: Option<&MachineNvLinkStatusObservation>,
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
            dpu_id_to_device_map.clone(),
            network_config,
            &observations.network,
            is_network_config_request_pending,
        );

        let infiniband =
            infiniband::InstanceInfinibandStatus::from_config_and_observation(ib_config, ib_status);

        let extension_services =
            extension_service::InstanceExtensionServicesStatus::from_config_and_observations(
                &dpu_id_to_device_map,
                extension_services_config,
                &observations.extension_services,
            );
        let extension_services_ready =
            extension_service::is_extension_services_ready(&extension_services);
        let nvlink =
            nvlink::InstanceNvLinkStatus::from_config_and_observation(nvlink_config, nvlink_status);

        let phone_home_last_contact = observations.phone_home_last_contact;

        // If additional configs are added, they need to be incorporated here
        let configs_synced = match (
            network.configs_synced,
            infiniband.configs_synced,
            extension_services.configs_synced,
            nvlink.configs_synced,
            instance_config_synced,
        ) {
            (
                SyncState::Synced,
                SyncState::Synced,
                SyncState::Synced,
                SyncState::Synced,
                SyncState::Synced,
            ) => SyncState::Synced,
            _ => SyncState::Pending,
        };

        let tenant = tenant::InstanceTenantStatus {
            state: match delete_requested {
                false => InstanceStatus::tenant_state(
                    machine_state,
                    configs_synced,
                    instance_config.os.phone_home_enabled,
                    phone_home_last_contact,
                    extension_services_ready,
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
            extension_services,
            nvlink,
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

    /// Observed status of extension services
    pub extension_services:
        HashMap<MachineId, extension_service::InstanceExtensionServiceStatusObservation>,

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
                false,
            )
            .unwrap(),
            tenant::TenantState::Invalid
        );
    }
}
