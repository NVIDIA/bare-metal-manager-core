/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use model::instance::status::SyncState;
use model::instance::status::tenant::{InstanceTenantStatus, TenantState};
use model::machine::{InstanceState, ManagedHostState};

use crate as rpc;
use crate::errors::RpcDataConversionError;

/// Converts machine state into the tenant-visible [`TenantState`].
///
/// When `repair_active` is true, [`TenantState::Repairing`] is returned only if the
/// instance would otherwise be tenant-ready (`InstanceState::Ready` with synced configs
/// and extension services ready). It does not override Failed, Updating, Configuring,
/// Provisioning, or Terminating.
///
/// When `operator_managed_networking` is true, NICo has no data-plane readiness
/// signal to wait for. Allocation and network-wait states are therefore projected
/// as tenant-ready while terminal and update states retain precedence.
pub fn instance_status_tenant_state(
    machine_state: ManagedHostState,
    configs_synced: SyncState,
    phone_home_enrolled: bool,
    phone_home_last_contact: Option<chrono::DateTime<chrono::Utc>>,
    extension_services_ready: bool,
    operator_managed_networking: bool,
    repair_active: bool,
) -> Result<TenantState, RpcDataConversionError> {
    // At this point, we are sure that instance is created.
    // If machine state is still ready, means state machine has not processed this instance
    // yet.

    let tenant_ready_state = || {
        if repair_active {
            TenantState::Repairing
        } else {
            TenantState::Ready
        }
    };

    let tenant_state = match machine_state {
        ManagedHostState::Ready => {
            if operator_managed_networking {
                tenant_ready_state()
            } else {
                TenantState::Provisioning
            }
        }
        ManagedHostState::Assigned { instance_state } => match instance_state {
            InstanceState::Init
            | InstanceState::WaitingForNetworkSegmentToBeReady
            | InstanceState::WaitingForNetworkConfig
            | InstanceState::WaitingForStorageConfig
            | InstanceState::WaitingForExtensionServicesConfig
            | InstanceState::WaitingForRebootToReady => {
                if operator_managed_networking {
                    tenant_ready_state()
                } else {
                    TenantState::Provisioning
                }
            }
            InstanceState::NetworkConfigUpdate { .. } => {
                if operator_managed_networking {
                    tenant_ready_state()
                } else {
                    TenantState::Configuring
                }
            }

            InstanceState::Ready if operator_managed_networking => tenant_ready_state(),
            InstanceState::Ready => {
                let phone_home_pending = phone_home_enrolled && phone_home_last_contact.is_none();

                // TODO phone_home_last_contact window? e.g. must have been received in last 10 minutes
                match (phone_home_pending, configs_synced, extension_services_ready) {
                    // If there is no pending phone-home, but configs are
                    // not synced, configs must have changed after provisioning finished
                    // since we entered Ready state.
                    (false, SyncState::Pending, _) => TenantState::Configuring,

                    // If there is no pending phone-home, but extension services are not ready,
                    // then extension services must have changed after provisioning finished
                    // since we entered Ready state.
                    (false, _, false) => TenantState::Configuring,

                    // If there is no pending phone-home and extension services are ready,
                    // the instance is tenant-ready; surface online repair only in this case.
                    (false, SyncState::Synced, true) if repair_active => TenantState::Repairing,
                    (false, SyncState::Synced, true) => TenantState::Ready,

                    // If there is a pending phone-home, we're still
                    // provisioning.
                    (true, _, _) => TenantState::Provisioning,
                }
            }
            // If termination had been requested (i.e., if the `deleted` column
            // of the instance record in the DB is non-null), then things would
            // have short-circuited to Terminating before ever even getting to
            // this tenant_state function.
            InstanceState::SwitchToAdminNetwork | InstanceState::WaitingForNetworkReconfig => {
                TenantState::Terminating
            }
            // When tenants request a custom pxe reboot, the managed hosts
            // will go through HostPlatformConfiguration and WaitingForDpusToUp
            // before going back to Ready
            InstanceState::WaitingForDpusToUp | InstanceState::HostPlatformConfiguration { .. } => {
                TenantState::Configuring
            }
            InstanceState::BootingWithDiscoveryImage { .. }
            | InstanceState::DPUReprovision { .. }
            | InstanceState::HostReprovision { .. } => TenantState::Updating,
            InstanceState::DpaProvisioning => TenantState::Updating,
            InstanceState::WaitingForDpaToBeReady => TenantState::Updating,
            InstanceState::Failed { .. } => TenantState::Failed,
        },
        ManagedHostState::ForceDeletion => TenantState::Terminating,
        _ => {
            tracing::error!(%machine_state, "Invalid state during state handling");
            TenantState::Invalid
        }
    };

    Ok(tenant_state)
}

impl TryFrom<InstanceTenantStatus> for rpc::InstanceTenantStatus {
    type Error = RpcDataConversionError;

    fn try_from(state: InstanceTenantStatus) -> Result<Self, Self::Error> {
        Ok(rpc::InstanceTenantStatus {
            state: rpc::TenantState::try_from(state.state)? as i32,
            state_details: state.state_details,
        })
    }
}

impl TryFrom<TenantState> for rpc::TenantState {
    type Error = RpcDataConversionError;

    fn try_from(state: TenantState) -> Result<Self, Self::Error> {
        Ok(match state {
            TenantState::Provisioning => rpc::TenantState::Provisioning,
            TenantState::DpuReprovisioning => rpc::TenantState::DpuReprovisioning,
            TenantState::Ready => rpc::TenantState::Ready,
            TenantState::Configuring => rpc::TenantState::Configuring,
            TenantState::Terminating => rpc::TenantState::Terminating,
            TenantState::Terminated => rpc::TenantState::Terminated,
            TenantState::Failed => rpc::TenantState::Failed,
            TenantState::HostReprovisioning => rpc::TenantState::HostReprovisioning,
            TenantState::Updating => rpc::TenantState::Updating,
            TenantState::Invalid => rpc::TenantState::Invalid,
            TenantState::Repairing => rpc::TenantState::Repairing,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases};
    use carbide_uuid::machine::MachineId;
    use chrono::Utc;
    use health_report::{HealthReport, REPAIR_REQUEST_MERGE_SOURCE};
    use model::health::HealthReportSources;
    use model::instance::status::SyncState;
    use model::machine::{
        DpuReprovisionStates, FailureCause, FailureDetails, FailureSource, HostPlatformConfigurationState,
        HostReprovisionState, InstanceState, ManagedHostState, NetworkConfigUpdateState, RetryInfo,
    };

    use super::*;

    /// Build a representative `InstanceState::Failed` for table inputs.
    fn failed_state() -> InstanceState {
        let machine_id =
            MachineId::from_str("fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0")
                .unwrap();
        InstanceState::Failed {
            details: FailureDetails {
                cause: FailureCause::NoError,
                failed_at: Utc::now(),
                source: FailureSource::StateMachine,
            },
            machine_id,
        }
    }

    #[test]
    fn repair_merge_active_detects_merge_sources() {
        let mut health = HealthReportSources::default();
        assert!(!health.repair_merge_active());
        health.merges.insert(
            REPAIR_REQUEST_MERGE_SOURCE.to_string(),
            HealthReport {
                source: REPAIR_REQUEST_MERGE_SOURCE.to_string(),
                ..Default::default()
            },
        );
        assert!(health.repair_merge_active());
    }

    #[test]
    fn repair_merge_tenant_state_precedence() {
        let machine_id =
            MachineId::from_str("fm100htjtiaehv1n5vh67tbmqq4eabcjdng40f7jupsadbedhruh6rag1l0")
                .unwrap();
        let failed = InstanceState::Failed {
            details: FailureDetails {
                cause: FailureCause::NoError,
                failed_at: Utc::now(),
                source: FailureSource::StateMachine,
            },
            machine_id,
        };

        // Each row: a (machine_state, configs_synced) pair under repair_active=true,
        // exercising which states repair-merge does or does not override.
        check_cases(
            [
                Case {
                    scenario: "tenant-ready with repair merge",
                    input: (
                        ManagedHostState::Assigned {
                            instance_state: InstanceState::Ready,
                        },
                        SyncState::Synced,
                    ),
                    expect: Yields(TenantState::Repairing),
                },
                Case {
                    scenario: "terminating with repair merge",
                    input: (
                        ManagedHostState::Assigned {
                            instance_state: InstanceState::SwitchToAdminNetwork,
                        },
                        SyncState::Synced,
                    ),
                    expect: Yields(TenantState::Terminating),
                },
                Case {
                    scenario: "reprovision with repair merge",
                    input: (
                        ManagedHostState::Assigned {
                            instance_state: InstanceState::DPUReprovision {
                                dpu_states: DpuReprovisionStates {
                                    states: HashMap::new(),
                                },
                            },
                        },
                        SyncState::Synced,
                    ),
                    expect: Yields(TenantState::Updating),
                },
                Case {
                    scenario: "configuring with repair merge",
                    input: (
                        ManagedHostState::Assigned {
                            instance_state: InstanceState::Ready,
                        },
                        SyncState::Pending,
                    ),
                    expect: Yields(TenantState::Configuring),
                },
                Case {
                    scenario: "failed with repair merge",
                    input: (
                        ManagedHostState::Assigned {
                            instance_state: failed,
                        },
                        SyncState::Synced,
                    ),
                    expect: Yields(TenantState::Failed),
                },
            ],
            |(machine_state, configs_synced)| {
                instance_status_tenant_state(
                    machine_state,
                    configs_synced,
                    false,
                    None,
                    true,
                    false,
                    true,
                )
                .map_err(drop)
            },
        );
    }

    #[test]
    fn operator_managed_allocations_project_as_tenant_ready() {
        // Allocated/network-wait states where Flat has no NICo readiness signal:
        // operator-managed networking should not wait on network observations.
        check_cases(
            [
                Case {
                    scenario: "allocated before state controller pickup",
                    input: ManagedHostState::Ready,
                    expect: Yields(TenantState::Ready),
                },
                Case {
                    scenario: "assigned init",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::Init,
                    },
                    expect: Yields(TenantState::Ready),
                },
                Case {
                    scenario: "waiting for network config",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkConfig,
                    },
                    expect: Yields(TenantState::Ready),
                },
                Case {
                    scenario: "network config update",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::NetworkConfigUpdate {
                            network_config_update_state:
                                model::machine::NetworkConfigUpdateState::WaitingForNetworkSegmentToBeReady,
                        },
                    },
                    expect: Yields(TenantState::Ready),
                },
            ],
            |machine_state| {
                instance_status_tenant_state(
                    machine_state,
                    SyncState::Pending,
                    true,
                    None,
                    false,
                    true,
                    false,
                )
                .map_err(drop)
            },
        );
    }

    /// Every `TenantState` arm maps to its `rpc::TenantState` counterpart. The
    /// conversion is fallible in signature only; each arm is expected to yield.
    #[test]
    fn tenant_state_to_rpc_maps_every_variant() {
        check_cases(
            [
                Case {
                    scenario: "provisioning",
                    input: TenantState::Provisioning,
                    expect: Yields(rpc::TenantState::Provisioning),
                },
                Case {
                    scenario: "dpu reprovisioning",
                    input: TenantState::DpuReprovisioning,
                    expect: Yields(rpc::TenantState::DpuReprovisioning),
                },
                Case {
                    scenario: "ready",
                    input: TenantState::Ready,
                    expect: Yields(rpc::TenantState::Ready),
                },
                Case {
                    scenario: "configuring",
                    input: TenantState::Configuring,
                    expect: Yields(rpc::TenantState::Configuring),
                },
                Case {
                    scenario: "terminating",
                    input: TenantState::Terminating,
                    expect: Yields(rpc::TenantState::Terminating),
                },
                Case {
                    scenario: "terminated",
                    input: TenantState::Terminated,
                    expect: Yields(rpc::TenantState::Terminated),
                },
                Case {
                    scenario: "failed",
                    input: TenantState::Failed,
                    expect: Yields(rpc::TenantState::Failed),
                },
                Case {
                    scenario: "host reprovisioning",
                    input: TenantState::HostReprovisioning,
                    expect: Yields(rpc::TenantState::HostReprovisioning),
                },
                Case {
                    scenario: "updating",
                    input: TenantState::Updating,
                    expect: Yields(rpc::TenantState::Updating),
                },
                Case {
                    scenario: "invalid",
                    input: TenantState::Invalid,
                    expect: Yields(rpc::TenantState::Invalid),
                },
                Case {
                    scenario: "repairing",
                    input: TenantState::Repairing,
                    expect: Yields(rpc::TenantState::Repairing),
                },
            ],
            |state| rpc::TenantState::try_from(state).map_err(drop),
        );
    }

    /// `InstanceTenantStatus` converts into its rpc message: the state arm is
    /// projected to its `i32` tag and `state_details` carries through verbatim,
    /// including when empty.
    #[test]
    fn instance_tenant_status_to_rpc_round_trips() {
        check_cases(
            [
                Case {
                    scenario: "ready with details",
                    input: InstanceTenantStatus {
                        state: TenantState::Ready,
                        state_details: "all good".to_string(),
                    },
                    expect: Yields(rpc::InstanceTenantStatus {
                        state: rpc::TenantState::Ready as i32,
                        state_details: "all good".to_string(),
                    }),
                },
                Case {
                    scenario: "failed with empty details",
                    input: InstanceTenantStatus {
                        state: TenantState::Failed,
                        state_details: String::new(),
                    },
                    expect: Yields(rpc::InstanceTenantStatus {
                        state: rpc::TenantState::Failed as i32,
                        state_details: String::new(),
                    }),
                },
                Case {
                    scenario: "repairing preserves details",
                    input: InstanceTenantStatus {
                        state: TenantState::Repairing,
                        state_details: "online repair".to_string(),
                    },
                    expect: Yields(rpc::InstanceTenantStatus {
                        state: rpc::TenantState::Repairing as i32,
                        state_details: "online repair".to_string(),
                    }),
                },
            ],
            |status| rpc::InstanceTenantStatus::try_from(status).map_err(drop),
        );
    }

    /// Default projection (no operator-managed networking, no active repair): every
    /// `InstanceState` arm plus the `ManagedHostState` arms resolve to their
    /// tenant-visible state.
    #[test]
    fn instance_status_tenant_state_default_projection() {
        check_cases(
            [
                Case {
                    scenario: "host ready -> provisioning",
                    input: ManagedHostState::Ready,
                    expect: Yields(TenantState::Provisioning),
                },
                Case {
                    scenario: "assigned init -> provisioning",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::Init,
                    },
                    expect: Yields(TenantState::Provisioning),
                },
                Case {
                    scenario: "waiting for network segment -> provisioning",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkSegmentToBeReady,
                    },
                    expect: Yields(TenantState::Provisioning),
                },
                Case {
                    scenario: "waiting for network config -> provisioning",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkConfig,
                    },
                    expect: Yields(TenantState::Provisioning),
                },
                Case {
                    scenario: "waiting for storage config -> provisioning",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForStorageConfig,
                    },
                    expect: Yields(TenantState::Provisioning),
                },
                Case {
                    scenario: "waiting for extension services config -> provisioning",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForExtensionServicesConfig,
                    },
                    expect: Yields(TenantState::Provisioning),
                },
                Case {
                    scenario: "waiting for reboot to ready -> provisioning",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForRebootToReady,
                    },
                    expect: Yields(TenantState::Provisioning),
                },
                Case {
                    scenario: "network config update -> configuring",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::NetworkConfigUpdate {
                            network_config_update_state:
                                NetworkConfigUpdateState::WaitingForConfigSynced,
                        },
                    },
                    expect: Yields(TenantState::Configuring),
                },
                Case {
                    scenario: "switch to admin network -> terminating",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::SwitchToAdminNetwork,
                    },
                    expect: Yields(TenantState::Terminating),
                },
                Case {
                    scenario: "waiting for network reconfig -> terminating",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForNetworkReconfig,
                    },
                    expect: Yields(TenantState::Terminating),
                },
                Case {
                    scenario: "waiting for dpus to up -> configuring",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForDpusToUp,
                    },
                    expect: Yields(TenantState::Configuring),
                },
                Case {
                    scenario: "host platform configuration -> configuring",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::HostPlatformConfiguration {
                            platform_config_state:
                                HostPlatformConfigurationState::CheckHostConfig,
                        },
                    },
                    expect: Yields(TenantState::Configuring),
                },
                Case {
                    scenario: "booting with discovery image -> updating",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::BootingWithDiscoveryImage {
                            retry: RetryInfo::default(),
                        },
                    },
                    expect: Yields(TenantState::Updating),
                },
                Case {
                    scenario: "dpu reprovision -> updating",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::DPUReprovision {
                            dpu_states: DpuReprovisionStates {
                                states: HashMap::new(),
                            },
                        },
                    },
                    expect: Yields(TenantState::Updating),
                },
                Case {
                    scenario: "host reprovision -> updating",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::HostReprovision {
                            reprovision_state: HostReprovisionState::WaitingForScript {},
                        },
                    },
                    expect: Yields(TenantState::Updating),
                },
                Case {
                    scenario: "dpa provisioning -> updating",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::DpaProvisioning,
                    },
                    expect: Yields(TenantState::Updating),
                },
                Case {
                    scenario: "waiting for dpa to be ready -> updating",
                    input: ManagedHostState::Assigned {
                        instance_state: InstanceState::WaitingForDpaToBeReady,
                    },
                    expect: Yields(TenantState::Updating),
                },
                Case {
                    scenario: "failed -> failed",
                    input: ManagedHostState::Assigned {
                        instance_state: failed_state(),
                    },
                    expect: Yields(TenantState::Failed),
                },
                Case {
                    scenario: "force deletion -> terminating",
                    input: ManagedHostState::ForceDeletion,
                    expect: Yields(TenantState::Terminating),
                },
                Case {
                    scenario: "unhandled host state -> invalid",
                    input: ManagedHostState::Created,
                    expect: Yields(TenantState::Invalid),
                },
            ],
            |machine_state| {
                instance_status_tenant_state(
                    machine_state,
                    SyncState::Synced,
                    false,
                    None,
                    true,
                    false,
                    false,
                )
                .map_err(drop)
            },
        );
    }

    /// The `InstanceState::Ready` arm fans out on phone-home, config sync, and
    /// extension-service readiness; cover each combination under default
    /// (non-operator) networking.
    #[test]
    fn instance_status_tenant_state_ready_fanout() {
        struct Row {
            scenario: &'static str,
            phone_home_enrolled: bool,
            phone_home_last_contact: Option<chrono::DateTime<Utc>>,
            configs_synced: SyncState,
            extension_services_ready: bool,
            repair_active: bool,
            expect: TenantState,
        }

        let rows = [
            Row {
                scenario: "synced and ready -> ready",
                phone_home_enrolled: false,
                phone_home_last_contact: None,
                configs_synced: SyncState::Synced,
                extension_services_ready: true,
                repair_active: false,
                expect: TenantState::Ready,
            },
            Row {
                scenario: "synced and ready with repair -> repairing",
                phone_home_enrolled: false,
                phone_home_last_contact: None,
                configs_synced: SyncState::Synced,
                extension_services_ready: true,
                repair_active: true,
                expect: TenantState::Repairing,
            },
            Row {
                scenario: "configs pending -> configuring",
                phone_home_enrolled: false,
                phone_home_last_contact: None,
                configs_synced: SyncState::Pending,
                extension_services_ready: true,
                repair_active: false,
                expect: TenantState::Configuring,
            },
            Row {
                scenario: "extension services not ready -> configuring",
                phone_home_enrolled: false,
                phone_home_last_contact: None,
                configs_synced: SyncState::Synced,
                extension_services_ready: false,
                repair_active: false,
                expect: TenantState::Configuring,
            },
            Row {
                scenario: "phone-home enrolled but not contacted -> provisioning",
                phone_home_enrolled: true,
                phone_home_last_contact: None,
                configs_synced: SyncState::Synced,
                extension_services_ready: true,
                repair_active: false,
                expect: TenantState::Provisioning,
            },
            Row {
                scenario: "phone-home enrolled and contacted -> ready",
                phone_home_enrolled: true,
                phone_home_last_contact: Some(Utc::now()),
                configs_synced: SyncState::Synced,
                extension_services_ready: true,
                repair_active: false,
                expect: TenantState::Ready,
            },
        ];

        check_cases(
            rows.map(|row| Case {
                scenario: row.scenario,
                input: row,
                expect: Yields(()),
            }),
            |row| {
                let expected = row.expect;
                instance_status_tenant_state(
                    ManagedHostState::Assigned {
                        instance_state: InstanceState::Ready,
                    },
                    row.configs_synced,
                    row.phone_home_enrolled,
                    row.phone_home_last_contact,
                    row.extension_services_ready,
                    false,
                    row.repair_active,
                )
                .map_err(drop)
                .map(|got| assert_eq!(got, expected))
            },
        );
    }
}
