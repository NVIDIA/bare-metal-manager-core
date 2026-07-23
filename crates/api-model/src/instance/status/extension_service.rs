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

use std::collections::HashMap;

use carbide_utils::none_if_empty::NoneIfEmpty;
use carbide_uuid::extension_service::ExtensionServiceId;
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use serde::{Deserialize, Serialize};

use crate::extension_service::ExtensionServiceType;
use crate::instance::config::extension_services::InstanceExtensionServicesConfig;
use crate::instance::status::SyncState;
use crate::machine::Machine;

/// The status of all extension services configured on an instance
#[derive(Clone, Debug)]
pub struct InstanceExtensionServicesStatus {
    /// The status of each configured extension service
    pub extension_services: Vec<InstanceExtensionServiceStatus>,

    /// Whether all desired extension service changes that the user has applied have taken effect
    pub configs_synced: SyncState,
}

impl InstanceExtensionServicesStatus {
    /// Derives the extension services status from the user's desired config
    /// and the observations from DPUs.
    /// For each extension service, we aggregate the statuses from all DPUs.
    /// The config passed must be from database (not rpc InstanceConfig), and must contain any terminating services.
    pub fn from_config_and_observations(
        dpu_ids: &[MachineId],
        config: Versioned<&InstanceExtensionServicesConfig>,
        observations: &HashMap<MachineId, InstanceExtensionServiceStatusObservation>,
    ) -> Self {
        // This means the instance has no extension services configured and all once terminating
        // services has been terminated from all DPUs and hence not present any more
        if config.service_configs.is_empty() {
            return Self {
                extension_services: vec![],
                configs_synced: SyncState::Synced,
            };
        }

        // Instance allocation rejects non-empty service_configs on zero-DPU
        // hosts, so, in practice, we *shouldn't* reach here. BUT, if we do,
        // assume it's from something like a stale pre-validation instance,
        // and just report unsynced.
        if dpu_ids.is_empty() {
            return Self::unsynced_for_config(&config);
        }

        let mut is_configs_synced = true;
        let mut extension_services = vec![];

        // Iterate through each configured service and aggregate status from all DPUs
        for service in config.service_configs.iter() {
            let mut dpu_statuses = vec![];

            for dpu_id in dpu_ids {
                match observations.get(dpu_id) {
                    // DPU has observation with matching config version
                    Some(obs) if obs.config_version == config.version => {
                        // Find the specific service in the DPU's observation
                        let service_status = obs.extension_service_statuses.iter().find(|s| {
                            s.service_id == service.service_id && s.version == service.version
                        });

                        if let Some(service_status) = service_status {
                            dpu_statuses.push(MachineExtensionServiceStatus {
                                machine_id: *dpu_id,
                                status: service_status.overall_state.clone(),
                                error_message: service_status.message.clone().none_if_empty(),
                                components: service_status.components.clone(),
                            });
                        } else {
                            // DPU has observation but service is not in it - mark as Unknown
                            dpu_statuses.push(MachineExtensionServiceStatus {
                                machine_id: *dpu_id,
                                status: ExtensionServiceDeploymentStatus::Unknown,
                                error_message: Some(
                                    format!("Status observation is found for DPU {} but service is not in it.", dpu_id)
                                ),
                                components: vec![],
                            });
                        }
                    }
                    // DPU either has no observation, or observation is for a different config version
                    _ => {
                        is_configs_synced = false;
                        dpu_statuses.push(MachineExtensionServiceStatus {
                            machine_id: *dpu_id,
                            status: ExtensionServiceDeploymentStatus::Unknown,
                            // Note: This is a normal transitional state, not necessarily an error
                            error_message: Some("No status observation observed for this extension service config version yet.".to_string()),
                            components: vec![],
                        });
                    }
                }
            }

            // Calculate overall status based on DPU statuses
            let overall_status = Self::calculate_overall_status(&dpu_statuses);

            extension_services.push(InstanceExtensionServiceStatus {
                service_id: service.service_id,
                version: service.version,
                overall_status,
                dpu_statuses,
                removed: service.removed.as_ref().map(|removed| removed.to_string()),
            });
        }

        Self {
            extension_services,
            configs_synced: if is_configs_synced {
                SyncState::Synced
            } else {
                SyncState::Pending
            },
        }
    }

    /// Calculate the overall status based on the statuses from all DPUs.
    ///
    /// Priority order (highest to lowest):
    /// 1. Error/Failed - Any DPU in error state makes the entire service in error state
    /// 2. Unknown - Any DPU with unknown status means overall status is unknown
    /// 3. Pending - Any DPU pending means the service is not fully deployed yet
    /// 4. Running - All DPUs must be running for overall status to be running
    /// 5. Terminating - Any DPU terminating (and none in higher priority states)
    /// 6. Terminated - All DPUs must be terminated for overall status to be terminated
    /// 7. Unknown - Fallback for unexpected state combinations (e.g., mixed Running/Terminated)
    fn calculate_overall_status(
        dpu_statuses: &[MachineExtensionServiceStatus],
    ) -> ExtensionServiceDeploymentStatus {
        if dpu_statuses.is_empty() {
            return ExtensionServiceDeploymentStatus::Unknown;
        }

        // If any DPU reports Failed or Error, the overall status is Failed
        if dpu_statuses.iter().any(|s| {
            matches!(
                s.status,
                ExtensionServiceDeploymentStatus::Failed | ExtensionServiceDeploymentStatus::Error
            )
        }) {
            return ExtensionServiceDeploymentStatus::Error;
        }

        if dpu_statuses
            .iter()
            .any(|s| matches!(s.status, ExtensionServiceDeploymentStatus::Unknown))
        {
            return ExtensionServiceDeploymentStatus::Unknown;
        }

        // If any DPU is Pending, the overall status is Pending
        if dpu_statuses
            .iter()
            .any(|s| matches!(s.status, ExtensionServiceDeploymentStatus::Pending))
        {
            return ExtensionServiceDeploymentStatus::Pending;
        }

        // If all DPUs are Running, the overall status is Running
        if dpu_statuses
            .iter()
            .all(|s| matches!(s.status, ExtensionServiceDeploymentStatus::Running))
        {
            return ExtensionServiceDeploymentStatus::Running;
        }

        // If any DPU is Terminating, the overall status is Terminating
        if dpu_statuses
            .iter()
            .any(|s| matches!(s.status, ExtensionServiceDeploymentStatus::Terminating))
        {
            return ExtensionServiceDeploymentStatus::Terminating;
        }

        // If all DPUs are Terminated, the overall status is Terminated
        if dpu_statuses
            .iter()
            .all(|s| matches!(s.status, ExtensionServiceDeploymentStatus::Terminated))
        {
            return ExtensionServiceDeploymentStatus::Terminated;
        }

        // Otherwise, Unknown. But we should not reach here.
        ExtensionServiceDeploymentStatus::Unknown
    }

    /// Returns instance extension services status when no DPUs has reported status for the current
    /// extension service config version
    fn unsynced_for_config(config: &InstanceExtensionServicesConfig) -> Self {
        Self {
            extension_services: config
                .service_configs
                .iter()
                .map(|service| InstanceExtensionServiceStatus {
                    service_id: service.service_id,
                    version: service.version,
                    overall_status: ExtensionServiceDeploymentStatus::Unknown,
                    dpu_statuses: Vec::new(),
                    removed: service.removed.as_ref().map(|removed| removed.to_string()),
                })
                .collect(),
            configs_synced: SyncState::Pending,
        }
    }

    /// Returns `(service_id, extension service config version)` for extension services that are
    /// marked removed and fully `Terminated` on every DPU. Cleanup must use this pair, not
    /// `service_id` alone, because multiple config versions for the same service can exist during
    /// rolldown/upgrade.
    pub fn get_terminated_service_keys(&self) -> Vec<(ExtensionServiceId, ConfigVersion)> {
        self.extension_services
            .iter()
            .filter(|svc| {
                svc.removed.is_some()
                    && svc.overall_status == ExtensionServiceDeploymentStatus::Terminated
                    // @TODO(Felicity): handle zero dpu case
                    && !svc.dpu_statuses.is_empty()
                    && svc.dpu_statuses.iter().all(|dpu_status| {
                        matches!(
                            dpu_status.status,
                            ExtensionServiceDeploymentStatus::Terminated
                        )
                    })
            })
            .map(|svc| (svc.service_id, svc.version))
            .collect()
    }
}

/// Status of an extension service on a single DPU/machine
#[derive(Clone, Debug)]
pub struct MachineExtensionServiceStatus {
    /// The ID of the DPU this status is from
    pub machine_id: MachineId,
    /// The deployment status of the extension service on this specific DPU
    pub status: ExtensionServiceDeploymentStatus,
    /// Optional error message if the service encountered issues on this DPU
    pub error_message: Option<String>,
    /// The status of individual components/containers of the extension service on this DPU
    pub components: Vec<ExtensionServiceComponent>,
}

/// Aggregated status of a single extension service across all DPUs
#[derive(Clone, Debug)]
pub struct InstanceExtensionServiceStatus {
    /// The unique identifier of the extension service
    pub service_id: ExtensionServiceId,
    /// The version of the extension service configuration
    pub version: ConfigVersion,
    /// The aggregated status across all DPUs (calculated from dpu_statuses)
    pub overall_status: ExtensionServiceDeploymentStatus,
    /// Per-DPU status details for this service
    pub dpu_statuses: Vec<MachineExtensionServiceStatus>,
    /// Timestamp when the service was marked for removal, if applicable
    /// When Some, the service is in the process of being terminated
    pub removed: Option<String>,
}

/// Extension service deployment status
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExtensionServiceDeploymentStatus {
    Unknown,
    Pending,
    Running,
    Terminating,
    Terminated,
    Failed,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionServiceComponent {
    pub name: String,
    pub version: String, // This is the version of the component, not the version of the extension service
    pub url: String,
    pub status: String,
}

/// A single extension service status reported by DPU agent
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionServiceStatusObservation {
    pub service_id: ExtensionServiceId,
    pub service_type: ExtensionServiceType,
    pub service_name: String,
    pub version: ConfigVersion,
    pub removed: Option<String>,
    pub overall_state: ExtensionServiceDeploymentStatus,
    pub components: Vec<ExtensionServiceComponent>,
    pub message: String,
}

/// Observation of extension service statuses reported by a single DPU
/// This represents what the DPU agent has observed and reported back to the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceExtensionServiceStatusObservation {
    /// The config version that the DPU has applied for extension services
    /// This is compared against the desired config version to determine if configs are synced
    pub config_version: ConfigVersion,

    /// The observed version of the instance config
    pub instance_config_version: Option<ConfigVersion>,

    /// The status of each extension service running on this DPU
    pub extension_service_statuses: Vec<ExtensionServiceStatusObservation>,

    /// The timestamp when the DPU made this observation
    pub observed_at: DateTime<Utc>,
}

impl InstanceExtensionServiceStatusObservation {
    /// Aggregates extension service observations from multiple DPUs
    /// Returns a map of DPU machine ID to the extension service observation
    pub fn aggregate_instance_observation(dpu_snapshots: &[Machine]) -> HashMap<MachineId, Self> {
        dpu_snapshots
            .iter()
            .filter_map(|dpu| {
                dpu.network_status_observation
                    .as_ref()
                    .and_then(|obs| obs.extension_service_observation.clone())
                    .map(|ext_obs| (dpu.id, ext_obs))
            })
            .collect()
    }

    pub fn any_observed_version_changed(&self, other: &Self) -> bool {
        if (self.config_version != other.config_version)
            || (self.instance_config_version != other.instance_config_version)
        {
            return true;
        }

        let self_extension_service_versions: HashMap<ExtensionServiceId, ConfigVersion> =
            HashMap::from_iter(
                self.extension_service_statuses
                    .iter()
                    .map(|svc| (svc.service_id, svc.version)),
            );
        let other_extension_service_versions: HashMap<ExtensionServiceId, ConfigVersion> =
            HashMap::from_iter(
                other
                    .extension_service_statuses
                    .iter()
                    .map(|svc| (svc.service_id, svc.version)),
            );

        self_extension_service_versions != other_extension_service_versions
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionServicesReadiness {
    /// Configs are fully applied, and all non-removed (if any) services are Running.
    Ready,
    /// Configs are not yet applied across all DPUs.
    ConfigsPending,
    /// Some non-removed service is not Running.
    NotFullyRunning,
    /// Some removed services are still terminating on some DPU.
    SomeTerminating,
}

pub fn compute_extension_services_readiness(
    extension_services_status: &InstanceExtensionServicesStatus,
) -> ExtensionServicesReadiness {
    if extension_services_status.configs_synced == SyncState::Pending {
        return ExtensionServicesReadiness::ConfigsPending;
    }

    if extension_services_status
        .extension_services
        .iter()
        .any(|s| {
            s.removed.is_none() && s.overall_status != ExtensionServiceDeploymentStatus::Running
        })
    {
        return ExtensionServicesReadiness::NotFullyRunning;
    }

    if extension_services_status
        .extension_services
        .iter()
        .any(|s| {
            s.removed.is_some() && s.overall_status != ExtensionServiceDeploymentStatus::Terminated
        })
    {
        return ExtensionServicesReadiness::SomeTerminating;
    }

    // All checks passed: configs synced, all active services running, no services terminating
    ExtensionServicesReadiness::Ready
}

pub fn is_extension_services_ready(
    extension_services_status: &InstanceExtensionServicesStatus,
) -> bool {
    compute_extension_services_readiness(extension_services_status)
        == ExtensionServicesReadiness::Ready
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use carbide_test_support::value_scenarios;
    use chrono::{TimeZone, Utc};

    use super::*;
    use crate::extension_service::ExtensionServiceType;
    use crate::instance::config::extension_services::{
        InstanceExtensionServiceConfig, InstanceExtensionServicesConfig,
    };

    fn get_dpu_ids() -> Vec<MachineId> {
        vec![
            MachineId::from_str("fm100dskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80")
                .unwrap(),
            MachineId::from_str("fm100ds27v4uuq7sgs4gsjummskt0b3tedugtpevjrbfh6su081n9jufcq0")
                .unwrap(),
        ]
    }

    fn get_test_service_id() -> ExtensionServiceId {
        ExtensionServiceId::from_str("00000000-0000-0000-0000-000000000000").unwrap()
    }

    fn create_service_config(version: ConfigVersion) -> InstanceExtensionServicesConfig {
        InstanceExtensionServicesConfig {
            service_configs: vec![InstanceExtensionServiceConfig {
                service_id: get_test_service_id(),
                version,
                removed: None,
            }],
        }
    }

    fn create_observation(
        config_version: ConfigVersion,
        service_version: ConfigVersion,
        status: ExtensionServiceDeploymentStatus,
    ) -> InstanceExtensionServiceStatusObservation {
        InstanceExtensionServiceStatusObservation {
            config_version,
            instance_config_version: None,
            extension_service_statuses: vec![ExtensionServiceStatusObservation {
                service_id: get_test_service_id(),
                service_type: ExtensionServiceType::KubernetesPod,
                service_name: "test-service".to_string(),
                version: service_version,
                removed: None,
                overall_state: status,
                components: vec![],
                message: String::new(),
            }],
            observed_at: Utc::now(),
        }
    }

    fn create_observations(
        statuses: impl IntoIterator<
            Item = (
                MachineId,
                ConfigVersion,
                ConfigVersion,
                ExtensionServiceDeploymentStatus,
            ),
        >,
    ) -> HashMap<MachineId, InstanceExtensionServiceStatusObservation> {
        statuses
            .into_iter()
            .map(|(dpu_id, config_version, service_version, status)| {
                (
                    dpu_id,
                    create_observation(config_version, service_version, status),
                )
            })
            .collect()
    }

    struct StatusInput {
        dpu_ids: Vec<MachineId>,
        config: InstanceExtensionServicesConfig,
        config_version: ConfigVersion,
        observations: HashMap<MachineId, InstanceExtensionServiceStatusObservation>,
    }

    fn status_input(
        dpu_ids: Vec<MachineId>,
        service_version: ConfigVersion,
        config_version: ConfigVersion,
        observations: HashMap<MachineId, InstanceExtensionServiceStatusObservation>,
    ) -> StatusInput {
        StatusInput {
            dpu_ids,
            config: create_service_config(service_version),
            config_version,
            observations,
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DpuStatusProjection {
        machine_id: MachineId,
        status: ExtensionServiceDeploymentStatus,
        error_message: Option<String>,
        components: Vec<ExtensionServiceComponent>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ServiceStatusProjection {
        service_id: ExtensionServiceId,
        version: u64,
        overall_status: ExtensionServiceDeploymentStatus,
        dpu_statuses: Vec<DpuStatusProjection>,
        removed: Option<String>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct StatusProjection {
        configs_synced: SyncState,
        extension_services: Vec<ServiceStatusProjection>,
    }

    fn project_status(status: InstanceExtensionServicesStatus) -> StatusProjection {
        StatusProjection {
            configs_synced: status.configs_synced,
            extension_services: status
                .extension_services
                .into_iter()
                .map(|service| ServiceStatusProjection {
                    service_id: service.service_id,
                    version: service.version.version_nr(),
                    overall_status: service.overall_status,
                    dpu_statuses: service
                        .dpu_statuses
                        .into_iter()
                        .map(|dpu| DpuStatusProjection {
                            machine_id: dpu.machine_id,
                            status: dpu.status,
                            error_message: dpu.error_message,
                            components: dpu.components,
                        })
                        .collect(),
                    removed: service.removed,
                })
                .collect(),
        }
    }

    fn expected_dpu_status(
        machine_id: MachineId,
        status: ExtensionServiceDeploymentStatus,
        error_message: Option<&str>,
    ) -> DpuStatusProjection {
        DpuStatusProjection {
            machine_id,
            status,
            error_message: error_message.map(str::to_string),
            components: vec![],
        }
    }

    fn expected_status(
        configs_synced: SyncState,
        overall_status: ExtensionServiceDeploymentStatus,
        dpu_statuses: Vec<DpuStatusProjection>,
    ) -> StatusProjection {
        StatusProjection {
            extension_services: vec![ServiceStatusProjection {
                service_id: get_test_service_id(),
                version: 1,
                overall_status,
                dpu_statuses,
                removed: None,
            }],
            configs_synced,
        }
    }

    #[test]
    fn extension_service_status_from_config_and_observations() {
        let service_version = ConfigVersion::initial();
        let config_version = ConfigVersion::initial();
        let [dpu1_id, dpu2_id] = get_dpu_ids().try_into().unwrap();
        let missing_observation =
            "No status observation observed for this extension service config version yet.";
        let component = ExtensionServiceComponent {
            name: "test-component".to_string(),
            version: "1.0.0".to_string(),
            url: "registry.example.test/test-component:1.0.0".to_string(),
            status: "Running".to_string(),
        };
        let service_message = "service is running";
        let mut synced_observation = create_observations([(
            dpu1_id,
            config_version,
            service_version,
            ExtensionServiceDeploymentStatus::Running,
        )]);
        let synced_service = &mut synced_observation
            .get_mut(&dpu1_id)
            .unwrap()
            .extension_service_statuses[0];
        synced_service.message = service_message.to_string();
        synced_service.components = vec![component.clone()];
        let stale_service_observation = create_observations([(
            dpu1_id,
            config_version,
            service_version.increment(),
            ExtensionServiceDeploymentStatus::Running,
        )]);
        let mut other_service_observation = create_observations([(
            dpu1_id,
            config_version,
            service_version,
            ExtensionServiceDeploymentStatus::Running,
        )]);
        other_service_observation
            .get_mut(&dpu1_id)
            .unwrap()
            .extension_service_statuses[0]
            .service_id =
            ExtensionServiceId::from_str("00000000-0000-0000-0000-000000000001").unwrap();
        let missing_service =
            format!("Status observation is found for DPU {dpu1_id} but service is not in it.");
        let removed_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let removed_at_text = "2026-01-01 00:00:00 UTC".to_string();
        let second_service_version = service_version.increment();

        value_scenarios!(
            run = |StatusInput {
                dpu_ids,
                config,
                config_version,
                observations,
            }| {
                project_status(InstanceExtensionServicesStatus::from_config_and_observations(
                    &dpu_ids,
                    Versioned::new(&config, config_version),
                    &observations,
                ))
            };
            "without configured services" {
                StatusInput {
                    dpu_ids: vec![dpu1_id],
                    config: InstanceExtensionServicesConfig {
                        service_configs: vec![],
                    },
                    config_version,
                    observations: HashMap::new(),
                } => StatusProjection {
                    configs_synced: SyncState::Synced,
                    extension_services: vec![],
                },
            }

            "with configured services but no target DPUs" {
                StatusInput {
                    dpu_ids: vec![],
                    config: InstanceExtensionServicesConfig {
                        service_configs: vec![
                            InstanceExtensionServiceConfig {
                                service_id: get_test_service_id(),
                                version: second_service_version,
                                removed: None,
                            },
                            InstanceExtensionServiceConfig {
                                service_id: get_test_service_id(),
                                version: service_version,
                                removed: Some(removed_at),
                            },
                        ],
                    },
                    config_version,
                    observations: HashMap::new(),
                } => StatusProjection {
                    configs_synced: SyncState::Pending,
                    extension_services: vec![
                        ServiceStatusProjection {
                            service_id: get_test_service_id(),
                            version: 2,
                            overall_status: ExtensionServiceDeploymentStatus::Unknown,
                            dpu_statuses: vec![],
                            removed: None,
                        },
                        ServiceStatusProjection {
                            service_id: get_test_service_id(),
                            version: 1,
                            overall_status: ExtensionServiceDeploymentStatus::Unknown,
                            dpu_statuses: vec![],
                            removed: Some(removed_at_text),
                        },
                    ],
                },
            }

            "without observations" {
                status_input(
                    vec![dpu1_id],
                    service_version,
                    config_version,
                    HashMap::new(),
                ) => expected_status(
                    SyncState::Pending,
                    ExtensionServiceDeploymentStatus::Unknown,
                    vec![expected_dpu_status(
                        dpu1_id,
                        ExtensionServiceDeploymentStatus::Unknown,
                        Some(missing_observation),
                    )],
                ),
            }

            "with a synced observation" {
                status_input(
                    vec![dpu1_id],
                    service_version,
                    config_version,
                    synced_observation,
                ) => expected_status(
                    SyncState::Synced,
                    ExtensionServiceDeploymentStatus::Running,
                    vec![DpuStatusProjection {
                        machine_id: dpu1_id,
                        status: ExtensionServiceDeploymentStatus::Running,
                        error_message: Some(service_message.to_string()),
                        components: vec![component],
                    }],
                ),
            }

            "when a synced observation only has a stale service version" {
                status_input(
                    vec![dpu1_id],
                    service_version,
                    config_version,
                    stale_service_observation,
                ) => expected_status(
                    SyncState::Synced,
                    ExtensionServiceDeploymentStatus::Unknown,
                    vec![expected_dpu_status(
                        dpu1_id,
                        ExtensionServiceDeploymentStatus::Unknown,
                        Some(missing_service.as_str()),
                    )],
                ),
            }

            "when a synced observation only has another service" {
                status_input(
                    vec![dpu1_id],
                    service_version,
                    config_version,
                    other_service_observation,
                ) => expected_status(
                    SyncState::Synced,
                    ExtensionServiceDeploymentStatus::Unknown,
                    vec![expected_dpu_status(
                        dpu1_id,
                        ExtensionServiceDeploymentStatus::Unknown,
                        Some(missing_service.as_str()),
                    )],
                ),
            }

            "with an outdated observation" {
                status_input(
                    vec![dpu1_id],
                    service_version,
                    config_version.increment(),
                    create_observations([(
                        dpu1_id,
                        config_version,
                        service_version,
                        ExtensionServiceDeploymentStatus::Running,
                    )]),
                ) => expected_status(
                    SyncState::Pending,
                    ExtensionServiceDeploymentStatus::Unknown,
                    vec![expected_dpu_status(
                        dpu1_id,
                        ExtensionServiceDeploymentStatus::Unknown,
                        Some(missing_observation),
                    )],
                ),
            }

            "with one of two DPU observations missing" {
                status_input(
                    vec![dpu1_id, dpu2_id],
                    service_version,
                    config_version,
                    create_observations([(
                        dpu1_id,
                        config_version,
                        service_version,
                        ExtensionServiceDeploymentStatus::Running,
                    )]),
                ) => expected_status(
                    SyncState::Pending,
                    ExtensionServiceDeploymentStatus::Unknown,
                    vec![
                        expected_dpu_status(
                            dpu1_id,
                            ExtensionServiceDeploymentStatus::Running,
                            None,
                        ),
                        expected_dpu_status(
                            dpu2_id,
                            ExtensionServiceDeploymentStatus::Unknown,
                            Some(missing_observation),
                        ),
                    ],
                ),
            }

            "with all DPU observations present" {
                status_input(
                    vec![dpu1_id, dpu2_id],
                    service_version,
                    config_version,
                    create_observations([
                        (
                            dpu1_id,
                            config_version,
                            service_version,
                            ExtensionServiceDeploymentStatus::Running,
                        ),
                        (
                            dpu2_id,
                            config_version,
                            service_version,
                            ExtensionServiceDeploymentStatus::Running,
                        ),
                    ]),
                ) => expected_status(
                    SyncState::Synced,
                    ExtensionServiceDeploymentStatus::Running,
                    vec![
                        expected_dpu_status(
                            dpu1_id,
                            ExtensionServiceDeploymentStatus::Running,
                            None,
                        ),
                        expected_dpu_status(
                            dpu2_id,
                            ExtensionServiceDeploymentStatus::Running,
                            None,
                        ),
                    ],
                ),
            }

            "scoped to target DPUs" {
                status_input(
                    vec![dpu1_id],
                    service_version,
                    config_version,
                    create_observations([
                        (
                            dpu1_id,
                            config_version,
                            service_version,
                            ExtensionServiceDeploymentStatus::Running,
                        ),
                        (
                            dpu2_id,
                            config_version,
                            service_version,
                            ExtensionServiceDeploymentStatus::Pending,
                        ),
                    ]),
                ) => expected_status(
                    SyncState::Synced,
                    ExtensionServiceDeploymentStatus::Running,
                    vec![expected_dpu_status(
                        dpu1_id,
                        ExtensionServiceDeploymentStatus::Running,
                        None,
                    )],
                ),
            }
        );
    }

    fn readiness_status(
        configs_synced: SyncState,
        services: impl IntoIterator<Item = (bool, ExtensionServiceDeploymentStatus)>,
    ) -> InstanceExtensionServicesStatus {
        InstanceExtensionServicesStatus {
            extension_services: services
                .into_iter()
                .map(|(removed, overall_status)| InstanceExtensionServiceStatus {
                    service_id: get_test_service_id(),
                    version: ConfigVersion::initial(),
                    overall_status,
                    dpu_statuses: vec![],
                    removed: removed.then(|| Utc::now().to_string()),
                })
                .collect(),
            configs_synced,
        }
    }

    #[test]
    fn extension_service_readiness() {
        value_scenarios!(
            run = |status| (
                compute_extension_services_readiness(&status),
                is_extension_services_ready(&status),
            );
            "configs pending" {
                readiness_status(
                    SyncState::Pending,
                    [(false, ExtensionServiceDeploymentStatus::Unknown)],
                ) => (ExtensionServicesReadiness::ConfigsPending, false),
            }

            "configs synced without services" {
                readiness_status(SyncState::Synced, []) =>
                    (ExtensionServicesReadiness::Ready, true),
            }

            "configs synced and service running" {
                readiness_status(
                    SyncState::Synced,
                    [(false, ExtensionServiceDeploymentStatus::Running)],
                ) => (ExtensionServicesReadiness::Ready, true),
            }

            "active service not running" {
                readiness_status(
                    SyncState::Synced,
                    [(false, ExtensionServiceDeploymentStatus::Pending)],
                ) => (ExtensionServicesReadiness::NotFullyRunning, false),
            }

            "removed service still terminating" {
                readiness_status(
                    SyncState::Synced,
                    [(true, ExtensionServiceDeploymentStatus::Terminating)],
                ) => (ExtensionServicesReadiness::SomeTerminating, false),
            }

            "removed service terminated" {
                readiness_status(
                    SyncState::Synced,
                    [(true, ExtensionServiceDeploymentStatus::Terminated)],
                ) => (ExtensionServicesReadiness::Ready, true),
            }

            "active failure takes precedence over removed termination" {
                readiness_status(
                    SyncState::Synced,
                    [
                        (false, ExtensionServiceDeploymentStatus::Failed),
                        (true, ExtensionServiceDeploymentStatus::Terminating),
                    ],
                ) => (ExtensionServicesReadiness::NotFullyRunning, false),
            }
        );
    }

    #[test]
    fn extension_service_calculate_overall_status() {
        value_scenarios!(
            run = |statuses: Vec<ExtensionServiceDeploymentStatus>| {
                let machine_id = get_dpu_ids()[0];
                let dpu_statuses = statuses
                    .into_iter()
                    .map(|status| MachineExtensionServiceStatus {
                        machine_id,
                        status,
                        error_message: None,
                        components: vec![],
                    })
                    .collect::<Vec<_>>();
                InstanceExtensionServicesStatus::calculate_overall_status(&dpu_statuses)
            };
            "all running" {
                vec![
                    ExtensionServiceDeploymentStatus::Running,
                    ExtensionServiceDeploymentStatus::Running,
                ] => ExtensionServiceDeploymentStatus::Running,
            }

            "one failed" {
                vec![
                    ExtensionServiceDeploymentStatus::Running,
                    ExtensionServiceDeploymentStatus::Failed,
                ] => ExtensionServiceDeploymentStatus::Error,
            }

            "error takes precedence over unknown" {
                vec![
                    ExtensionServiceDeploymentStatus::Unknown,
                    ExtensionServiceDeploymentStatus::Error,
                ] => ExtensionServiceDeploymentStatus::Error,
            }

            "unknown takes precedence over pending" {
                vec![
                    ExtensionServiceDeploymentStatus::Pending,
                    ExtensionServiceDeploymentStatus::Unknown,
                ] => ExtensionServiceDeploymentStatus::Unknown,
            }

            "one pending" {
                vec![
                    ExtensionServiceDeploymentStatus::Running,
                    ExtensionServiceDeploymentStatus::Pending,
                ] => ExtensionServiceDeploymentStatus::Pending,
            }

            "pending takes precedence over terminating" {
                vec![
                    ExtensionServiceDeploymentStatus::Terminating,
                    ExtensionServiceDeploymentStatus::Pending,
                ] => ExtensionServiceDeploymentStatus::Pending,
            }

            "one terminating" {
                vec![
                    ExtensionServiceDeploymentStatus::Running,
                    ExtensionServiceDeploymentStatus::Terminating,
                ] => ExtensionServiceDeploymentStatus::Terminating,
            }

            "terminating takes precedence over terminated" {
                vec![
                    ExtensionServiceDeploymentStatus::Terminated,
                    ExtensionServiceDeploymentStatus::Terminating,
                ] => ExtensionServiceDeploymentStatus::Terminating,
            }

            "all terminated" {
                vec![
                    ExtensionServiceDeploymentStatus::Terminated,
                    ExtensionServiceDeploymentStatus::Terminated,
                ] => ExtensionServiceDeploymentStatus::Terminated,
            }

            "mixed running and terminated" {
                vec![
                    ExtensionServiceDeploymentStatus::Running,
                    ExtensionServiceDeploymentStatus::Terminated,
                ] => ExtensionServiceDeploymentStatus::Unknown,
            }

            "empty" {
                vec![] => ExtensionServiceDeploymentStatus::Unknown,
            }
        );
    }

    #[test]
    fn extension_service_observations_from_dpu_snapshots() {
        let config_version = ConfigVersion::initial();
        let observation = create_observation(
            config_version,
            ConfigVersion::initial(),
            ExtensionServiceDeploymentStatus::Running,
        );
        let mut observed_dpu = crate::test_support::machine_snapshot::dpu_machine(0);
        observed_dpu
            .network_status_observation
            .as_mut()
            .unwrap()
            .extension_service_observation = Some(observation.clone());
        let observed_dpu_id = observed_dpu.id;

        value_scenarios!(
            run = |dpu_snapshots: Vec<Machine>| {
                InstanceExtensionServiceStatusObservation::aggregate_instance_observation(
                    &dpu_snapshots,
                )
            };
            "without snapshots" {
                vec![] => HashMap::new(),
            }

            "snapshot without an extension-service observation" {
                vec![crate::test_support::machine_snapshot::dpu_machine(1)] => HashMap::new(),
            }

            "mixed snapshots" {
                vec![
                    observed_dpu,
                    crate::test_support::machine_snapshot::dpu_machine(1),
                ] => HashMap::from([(observed_dpu_id, observation)]),
            }
        );
    }

    fn create_observation_two_versions(
        dpu_id: MachineId,
        cfg_version: ConfigVersion,
        v_new: ConfigVersion,
        new_state: ExtensionServiceDeploymentStatus,
        v_old: ConfigVersion,
        old_state: ExtensionServiceDeploymentStatus,
    ) -> HashMap<MachineId, InstanceExtensionServiceStatusObservation> {
        let mut observations = HashMap::new();
        observations.insert(
            dpu_id,
            InstanceExtensionServiceStatusObservation {
                config_version: cfg_version,
                instance_config_version: None,
                extension_service_statuses: vec![
                    ExtensionServiceStatusObservation {
                        service_id: get_test_service_id(),
                        service_type: ExtensionServiceType::KubernetesPod,
                        service_name: "test-service".to_string(),
                        version: v_new,
                        removed: None,
                        overall_state: new_state,
                        components: vec![],
                        message: String::new(),
                    },
                    ExtensionServiceStatusObservation {
                        service_id: get_test_service_id(),
                        service_type: ExtensionServiceType::KubernetesPod,
                        service_name: "test-service".to_string(),
                        version: v_old,
                        removed: Some(Utc::now().to_rfc3339()),
                        overall_state: old_state,
                        components: vec![],
                        message: String::new(),
                    },
                ],
                observed_at: chrono::Utc::now(),
            },
        );
        observations
    }

    fn machine_statuses(
        statuses: impl IntoIterator<Item = (MachineId, ExtensionServiceDeploymentStatus)>,
    ) -> Vec<MachineExtensionServiceStatus> {
        statuses
            .into_iter()
            .map(|(machine_id, status)| MachineExtensionServiceStatus {
                machine_id,
                status,
                error_message: None,
                components: vec![],
            })
            .collect()
    }

    fn service_status(
        version: ConfigVersion,
        removed: bool,
        overall_status: ExtensionServiceDeploymentStatus,
        dpu_statuses: Vec<MachineExtensionServiceStatus>,
    ) -> InstanceExtensionServiceStatus {
        InstanceExtensionServiceStatus {
            service_id: get_test_service_id(),
            version,
            overall_status,
            dpu_statuses,
            removed: removed.then(|| "removed".to_string()),
        }
    }

    #[test]
    fn extension_service_get_terminated_service_keys() {
        let [dpu1_id, dpu2_id] = get_dpu_ids().try_into().unwrap();

        let init_version = ConfigVersion::initial();
        let second_version = init_version.increment();
        let config = InstanceExtensionServicesConfig {
            service_configs: vec![
                InstanceExtensionServiceConfig {
                    service_id: get_test_service_id(),
                    version: second_version,
                    removed: None,
                },
                InstanceExtensionServiceConfig {
                    service_id: get_test_service_id(),
                    version: init_version,
                    removed: Some(Utc::now()),
                },
            ],
        };
        let config_version = ConfigVersion::initial();
        let observations = create_observation_two_versions(
            dpu1_id,
            config_version,
            second_version,
            ExtensionServiceDeploymentStatus::Running,
            init_version,
            ExtensionServiceDeploymentStatus::Terminated,
        );

        let aggregated_status = InstanceExtensionServicesStatus::from_config_and_observations(
            &[dpu1_id],
            Versioned::new(&config, config_version),
            &observations,
        );

        value_scenarios!(
            run = |status: InstanceExtensionServicesStatus| {
                status.get_terminated_service_keys()
            };
            "removed version terminated on every DPU" {
                aggregated_status => vec![(get_test_service_id(), init_version)],
            }

            "active version" {
                InstanceExtensionServicesStatus {
                    extension_services: vec![service_status(
                        init_version,
                        false,
                        ExtensionServiceDeploymentStatus::Terminated,
                        machine_statuses([(
                            dpu1_id,
                            ExtensionServiceDeploymentStatus::Terminated,
                        )]),
                    )],
                    configs_synced: SyncState::Synced,
                } => vec![],
            }

            "removed version not terminated overall" {
                InstanceExtensionServicesStatus {
                    extension_services: vec![service_status(
                        init_version,
                        true,
                        ExtensionServiceDeploymentStatus::Terminating,
                        machine_statuses([(
                            dpu1_id,
                            ExtensionServiceDeploymentStatus::Terminated,
                        )]),
                    )],
                    configs_synced: SyncState::Synced,
                } => vec![],
            }

            "removed version without DPU statuses" {
                InstanceExtensionServicesStatus {
                    extension_services: vec![service_status(
                        init_version,
                        true,
                        ExtensionServiceDeploymentStatus::Terminated,
                        vec![],
                    )],
                    configs_synced: SyncState::Synced,
                } => vec![],
            }

            "removed version with one DPU not terminated" {
                InstanceExtensionServicesStatus {
                    extension_services: vec![service_status(
                        init_version,
                        true,
                        ExtensionServiceDeploymentStatus::Terminated,
                        machine_statuses([
                            (
                                dpu1_id,
                                ExtensionServiceDeploymentStatus::Terminated,
                            ),
                            (dpu2_id, ExtensionServiceDeploymentStatus::Running),
                        ]),
                    )],
                    configs_synced: SyncState::Synced,
                } => vec![],
            }
        );
    }
}
