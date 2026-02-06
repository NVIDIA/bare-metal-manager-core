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

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::extension_service::ExtensionServiceId;
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use rpc::forge as rpc;
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

impl TryFrom<InstanceExtensionServicesStatus> for rpc::InstanceDpuExtensionServicesStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: InstanceExtensionServicesStatus) -> Result<Self, Self::Error> {
        let mut extension_services = Vec::with_capacity(status.extension_services.len());
        for service in status.extension_services {
            extension_services.push(rpc::InstanceDpuExtensionServiceStatus::try_from(service)?);
        }
        Ok(rpc::InstanceDpuExtensionServicesStatus {
            dpu_extension_services: extension_services,
            configs_synced: rpc::SyncState::try_from(status.configs_synced)? as i32,
        })
    }
}

impl InstanceExtensionServicesStatus {
    /// Derives the extension services status from the user's desired config
    /// and the observations from DPUs.
    /// For each extension service, we aggregate the statuses from all DPUs.
    /// The config passed must be from database (not rpc InstanceConfig), and must contain any terminating services.
    pub fn from_config_and_observations(
        dpu_id_to_device_map: &HashMap<String, Vec<MachineId>>,
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

        // Extract all unique DPU machine IDs from the dpu_id_to_device_map
        let all_dpu_ids: Vec<MachineId> =
            dpu_id_to_device_map.values().flatten().copied().collect();

        // @TODO(Felicity): Zero DPU for this instance? Maybe deny extension service config if no DPUs?
        if all_dpu_ids.is_empty() {
            return Self::unsynced_for_config(&config);
        }

        let mut is_configs_synced = true;
        let mut extension_services = vec![];

        // Iterate through each configured service and aggregate status from all DPUs
        for service in config.service_configs.iter() {
            let mut dpu_statuses = vec![];

            for dpu_id in &all_dpu_ids {
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
                                error_message: if service_status.message.is_empty() {
                                    None
                                } else {
                                    Some(service_status.message.clone())
                                },
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

    /// Returns the set of service IDs that are marked as removed and have been fully terminated
    /// across all DPUs (i.e., all DPUs report the service as Terminated)
    pub fn get_terminated_service_ids(&self) -> std::collections::HashSet<ExtensionServiceId> {
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
            .map(|svc| svc.service_id)
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

impl From<rpc::DpuExtensionServiceDeploymentStatus> for ExtensionServiceDeploymentStatus {
    fn from(status: rpc::DpuExtensionServiceDeploymentStatus) -> Self {
        match status {
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceUnknown => Self::Unknown,
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServicePending => Self::Pending,
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceRunning => Self::Running,
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceTerminating => {
                Self::Terminating
            }
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceTerminated => {
                Self::Terminated
            }
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceFailed => Self::Failed,
            rpc::DpuExtensionServiceDeploymentStatus::DpuExtensionServiceError => Self::Error,
        }
    }
}

impl From<ExtensionServiceDeploymentStatus> for rpc::DpuExtensionServiceDeploymentStatus {
    fn from(status: ExtensionServiceDeploymentStatus) -> Self {
        match status {
            ExtensionServiceDeploymentStatus::Unknown => Self::DpuExtensionServiceUnknown,
            ExtensionServiceDeploymentStatus::Pending => Self::DpuExtensionServicePending,
            ExtensionServiceDeploymentStatus::Running => Self::DpuExtensionServiceRunning,
            ExtensionServiceDeploymentStatus::Terminating => Self::DpuExtensionServiceTerminating,
            ExtensionServiceDeploymentStatus::Terminated => Self::DpuExtensionServiceTerminated,
            ExtensionServiceDeploymentStatus::Failed => Self::DpuExtensionServiceFailed,
            ExtensionServiceDeploymentStatus::Error => Self::DpuExtensionServiceError,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionServiceComponent {
    pub name: String,
    pub version: String, // This is the version of the component, not the version of the extension service
    pub url: String,
    pub status: String,
}

impl TryFrom<rpc::DpuExtensionServiceComponent> for ExtensionServiceComponent {
    type Error = RpcDataConversionError;

    fn try_from(component: rpc::DpuExtensionServiceComponent) -> Result<Self, Self::Error> {
        Ok(Self {
            name: component.name,
            version: component.version,
            url: component.url,
            status: component.status,
        })
    }
}

impl From<ExtensionServiceComponent> for rpc::DpuExtensionServiceComponent {
    fn from(component: ExtensionServiceComponent) -> Self {
        Self {
            name: component.name,
            version: component.version,
            url: component.url,
            status: component.status,
        }
    }
}

impl TryFrom<MachineExtensionServiceStatus> for rpc::DpuExtensionServiceStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: MachineExtensionServiceStatus) -> Result<Self, Self::Error> {
        Ok(Self {
            dpu_machine_id: Some(status.machine_id),
            status: rpc::DpuExtensionServiceDeploymentStatus::from(status.status).into(),
            error_message: status.error_message,
            components: status
                .components
                .into_iter()
                .map(rpc::DpuExtensionServiceComponent::from)
                .collect(),
        })
    }
}

impl TryFrom<InstanceExtensionServiceStatus> for rpc::InstanceDpuExtensionServiceStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: InstanceExtensionServiceStatus) -> Result<Self, Self::Error> {
        let dpu_statuses = status
            .dpu_statuses
            .into_iter()
            .map(rpc::DpuExtensionServiceStatus::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            service_id: status.service_id.into(),
            version: status.version.to_string(),
            deployment_status: rpc::DpuExtensionServiceDeploymentStatus::from(
                status.overall_status,
            )
            .into(),
            dpu_statuses,
            removed: status.removed,
        })
    }
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

impl TryFrom<rpc::DpuExtensionServiceStatusObservation> for ExtensionServiceStatusObservation {
    type Error = RpcDataConversionError;

    fn try_from(
        observation: rpc::DpuExtensionServiceStatusObservation,
    ) -> Result<Self, Self::Error> {
        let service_id = observation
            .service_id
            .parse::<ExtensionServiceId>()
            .map_err(|e| {
                RpcDataConversionError::InvalidUuid("ExtensionServiceId", e.to_string())
            })?;

        let service_type = rpc::DpuExtensionServiceType::try_from(observation.service_type)
            .map_err(|_| {
                RpcDataConversionError::InvalidValue(
                    observation.service_type.to_string(),
                    "service_type".to_string(),
                )
            })?
            .into();

        let overall_state = rpc::DpuExtensionServiceDeploymentStatus::try_from(observation.state)
            .map_err(|_| {
                RpcDataConversionError::InvalidValue(
                    observation.state.to_string(),
                    "state".to_string(),
                )
            })?
            .into();

        let components = observation
            .components
            .into_iter()
            .map(ExtensionServiceComponent::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let version = observation.version.parse::<ConfigVersion>().map_err(|e| {
            RpcDataConversionError::InvalidConfigVersion(format!(
                "Failed to parse version as ConfigVersion: {}",
                e
            ))
        })?;

        Ok(Self {
            service_id,
            service_type,
            service_name: observation.service_name,
            version,
            removed: observation.removed,
            overall_state,
            components,
            message: observation.message,
        })
    }
}

impl From<ExtensionServiceStatusObservation> for rpc::DpuExtensionServiceStatusObservation {
    fn from(observation: ExtensionServiceStatusObservation) -> Self {
        Self {
            service_id: observation.service_id.into(),
            service_type: rpc::DpuExtensionServiceType::from(observation.service_type).into(),
            service_name: observation.service_name,
            version: observation.version.to_string(),
            removed: observation.removed,
            state: rpc::DpuExtensionServiceDeploymentStatus::from(observation.overall_state).into(),
            components: observation
                .components
                .into_iter()
                .map(|c| rpc::DpuExtensionServiceComponent {
                    name: c.name,
                    version: c.version,
                    url: c.url,
                    status: c.status,
                })
                .collect(),
            message: observation.message,
        }
    }
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

    use super::*;
    use crate::extension_service::ExtensionServiceType;
    use crate::instance::config::extension_services::{
        InstanceExtensionServiceConfig, InstanceExtensionServicesConfig,
    };

    fn get_test_machine_id() -> MachineId {
        MachineId::from_str("fm100dskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80").unwrap()
    }

    fn get_test_service_id() -> ExtensionServiceId {
        ExtensionServiceId::from_str("00000000-0000-0000-0000-000000000000").unwrap()
    }

    fn create_dpu_map_with_one_dpu() -> HashMap<String, Vec<MachineId>> {
        let mut map = HashMap::new();
        map.insert("device0".to_string(), vec![get_test_machine_id()]);
        map
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
    ) -> HashMap<MachineId, InstanceExtensionServiceStatusObservation> {
        let mut observations = HashMap::new();
        observations.insert(
            MachineId::from_str("fm100dskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80")
                .unwrap(),
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
                observed_at: chrono::Utc::now(),
            },
        );
        observations
    }

    #[test]
    fn extension_service_status_without_observations() {
        let service_version = ConfigVersion::initial();
        let config = create_service_config(service_version);

        let config_version = ConfigVersion::initial();
        let dpu_map = create_dpu_map_with_one_dpu();

        let status = InstanceExtensionServicesStatus::from_config_and_observations(
            &dpu_map,
            Versioned::new(&config, config_version),
            &HashMap::new(),
        );

        // Without observations, should be unsynced with DPU status showing Unknown
        assert_eq!(status.configs_synced, SyncState::Pending);
        assert_eq!(status.extension_services.len(), 1);
        assert_eq!(status.extension_services[0].version.version_nr(), 1);
        assert_eq!(
            status.extension_services[0].overall_status,
            ExtensionServiceDeploymentStatus::Unknown
        );
        assert_eq!(status.extension_services[0].dpu_statuses.len(), 1);
        assert_eq!(
            status.extension_services[0].dpu_statuses[0].status,
            ExtensionServiceDeploymentStatus::Unknown
        );

        // Readiness check: configs are not synced, so should be ConfigsPending
        let readiness = compute_extension_services_readiness(&status);
        assert_eq!(readiness, ExtensionServicesReadiness::ConfigsPending);
    }

    #[test]
    fn extension_service_status_with_synced_observations() {
        let service_version = ConfigVersion::initial();
        let config = create_service_config(service_version);
        let config_version = ConfigVersion::initial();

        let dpu_map = create_dpu_map_with_one_dpu();
        let observations = create_observation(
            config_version,
            service_version,
            ExtensionServiceDeploymentStatus::Running,
        );

        let status = InstanceExtensionServicesStatus::from_config_and_observations(
            &dpu_map,
            Versioned::new(&config, config_version),
            &observations,
        );

        assert_eq!(status.configs_synced, SyncState::Synced);
        assert_eq!(status.extension_services.len(), 1);
        assert_eq!(
            status.extension_services[0].overall_status,
            ExtensionServiceDeploymentStatus::Running
        );
        assert_eq!(status.extension_services[0].dpu_statuses.len(), 1);
        assert_eq!(
            status.extension_services[0].dpu_statuses[0].machine_id,
            get_test_machine_id(),
        );
        assert_eq!(
            status.extension_services[0].dpu_statuses[0].status,
            ExtensionServiceDeploymentStatus::Running
        );

        // Readiness check: configs synced and all services running, should be Ready
        let readiness = compute_extension_services_readiness(&status);
        assert_eq!(readiness, ExtensionServicesReadiness::Ready);
    }

    #[test]
    fn extension_service_status_with_outdated_observation() {
        let config = create_service_config(ConfigVersion::initial());
        let version = ConfigVersion::initial();
        let dpu_map = create_dpu_map_with_one_dpu();
        let observations = create_observation(
            ConfigVersion::initial(),
            ConfigVersion::initial(),
            ExtensionServiceDeploymentStatus::Running,
        );

        let status = InstanceExtensionServicesStatus::from_config_and_observations(
            &dpu_map,
            Versioned::new(&config, version.increment()), // Increment config version for extension service config
            &observations,                                // Observation has initial config version
        );

        // Should be unsynced due to version mismatch, with DPU status showing Unknown
        assert_eq!(status.configs_synced, SyncState::Pending);
        assert_eq!(status.extension_services.len(), 1);
        assert_eq!(
            status.extension_services[0].overall_status,
            ExtensionServiceDeploymentStatus::Unknown
        );
        assert_eq!(status.extension_services[0].dpu_statuses.len(), 1);
        assert_eq!(
            status.extension_services[0].dpu_statuses[0].status,
            ExtensionServiceDeploymentStatus::Unknown
        );
        assert!(
            status.extension_services[0].dpu_statuses[0]
                .error_message
                .as_ref()
                .unwrap()
                .contains(
                    "No status observation observed for this extension service config version yet."
                )
        );

        // Readiness check: configs not synced (version mismatch), should be ConfigsPending
        let readiness = compute_extension_services_readiness(&status);
        assert_eq!(readiness, ExtensionServicesReadiness::ConfigsPending);
    }

    #[test]
    fn extension_service_status_with_multiple_dpus_one_missing_observation() {
        let service_version = ConfigVersion::initial();
        let config = create_service_config(service_version);

        let config_version = ConfigVersion::initial();

        // Create a map with two DPUs
        let dpu1_id = get_test_machine_id();
        let dpu2_id =
            MachineId::from_str("fm100ds27v4uuq7sgs4gsjummskt0b3tedugtpevjrbfh6su081n9jufcq0")
                .unwrap();
        let mut dpu_map = HashMap::new();
        dpu_map.insert("device0".to_string(), vec![dpu1_id, dpu2_id]);

        // Create observation for only one DPU
        let observations = create_observation(
            config_version,
            service_version,
            ExtensionServiceDeploymentStatus::Running,
        );

        let status = InstanceExtensionServicesStatus::from_config_and_observations(
            &dpu_map,
            Versioned::new(&config, config_version),
            &observations,
        );

        // Should be unsynced because one DPU is missing observation
        assert_eq!(status.configs_synced, SyncState::Pending);
        assert_eq!(status.extension_services.len(), 1);
        assert_eq!(
            status.extension_services[0].overall_status,
            ExtensionServiceDeploymentStatus::Unknown
        );
        assert_eq!(status.extension_services[0].dpu_statuses.len(), 2);

        // One DPU should have Running status, the other Unknown
        let running_count = status.extension_services[0]
            .dpu_statuses
            .iter()
            .filter(|s| s.status == ExtensionServiceDeploymentStatus::Running)
            .count();
        let unknown_count = status.extension_services[0]
            .dpu_statuses
            .iter()
            .filter(|s| s.status == ExtensionServiceDeploymentStatus::Unknown)
            .count();
        assert_eq!(running_count, 1);
        assert_eq!(unknown_count, 1);

        // Readiness check: configs not synced (one DPU missing observation), should be ConfigsPending
        let readiness = compute_extension_services_readiness(&status);
        assert_eq!(readiness, ExtensionServicesReadiness::ConfigsPending);
    }

    #[test]
    fn extension_service_status_with_all_dpus_reporting() {
        let service_version = ConfigVersion::initial();
        let config = create_service_config(service_version);
        let config_version = ConfigVersion::initial();

        // Create a map with two DPUs
        let dpu1_id = get_test_machine_id();
        let dpu2_id =
            MachineId::from_str("fm100ds27v4uuq7sgs4gsjummskt0b3tedugtpevjrbfh6su081n9jufcq0")
                .unwrap();
        let mut dpu_map = HashMap::new();
        dpu_map.insert("device0".to_string(), vec![dpu1_id, dpu2_id]);

        // Create observations for both DPUs
        let mut observations = HashMap::new();
        observations.insert(
            dpu1_id,
            InstanceExtensionServiceStatusObservation {
                config_version,
                instance_config_version: None,
                extension_service_statuses: vec![ExtensionServiceStatusObservation {
                    service_id: get_test_service_id(),
                    service_type: ExtensionServiceType::KubernetesPod,
                    service_name: "test-service".to_string(),
                    version: service_version,
                    removed: None,
                    overall_state: ExtensionServiceDeploymentStatus::Running,
                    components: vec![],
                    message: String::new(),
                }],
                observed_at: chrono::Utc::now(),
            },
        );
        observations.insert(
            dpu2_id,
            InstanceExtensionServiceStatusObservation {
                config_version,
                instance_config_version: None,
                extension_service_statuses: vec![ExtensionServiceStatusObservation {
                    service_id: get_test_service_id(),
                    service_type: ExtensionServiceType::KubernetesPod,
                    service_name: "test-service".to_string(),
                    version: service_version,
                    removed: None,
                    overall_state: ExtensionServiceDeploymentStatus::Running,
                    components: vec![],
                    message: String::new(),
                }],
                observed_at: chrono::Utc::now(),
            },
        );

        let status = InstanceExtensionServicesStatus::from_config_and_observations(
            &dpu_map,
            Versioned::new(&config, config_version),
            &observations,
        );

        // Should be synced because all DPUs have observations
        assert_eq!(status.configs_synced, SyncState::Synced);
        assert_eq!(status.extension_services.len(), 1);
        assert_eq!(
            status.extension_services[0].overall_status,
            ExtensionServiceDeploymentStatus::Running
        );
        assert_eq!(status.extension_services[0].dpu_statuses.len(), 2);

        // Both DPUs should have Running status
        let running_count = status.extension_services[0]
            .dpu_statuses
            .iter()
            .filter(|s| s.status == ExtensionServiceDeploymentStatus::Running)
            .count();
        assert_eq!(running_count, 2);

        // Readiness check: configs synced and all services running, should be Ready
        let readiness = compute_extension_services_readiness(&status);
        assert_eq!(readiness, ExtensionServicesReadiness::Ready);
    }

    #[test]
    fn extension_service_calculate_overall_status_all_running() {
        let dpu_statuses = vec![
            MachineExtensionServiceStatus {
                machine_id: MachineId::from_str(
                    "fm100dskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80",
                )
                .unwrap(),
                status: ExtensionServiceDeploymentStatus::Running,
                error_message: None,
                components: vec![],
            },
            MachineExtensionServiceStatus {
                machine_id: MachineId::from_str(
                    "fm100dskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80",
                )
                .unwrap(),
                status: ExtensionServiceDeploymentStatus::Running,
                error_message: None,
                components: vec![],
            },
        ];

        let overall_status =
            InstanceExtensionServicesStatus::calculate_overall_status(&dpu_statuses);
        assert_eq!(overall_status, ExtensionServiceDeploymentStatus::Running);
    }

    #[test]
    fn extension_service_calculate_overall_status_one_failed() {
        let dpu_statuses = vec![
            MachineExtensionServiceStatus {
                machine_id: MachineId::from_str(
                    "fm100dskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80",
                )
                .unwrap(),
                status: ExtensionServiceDeploymentStatus::Running,
                error_message: None,
                components: vec![],
            },
            MachineExtensionServiceStatus {
                machine_id: MachineId::from_str(
                    "fm100ds27v4uuq7sgs4gsjummskt0b3tedugtpevjrbfh6su081n9jufcq0",
                )
                .unwrap(),
                status: ExtensionServiceDeploymentStatus::Failed,
                error_message: Some("Test error".to_string()),
                components: vec![],
            },
        ];

        let overall_status =
            InstanceExtensionServicesStatus::calculate_overall_status(&dpu_statuses);
        // If any DPU reports Failed, the overall status is Error
        assert_eq!(overall_status, ExtensionServiceDeploymentStatus::Error);
    }

    #[test]
    fn extension_service_calculate_overall_status_empty() {
        let dpu_statuses = vec![];
        let overall_status =
            InstanceExtensionServicesStatus::calculate_overall_status(&dpu_statuses);
        assert_eq!(overall_status, ExtensionServiceDeploymentStatus::Unknown);
    }
}
