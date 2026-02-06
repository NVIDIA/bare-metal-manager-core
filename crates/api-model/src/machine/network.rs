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
use std::net::Ipv4Addr;
use std::time::SystemTime;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Duration, Utc};
use config_version::ConfigVersion;
use health_report::HealthReport;
use serde::{Deserialize, Serialize};

use crate::instance::status::extension_service::{
    ExtensionServiceStatusObservation, InstanceExtensionServiceStatusObservation,
};
use crate::instance::status::network::{
    InstanceInterfaceStatusObservation, InstanceNetworkStatusObservation,
};

/// The network status that was last reported by the networking subsystem
/// Stored in a Postgres JSON field so new fields have to be Option until fully deployed
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineNetworkStatusObservation {
    pub machine_id: MachineId,
    pub agent_version: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub network_config_version: Option<ConfigVersion>,
    pub client_certificate_expiry: Option<i64>,
    pub agent_version_superseded_at: Option<DateTime<Utc>>,
    pub instance_network_observation: Option<InstanceNetworkStatusObservation>,
    pub extension_service_observation: Option<InstanceExtensionServiceStatusObservation>,
}

impl MachineNetworkStatusObservation {
    pub fn any_observed_version_changed(&self, other: &Self) -> bool {
        if self.network_config_version != other.network_config_version {
            return true;
        }

        if match (
            &self.instance_network_observation,
            &other.instance_network_observation,
        ) {
            (None, Some(_)) => true,
            (Some(_), None) => true,
            (None, None) => false,
            (Some(a), Some(b)) => a.any_observed_version_changed(b),
        } {
            return true;
        }

        if match (
            &self.extension_service_observation,
            &other.extension_service_observation,
        ) {
            (None, Some(_)) => true,
            (Some(_), None) => true,
            (None, None) => false,
            (Some(a), Some(b)) => a.any_observed_version_changed(b),
        } {
            return true;
        }

        false
    }

    pub fn expired_version_health_report(
        &self,
        staleness_threshold: Duration,
        prevent_allocations: bool,
    ) -> Option<HealthReport> {
        let Some(agent_version) = self.agent_version.as_ref() else {
            return Some(health_report::HealthReport::stale_agent_version(
                "forge-dpu-agent".to_string(),
                self.machine_id.to_string(),
                "Agent version is not known".to_string(),
                prevent_allocations,
            ));
        };

        if agent_version == carbide_version::v!(build_version) {
            // Same version as the server, all good.
            return None;
        }

        match self.agent_version_superseded_at {
            Some(superseded_at) => {
                let staleness = Utc::now().signed_duration_since(superseded_at);
                if staleness > staleness_threshold {
                    Some(health_report::HealthReport::stale_agent_version(
                        "forge-dpu-agent".to_string(),
                        self.machine_id.to_string(),
                        format!(
                            "Agent version is {}, which is out of date for {}",
                            agent_version,
                            config_version::format_duration(staleness),
                        ),
                        prevent_allocations,
                    ))
                } else {
                    None
                }
            }
            None => {
                tracing::debug!(
                        machine_id = %self.machine_id,
                        agent_version = %agent_version,
                        "DPU is on a stale agent version which we don't know about. Cannot know how stale it is, will not prevent allocations");
                None
            }
        }
    }
}

impl TryFrom<rpc::DpuNetworkStatus> for MachineNetworkStatusObservation {
    type Error = RpcDataConversionError;

    fn try_from(obs: rpc::DpuNetworkStatus) -> Result<Self, Self::Error> {
        let observed_at = match obs.observed_at {
            Some(timestamp) => {
                let system_time = SystemTime::try_from(timestamp)
                    .map_err(|_| Self::Error::InvalidTimestamp(timestamp.to_string()))?;
                DateTime::from(system_time)
            }
            None => Utc::now(),
        };

        // We're going to piggy-back on InstanceNetworkStatusObservation
        // to get the instance_config_version for now.
        let instance_config_version = match obs.instance_config_version {
            Some(version_string) => match version_string.as_str().parse() {
                Ok(version) => Some(version),
                _ => {
                    return Err(RpcDataConversionError::InvalidConfigVersion(format!(
                        "applied_config.instance_config_version: {version_string}"
                    )));
                }
            },
            _ => None,
        };

        let instance_network_observation =
            if let Some(version_string) = obs.instance_network_config_version {
                let Ok(version) = version_string.as_str().parse() else {
                    return Err(RpcDataConversionError::InvalidConfigVersion(format!(
                        "applied_config.instance_network_config_version: {version_string}"
                    )));
                };
                let mut interfaces: Vec<InstanceInterfaceStatusObservation> = vec![];
                for iface in obs.interfaces {
                    let v = iface.try_into()?;
                    interfaces.push(v);
                }

                Some(InstanceNetworkStatusObservation {
                    config_version: version,
                    instance_config_version,
                    observed_at,
                    interfaces,
                })
            } else {
                None
            };

        let extension_service_observation =
            if let Some(version_string) = obs.dpu_extension_service_version {
                let Ok(version) = version_string.as_str().parse() else {
                    return Err(RpcDataConversionError::InvalidConfigVersion(format!(
                        "applied_config.extension_service_version: {version_string}"
                    )));
                };

                let mut extension_service_statuses: Vec<ExtensionServiceStatusObservation> = vec![];
                for service in obs.dpu_extension_services {
                    let v = service.try_into()?;
                    extension_service_statuses.push(v);
                }

                Some(InstanceExtensionServiceStatusObservation {
                    config_version: version,
                    instance_config_version,
                    extension_service_statuses,
                    observed_at,
                })
            } else {
                None
            };

        Ok(MachineNetworkStatusObservation {
            observed_at,
            machine_id: obs
                .dpu_machine_id
                .ok_or(Self::Error::MissingArgument("dpu_machine_id"))?,
            agent_version: obs.dpu_agent_version.clone(),
            network_config_version: obs.network_config_version.and_then(|n| n.parse().ok()),
            client_certificate_expiry: obs.client_certificate_expiry_unix_epoch_secs,
            agent_version_superseded_at: None,
            instance_network_observation,
            extension_service_observation,
        })
    }
}

// TODO: This API is only used by the carbide-web generating the Network Status page
// It improperly returns the values of a lot of things - since those are not actually
// persisted.
// It would be preferable to migrate carbide-web from reading the status to using
// a better supported API. E.g. the FindMachinesByIds one.
impl From<MachineNetworkStatusObservation> for rpc::DpuNetworkStatus {
    fn from(m: MachineNetworkStatusObservation) -> rpc::DpuNetworkStatus {
        rpc::DpuNetworkStatus {
            dpu_machine_id: Some(m.machine_id),
            dpu_agent_version: m.agent_version.clone(),
            observed_at: Some(m.observed_at.into()),
            network_config_version: m.network_config_version.map(|v| v.version_string()),
            instance_id: None,
            instance_config_version: None,
            instance_network_config_version: None,
            interfaces: vec![],
            network_config_error: None,
            client_certificate_expiry_unix_epoch_secs: None,
            dpu_health: None,
            fabric_interfaces: vec![],
            last_dhcp_requests: vec![],
            dpu_extension_service_version: None,
            dpu_extension_services: vec![],
        }
    }
}

/// Desired network configuration for an instance.
/// This is persisted to a Postgres JSON column, so only use Option
/// fields for easier migrations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedHostNetworkConfig {
    pub loopback_ip: Option<Ipv4Addr>,
    pub secondary_overlay_vtep_ip: Option<Ipv4Addr>,
    pub use_admin_network: Option<bool>,
    pub quarantine_state: Option<ManagedHostQuarantineState>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedHostQuarantineState {
    pub reason: Option<String>,
    pub mode: ManagedHostQuarantineMode,
}

impl ManagedHostQuarantineState {
    pub fn reason_str(&self) -> &str {
        self.reason.as_deref().unwrap_or("")
    }

    pub fn mode_str(&self) -> &str {
        self.mode.as_str()
    }
}

impl From<ManagedHostQuarantineState> for rpc::ManagedHostQuarantineState {
    fn from(m: ManagedHostQuarantineState) -> Self {
        Self {
            mode: rpc::ManagedHostQuarantineMode::from(m.mode) as i32,
            reason: m.reason,
        }
    }
}

impl From<ManagedHostQuarantineMode> for rpc::ManagedHostQuarantineMode {
    fn from(m: ManagedHostQuarantineMode) -> Self {
        match m {
            ManagedHostQuarantineMode::BlockAllTraffic => {
                rpc::ManagedHostQuarantineMode::BlockAllTraffic
            }
        }
    }
}

impl TryFrom<rpc::ManagedHostQuarantineState> for ManagedHostQuarantineState {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::ManagedHostQuarantineState) -> Result<Self, Self::Error> {
        Ok(Self {
            reason: value.reason,
            mode: rpc::ManagedHostQuarantineMode::try_from(value.mode)
                .map_err(|_| {
                    RpcDataConversionError::InvalidValue(value.mode.to_string(), "mode".to_string())
                })?
                .into(),
        })
    }
}

impl From<rpc::ManagedHostQuarantineMode> for ManagedHostQuarantineMode {
    fn from(m: rpc::ManagedHostQuarantineMode) -> Self {
        match m {
            rpc::ManagedHostQuarantineMode::BlockAllTraffic => Self::BlockAllTraffic,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagedHostQuarantineMode {
    BlockAllTraffic,
}

impl ManagedHostQuarantineMode {
    fn as_str(&self) -> &'static str {
        match self {
            ManagedHostQuarantineMode::BlockAllTraffic => "BlockAllTraffic",
        }
    }
}

impl Default for ManagedHostNetworkConfig {
    fn default() -> Self {
        ManagedHostNetworkConfig {
            loopback_ip: None,
            secondary_overlay_vtep_ip: None,
            use_admin_network: Some(true),
            quarantine_state: None,
        }
    }
}
