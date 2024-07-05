use std::{net::Ipv4Addr, time::SystemTime};

use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use rpc::forge as rpc;
use serde::{Deserialize, Serialize};

use crate::model::RpcDataConversionError;

/// The network status that was last reported by the networking subsystem
/// Stored in a Postgres JSON field so new fields have to be Option until fully deployed
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineNetworkStatusObservation {
    pub machine_id: String,
    pub agent_version: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub health_status: HealthStatus,
    pub network_config_version: Option<ConfigVersion>,
    pub client_certificate_expiry: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub passed: Vec<String>,
    pub failed: Vec<String>,
    pub message: Option<String>,
}

impl TryFrom<rpc::DpuNetworkStatus> for MachineNetworkStatusObservation {
    type Error = RpcDataConversionError;

    fn try_from(obs: rpc::DpuNetworkStatus) -> Result<Self, Self::Error> {
        let health = obs.health.ok_or(Self::Error::MissingArgument("health"))?;
        let observed_at = match obs.observed_at {
            Some(timestamp) => {
                let system_time = SystemTime::try_from(timestamp.clone())
                    .map_err(|_| Self::Error::InvalidTimestamp(timestamp.to_string()))?;
                DateTime::from(system_time)
            }
            None => Utc::now(),
        };
        Ok(MachineNetworkStatusObservation {
            observed_at,
            machine_id: obs
                .dpu_machine_id
                .ok_or(Self::Error::MissingArgument("dpu_machine_id"))?
                .id,
            agent_version: obs.dpu_agent_version.clone(),
            health_status: HealthStatus {
                is_healthy: health.is_healthy,
                passed: health.passed,
                failed: health.failed,
                message: health.message,
            },
            network_config_version: obs.network_config_version.and_then(|n| n.parse().ok()),
            client_certificate_expiry: obs.client_certificate_expiry_unix_epoch_secs,
        })
    }
}

impl From<MachineNetworkStatusObservation> for rpc::DpuNetworkStatus {
    fn from(m: MachineNetworkStatusObservation) -> rpc::DpuNetworkStatus {
        rpc::DpuNetworkStatus {
            dpu_machine_id: Some(::rpc::common::MachineId { id: m.machine_id }),
            dpu_agent_version: m.agent_version.clone(),
            observed_at: Some(m.observed_at.into()),
            health: Some(m.health_status.into()),
            network_config_version: m.network_config_version.map(|v| v.version_string()),
            instance_id: None,
            instance_config_version: None,
            interfaces: vec![],
            network_config_error: None,
            client_certificate_expiry_unix_epoch_secs: None,
            dpu_health: None, // TODO
        }
    }
}

impl From<HealthStatus> for rpc::NetworkHealth {
    fn from(h: HealthStatus) -> rpc::NetworkHealth {
        rpc::NetworkHealth {
            is_healthy: h.is_healthy,
            passed: h.passed.clone(),
            failed: h.failed.clone(),
            message: h.message.clone(),
        }
    }
}

/// Desired network configuration for an instance.
/// This is persisted to a Postgres JSON column, so only use Option
/// fields for easier migrations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedHostNetworkConfig {
    pub loopback_ip: Option<Ipv4Addr>,
    pub use_admin_network: Option<bool>,
}

impl Default for ManagedHostNetworkConfig {
    fn default() -> Self {
        ManagedHostNetworkConfig {
            loopback_ip: None,
            use_admin_network: Some(true),
        }
    }
}
