use std::{net::IpAddr, time::SystemTime};

use chrono::{DateTime, Utc};
use rpc::forge as rpc;
use serde::{Deserialize, Serialize};

use crate::model::RpcDataConversionError;

/// The network status that was last reported by the networking subystem
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineNetworkStatus {
    machine_id: String,
    observed_at: DateTime<Utc>,
    health_status: HealthStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub passed: Vec<String>,
    pub failed: Vec<String>,
    pub message: Option<String>,
}

impl TryFrom<rpc::ManagedHostNetworkStatusObservation> for MachineNetworkStatus {
    type Error = RpcDataConversionError;

    fn try_from(obs: rpc::ManagedHostNetworkStatusObservation) -> Result<Self, Self::Error> {
        let health = obs.health.ok_or(Self::Error::MissingArgument("health"))?;
        let observed_at = match obs.observed_at {
            Some(timestamp) => {
                let system_time = SystemTime::try_from(timestamp.clone())
                    .map_err(|_| Self::Error::InvalidTimestamp(timestamp.to_string()))?;
                DateTime::from(system_time)
            }
            None => {
                return Err(Self::Error::MissingArgument("observed_at"));
            }
        };
        Ok(MachineNetworkStatus {
            observed_at,
            machine_id: obs
                .dpu_machine_id
                .ok_or(Self::Error::MissingArgument("dpu_machine_id"))?
                .id,
            health_status: HealthStatus {
                is_healthy: health.is_healthy,
                passed: health.passed,
                failed: health.failed,
                message: health.message,
            },
        })
    }
}

impl From<MachineNetworkStatus> for rpc::ManagedHostNetworkStatusObservation {
    fn from(m: MachineNetworkStatus) -> rpc::ManagedHostNetworkStatusObservation {
        rpc::ManagedHostNetworkStatusObservation {
            dpu_machine_id: Some(rpc::MachineId { id: m.machine_id }),
            observed_at: Some(m.observed_at.into()),
            health: Some(rpc::NetworkHealth {
                is_healthy: m.health_status.is_healthy,
                passed: m.health_status.passed,
                failed: m.health_status.failed,
                message: m.health_status.message,
            }),
        }
    }
}

/// Desired network configuration for an instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
// TODO: serde renames? defaults for missing fields?
pub struct ManagedHostNetworkConfig {
    /// Enables access to the Forge admin network for the x86 host
    admin_network_enabled: bool,
    /// TODO: Do we need the mapping from interface to IP as in the current Leaf spec
    /// or multiple IPs for IPv4 vs IPv6?
    host_admin_ip: Option<IpAddr>,
    /// DHCP server that the Host DHCP requests should be relayed to
    dhcp_servers: Vec<String>, // TODO: IpAddr vs String?
}

impl ManagedHostNetworkConfig {
    /// Network config for a branch new machine
    pub fn initial() -> ManagedHostNetworkConfig {
        ManagedHostNetworkConfig {
            // we are on the admin network until a tenant arrives
            admin_network_enabled: true,
            // assigned during DHCP
            host_admin_ip: None,
            // assigned during DHCP?
            dhcp_servers: vec![],
        }
    }
}
