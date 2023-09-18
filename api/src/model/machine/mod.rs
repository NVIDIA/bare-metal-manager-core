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

use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use self::network::{MachineNetworkStatusObservation, ManagedHostNetworkConfig};
use super::{
    bmc_info::BmcInfo,
    config_version::{ConfigVersion, Versioned},
    instance::snapshot::InstanceSnapshot,
};
use crate::model::hardware_info::{BMCVendor, HardwareInfo};

pub mod machine_id;
pub mod network;
use machine_id::MachineId;

/// Represents the current state of `Machine`
#[derive(Debug, Clone)]
pub struct ManagedHostStateSnapshot {
    pub host_snapshot: MachineSnapshot,
    pub dpu_snapshot: MachineSnapshot,
    pub dpu_ssh_ip_address: IpAddr,
    /// If there is an instance provisioned on top of the machine, this holds
    /// it's state
    pub instance: Option<InstanceSnapshot>,
    pub managed_state: ManagedHostState,
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone)]
pub struct MachineSnapshot {
    /// Machine ID
    pub machine_id: MachineId,
    /// Hardware Information that was discovered about this Machine
    pub hardware_info: Option<HardwareInfo>,
    /// The desired network configuration for this machine
    /// Includes the loopback_ip address. Do not query that
    /// directly, use `.loopback_ip()` instead.
    pub network_config: Versioned<ManagedHostNetworkConfig>,
    /// The actual network configuration, as reported by forge-dpu-agent
    pub network_status_observation: Option<MachineNetworkStatusObservation>,
    /// BMC related information
    pub bmc_info: BmcInfo,
    pub bmc_vendor: BMCVendor,
    /// Network interfaces
    pub interfaces: Vec<MachineInterfaceSnapshot>,
    /// Desired state of the machine
    pub current: CurrentMachineState,
    /// Last discovery request from scout.
    pub last_discovery_time: Option<DateTime<Utc>>,
    /// Last reboot time. Calculated from forge_agent_control call.
    pub last_reboot_time: Option<DateTime<Utc>>,
    /// Last cleanup completed message received from scout.
    pub last_cleanup_time: Option<DateTime<Utc>>,
    /// Failure cause. Needed to move machine in failed state.
    pub failure_details: FailureDetails,
    /// Reprovisioning is needed?
    pub reprovision_requested: Option<ReprovisionRequest>,
}

impl MachineSnapshot {
    pub fn loopback_ip(&self) -> Option<Ipv4Addr> {
        self.network_config.loopback_ip
    }
    pub fn use_admin_network(&self) -> bool {
        self.network_config.use_admin_network.unwrap_or(true)
    }
    pub fn has_healthy_network(&self) -> bool {
        match &self.network_status_observation {
            None => false,
            Some(obs) => obs.health_status.is_healthy,
        }
    }
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentMachineState {
    pub state: ManagedHostState,
    pub version: ConfigVersion,
}

/// Possible Machine state-machine implementation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
/// Possible ManagedHost state-machine implementation
/// Only DPU machine field in DB will contain state. Host will be empty. DPU state field will be
/// used to derive state for DPU and Host both.
pub enum ManagedHostState {
    /// DPU is not yet ready.
    DPUNotReady { machine_state: MachineState },
    /// DPU is ready, Host is not yet Ready.
    HostNotReady { machine_state: MachineState },
    /// Host is Ready for instance creation.
    Ready,
    /// Host is assigned to an Instance.
    Assigned { instance_state: InstanceState },
    /// Some cleanup is going on.
    WaitingForCleanup { cleanup_state: CleanupState },
    /// Intermediate state for machine to be created.
    /// This state is not processed anywhere. Correct state is updated immediately.
    Created,
    /// A forced deletion process has been triggered by the admin CLI
    /// State controller will no longer manage the Machine
    ForceDeletion,

    /// Machine moved to failed state. Recovery will be based on FailedCause
    Failed {
        details: FailureDetails,
        machine_id: MachineId,
    },

    /// State used to indicate that DPU reprovisioning is going on.
    DPUReprovision { reprovision_state: ReprovisionState },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ReprovisionState {
    FirmwareUpgrade,
    BufferTime,
    WaitingForDiscovery,
    WaitingForNetworkInstall,
    WaitingForNetworkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FailureCause {
    NoError,
    NVMECleanFailed { err: String },
    Discovery { err: String },
    UnhandledState { err: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FailureSource {
    NoError,
    Scout,
    StateMachine,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct FailureDetails {
    pub cause: FailureCause,
    pub failed_at: DateTime<Utc>,
    pub source: FailureSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum MachineState {
    Init,
    WaitingForNetworkInstall,
    WaitingForNetworkConfig,
    WaitingForDiscovery,
    Discovered,
    /// Lockdown handling.
    WaitingForLockdown {
        lockdown_info: LockdownInfo,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct LockdownInfo {
    pub state: LockdownState,
    pub mode: LockdownMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum CleanupState {
    HostCleanup,
    DisableBIOSBMCLockdown,
}

/// Substates of enabling/disabling lockdown
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")] // No tag requried - this is not nested
pub enum LockdownState {
    /// We simply wait in this state for a certain amount of time to allow the
    /// DPU to go down. Besides waiting to other checks are performed.
    TimeWaitForDPUDown,
    /// In this state we check whether the DPU restarted and is reachable again
    WaitForDPUUp,
}

/// Whether lockdown should be enabled or disabled in an operation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")] // No tag required - this will never be nested
pub enum LockdownMode {
    Enable,
}

/// Possible Instance state-machine implementation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum InstanceState {
    Init, // Instance is created but not picked by state machine yet.
    WaitingForNetworkConfig,
    Ready,
    BootingWithDiscoveryImage,
    SwitchToAdminNetwork,
    WaitingForNetworkReconfig,
}

/// Struct to store information if Reprovision is requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReprovisionRequest {
    pub requested_at: DateTime<Utc>,
    pub initiator: String,
    pub update_firmware: bool,
}

impl Display for MachineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for InstanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for CleanupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for LockdownState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for FailureSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for FailureCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureCause::NVMECleanFailed { .. } => write!(f, "NVMECleanFailed"),
            FailureCause::NoError => write!(f, "NoError"),
            FailureCause::Discovery { .. } => write!(f, "Discovery"),
            FailureCause::UnhandledState { .. } => write!(f, "UnknownState"),
        }
    }
}

impl Display for FailureDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.source, self.cause)
    }
}

impl Display for ReprovisionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for ManagedHostState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagedHostState::DPUNotReady { machine_state } => write!(f, "DPU/{}", machine_state),
            ManagedHostState::HostNotReady { machine_state } => write!(f, "Host/{}", machine_state),
            ManagedHostState::Ready => write!(f, "Ready"),
            ManagedHostState::Assigned { instance_state } => {
                write!(f, "Assigned/{}", instance_state)
            }
            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                write!(f, "WaitingForCleanup/{}", cleanup_state)
            }
            ManagedHostState::ForceDeletion => write!(f, "ForceDeletion"),
            ManagedHostState::Created => write!(f, "Created"),
            ManagedHostState::Failed { details, .. } => {
                write!(f, "Failed/{}", details.cause)
            }
            ManagedHostState::DPUReprovision { reprovision_state } => {
                write!(f, "Reprovisioning/{}", reprovision_state)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineInterfaceSnapshot {
    pub id: uuid::Uuid,
    pub hostname: String,
    pub is_primary: bool,
    pub mac_address: String,
    pub ip_address: IpAddr,
    pub vlan_id: u32,
    pub vni: u32,
    pub gateway_cidr: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_deserialize_no_error() {
        let serialized = r#"{"cause": "noerror", "source": "noerror", "failed_at": "2023-07-31T11:26:18.261228950Z"}"#;
        let deserialized: FailureDetails = serde_json::from_str(serialized).unwrap();

        let expected_time =
            chrono::DateTime::parse_from_rfc3339("2023-07-31T11:26:18.261228950+00:00").unwrap();
        assert_eq!(FailureCause::NoError, deserialized.cause);
        assert_eq!(expected_time, deserialized.failed_at);
    }

    #[test]
    fn test_json_deserialize_nvme_error() {
        let serialized = r#"{"cause": {"nvmecleanfailed":{"err": "error1"}},  "source": "noerror","failed_at": "2023-07-31T11:26:18.261228950Z"}"#;
        let deserialized: FailureDetails = serde_json::from_str(serialized).unwrap();

        let expected_time =
            chrono::DateTime::parse_from_rfc3339("2023-07-31T11:26:18.261228950+00:00").unwrap();
        assert_eq!(
            FailureCause::NVMECleanFailed {
                err: "error1".to_string()
            },
            deserialized.cause
        );
        assert_eq!(expected_time, deserialized.failed_at);
    }

    #[test]
    fn test_json_deserialize_reprovisioning_state() {
        let serialized = r#"{"state":"dpureprovision","reprovision_state":"firmwareupgrade"}"#;
        let deserialized: ManagedHostState = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            deserialized,
            ManagedHostState::DPUReprovision {
                reprovision_state: ReprovisionState::FirmwareUpgrade
            }
        );
    }
}
