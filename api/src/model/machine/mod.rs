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

use std::{fmt::Display, net::Ipv4Addr};

use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use libredfish::SystemPowerControl;
use serde::{Deserialize, Serialize};

use self::network::{MachineNetworkStatusObservation, ManagedHostNetworkConfig};
use super::{
    bmc_info::BmcInfo, hardware_info::MachineInventory, instance::snapshot::InstanceSnapshot,
};
use crate::cfg::DpuComponent;
use crate::db::machine_interface::MachineInterfaceId;
use crate::model::hardware_info::HardwareInfo;

pub mod machine_id;
pub mod network;
pub mod upgrade_policy;
use machine_id::MachineId;
use strum_macros::EnumIter;

pub fn get_display_ids(machines: &[MachineSnapshot]) -> String {
    machines
        .iter()
        .map(|x| x.machine_id.to_string())
        .collect::<Vec<String>>()
        .join("/")
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone)]
pub struct ManagedHostStateSnapshot {
    pub host_snapshot: MachineSnapshot,
    pub dpu_snapshots: Vec<MachineSnapshot>,
    /// If there is an instance provisioned on top of the machine, this holds
    /// it's state
    pub instance: Option<InstanceSnapshot>,
    pub managed_state: ManagedHostState,
}

/// Represents the last_reboot_requested data
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MachineLastRebootRequestedMode {
    Reboot,
    PowerOff,
    PowerOn,
    GracefulShutdown,
}

impl From<SystemPowerControl> for MachineLastRebootRequestedMode {
    fn from(value: SystemPowerControl) -> Self {
        match value {
            SystemPowerControl::On => Self::PowerOn,
            SystemPowerControl::GracefulShutdown => Self::PowerOff,
            SystemPowerControl::ForceOff => Self::PowerOff,
            SystemPowerControl::GracefulRestart => Self::Reboot,
            SystemPowerControl::ForceRestart => Self::Reboot,
        }
    }
}

impl Display for MachineLastRebootRequestedMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineLastRebootRequested {
    pub time: DateTime<Utc>,
    pub mode: MachineLastRebootRequestedMode,
}

impl Default for MachineLastRebootRequested {
    fn default() -> Self {
        MachineLastRebootRequested {
            time: Default::default(),
            mode: MachineLastRebootRequestedMode::Reboot,
        }
    }
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone)]
pub struct MachineSnapshot {
    /// Machine ID
    pub machine_id: MachineId,
    /// Hardware Information that was discovered about this Machine
    pub hardware_info: Option<HardwareInfo>,
    /// Inventory related to a machine.
    /// Software and versions installed on the machine.
    pub inventory: MachineInventory,
    /// The desired network configuration for this machine
    /// Includes the loopback_ip address. Do not query that
    /// directly, use `.loopback_ip()` instead.
    pub network_config: Versioned<ManagedHostNetworkConfig>,
    /// The actual network configuration, as reported by forge-dpu-agent
    pub network_status_observation: Option<MachineNetworkStatusObservation>,
    /// BMC related information
    pub bmc_info: BmcInfo,
    pub bmc_vendor: bmc_vendor::BMCVendor,
    /// Network interfaces
    pub interfaces: Vec<MachineInterfaceSnapshot>,
    /// Desired state of the machine
    pub current: CurrentMachineState,
    /// Last discovery request from scout.
    pub last_discovery_time: Option<DateTime<Utc>>,
    /// Last reboot time. Calculated from forge_agent_control call.
    pub last_reboot_time: Option<DateTime<Utc>>,
    /// Last reboot requested time.
    pub last_reboot_requested: Option<MachineLastRebootRequested>,
    /// Last cleanup completed message received from scout.
    pub last_cleanup_time: Option<DateTime<Utc>>,
    /// Failure cause. Needed to move machine in failed state.
    pub failure_details: FailureDetails,
    /// Reprovisioning is needed?
    pub reprovision_requested: Option<ReprovisionRequest>,
    pub bios_password_set_time: Option<DateTime<Utc>>,
    /// Last host validation finished.
    pub last_machine_validation_time: Option<DateTime<Utc>>,
    /// current machine validation id.
    pub current_machine_validation_id: Option<uuid::Uuid>,
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
    /// Dpu was discovered by a site-explorer and is being configuring via redfish.
    DpuDiscoveringState {
        discovering_state: DpuDiscoveringState,
    },
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
        #[serde(default)]
        retry_count: u32,
    },

    /// State used to indicate that DPU reprovisioning is going on.
    DPUReprovision { reprovision_state: ReprovisionState },

    /// State used to indicate the API is currently waiting on the
    /// machine to send attestation measurements, or waiting for
    /// measurements to match a valid/approved measurement bundle,
    /// before continuing on towards a Ready state.
    Measuring { measuring_state: MeasuringState },
}

impl ManagedHostState {
    pub fn as_reprovision_state(&self) -> Option<&ReprovisionState> {
        match self {
            ManagedHostState::DPUReprovision { reprovision_state } => Some(reprovision_state),
            ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision { reprovision_state },
            } => Some(reprovision_state),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ReprovisionState {
    FirmwareUpgrade,
    PowerDown,
    BufferTime,
    WaitingForNetworkInstall,
    WaitingForNetworkConfig,
}

/// MeasuringState contains states used for host attestion (or
/// measured boot).
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MeasuringState {
    /// WaitingForMeasurements is reported when the machine
    /// has reached a state where the API is now expecting
    /// measurements from the machine, which Scout sends upon
    /// receiving an Action::Measure from the API.
    WaitingForMeasurements,

    /// PendingBundle is reported when the API has received
    /// measurements from the machine, but the measurements
    /// do not match a known bundle. At this point, a matching
    /// bundle needs to be created, either via "promoting" a
    /// measurement report from a machine (through manual
    /// interaction or trusted approval automation), or by
    /// manually creating a new bundle.
    PendingBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FailureCause {
    NoError,
    NVMECleanFailed { err: String },
    Discovery { err: String },
    MachineValidation { err: String },
    UnhandledState { err: String },

    // Host Attestation / Measured Boot related failure causes.
    //
    // MeasurementsFailedSignatureCheck is returned when the
    // signed PCR quote fails signature verification. That is,
    // we cannot verify the PCR (Platform Configuration Register,
    // in the context of Trusted Platform Modules) values were
    // signed by the TPM. If this state is being reported, a TPM
    // event log should have been dumped by the API for viewing.
    MeasurementsFailedSignatureCheck { err: String },

    // MeasurementsRetired is returned when the measurements
    // provided by the machine match a bundle that has been
    // marked as retired, thus not allowing the machine to
    // move forward towards a Ready state.
    MeasurementsRetired { err: String },

    // MeasurementsRevoked is returned when the measurements
    // provided by the machine match a bundle that has been
    // marked as revoked, thus not allowing the machine to
    // move forward towards a Ready state.
    //
    // The difference between retired and revoked is that a
    // retired bundle can be moved out of retirement, whereas
    // a revoked bundle cannot.
    MeasurementsRevoked { err: String },
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
#[serde(tag = "bmcfirmwareupdatesubstate", rename_all = "lowercase")]
pub enum BmcFirmwareUpdateSubstate {
    WaitForUpdateCompletion {
        firmware_type: DpuComponent,
        task_id: String,
    },
    HostPowerOff,
    Reboot {
        count: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "dpudiscoverystate", rename_all = "lowercase")]
pub enum DpuDiscoveringState {
    /// Dpu discovery via redfish states
    Initializing,
    BmcFirmwareUpdate {
        substate: BmcFirmwareUpdateSubstate,
    },
    Configuring,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum MachineState {
    Init,
    WaitingForPlatformConfiguration,
    WaitingForNetworkInstall,
    WaitingForNetworkConfig,
    UefiSetup {
        uefi_setup_info: UefiSetupInfo,
    },
    WaitingForDiscovery,
    Discovered,
    /// Lockdown handling.
    WaitingForLockdown {
        lockdown_info: LockdownInfo,
    },
    MachineValidating {
        context: String,
        id: uuid::Uuid,
        completed: usize,
        total: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct LockdownInfo {
    pub state: LockdownState,
    pub mode: LockdownMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct UefiSetupInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uefi_password_jid: Option<String>,
    pub uefi_setup_state: UefiSetupState,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, EnumIter)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum UefiSetupState {
    SetUefiPassword,
    WaitForPasswordJobScheduled,
    PowercycleHost,
    WaitForPasswordJobCompletion,
    LockdownHost,
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

/// Whether lockdown should be enabled or disabled in an operation
#[derive(Debug, Default, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")] // No tag required - this will never be nested
pub struct RetryInfo {
    pub count: u64,
}

/// Possible Instance state-machine implementation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum InstanceState {
    Init, // Instance is created but not picked by state machine yet.
    WaitingForNetworkConfig,
    Ready,
    BootingWithDiscoveryImage {
        #[serde(default)]
        retry: RetryInfo,
    },
    SwitchToAdminNetwork,
    WaitingForNetworkReconfig,
    DPUReprovision {
        reprovision_state: ReprovisionState,
    },
}

/// Struct to store information if Reprovision is requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReprovisionRequest {
    pub requested_at: DateTime<Utc>,
    pub initiator: String,
    pub update_firmware: bool,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub user_approval_received: bool,
    #[serde(default)]
    pub restart_reprovision_requested_at: DateTime<Utc>,
}

/// Should a forge-dpu-agent upgrade itself?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeDecision {
    pub should_upgrade: bool,
    pub to_version: String,
    pub last_updated: DateTime<Utc>,
}

impl From<ReprovisionRequest> for ::rpc::forge::InstanceUpdateStatus {
    fn from(value: ReprovisionRequest) -> Self {
        ::rpc::forge::InstanceUpdateStatus {
            module: ::rpc::forge::instance_update_status::Module::Dpu as i32,
            initiator: value.initiator,
            trigger_received_at: Some(value.requested_at.into()),
            update_triggered_at: value.started_at.map(|x| x.into()),
            user_approval_received: value.user_approval_received,
        }
    }
}

impl Display for DpuDiscoveringState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
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
            FailureCause::MeasurementsFailedSignatureCheck { .. } => {
                write!(f, "MeasurementsFailedSignatureCheck")
            }
            FailureCause::MeasurementsRetired { .. } => write!(f, "MeasurementsRetired"),
            FailureCause::MeasurementsRevoked { .. } => write!(f, "MeasurementsRevoked"),
            FailureCause::MachineValidation { .. } => write!(f, "MachineValidation"),
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

impl Display for MeasuringState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for ManagedHostState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagedHostState::DpuDiscoveringState { discovering_state } => {
                write!(f, "DPUDiscovering/{}", discovering_state)
            }
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
            ManagedHostState::Measuring { measuring_state } => {
                write!(f, "Measuring/{}", measuring_state)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineInterfaceSnapshot {
    pub id: MachineInterfaceId,
    pub hostname: String,
    pub is_primary: bool,
    pub mac_address: String,
}

pub struct InstanceNextStateResolver;
pub struct MachineNextStateResolver;

pub trait NextReprovisionState {
    fn next_state(&self, current_state: &ReprovisionState) -> ManagedHostState;
}

impl NextReprovisionState for MachineNextStateResolver {
    fn next_state(&self, current_state: &ReprovisionState) -> ManagedHostState {
        match current_state {
            ReprovisionState::FirmwareUpgrade => ManagedHostState::DPUReprovision {
                reprovision_state: ReprovisionState::PowerDown,
            },
            ReprovisionState::PowerDown => ManagedHostState::DPUReprovision {
                reprovision_state: ReprovisionState::WaitingForNetworkInstall,
            },
            ReprovisionState::WaitingForNetworkInstall => ManagedHostState::DPUReprovision {
                reprovision_state: ReprovisionState::BufferTime,
            },
            ReprovisionState::BufferTime => ManagedHostState::DPUReprovision {
                reprovision_state: ReprovisionState::WaitingForNetworkConfig,
            },
            ReprovisionState::WaitingForNetworkConfig => ManagedHostState::HostNotReady {
                machine_state: MachineState::Discovered,
            },
        }
    }
}

impl NextReprovisionState for InstanceNextStateResolver {
    fn next_state(&self, current_state: &ReprovisionState) -> ManagedHostState {
        match current_state {
            ReprovisionState::FirmwareUpgrade => ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision {
                    reprovision_state: ReprovisionState::PowerDown,
                },
            },
            ReprovisionState::PowerDown => ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision {
                    reprovision_state: ReprovisionState::WaitingForNetworkInstall,
                },
            },
            ReprovisionState::WaitingForNetworkInstall => ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision {
                    reprovision_state: ReprovisionState::BufferTime,
                },
            },
            ReprovisionState::BufferTime => ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision {
                    reprovision_state: ReprovisionState::WaitingForNetworkConfig,
                },
            },
            ReprovisionState::WaitingForNetworkConfig => ManagedHostState::Assigned {
                instance_state: InstanceState::Ready,
            },
        }
    }
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

    #[test]
    fn test_json_deserialize_reprovisioning_state_for_instance() {
        let serialized = r#"{"state":"assigned","instance_state":{"state":"dpureprovision","reprovision_state":"firmwareupgrade"}}"#;
        let deserialized: ManagedHostState = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            deserialized,
            ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision {
                    reprovision_state: ReprovisionState::FirmwareUpgrade,
                },
            }
        );
    }

    #[test]
    fn test_json_deserialize_bootingwithdiscoveryimage_state_for_instance() {
        let serialized =
            r#"{"state":"assigned","instance_state":{"state":"bootingwithdiscoveryimage"}}"#;
        let deserialized: ManagedHostState = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            deserialized,
            ManagedHostState::Assigned {
                instance_state: InstanceState::BootingWithDiscoveryImage {
                    retry: RetryInfo { count: 0 }
                },
            }
        );
    }

    #[test]
    fn test_json_deserialize_bootingwithdiscoveryimage_state_with_retry_for_instance() {
        let serialized = r#"{"state":"assigned","instance_state":{"state":"bootingwithdiscoveryimage", "retry":{"count": 10}}}"#;
        let deserialized: ManagedHostState = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            deserialized,
            ManagedHostState::Assigned {
                instance_state: InstanceState::BootingWithDiscoveryImage {
                    retry: RetryInfo { count: 10 }
                }
            }
        );
    }

    #[test]
    fn test_json_deserialize_machine_last_reboot_requested() {
        let serialized = r#"{"time":"2023-07-31T11:26:18.261228950+00:00","mode":"Reboot"}"#;
        let deserialized: MachineLastRebootRequested = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            chrono::DateTime::parse_from_rfc3339("2023-07-31T11:26:18.261228950+00:00").unwrap(),
            deserialized.time,
        );
        assert!(matches!(
            deserialized.mode,
            MachineLastRebootRequestedMode::Reboot,
        ));
    }
}
