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

use std::fmt::Display;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::{config_version::ConfigVersion, instance::snapshot::InstanceSnapshot};
use crate::model::hardware_info::HardwareInfo;

pub mod machine_id;
pub mod network;
use machine_id::MachineId;

pub const DPU_PHYSICAL_NETWORK_INTERFACE: &str = "pf0hpf";
pub const DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER: &str = "pf0vf";

/// Represents the current state of `Machine`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedHostStateSnapshot {
    pub host_snapshot: Option<MachineSnapshot>,
    pub dpu_snapshot: MachineSnapshot,
    /// If there is an instance provisioned on top of the machine, this holds
    /// it's state
    pub instance: Option<InstanceSnapshot>,
    pub managed_state: ManagedHostState,
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineSnapshot {
    /// Machine ID
    pub machine_id: MachineId,
    /// Hardware Information that was discovered about this Machine
    pub hardware_info: Option<HardwareInfo>,
    /// Desired state of the machine
    pub current: CurrentMachineState,
    /// Last discovery request from scout.
    pub last_discovery_time: Option<DateTime<Utc>>,
    /// Last reboot time. Calculated from forge_agent_control call.
    pub last_reboot_time: Option<DateTime<Utc>>,
    /// Last Cleanup completed messge received from scout.
    pub last_cleanup_time: Option<DateTime<Utc>>,
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
    DPUNotReady(MachineState),
    /// DPU is ready, Host is not yet Ready.
    HostNotReady(MachineState),
    /// Host is Ready for instance creation.
    Ready,
    /// Host is assigned to an Instance.
    Assigned(InstanceState),
    /// Some cleanup is going on.
    WaitingForCleanup(CleanupState),
    /// Intermediate state for machine to be created.
    /// This state is not processed anywhere. Correct satte is updated immediately.
    Created,
    /// A forced deletion process has been triggered by the admin CLI
    /// State controller will no longer manage the Machine
    ForceDeletion,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum MachineState {
    Init,
    WaitingForDiscovery,
    Discovered,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum CleanupState {
    HostCleanup,
    DisableBIOSBMCLockdown,
}

/// Possible Instance state-machine implementation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum InstanceState {
    Init, // Instance is created but not picked by state machine yet.
    WaitingForNetworkConfig,
    Ready,
    DeletingManagedResource,
    WaitingForNetworkReconfig,
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

impl Display for ManagedHostState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagedHostState::DPUNotReady(s) => write!(f, "DPU/{}", s),
            ManagedHostState::HostNotReady(s) => write!(f, "Host/{}", s),
            ManagedHostState::Ready => write!(f, "Ready"),
            ManagedHostState::Assigned(s) => write!(f, "Assigned/{}", s),
            ManagedHostState::WaitingForCleanup(s) => write!(f, "WaitingForCleanup/{}", s),
            ManagedHostState::ForceDeletion => write!(f, "ForceDeletion"),
            ManagedHostState::Created => write!(f, "Created"),
        }
    }
}
