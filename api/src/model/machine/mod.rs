/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use serde::{Deserialize, Serialize};

use crate::model::hardware_info::HardwareInfo;

use super::{config_version::ConfigVersion, instance::snapshot::InstanceSnapshot};

pub mod machine_id;

pub const DPU_PHYSICAL_NETWORK_INTERFACE: &str = "pf0hpf";
pub const DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER: &str = "pf0vf";

/// Represents the current state of `Machine`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineStateSnapshot {
    /// Machine ID
    pub machine_id: uuid::Uuid,
    /// Hardware Information that was discovered about this Machine
    pub hardware_info: HardwareInfo,
    /// Desired state of the machine
    pub current: CurrentMachineState,
    /// If there is an instance provisioned on top of the machine, this holds
    /// it's state
    pub instance: Option<InstanceSnapshot>,
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentMachineState {
    pub state: MachineState,
    pub version: ConfigVersion,
}

/// Possible Machine state-machine implementation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum MachineState {
    Init,
    Adopted,
    Ready,
    Assigned,
    Reset,
    Cleanedup,
    Broken,
    Decommissioned,
    Removed,
    /// A forced deletion process has been triggered by the admin CLI
    /// State controller will no longer manage the Machine
    ForceDeletion,
}

impl Display for MachineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            MachineState::Init => write!(f, "init"),
            MachineState::Adopted => write!(f, "adopt"),
            MachineState::Ready => write!(f, "ready"),
            MachineState::Assigned => write!(f, "assigned"),
            MachineState::Reset => write!(f, "reset"),
            MachineState::Cleanedup => write!(f, "cleanup"),
            MachineState::Broken => write!(f, "broken"),
            MachineState::Decommissioned => write!(f, "decommissioned"),
            MachineState::Removed => write!(f, "removed"),
            MachineState::ForceDeletion => write!(f, "force_deletion"),
        }
    }
}
