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

use serde::{Deserialize, Serialize};

use crate::model::hardware_info::HardwareInfo;

use super::instance::snapshot::InstanceSnapshot;

pub const DPU_PHYSICAL_NETWORK_INTERFACE: &str = "pf0hpf";
pub const DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER: &str = "pf0vf";

/// Represents the current state of `Machine`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineStateSnapshot {
    /// Machine ID
    pub machine_id: uuid::Uuid,
    /// Hardware Information that was discovered about this Machine
    pub hardware_info: HardwareInfo,
    /// Machine configuration. This represents the desired state of the Machine
    /// The machine might not yet be in that state, but work would be underway
    /// to get the Machine into this state
    pub config: MachineConfig,
    /// Desired state of the machine
    pub current: CurrentMachineState,
    /// If there is an instance provisioned on top of the machine, this holds
    /// it's state
    pub instance: Option<InstanceSnapshot>,
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentMachineState {}

/// Machine configuration. This represents the desired state of the Machine
/// The machine might not yet be in that state, but work would be underway
/// to get the Machine into this state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineConfig {}
