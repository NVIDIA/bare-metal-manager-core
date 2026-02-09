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

use carbide_uuid::machine::MachineId;
use clap::{Parser, ValueEnum};

use crate::machine::NetworkCommand;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(subcommand, about = "DPU Reprovisioning handling")]
    Reprovision(DpuReprovision),
    #[clap(about = "Get or set forge-dpu-agent upgrade policy")]
    AgentUpgradePolicy(AgentUpgrade),
    #[clap(about = "View DPU firmware status")]
    Versions(DpuVersionOptions),
    #[clap(about = "View DPU Status")]
    Status,
    #[clap(subcommand, about = "Networking information")]
    Network(NetworkCommand),
}

#[derive(Parser, Debug)]
pub enum DpuReprovision {
    #[clap(about = "Set the DPU in reprovisioning mode.")]
    Set(DpuReprovisionSet),
    #[clap(about = "Clear the reprovisioning mode.")]
    Clear(DpuReprovisionClear),
    #[clap(about = "List all DPUs pending reprovisioning.")]
    List,
    #[clap(about = "Restart the DPU reprovision.")]
    Restart(DpuReprovisionRestart),
}

#[derive(Parser, Debug)]
pub struct DpuReprovisionSet {
    #[clap(
        short,
        long,
        help = "DPU Machine ID for which reprovisioning is needed, or host machine id if all DPUs should be reprovisioned."
    )]
    pub id: MachineId,

    #[clap(short, long, action)]
    pub update_firmware: bool,

    #[clap(
        long,
        alias = "maintenance_reference",
        help = "If set, a HostUpdateInProgress health alert will be applied to the host"
    )]
    pub update_message: Option<String>,
}

#[derive(Parser, Debug)]
pub struct DpuReprovisionClear {
    #[clap(
        short,
        long,
        help = "DPU Machine ID for which reprovisioning should be cleared, or host machine id if all DPUs should be cleared."
    )]
    pub id: MachineId,

    #[clap(short, long, action)]
    pub update_firmware: bool,
}

#[derive(Parser, Debug)]
pub struct DpuReprovisionRestart {
    #[clap(
        short,
        long,
        help = "Host Machine ID for which reprovisioning should be restarted."
    )]
    pub id: MachineId,

    #[clap(short, long, action)]
    pub update_firmware: bool,
}

#[derive(Parser, Debug)]
pub struct DpuVersionOptions {
    #[clap(short, long, help = "Only show DPUs that need upgrades")]
    pub updates_only: bool,
}

#[derive(Parser, Debug)]
pub struct AgentUpgrade {
    #[clap(long)]
    pub set: Option<AgentUpgradePolicyChoice>,
}

// Should match api/src/model/machine/upgrade_policy.rs AgentUpgradePolicy
#[derive(ValueEnum, Debug, Clone)]
pub enum AgentUpgradePolicyChoice {
    Off,
    UpOnly,
    UpDown,
}

impl std::fmt::Display for AgentUpgradePolicyChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // enums are a special case where their debug impl is their name ("Off")
        std::fmt::Debug::fmt(self, f)
    }
}

// From the RPC
impl From<i32> for AgentUpgradePolicyChoice {
    fn from(rpc_policy: i32) -> Self {
        use rpc::forge::AgentUpgradePolicy::*;
        match rpc_policy {
            n if n == Off as i32 => AgentUpgradePolicyChoice::Off,
            n if n == UpOnly as i32 => AgentUpgradePolicyChoice::UpOnly,
            n if n == UpDown as i32 => AgentUpgradePolicyChoice::UpDown,
            _ => {
                unreachable!();
            }
        }
    }
}
