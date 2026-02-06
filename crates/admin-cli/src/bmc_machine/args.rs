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
use mac_address::MacAddress;

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    #[clap(about = "Reset BMC")]
    BmcReset(BmcResetArgs),
    #[clap(about = "Redfish Power Control")]
    AdminPowerControl(AdminPowerControlArgs),
    CreateBmcUser(CreateBmcUserArgs),
    DeleteBmcUser(DeleteBmcUserArgs),
    #[clap(about = "Enable infinite boot")]
    EnableInfiniteBoot(InfiniteBootArgs),
    #[clap(about = "Check if infinite boot is enabled")]
    IsInfiniteBootEnabled(InfiniteBootArgs),
    #[clap(about = "Enable or disable lockdown")]
    Lockdown(LockdownArgs),
    #[clap(about = "Check lockdown status")]
    LockdownStatus(LockdownStatusArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct BmcResetArgs {
    #[clap(long, help = "ID of the machine to reboot")]
    pub machine: String,
    #[clap(short, long, help = "Use ipmitool")]
    pub use_ipmitool: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct AdminPowerControlArgs {
    #[clap(long, help = "ID of the machine to reboot")]
    pub machine: String,
    #[clap(long, help = "Power control action")]
    pub action: AdminPowerControlAction,
}

#[derive(ValueEnum, Parser, Debug, Clone)]
pub enum AdminPowerControlAction {
    On,
    GracefulShutdown,
    ForceOff,
    GracefulRestart,
    ForceRestart,
    ACPowercycle,
}

impl From<AdminPowerControlAction> for rpc::forge::admin_power_control_request::SystemPowerControl {
    fn from(c_type: AdminPowerControlAction) -> Self {
        match c_type {
            AdminPowerControlAction::On => {
                rpc::forge::admin_power_control_request::SystemPowerControl::On
            }
            AdminPowerControlAction::GracefulShutdown => {
                rpc::forge::admin_power_control_request::SystemPowerControl::GracefulShutdown
            }
            AdminPowerControlAction::ForceOff => {
                rpc::forge::admin_power_control_request::SystemPowerControl::ForceOff
            }
            AdminPowerControlAction::GracefulRestart => {
                rpc::forge::admin_power_control_request::SystemPowerControl::GracefulRestart
            }
            AdminPowerControlAction::ForceRestart => {
                rpc::forge::admin_power_control_request::SystemPowerControl::ForceRestart
            }
            AdminPowerControlAction::ACPowercycle => {
                rpc::forge::admin_power_control_request::SystemPowerControl::AcPowercycle
            }
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub struct InfiniteBootArgs {
    #[clap(long, help = "ID of the machine to enable/query infinite boot")]
    pub machine: String,
    #[clap(short, long, help = "Issue reboot to apply BIOS change")]
    pub reboot: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct LockdownArgs {
    #[clap(long, help = "ID of the machine to enable/disable lockdown")]
    pub machine: MachineId,
    #[clap(short, long, help = "Issue reboot to apply lockdown change")]
    pub reboot: bool,
    #[clap(
        long,
        conflicts_with = "disable",
        required_unless_present = "disable",
        help = "Enable lockdown"
    )]
    pub enable: bool,
    #[clap(
        long,
        conflicts_with = "enable",
        required_unless_present = "enable",
        help = "Disable lockdown"
    )]
    pub disable: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct LockdownStatusArgs {
    #[clap(long, help = "ID of the machine to check lockdown status")]
    pub machine: MachineId,
}

#[derive(Parser, Debug, Clone)]
pub struct CreateBmcUserArgs {
    #[clap(long, short, help = "IP of the BMC where we want to create a new user")]
    pub ip_address: Option<String>,
    #[clap(long, help = "MAC of the BMC where we want to create a new user")]
    pub mac_address: Option<MacAddress>,
    #[clap(
        long,
        short,
        help = "ID of the machine where we want to create a new user"
    )]
    pub machine: Option<String>,

    #[clap(long, short, help = "Username of new BMC account")]
    pub username: String,
    #[clap(long, short, help = "Password of new BMC account")]
    pub password: String,
    #[clap(
        long,
        short,
        help = "Role of new BMC account ('administrator', 'operator', 'readonly', 'noaccess')"
    )]
    pub role_id: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteBmcUserArgs {
    #[clap(long, short, help = "IP of the BMC where we want to delete a user")]
    pub ip_address: Option<String>,
    #[clap(long, help = "MAC of the BMC where we want to delete a user")]
    pub mac_address: Option<MacAddress>,
    #[clap(long, short, help = "ID of the machine where we want to delete a user")]
    pub machine: Option<String>,

    #[clap(long, short, help = "Username of BMC account to delete")]
    pub username: String,
}
