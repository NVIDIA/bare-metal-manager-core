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

use clap::{Args as ClapArgs, Parser, Subcommand};

use crate::component_manager::common::{
    ComputeTrayComponentArg, MachineTargetArgs, NvSwitchComponentArg, PowerShelfComponentArg,
    PowerShelfTargetArgs, RackTargetArgs, SwitchTargetArgs,
};

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub target: Target,
}

#[derive(Subcommand, Debug)]
pub enum Target {
    #[clap(about = "Queue firmware on NVLink switches")]
    Switch(SwitchArgs),

    #[clap(about = "Queue firmware on power shelves")]
    PowerShelf(PowerShelfArgs),

    #[clap(about = "Queue firmware on compute trays")]
    ComputeTray(ComputeTrayArgs),

    #[clap(about = "Queue firmware on all eligible devices in racks")]
    Rack(RackArgs),
}

#[derive(ClapArgs, Debug)]
pub struct SwitchArgs {
    #[clap(flatten)]
    pub ids: SwitchTargetArgs,

    #[clap(long = "target-version", help = "Firmware target version")]
    pub target_version: String,

    #[clap(
        long = "component",
        value_enum,
        value_delimiter = ',',
        help = "NVLink switch components to update; omit to update all supported components"
    )]
    pub components: Vec<NvSwitchComponentArg>,
}

#[derive(ClapArgs, Debug)]
pub struct PowerShelfArgs {
    #[clap(flatten)]
    pub ids: PowerShelfTargetArgs,

    #[clap(long = "target-version", help = "Firmware target version")]
    pub target_version: String,

    #[clap(
        long = "component",
        value_enum,
        value_delimiter = ',',
        help = "Power shelf components to update; omit to update all supported components"
    )]
    pub components: Vec<PowerShelfComponentArg>,
}

#[derive(ClapArgs, Debug)]
pub struct ComputeTrayArgs {
    #[clap(flatten)]
    pub ids: MachineTargetArgs,

    #[clap(long = "target-version", help = "Firmware target version")]
    pub target_version: String,

    #[clap(
        long = "component",
        value_enum,
        value_delimiter = ',',
        help = "Compute tray components to update; omit to update all supported components"
    )]
    pub components: Vec<ComputeTrayComponentArg>,
}

#[derive(ClapArgs, Debug)]
pub struct RackArgs {
    #[clap(flatten)]
    pub ids: RackTargetArgs,

    #[clap(long = "target-version", help = "Firmware target version")]
    pub target_version: String,
}

impl From<Args> for rpc::forge::UpdateComponentFirmwareRequest {
    fn from(args: Args) -> Self {
        match args.target {
            Target::Switch(target) => Self {
                target_version: target.target_version,
                target: Some(
                    rpc::forge::update_component_firmware_request::Target::Switches(
                        rpc::forge::UpdateSwitchFirmwareTarget {
                            switch_ids: Some(target.ids.into()),
                            components: target
                                .components
                                .into_iter()
                                .map(|component| {
                                    rpc::forge::NvSwitchComponent::from(component) as i32
                                })
                                .collect(),
                        },
                    ),
                ),
            },
            Target::PowerShelf(target) => Self {
                target_version: target.target_version,
                target: Some(
                    rpc::forge::update_component_firmware_request::Target::PowerShelves(
                        rpc::forge::UpdatePowerShelfFirmwareTarget {
                            power_shelf_ids: Some(target.ids.into()),
                            components: target
                                .components
                                .into_iter()
                                .map(|component| {
                                    rpc::forge::PowerShelfComponent::from(component) as i32
                                })
                                .collect(),
                        },
                    ),
                ),
            },
            Target::ComputeTray(target) => Self {
                target_version: target.target_version,
                target: Some(
                    rpc::forge::update_component_firmware_request::Target::ComputeTrays(
                        rpc::forge::UpdateComputeTrayFirmwareTarget {
                            machine_ids: Some(target.ids.into()),
                            components: target
                                .components
                                .into_iter()
                                .map(|component| {
                                    rpc::forge::ComputeTrayComponent::from(component) as i32
                                })
                                .collect(),
                        },
                    ),
                ),
            },
            Target::Rack(target) => Self {
                target_version: target.target_version,
                target: Some(
                    rpc::forge::update_component_firmware_request::Target::Racks(
                        rpc::forge::UpdateRackFirmwareTarget {
                            rack_ids: Some(target.ids.into()),
                        },
                    ),
                ),
            },
        }
    }
}
