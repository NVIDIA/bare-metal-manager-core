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

use clap::Parser;

use crate::component_manager::common::{PowerActionArg, PowerControlTargetArgs};

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(subcommand)]
    pub target: PowerControlTargetArgs,

    #[clap(
        long = "action",
        value_enum,
        help = "Power control action to apply to the targeted components"
    )]
    pub action: PowerActionArg,
}

impl From<Args> for rpc::forge::ComponentPowerControlRequest {
    fn from(args: Args) -> Self {
        let action = ::rpc::common::SystemPowerControl::from(args.action) as i32;
        match args.target {
            PowerControlTargetArgs::Switch(target) => Self {
                target: Some(
                    rpc::forge::component_power_control_request::Target::SwitchIds(target.into()),
                ),
                action,
            },
            PowerControlTargetArgs::PowerShelf(target) => Self {
                target: Some(
                    rpc::forge::component_power_control_request::Target::PowerShelfIds(
                        target.into(),
                    ),
                ),
                action,
            },
            PowerControlTargetArgs::ComputeTray(target) => Self {
                target: Some(
                    rpc::forge::component_power_control_request::Target::MachineIds(target.into()),
                ),
                action,
            },
        }
    }
}
