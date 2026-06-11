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

use crate::component_manager::common::DeviceTargetArgs;

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

List available firmware versions for switches:
    $ nico-admin-cli component-manager get-firmware-versions switch \
    --switch-id 12345678-1234-5678-90ab-cdef01234567

List versions for power shelves:
    $ nico-admin-cli component-manager get-firmware-versions power-shelf \
    --power-shelf-id 12345678-1234-5678-90ab-cdef01234567

List versions for an entire rack:
    $ nico-admin-cli component-manager get-firmware-versions rack \
    --rack-id 12345678-1234-5678-90ab-cdef01234567

")]
pub struct Args {
    #[clap(subcommand)]
    pub target: DeviceTargetArgs,
}

impl From<Args> for rpc::forge::ListComponentFirmwareVersionsRequest {
    fn from(args: Args) -> Self {
        match args.target {
            DeviceTargetArgs::Switch(target) => Self {
                target: Some(
                    rpc::forge::list_component_firmware_versions_request::Target::SwitchIds(
                        target.into(),
                    ),
                ),
            },
            DeviceTargetArgs::PowerShelf(target) => Self {
                target: Some(
                    rpc::forge::list_component_firmware_versions_request::Target::PowerShelfIds(
                        target.into(),
                    ),
                ),
            },
            DeviceTargetArgs::ComputeTray(target) => Self {
                target: Some(
                    rpc::forge::list_component_firmware_versions_request::Target::MachineIds(
                        target.into(),
                    ),
                ),
            },
            DeviceTargetArgs::Rack(target) => Self {
                target: Some(
                    rpc::forge::list_component_firmware_versions_request::Target::RackIds(
                        target.into(),
                    ),
                ),
            },
        }
    }
}
