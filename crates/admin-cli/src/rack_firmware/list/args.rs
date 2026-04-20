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

#[derive(Parser, Debug)]
pub struct Args {
    #[clap(long, help = "Show only available configurations.")]
    pub only_available: bool,
    #[clap(help = "Filter by rack hardware type.")]
    pub rack_hardware_type: Option<String>,
}

impl From<Args> for rpc::forge::RackFirmwareSearchFilter {
    fn from(args: Args) -> Self {
        Self {
            only_available: args.only_available,
            rack_hardware_type: args
                .rack_hardware_type
                .map(|v| rpc::common::RackHardwareType { value: v }),
        }
    }
}
