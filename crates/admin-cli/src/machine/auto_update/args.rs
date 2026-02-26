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
use clap::{ArgGroup, Parser};

#[derive(Parser, Debug, Clone)]
#[clap(group(ArgGroup::new("autoupdate_action").required(true).args(&["enable", "disable", "clear"])))]
pub struct Args {
    #[clap(long, help = "Machine ID of the host to change")]
    pub machine: MachineId,
    #[clap(
        short = 'e',
        long,
        action,
        help = "Enable auto updates even if globally disabled or individually disabled by config files"
    )]
    pub enable: bool,
    #[clap(
        short = 'd',
        long,
        action,
        help = "Disable auto updates even if globally enabled or individually enabled by config files"
    )]
    pub disable: bool,
    #[clap(
        short = 'c',
        long,
        action,
        help = "Perform auto updates according to config files"
    )]
    pub clear: bool,
}
