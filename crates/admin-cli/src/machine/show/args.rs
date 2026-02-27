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
use clap::Parser;

#[derive(Parser, Debug)]
#[clap(disable_help_flag = true)]
pub struct Args {
    #[clap(long, action = clap::ArgAction::HelpLong)]
    pub help: Option<bool>,

    #[clap(
        short,
        long,
        action,
        conflicts_with = "machine",
        help = "Show all machines (DEPRECATED)"
    )]
    pub all: bool,

    #[clap(
        short,
        long,
        action,
        conflicts_with = "machine",
        help = "Show only DPUs"
    )]
    pub dpus: bool,

    #[clap(
        short,
        long,
        action,
        conflicts_with = "machine",
        help = "Show only hosts"
    )]
    pub hosts: bool,

    #[clap(
        short = 't',
        long,
        action,
        // DPUs don't get associated with instance types.
        // Wouldn't hurt to allow the query, but might as well
        // be helpful here.
        conflicts_with = "dpus",
        help = "Show only machines for this instance type"
    )]
    pub instance_type_id: Option<String>,

    #[clap(
        default_value(None),
        help = "The machine to query, leave empty for all (default)"
    )]
    pub machine: Option<MachineId>,

    #[clap(
        short = 'c',
        long,
        default_value("5"),
        help = "History count. Valid if `machine` argument is passed."
    )]
    pub history_count: u32,
}
