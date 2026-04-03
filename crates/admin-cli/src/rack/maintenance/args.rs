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

use carbide_uuid::rack::RackId;
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Args {
    #[clap(about = "Start on-demand rack maintenance (full rack or partial)")]
    Start(MaintenanceOptions),
}

#[derive(Parser, Debug)]
pub struct MaintenanceOptions {
    #[clap(short, long, help = "Rack ID to start maintenance on")]
    pub rack: RackId,

    #[clap(
        long,
        help = "Machine IDs to include (omit for full rack)",
        num_args = 1..,
        value_delimiter = ','
    )]
    pub machine_ids: Option<Vec<String>>,

    #[clap(
        long,
        help = "Switch IDs to include (omit for full rack)",
        num_args = 1..,
        value_delimiter = ','
    )]
    pub switch_ids: Option<Vec<String>>,

    #[clap(
        long,
        help = "Power shelf IDs to include (omit for full rack)",
        num_args = 1..,
        value_delimiter = ','
    )]
    pub power_shelf_ids: Option<Vec<String>>,

    #[clap(
        long,
        help = "Maintenance activities to perform: firmware-upgrade, configure-nmx-cluster, power-sequence (omit for all)",
        num_args = 1..,
        value_delimiter = ','
    )]
    pub activities: Option<Vec<String>>,

    #[clap(
        long,
        help = "Target firmware version for firmware-upgrade activity (omit for RMS default)"
    )]
    pub firmware_version: Option<String>,

    #[clap(
        long,
        help = "Firmware components to update, e.g. BMC,CPLD,BIOS (omit for all components)",
        num_args = 1..,
        value_delimiter = ','
    )]
    pub components: Option<Vec<String>>,
}
