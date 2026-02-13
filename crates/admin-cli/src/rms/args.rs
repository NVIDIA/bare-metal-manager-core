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

#[derive(Parser, Debug, Clone)]
pub struct RmsAction {
    #[clap(subcommand)]
    pub command: Cmd,

    #[clap(long, global = true, help = "URL of RMS API endpoint (required).")]
    pub url: Option<String>,

    #[clap(long, global = true, help = "Root CA path")]
    pub root_ca: Option<String>,

    #[clap(long, global = true, help = "Client certificate path")]
    pub client_cert: Option<String>,

    #[clap(long, global = true, help = "Client key path")]
    pub client_key: Option<String>,
}

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    #[clap(about = "Get the full RMS inventory")]
    Inventory,
    #[clap(about = "Get the power on sequence")]
    PowerOnSequence(PowerOnSequence),
    #[clap(about = "Get the power state for a given node")]
    PowerState(PowerState),
    #[clap(about = "Get the firmware inventory for a given node")]
    FirmwareInventory(FirmwareInventory),
}

#[derive(Parser, Debug, Clone)]
pub struct PowerOnSequence {
    #[clap(help = "Rack ID to get power sequence for")]
    pub rack_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct PowerState {
    #[clap(help = "Rack ID to get power sequence for")]
    pub rack_id: String,
    #[clap(help = "Node ID to get power state for")]
    pub node_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct FirmwareInventory {
    #[clap(help = "Rack ID to get power sequence for")]
    pub rack_id: String,
    #[clap(help = "Node ID to get firmware inventory for")]
    pub node_id: String,
}
