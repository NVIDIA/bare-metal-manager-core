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
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    #[clap(about = "Get Full Rms Inventory")]
    Inventory,
    #[clap(about = "Add a node to Rms")]
    AddNode(AddNode),
    #[clap(about = "Remove a node from Rms")]
    RemoveNode(RemoveNode),
    #[clap(about = "Get Poweron Order for a rack")]
    PoweronOrder(PoweronOrder),
    #[clap(about = "Get Power State for a given node")]
    PowerState(PowerState),
    #[clap(about = "Get Firmware Inventory for a given node")]
    FirmwareInventory(FirmwareInventory),
    #[clap(about = "Get Available Firmware Images for a given node")]
    AvailableFwImages(AvailableFwImages),
    #[clap(about = "Get BKC Files")]
    BkcFiles,
    #[clap(about = "Check BKC Compliance")]
    CheckBkcCompliance,
}

#[derive(Parser, Debug, Clone)]
pub struct PoweronOrder {
    #[clap(help = "Rack ID")]
    pub rack_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct RemoveNode {
    #[clap(help = "Rack ID")]
    pub rack_id: String,
    #[clap(help = "Node ID to remove")]
    pub node_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct PowerState {
    #[clap(help = "Rack ID")]
    pub rack_id: String,
    #[clap(help = "Node ID to get power state for")]
    pub node_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct FirmwareInventory {
    #[clap(help = "Rack ID")]
    pub rack_id: String,
    #[clap(help = "Node ID to get firmware inventory for")]
    pub node_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct AvailableFwImages {
    #[clap(help = "Rack ID (optional)")]
    pub rack_id: Option<String>,
    #[clap(help = "Node ID to get available firmware images for (optional)")]
    pub node_id: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct AddNode {
    #[clap(help = "Rack ID")]
    pub rack_id: String,
    #[clap(help = "Node ID")]
    pub node_id: String,
    #[clap(help = "MAC address")]
    pub mac_address: String,
    #[clap(help = "IP address")]
    pub ip_address: String,
    #[clap(help = "Port")]
    pub port: i32,
    #[clap(help = "Node type (optional)")]
    pub node_type: Option<i32>,
}
