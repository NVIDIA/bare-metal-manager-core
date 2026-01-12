/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    #[clap(about = "Get Full Rms Inventory")]
    Inventory,
    #[clap(about = "Remove a node from Rms")]
    RemoveNode(RemoveNode),
    #[clap(about = "Get Poweron Order")]
    PoweronOrder,
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
pub struct RemoveNode {
    #[clap(help = "Node ID to remove")]
    pub node_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct PowerState {
    #[clap(help = "Node ID to get power state for")]
    pub node_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct FirmwareInventory {
    #[clap(help = "Node ID to get firmware inventory for")]
    pub node_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct AvailableFwImages {
    #[clap(help = "Node ID to get available firmware images for")]
    pub node_id: String,
}
