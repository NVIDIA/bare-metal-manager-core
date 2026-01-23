/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Show rack information")]
    Show(ShowRack),
    #[clap(about = "List all racks")]
    List,
    #[clap(about = "Delete the rack")]
    Delete(DeleteRack),
}

#[derive(Parser, Debug)]
pub struct ShowRack {
    #[clap(help = "Rack ID or name to show (leave empty for all)")]
    pub identifier: Option<String>,
}

#[derive(Parser, Debug)]
pub struct DeleteRack {
    #[clap(
        help = "Rack ID or name to delete (should not have any associated compute trays, nvlink switches or power shelves)"
    )]
    pub identifier: String,
}
