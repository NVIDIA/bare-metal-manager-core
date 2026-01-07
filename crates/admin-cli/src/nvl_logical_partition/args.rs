/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
    #[clap(about = "Display logical partition information")]
    Show(ShowLogicalPartition),
    #[clap(about = "Create logical partition")]
    Create(CreateLogicalPartition),
    #[clap(about = "Delete logical partition")]
    Delete(DeleteLogicalPartition),
}

#[derive(Parser, Debug)]
pub struct ShowLogicalPartition {
    #[clap(
        default_value(""),
        help = "Optional, Logical Partition ID to search for"
    )]
    pub id: String,
    #[clap(short, long, help = "Optional, Logical Partition Name to search for")]
    pub name: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct CreateLogicalPartition {
    #[clap(short = 'n', long, help = "name of the partition")]
    pub name: String,
    #[clap(short = 't', long, help = "tenant organization id of the partition")]
    pub tenant_organization_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteLogicalPartition {
    #[clap(short = 'n', long, help = "name of the partition")]
    pub name: String,
}
