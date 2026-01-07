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
    #[clap(about = "Display NvLink partition information")]
    Show(ShowNvlPartition),
}

#[derive(Parser, Debug)]
pub struct ShowNvlPartition {
    #[clap(
        default_value(""),
        help = "Optional, NvLink Partition ID to search for"
    )]
    pub id: String,
    #[clap(short, long, help = "Optional, Tenant Organization ID to search for")]
    pub tenant_org_id: Option<String>,
    #[clap(short, long, help = "Optional, NvLink Partition Name to search for")]
    pub name: Option<String>,
}
