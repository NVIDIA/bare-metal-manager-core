/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::infiniband::IBPartitionId;
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Display InfiniBand Partition information")]
    Show(ShowIbPartition),
}

#[derive(Parser, Debug)]
pub struct ShowIbPartition {
    #[clap(
        default_value(None),
        help = "The InfiniBand Partition ID to query, leave empty for all (default)"
    )]
    pub id: Option<IBPartitionId>,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The InfiniBand Partition name to query")]
    pub name: Option<String>,
}
