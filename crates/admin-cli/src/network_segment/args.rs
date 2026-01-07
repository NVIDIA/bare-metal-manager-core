/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::network::NetworkSegmentId;
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Display Network Segment information")]
    Show(ShowNetworkSegment),
    #[clap(about = "Delete Network Segment")]
    Delete(DeleteNetworkSegment),
}

#[derive(Parser, Debug)]
pub struct ShowNetworkSegment {
    #[clap(
        default_value(None),
        help = "The network segment to query, leave empty for all (default)"
    )]
    pub network: Option<NetworkSegmentId>,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The VPC name to query")]
    pub name: Option<String>,
}

#[derive(Parser, Debug)]
pub struct DeleteNetworkSegment {
    #[clap(long, help = "Id of the network segment")]
    pub id: NetworkSegmentId,
}
