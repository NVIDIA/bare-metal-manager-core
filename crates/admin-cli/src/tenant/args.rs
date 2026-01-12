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

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    #[clap(about = "Display tenant details")]
    Show(ShowTenant),
    #[clap(about = "Update an existing tenant")]
    Update(UpdateTenant),
}

#[derive(Parser, Debug, Clone)]
pub struct ShowTenant {
    #[clap(help = "Optional, tenant org ID to restrict the search")]
    pub tenant_org: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct UpdateTenant {
    #[clap(help = "Tenant org ID to update", default_value(None))]
    pub tenant_org: String,

    #[clap(
        short = 'p',
        long,
        help = "Optional, routing profile to apply to the tenant",
        default_value(None)
    )]
    #[arg(value_enum)]
    pub routing_profile_type: Option<TenantRoutingProfileType>,

    #[clap(
        short = 'v',
        long,
        help = "Optional, version to use for comparison when performing the update, which will be rejected if the actual version of the record does not match the value of this parameter"
    )]
    pub version: Option<String>,

    #[clap(short = 'n', long, help = "Organization name of the tenant")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum TenantRoutingProfileType {
    // Admin variant is an implicit profile of the admin network VPC
    // and is not a valid value, and so it can/should be omitted.
    Internal,
    PrivilegedInternal,
    External,
    Maintenance,
}

impl From<TenantRoutingProfileType> for rpc::forge::RoutingProfileType {
    fn from(p: TenantRoutingProfileType) -> Self {
        match p {
            TenantRoutingProfileType::Internal => rpc::forge::RoutingProfileType::Internal,
            TenantRoutingProfileType::PrivilegedInternal => {
                rpc::forge::RoutingProfileType::PrivilegedInternal
            }
            TenantRoutingProfileType::External => rpc::forge::RoutingProfileType::External,
            TenantRoutingProfileType::Maintenance => rpc::forge::RoutingProfileType::Maintenance,
        }
    }
}
