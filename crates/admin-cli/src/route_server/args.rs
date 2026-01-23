/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use rpc::forge::RouteServerSourceType;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Get all route servers")]
    Get,

    #[clap(about = "Add route server addresses")]
    Add(AddressArgs),

    #[clap(about = "Remove route server addresses")]
    Remove(AddressArgs),

    #[clap(about = "Replace all route server addresses")]
    Replace(AddressArgs),
}

// AddressArgs is used for add/remove/replace operations
// for route server addresses, with support for overriding
// the source_type to not be admin_api, and make ephemeral
// changes against whatever was loaded up via the config
// file at start.
#[derive(Parser, Debug)]
pub struct AddressArgs {
    #[arg(value_delimiter = ',', help = "Comma-separated list of IPv4 addresses")]
    pub ip: Vec<std::net::Ipv4Addr>,

    // The optional source_type to set. If unset, this
    // defaults to admin_api, which is what we'd expect.
    // Override with --source_type=config to make
    // ephemeral changes to config file-based entries,
    // which is really intended for break-glass types
    // of scenarios.
    #[arg(
        long,
        default_value = "admin_api",
        help = "The source_type to use for the target addresses. Defaults to admin_api."
    )]
    pub source_type: RouteServerSourceType,
}
