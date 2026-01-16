/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;

#[derive(Clone, Parser, Debug)]
pub struct IpRouterPair {
    pub ip_address: String,
    pub targz: std::path::PathBuf,
}

impl From<String> for IpRouterPair {
    fn from(value: String) -> Self {
        let mut parts = value.split(',');
        let ip_address = parts.next().unwrap();
        let targz = parts.next().unwrap();
        let targz = PathBuf::from_str(targz).unwrap();

        IpRouterPair {
            ip_address: ip_address.to_owned(),
            targz,
        }
    }
}

#[derive(Clone, Parser, Debug)]
pub struct Args {
    #[clap(short, long)]
    pub cert_path: Option<String>,

    #[clap(short, long)]
    pub port: Option<u16>,

    #[clap(
        long,
        help = "Path to .tar.gz file of redfish data to output. Create it from libredfish tests/mockups/<vendor>"
    )]
    pub targz: Option<std::path::PathBuf>,

    #[clap(
        long,
        help = "An ip_address and .tar.gz file pair (comma separated).\nThe file is an archive of redfish data when the request is forwarded to a specific IP address.\nRepeat for different machines"
    )]
    pub ip_router: Option<Vec<IpRouterPair>>,
}

pub fn parse_args() -> Args {
    Args::parse()
}
