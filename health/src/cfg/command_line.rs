/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#[derive(Parser)]
#[clap(name = env!("CARGO_BIN_NAME"))]
pub struct Options {
    #[clap(long, default_value = "false", help = "Print version number and exit")]
    pub version: bool,

    #[clap(
        short,
        long,
        alias("url"),
        require_equals(true),
        default_value = "https://carbide-api.forge-system.svc.cluster.local"
    )]
    pub api: String,

    #[clap(
        long,
        help = "Full path of root CA in PEM format",
        default_value_t = String::from("/var/run/secrets/spiffe.io/ca.crt"),
    )]
    pub root_ca: String,

    #[clap(
        long,
        help = "Full path of client cert in PEM format",
        default_value_t = String::from("/var/run/secrets/spiffe.io/tls.crt"),
    )]
    pub client_cert: String,

    #[clap(
        long,
        help = "Full path of client key",
        default_value_t = String::from("/var/run/secrets/spiffe.io/tls.key"),
    )]
    pub client_key: String,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
