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

use std::net::SocketAddr;

use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    #[clap(about = "Show Rshim Status")]
    GetRshimStatus(SshArgs),
    #[clap(about = "Disable Rshim")]
    DisableRshim(SshArgs),
    #[clap(about = "EnableRshim")]
    EnableRshim(SshArgs),
    #[clap(about = "Copy BFB to the DPU BMC's RSHIM ")]
    CopyBfb(CopyBfbArgs),
    #[clap(about = "Show the DPU's BMC's OBMC log")]
    ShowObmcLog(SshArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct BmcCredentials {
    #[clap(help = "BMC IP Address")]
    pub bmc_ip_address: SocketAddr,
    #[clap(help = "BMC Username")]
    pub bmc_username: String,
    #[clap(help = "BMC Password")]
    pub bmc_password: String,
}

#[derive(Parser, Debug, Clone)]
pub struct SshArgs {
    #[clap(flatten)]
    pub credentials: BmcCredentials,
}

#[derive(Parser, Debug, Clone)]
pub struct CopyBfbArgs {
    #[clap(flatten)]
    pub ssh_args: SshArgs,
    #[clap(help = "BFB Path")]
    pub bfb_path: String,
}
