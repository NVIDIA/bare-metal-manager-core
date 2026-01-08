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

pub mod args;
pub mod cmds;

#[cfg(test)]
mod tests;

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Cmd;
pub use cmds::show_discovered_managed_host as show_site_explorer_discovered_managed_host;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, mut ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::GetReport(mode) => {
                cmds::show_discovered_managed_host(
                    &ctx.api_client,
                    &mut ctx.output_file,
                    ctx.config.format,
                    ctx.config.page_size,
                    mode,
                )
                .await
            }
            Cmd::Explore(opts) => cmds::explore(&ctx.api_client, &opts.address, opts.mac).await,
            Cmd::ReExplore(opts) => cmds::re_explore(&ctx.api_client, opts).await,
            Cmd::ClearError(opts) => cmds::clear_error(&ctx.api_client, opts.address).await,
            Cmd::Delete(opts) => cmds::delete_endpoint(&ctx.api_client, opts).await,
            Cmd::Remediation(opts) => cmds::remediation(&ctx.api_client, opts).await,
            Cmd::IsBmcInManagedHost(opts) => {
                cmds::is_bmc_in_managed_host(&ctx.api_client, &opts.address, opts.mac).await
            }
            Cmd::HaveCredentials(opts) => {
                cmds::have_credentials(&ctx.api_client, &opts.address, opts.mac).await
            }
            Cmd::CopyBfbToDpuRshim(args) => {
                cmds::copy_bfb_to_dpu_rshim(&ctx.api_client, args).await
            }
        }
    }
}
