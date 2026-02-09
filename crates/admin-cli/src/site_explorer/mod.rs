/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
