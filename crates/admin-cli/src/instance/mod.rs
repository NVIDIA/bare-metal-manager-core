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

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, mut ctx: RuntimeContext) -> CarbideCliResult<()> {
        // Build the internal GlobalOptions from RuntimeContext for handlers that need it
        let opts = args::GlobalOptions {
            format: ctx.config.format,
            page_size: ctx.config.page_size,
            sort_by: &ctx.config.sort_by,
            cloud_unsafe_op: if ctx.config.cloud_unsafe_op_enabled {
                Some("enabled".to_string())
            } else {
                None
            },
        };

        match self {
            Cmd::Show(args) => {
                cmds::handle_show(
                    args,
                    &mut ctx.output_file,
                    &opts.format,
                    &ctx.api_client,
                    opts.page_size,
                    opts.sort_by,
                )
                .await?
            }
            Cmd::Reboot(args) => cmds::handle_reboot(args, &ctx.api_client).await?,
            Cmd::Release(args) => cmds::release(&ctx.api_client, args, opts).await?,
            Cmd::Allocate(args) => cmds::allocate(&ctx.api_client, args, opts).await?,
            Cmd::UpdateOS(args) => cmds::update_os(&ctx.api_client, args, opts).await?,
            Cmd::UpdateIbConfig(args) => {
                cmds::update_ib_config(&ctx.api_client, args, opts).await?
            }
        }
        Ok(())
    }
}
