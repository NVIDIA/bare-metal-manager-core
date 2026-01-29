/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
