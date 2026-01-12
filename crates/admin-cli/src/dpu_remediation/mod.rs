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
        match self {
            Cmd::Create(args) => cmds::create_dpu_remediation(args, &ctx.api_client).await,
            Cmd::Approve(args) => cmds::approve_dpu_remediation(args, &ctx.api_client).await,
            Cmd::Revoke(args) => cmds::revoke_dpu_remediation(args, &ctx.api_client).await,
            Cmd::Enable(args) => cmds::enable_dpu_remediation(args, &ctx.api_client).await,
            Cmd::Disable(args) => cmds::disable_dpu_remediation(args, &ctx.api_client).await,
            Cmd::Show(args) => {
                cmds::handle_show(
                    args,
                    ctx.config.format,
                    &mut ctx.output_file,
                    &ctx.api_client,
                    ctx.config.page_size,
                )
                .await
            }
            Cmd::ListApplied(args) => {
                cmds::handle_list_applied(
                    args,
                    ctx.config.format,
                    &mut ctx.output_file,
                    &ctx.api_client,
                    ctx.config.page_size,
                )
                .await
            }
        }
    }
}
