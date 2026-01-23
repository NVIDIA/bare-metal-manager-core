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

pub mod args;
pub mod cmds;

#[cfg(test)]
mod tests;

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Cmd;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Create(args) => {
                cmds::handle_create(args, ctx.config.format, &ctx.api_client).await
            }
            Cmd::Update(args) => {
                cmds::handle_update(args, ctx.config.format, &ctx.api_client).await
            }
            Cmd::Delete(args) => {
                cmds::handle_delete(args, ctx.config.format, &ctx.api_client).await
            }
            Cmd::Show(args) => {
                cmds::handle_show(
                    args,
                    ctx.config.format,
                    &ctx.api_client,
                    ctx.config.page_size,
                )
                .await
            }
            Cmd::GetVersion(args) => cmds::handle_get_version(args, &ctx.api_client).await,
            Cmd::ShowInstances(args) => {
                cmds::handle_show_instances(args, ctx.config.format, &ctx.api_client).await
            }
        }
    }
}
