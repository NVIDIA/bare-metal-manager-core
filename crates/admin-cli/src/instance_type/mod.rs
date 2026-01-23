/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
            Cmd::Create(args) => cmds::create(args, ctx.config.format, &ctx.api_client).await,
            Cmd::Show(args) => {
                cmds::show(
                    args,
                    ctx.config.format,
                    &ctx.api_client,
                    ctx.config.page_size,
                    ctx.config.extended,
                )
                .await
            }
            Cmd::Update(args) => cmds::update(args, ctx.config.format, &ctx.api_client).await,
            Cmd::Delete(args) => cmds::delete(args, &ctx.api_client).await,
            Cmd::Associate(args) => cmds::create_association(args, &ctx.api_client).await,
            Cmd::Disassociate(args) => {
                cmds::remove_association(args, ctx.config.cloud_unsafe_op_enabled, &ctx.api_client)
                    .await
            }
        }
    }
}
