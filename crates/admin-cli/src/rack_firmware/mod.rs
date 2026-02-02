/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
            Cmd::Create(ref args) => cmds::create(args, ctx.config.format, &ctx.api_client).await?,
            Cmd::Get(ref args) => cmds::get(args, ctx.config.format, &ctx.api_client).await?,
            Cmd::List(ref args) => cmds::list(args, ctx.config.format, &ctx.api_client).await?,
            Cmd::Delete(ref args) => cmds::delete(args, &ctx.api_client).await?,
            Cmd::Apply(ref args) => cmds::apply(args, ctx.config.format, &ctx.api_client).await?,
        }
        Ok(())
    }
}
