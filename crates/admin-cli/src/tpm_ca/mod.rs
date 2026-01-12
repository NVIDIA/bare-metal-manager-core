/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
            Cmd::Show => cmds::show(&ctx.api_client).await,
            Cmd::Delete(delete_opts) => cmds::delete(delete_opts.ca_id, &ctx.api_client).await,
            Cmd::Add(add_opts) => cmds::add_filename(&add_opts.filename, &ctx.api_client).await,
            Cmd::AddBulk(add_opts) => cmds::add_bulk(&add_opts.dirname, &ctx.api_client).await,
            Cmd::ShowUnmatchedEk => cmds::show_unmatched_ek(&ctx.api_client).await,
        }
    }
}
