/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

// Export so the CLI builder can just pull in ping::Opts.
// This is different than others that pull in Cmd, since
// this is just a single top-level command without any
// subcommands.
use ::rpc::admin_cli::CarbideCliResult;
pub use args::Opts;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Opts {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        cmds::ping(&ctx.api_client, &self).await?;
        Ok(())
    }
}
