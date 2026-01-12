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
            Cmd::BmcReset(args) => cmds::bmc_reset(args, &ctx.api_client).await,
            Cmd::AdminPowerControl(args) => cmds::admin_power_control(args, &ctx.api_client).await,
            Cmd::CreateBmcUser(args) => cmds::create_bmc_user(args, &ctx.api_client).await,
            Cmd::DeleteBmcUser(args) => cmds::delete_bmc_user(args, &ctx.api_client).await,
            Cmd::EnableInfiniteBoot(args) => {
                cmds::enable_infinite_boot(args, &ctx.api_client).await
            }
            Cmd::IsInfiniteBootEnabled(args) => {
                cmds::is_infinite_boot_enabled(args, &ctx.api_client).await
            }
            Cmd::Lockdown(args) => cmds::lockdown(args, &ctx.api_client).await,
            Cmd::LockdownStatus(args) => cmds::lockdown_status(args, &ctx.api_client).await,
        }
    }
}
