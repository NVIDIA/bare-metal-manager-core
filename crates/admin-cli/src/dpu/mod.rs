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
        match self {
            Cmd::Reprovision(reprov) => cmds::reprovision(&ctx.api_client, reprov).await,
            Cmd::AgentUpgradePolicy(args::AgentUpgrade { set }) => {
                cmds::agent_upgrade_policy(&ctx.api_client, set).await
            }
            Cmd::Versions(options) => {
                cmds::versions(
                    &mut ctx.output_file,
                    ctx.config.format,
                    &ctx.api_client,
                    options,
                    ctx.config.page_size,
                )
                .await
            }
            Cmd::Status => {
                cmds::status(
                    &mut ctx.output_file,
                    ctx.config.format,
                    &ctx.api_client,
                    ctx.config.page_size,
                )
                .await
            }
            Cmd::Network(cmd) => {
                cmds::network(
                    &ctx.api_client,
                    &mut ctx.output_file,
                    cmd,
                    ctx.config.format,
                )
                .await
            }
        }
    }
}
