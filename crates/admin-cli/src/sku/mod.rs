/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
            Cmd::Show(args) => {
                cmds::show(
                    args,
                    &ctx.api_client,
                    &mut ctx.output_file,
                    &ctx.config.format,
                    ctx.config.extended,
                )
                .await
            }
            Cmd::ShowMachines(args) => {
                cmds::show_machines(
                    args,
                    &ctx.api_client,
                    &mut ctx.output_file,
                    &ctx.config.format,
                )
                .await
            }
            Cmd::Generate(args) => {
                cmds::generate(
                    args,
                    &ctx.api_client,
                    &mut ctx.output_file,
                    &ctx.config.format,
                    ctx.config.extended,
                )
                .await
            }
            Cmd::Create(args) => {
                cmds::create(
                    args,
                    &ctx.api_client,
                    &mut ctx.output_file,
                    &ctx.config.format,
                )
                .await
            }
            Cmd::Delete { sku_id } => cmds::delete(sku_id, &ctx.api_client).await,
            Cmd::Assign {
                sku_id,
                machine_id,
                force,
            } => cmds::assign(sku_id, machine_id, force, &ctx.api_client).await,
            Cmd::Unassign(args) => cmds::unassign(args, &ctx.api_client).await,
            Cmd::Verify { machine_id } => cmds::verify(machine_id, &ctx.api_client).await,
            Cmd::UpdateMetadata(args) => cmds::update_metadata(args, &ctx.api_client).await,
            Cmd::BulkUpdateMetadata(args) => {
                cmds::bulk_update_metadata(args, &ctx.api_client).await
            }
            Cmd::Replace(args) => {
                cmds::replace(
                    args,
                    &ctx.api_client,
                    &mut ctx.output_file,
                    &ctx.config.format,
                )
                .await
            }
        }
    }
}
