/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge::NetworkSegmentDeletionRequest;
pub use args::Cmd;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Show(args) => {
                cmds::handle_show(
                    args,
                    ctx.config.format,
                    &ctx.api_client,
                    ctx.config.page_size,
                )
                .await?
            }
            Cmd::Delete(args) => {
                if !ctx.config.cloud_unsafe_op_enabled {
                    return Err(CarbideCliError::GenericError(
                        "Operation not allowed due to potential inconsistencies with cloud database."
                            .to_owned(),
                    ));
                }
                ctx.api_client
                    .0
                    .delete_network_segment(NetworkSegmentDeletionRequest { id: Some(args.id) })
                    .await?;
            }
        }
        Ok(())
    }
}
