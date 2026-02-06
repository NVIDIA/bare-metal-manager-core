/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
