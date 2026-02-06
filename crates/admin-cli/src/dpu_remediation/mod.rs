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

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Cmd;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, mut ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Create(args) => cmds::create_dpu_remediation(args, &ctx.api_client).await,
            Cmd::Approve(args) => cmds::approve_dpu_remediation(args, &ctx.api_client).await,
            Cmd::Revoke(args) => cmds::revoke_dpu_remediation(args, &ctx.api_client).await,
            Cmd::Enable(args) => cmds::enable_dpu_remediation(args, &ctx.api_client).await,
            Cmd::Disable(args) => cmds::disable_dpu_remediation(args, &ctx.api_client).await,
            Cmd::Show(args) => {
                cmds::handle_show(
                    args,
                    ctx.config.format,
                    &mut ctx.output_file,
                    &ctx.api_client,
                    ctx.config.page_size,
                )
                .await
            }
            Cmd::ListApplied(args) => {
                cmds::handle_list_applied(
                    args,
                    ctx.config.format,
                    &mut ctx.output_file,
                    &ctx.api_client,
                    ctx.config.page_size,
                )
                .await
            }
        }
    }
}
