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

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Cmd;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Enable(query) => {
                cmds::modify_dpf_state(&query, ctx.config.format, &ctx.api_client, true).await
            }
            Cmd::Disable(query) => {
                cmds::modify_dpf_state(&query, ctx.config.format, &ctx.api_client, false).await
            }
            Cmd::Show(query) => {
                cmds::show(
                    &query,
                    ctx.config.format,
                    ctx.config.page_size,
                    &ctx.api_client,
                )
                .await
            }
        }
    }
}
