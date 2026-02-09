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

// Export so the CLI builder can just pull in version::Opts.
// This is different than others that pull in Cmd, since
// this is just a single top-level command without any
// subcommands.
use ::rpc::admin_cli::CarbideCliResult;
pub use args::Opts;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Opts {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        cmds::handle_show_version(&self, &ctx.api_client, ctx.config.format).await
    }
}
