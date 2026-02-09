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
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::ExternalConfig(config_command) => match config_command {
                args::ExternalConfigCommand::Show(opts) => {
                    cmds::external_config_show(
                        &ctx.api_client,
                        opts.name,
                        ctx.config.extended,
                        ctx.config.format,
                    )
                    .await
                }
                args::ExternalConfigCommand::AddUpdate(opts) => {
                    cmds::external_config_add_update(
                        &ctx.api_client,
                        opts.name,
                        opts.file_name,
                        opts.description,
                    )
                    .await
                }
                args::ExternalConfigCommand::Remove(opts) => {
                    cmds::remove_external_config(&ctx.api_client, opts.name).await
                }
            },
            Cmd::Results(cmd) => match cmd {
                args::ResultsCommand::Show(options) => {
                    cmds::handle_results_show(
                        options,
                        ctx.config.format,
                        &ctx.api_client,
                        ctx.config.page_size,
                        ctx.config.extended,
                    )
                    .await
                }
            },
            Cmd::Runs(cmd) => match cmd {
                args::RunsCommand::Show(options) => {
                    cmds::handle_runs_show(
                        options,
                        ctx.config.format,
                        &ctx.api_client,
                        ctx.config.page_size,
                    )
                    .await
                }
            },
            Cmd::OnDemand(on_demand_command) => match on_demand_command {
                args::OnDemandCommand::Start(options) => {
                    cmds::on_demand_machine_validation(&ctx.api_client, options).await
                }
            },
            Cmd::Tests(tests_command) => match *tests_command {
                args::TestsCommand::Show(options) => {
                    cmds::show_tests(
                        &ctx.api_client,
                        options,
                        ctx.config.format,
                        ctx.config.extended,
                    )
                    .await
                }
                args::TestsCommand::Verify(options) => {
                    cmds::machine_validation_test_verfied(&ctx.api_client, options).await
                }
                args::TestsCommand::Enable(options) => {
                    cmds::machine_validation_test_enable(&ctx.api_client, options).await
                }
                args::TestsCommand::Disable(options) => {
                    cmds::machine_validation_test_disable(&ctx.api_client, options).await
                }
                args::TestsCommand::Add(options) => {
                    cmds::machine_validation_test_add(&ctx.api_client, options).await
                }
                args::TestsCommand::Update(options) => {
                    cmds::machine_validation_test_update(&ctx.api_client, options).await
                }
            },
        }
    }
}
