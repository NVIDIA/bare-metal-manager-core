/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
pub use args::Cmd;

use crate::rpc::ApiClient;

pub async fn dispatch(
    cmd: Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
    extended: bool,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::ExternalConfig(config_command) => match config_command {
            args::ExternalConfigCommand::Show(opts) => {
                cmds::external_config_show(api_client, opts.name, extended, format).await
            }
            args::ExternalConfigCommand::AddUpdate(opts) => {
                cmds::external_config_add_update(
                    api_client,
                    opts.name,
                    opts.file_name,
                    opts.description,
                )
                .await
            }
            args::ExternalConfigCommand::Remove(opts) => {
                cmds::remove_external_config(api_client, opts.name).await
            }
        },
        Cmd::Results(cmd) => match cmd {
            args::ResultsCommand::Show(options) => {
                cmds::handle_results_show(options, format, api_client, page_size, extended).await
            }
        },
        Cmd::Runs(cmd) => match cmd {
            args::RunsCommand::Show(options) => {
                cmds::handle_runs_show(options, format, api_client, page_size).await
            }
        },
        Cmd::OnDemand(on_demand_command) => match on_demand_command {
            args::OnDemandCommand::Start(options) => {
                cmds::on_demand_machine_validation(api_client, options).await
            }
        },
        Cmd::Tests(tests_command) => match *tests_command {
            args::TestsCommand::Show(options) => {
                cmds::show_tests(api_client, options, format, extended).await
            }
            args::TestsCommand::Verify(options) => {
                cmds::machine_validation_test_verfied(api_client, options).await
            }
            args::TestsCommand::Enable(options) => {
                cmds::machine_validation_test_enable(api_client, options).await
            }
            args::TestsCommand::Disable(options) => {
                cmds::machine_validation_test_disable(api_client, options).await
            }
            args::TestsCommand::Add(options) => {
                cmds::machine_validation_test_add(api_client, options).await
            }
            args::TestsCommand::Update(options) => {
                cmds::machine_validation_test_update(api_client, options).await
            }
        },
    }
}
