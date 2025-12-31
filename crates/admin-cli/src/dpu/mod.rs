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

use std::pin::Pin;

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
pub use args::Cmd;

use crate::rpc::ApiClient;

pub async fn dispatch(
    cmd: Cmd,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Reprovision(reprov) => cmds::reprovision(api_client, reprov).await,
        Cmd::AgentUpgradePolicy(args::AgentUpgrade { set }) => {
            cmds::agent_upgrade_policy(api_client, set).await
        }
        Cmd::Versions(options) => {
            cmds::versions(output_file, format, api_client, options, page_size).await
        }
        Cmd::Status => cmds::status(output_file, format, api_client, page_size).await,
        Cmd::Network(cmd) => cmds::network(api_client, output_file, cmd, format).await,
    }
}
