/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::cfg::cli_options::SortField;
use crate::rpc::ApiClient;
use crate::{debug_bundle, firmware};

pub async fn dispatch(
    cmd: Cmd,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
    sort_by: SortField,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Show(args) => {
            cmds::show(output_file, args, format, api_client, page_size, sort_by).await
        }
        Cmd::Maintenance(action) => cmds::maintenance(api_client, action).await,
        Cmd::Quarantine(action) => cmds::quarantine(api_client, action).await,
        Cmd::ResetHostReprovisioning(args) => {
            cmds::reset_host_reprovisioning(api_client, args).await
        }
        Cmd::PowerOptions(options) => match options {
            args::PowerOptions::Show(args) => {
                cmds::power_options_show(args, format, api_client).await
            }
            args::PowerOptions::Update(args) => cmds::update_power_option(args, api_client).await,
        },
        Cmd::StartUpdates(options) => {
            firmware::cmds::start_updates(api_client, options)
                .await
                .map_err(|e| ::rpc::admin_cli::CarbideCliError::GenericError(e.to_string()))?;
            Ok(())
        }
        Cmd::DebugBundle(args) => debug_bundle::handle_debug_bundle(args, api_client).await,
        Cmd::SetPrimaryDpu(args) => cmds::set_primary_dpu(api_client, args).await,
    }
}
