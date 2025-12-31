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

use std::pin::Pin;

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
pub use args::Cmd;
pub use cmds::show_discovered_managed_host as show_site_explorer_discovered_managed_host;

use crate::rpc::ApiClient;

pub async fn dispatch(
    cmd: Cmd,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::GetReport(mode) => {
            cmds::show_discovered_managed_host(api_client, output_file, format, page_size, mode)
                .await
        }
        Cmd::Explore(opts) => cmds::explore(api_client, &opts.address, opts.mac).await,
        Cmd::ReExplore(opts) => cmds::re_explore(api_client, opts).await,
        Cmd::ClearError(opts) => cmds::clear_error(api_client, opts.address).await,
        Cmd::Delete(opts) => cmds::delete_endpoint(api_client, opts).await,
        Cmd::Remediation(opts) => cmds::remediation(api_client, opts).await,
        Cmd::IsBmcInManagedHost(opts) => {
            cmds::is_bmc_in_managed_host(api_client, &opts.address, opts.mac).await
        }
        Cmd::HaveCredentials(opts) => {
            cmds::have_credentials(api_client, &opts.address, opts.mac).await
        }
        Cmd::CopyBfbToDpuRshim(args) => cmds::copy_bfb_to_dpu_rshim(api_client, args).await,
    }
}
