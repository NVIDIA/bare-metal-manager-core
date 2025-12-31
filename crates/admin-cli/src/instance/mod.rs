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

use crate::cfg::cli_options::SortField;
use crate::rpc::ApiClient;

pub async fn dispatch(
    cmd: Cmd,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
    sort_by: &SortField,
    cloud_unsafe_op: Option<String>,
) -> CarbideCliResult<()> {
    let opts = args::GlobalOptions {
        format,
        page_size,
        sort_by,
        cloud_unsafe_op,
    };

    match cmd {
        Cmd::Show(args) => {
            cmds::handle_show(
                args,
                output_file,
                &opts.format,
                api_client,
                opts.page_size,
                opts.sort_by,
            )
            .await
        }
        Cmd::Reboot(args) => cmds::handle_reboot(args, api_client).await,
        Cmd::Release(args) => cmds::release(api_client, args, &opts).await,
        Cmd::Allocate(args) => cmds::allocate(api_client, args, &opts).await,
        Cmd::UpdateOS(args) => cmds::update_os(api_client, args, &opts).await,
        Cmd::UpdateIbConfig(args) => cmds::update_ib_config(api_client, args, &opts).await,
    }
}
