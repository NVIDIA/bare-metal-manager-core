/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
pub use args::Cmd;

use crate::rpc::ApiClient;

// dispatch routes network_segment commands.
pub async fn dispatch(
    cmd: Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
    cloud_unsafe_op_enabled: bool,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Show(args) => cmds::handle_show(args, format, api_client, page_size).await,
        Cmd::Delete(args) => {
            if !cloud_unsafe_op_enabled {
                return Err(CarbideCliError::GenericError(
                    "Operation not allowed due to potential inconsistencies with cloud database."
                        .to_owned(),
                ));
            }
            api_client.delete_network_segment(args.id).await?;
            Ok(())
        }
    }
}
