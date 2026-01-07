/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

/// dispatch routes instance_type commands.
pub async fn dispatch(
    cmd: Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
    verbose: bool,
    cloud_unsafe_operation_allowed: bool,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Create(args) => cmds::create(args, format, api_client).await,
        Cmd::Show(args) => cmds::show(args, format, api_client, page_size, verbose).await,
        Cmd::Update(args) => cmds::update(args, format, api_client).await,
        Cmd::Delete(args) => cmds::delete(args, api_client).await,
        Cmd::Associate(args) => cmds::create_association(args, api_client).await,
        Cmd::Disassociate(args) => {
            cmds::remove_association(args, cloud_unsafe_operation_allowed, api_client).await
        }
    }
}
