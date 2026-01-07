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

// dispatch routes network_security_group commands.
pub async fn dispatch(
    cmd: Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
    verbose: bool,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Create(args) => cmds::create(args, format, api_client).await,
        Cmd::Show(args) => cmds::show(args, format, api_client, page_size, verbose).await,
        Cmd::Update(args) => cmds::update(args, format, api_client).await,
        Cmd::Delete(args) => cmds::delete(args, api_client).await,
        Cmd::ShowAttachments(args) => cmds::show_attachments(args, format, api_client).await,
        Cmd::Attach(args) => cmds::attach(args, api_client).await,
        Cmd::Detach(args) => cmds::detach(args, api_client).await,
    }
}
