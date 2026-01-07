/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

// dispatch routes dpu_remediation commands.
pub async fn dispatch(
    cmd: Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
    output: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    page_size: usize,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Create(args) => cmds::create_dpu_remediation(args, api_client).await?,
        Cmd::Approve(args) => cmds::approve_dpu_remediation(args, api_client).await?,
        Cmd::Revoke(args) => cmds::revoke_dpu_remediation(args, api_client).await?,
        Cmd::Enable(args) => cmds::enable_dpu_remediation(args, api_client).await?,
        Cmd::Disable(args) => cmds::disable_dpu_remediation(args, api_client).await?,
        Cmd::Show(args) => cmds::handle_show(args, format, output, api_client, page_size).await?,
        Cmd::ListApplied(args) => {
            cmds::handle_list_applied(args, format, output, api_client, page_size).await?
        }
    }
    Ok(())
}
