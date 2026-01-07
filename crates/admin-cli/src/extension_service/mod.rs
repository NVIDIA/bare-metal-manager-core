/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

// dispatch routes extension_service commands.
pub async fn dispatch(
    cmd: Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Create(args) => cmds::handle_create(args, format, api_client).await,
        Cmd::Update(args) => cmds::handle_update(args, format, api_client).await,
        Cmd::Delete(args) => cmds::handle_delete(args, format, api_client).await,
        Cmd::Show(args) => cmds::handle_show(args, format, api_client, page_size).await,
        Cmd::GetVersion(args) => cmds::handle_get_version(args, api_client).await,
        Cmd::ShowInstances(args) => cmds::handle_show_instances(args, format, api_client).await,
    }
}
