/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use ::rpc::admin_cli::OutputFormat;
pub use args::Cmd;

use crate::rpc::ApiClient;

// dispatch routes expected_switch commands.
pub async fn dispatch(
    cmd: &Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
) -> color_eyre::Result<()> {
    match cmd {
        Cmd::Show(query) => Ok(cmds::show(query, api_client, format).await?),
        Cmd::Add(data) => cmds::add(data, api_client).await,
        Cmd::Delete(query) => Ok(cmds::delete(query, api_client).await?),
        Cmd::Update(data) => cmds::update(data, api_client).await,
        Cmd::ReplaceAll(request) => Ok(cmds::replace_all(request, api_client).await?),
        Cmd::Erase => Ok(cmds::erase(api_client).await?),
    }
}
