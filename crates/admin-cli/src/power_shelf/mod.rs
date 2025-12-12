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

// dispatch routes power_shelf commands.
pub async fn dispatch(
    cmd: &Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
) -> color_eyre::Result<()> {
    match cmd {
        Cmd::Show(show_opts) => Ok(cmds::handle_show(show_opts, format, api_client).await?),
        Cmd::List => cmds::list_power_shelves(api_client).await,
    }
}
