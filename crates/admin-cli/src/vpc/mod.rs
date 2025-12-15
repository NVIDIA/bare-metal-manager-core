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

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
pub use args::Cmd;

use crate::rpc::ApiClient;

// dispatch routes vpc commands.
pub async fn dispatch(
    cmd: Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Show(args) => cmds::show(args, format, api_client, page_size).await,
        Cmd::SetVirtualizer(args) => cmds::set_network_virtualization_type(api_client, args).await,
    }
}
