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

// dispatch routes vpc_peering commands.
pub async fn dispatch(
    cmd: &Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Create(data) => cmds::create(data, format, api_client).await,
        Cmd::Show(query) => cmds::show(query, format, api_client).await,
        Cmd::Delete(query) => cmds::delete(query, format, api_client).await,
    }
}
