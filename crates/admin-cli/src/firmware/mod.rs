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

use std::pin::Pin;

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
pub use args::Cmd;

use crate::rpc::ApiClient;

// dispatch routes firmware commands.
pub async fn dispatch(
    cmd: &Cmd,
    api_client: &ApiClient,
    format: OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Show(args) => cmds::show(args, format, output_file, api_client).await,
    }
}
