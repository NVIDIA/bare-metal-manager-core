/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

// dispatch routes sku commands.
pub async fn dispatch(
    cmd: Cmd,
    api_client: &ApiClient,
    output: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    format: &OutputFormat,
    extended: bool,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Show(args) => cmds::show(args, api_client, output, format, extended).await,
        Cmd::ShowMachines(args) => cmds::show_machines(args, api_client, output, format).await,
        Cmd::Generate(args) => cmds::generate(args, api_client, output, format, extended).await,
        Cmd::Create(args) => cmds::create(args, api_client, output, format).await,
        Cmd::Delete { sku_id } => cmds::delete(sku_id, api_client).await,
        Cmd::Assign {
            sku_id,
            machine_id,
            force,
        } => cmds::assign(sku_id, machine_id, force, api_client).await,
        Cmd::Unassign(args) => cmds::unassign(args, api_client).await,
        Cmd::Verify { machine_id } => cmds::verify(machine_id, api_client).await,
        Cmd::UpdateMetadata(args) => cmds::update_metadata(args, api_client).await,
        Cmd::BulkUpdateMetadata(args) => cmds::bulk_update_metadata(args, api_client).await,
        Cmd::Replace(args) => cmds::replace(args, api_client, output, format).await,
    }
}
