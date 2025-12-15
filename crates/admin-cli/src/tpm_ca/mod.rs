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

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Cmd;

use crate::rpc::ApiClient;

// dispatch routes tpm-ca commands.
pub async fn dispatch(cmd: &Cmd, api_client: &ApiClient) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Show => cmds::show(api_client).await,
        Cmd::Delete(delete_opts) => cmds::delete(delete_opts.ca_id, api_client).await,
        Cmd::Add(add_opts) => cmds::add_filename(&add_opts.filename, api_client).await,
        Cmd::AddBulk(add_opts) => cmds::add_bulk(&add_opts.dirname, api_client).await,
        Cmd::ShowUnmatchedEk => cmds::show_unmatched_ek(api_client).await,
    }
}
