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

use crate::cfg::runtime::RuntimeContext;

// dispatch routes vpc_peering commands.
pub async fn dispatch(cmd: Cmd, ctx: RuntimeContext) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Create(data) => cmds::create(&data, ctx.config.format, &ctx.api_client).await,
        Cmd::Show(query) => cmds::show(&query, ctx.config.format, &ctx.api_client).await,
        Cmd::Delete(query) => cmds::delete(&query, ctx.config.format, &ctx.api_client).await,
    }
}
