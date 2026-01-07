/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

pub use args::Cmd;

use crate::cfg::runtime::RuntimeContext;

// dispatch routes rack commands.
pub async fn dispatch(cmd: Cmd, ctx: RuntimeContext) -> color_eyre::Result<()> {
    match cmd {
        Cmd::Show(show_opts) => cmds::show_rack(&ctx.api_client, &show_opts).await,
        Cmd::List => cmds::list_racks(&ctx.api_client).await,
        Cmd::Delete(delete_opts) => cmds::delete_rack(&ctx.api_client, &delete_opts).await,
    }
}
