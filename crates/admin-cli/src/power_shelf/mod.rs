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

pub use args::Cmd;

use crate::cfg::runtime::RuntimeContext;

// dispatch routes power_shelf commands.
pub async fn dispatch(cmd: Cmd, ctx: RuntimeContext) -> color_eyre::Result<()> {
    match cmd {
        Cmd::Show(show_opts) => {
            Ok(cmds::handle_show(&show_opts, ctx.config.format, &ctx.api_client).await?)
        }
        Cmd::List => cmds::list_power_shelves(&ctx.api_client).await,
    }
}
