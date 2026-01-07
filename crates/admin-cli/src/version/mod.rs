/*
 * SPDX-FileCopyrightText: Copyright (c) 2023-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
// Export so the CLI builder can just pull in version::Opts.
// This is different than others that pull in Cmd, since
// this is just a single top-level command without any
// subcommands.
pub use args::Opts;

use crate::cfg::runtime::RuntimeContext;

// dispatch routes version commands.
pub async fn dispatch(opts: Opts, ctx: RuntimeContext) -> CarbideCliResult<()> {
    // No match here since version just has a single
    // command it does, but still maintain the pattern
    // of having a dispatcher.
    cmds::handle_show_version(&opts, &ctx.api_client, ctx.config.format).await
}
