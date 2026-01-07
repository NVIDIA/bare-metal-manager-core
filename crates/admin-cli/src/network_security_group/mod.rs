/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

// dispatch routes network_security_group commands.
pub async fn dispatch(cmd: Cmd, ctx: RuntimeContext) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Create(args) => cmds::create(args, ctx.config.format, &ctx.api_client).await,
        Cmd::Show(args) => {
            cmds::show(
                args,
                ctx.config.format,
                &ctx.api_client,
                ctx.config.page_size,
                ctx.config.extended,
            )
            .await
        }
        Cmd::Update(args) => cmds::update(args, ctx.config.format, &ctx.api_client).await,
        Cmd::Delete(args) => cmds::delete(args, &ctx.api_client).await,
        Cmd::ShowAttachments(args) => {
            cmds::show_attachments(args, ctx.config.format, &ctx.api_client).await
        }
        Cmd::Attach(args) => cmds::attach(args, &ctx.api_client).await,
        Cmd::Detach(args) => cmds::detach(args, &ctx.api_client).await,
    }
}
