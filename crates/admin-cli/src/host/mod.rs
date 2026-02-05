/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#[cfg(test)]
mod tests;

use ::rpc::admin_cli::CarbideCliResult;
pub use args::Cmd;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::SetUefiPassword(query) => cmds::set_uefi_password(query, &ctx.api_client).await,
            Cmd::ClearUefiPassword(query) => {
                cmds::clear_uefi_password(query, &ctx.api_client).await
            }
            Cmd::GenerateHostUefiPassword => cmds::generate_uefi_password(),
            Cmd::Reprovision(reprovision) => match reprovision {
                args::HostReprovision::Set(data) => {
                    cmds::trigger_reprovisioning(
                        data.id,
                        ::rpc::forge::host_reprovisioning_request::Mode::Set,
                        &ctx.api_client,
                        data.update_message,
                    )
                    .await
                }
                args::HostReprovision::Clear(data) => {
                    cmds::trigger_reprovisioning(
                        data.id,
                        ::rpc::forge::host_reprovisioning_request::Mode::Clear,
                        &ctx.api_client,
                        None,
                    )
                    .await
                }
                args::HostReprovision::List => cmds::list_hosts_pending(&ctx.api_client).await,
                args::HostReprovision::MarkManualUpgradeComplete(data) => {
                    cmds::mark_manual_firmware_upgrade_complete(data.id, &ctx.api_client).await
                }
            },
        }
    }
}
