/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
