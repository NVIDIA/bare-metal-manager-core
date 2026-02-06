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
use crate::{debug_bundle, firmware};

impl Dispatch for Cmd {
    async fn dispatch(self, mut ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Show(args) => {
                cmds::show(
                    &mut ctx.output_file,
                    args,
                    ctx.config.format,
                    &ctx.api_client,
                    ctx.config.page_size,
                    ctx.config.sort_by,
                )
                .await?
            }
            Cmd::Maintenance(action) => cmds::maintenance(&ctx.api_client, action).await?,
            Cmd::Quarantine(action) => cmds::quarantine(&ctx.api_client, action).await?,
            Cmd::ResetHostReprovisioning(args) => {
                cmds::reset_host_reprovisioning(&ctx.api_client, args).await?
            }
            Cmd::PowerOptions(options) => match options {
                args::PowerOptions::Show(args) => {
                    cmds::power_options_show(args, ctx.config.format, &ctx.api_client).await?
                }
                args::PowerOptions::Update(args) => {
                    cmds::update_power_option(args, &ctx.api_client).await?
                }
                args::PowerOptions::GetMachineIngestionState(mac_address) => {
                    cmds::get_machine_state(&ctx.api_client, &mac_address.mac_address).await?
                }
                args::PowerOptions::AllowIngestionAndPowerOn(mac_address) => {
                    cmds::allow_ingestion_and_power_on(&ctx.api_client, &mac_address.mac_address)
                        .await?
                }
            },
            Cmd::StartUpdates(options) => {
                firmware::cmds::start_updates(&ctx.api_client, options).await?
            }
            Cmd::DebugBundle(args) => {
                debug_bundle::handle_debug_bundle(args, &ctx.api_client).await?
            }
            Cmd::SetPrimaryDpu(args) => cmds::set_primary_dpu(&ctx.api_client, args).await?,
        }
        Ok(())
    }
}
