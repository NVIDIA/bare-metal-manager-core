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
// TODO(chet): There was some cross-talk of sorts between
// commands in here, so I'm re-exporting some things here
// temporarily, and I'll either clean up the cross-talk,
// or just make the call-sites import ::args and ::cmds
// as needed.
pub use args::{
    HealthOverrideTemplates, MachineAutoupdate, MachineQuery, NetworkCommand, ShowMachine,
};
pub use cmds::{get_health_report, get_next_free_machine, handle_show};

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;

impl Dispatch for Cmd {
    async fn dispatch(self, mut ctx: RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Cmd::Show(args) => {
                cmds::handle_show(
                    args,
                    &ctx.config.format,
                    &mut ctx.output_file,
                    &ctx.api_client,
                    ctx.config.page_size,
                    &ctx.config.sort_by,
                )
                .await?
            }
            Cmd::DpuSshCredentials(query) => {
                cmds::dpu_ssh_credentials(&ctx.api_client, query, ctx.config.format).await?
            }
            Cmd::Network(cmd) => {
                cmds::network(
                    &ctx.api_client,
                    cmd,
                    ctx.config.format,
                    &mut ctx.output_file,
                )
                .await?
            }
            Cmd::HealthOverride(cmd) => {
                cmds::handle_override(cmd, ctx.config.format, &ctx.api_client).await?
            }
            Cmd::Reboot(args) => cmds::reboot(&ctx.api_client, args).await?,
            Cmd::ForceDelete(query) => cmds::force_delete(query, &ctx.api_client).await?,
            Cmd::AutoUpdate(cfg) => cmds::autoupdate(cfg, &ctx.api_client).await?,
            Cmd::Metadata(cmd) => {
                cmds::metadata(
                    &ctx.api_client,
                    cmd,
                    &mut ctx.output_file,
                    ctx.config.format,
                    ctx.config.extended,
                )
                .await?
            }
            Cmd::HardwareInfo(cmd) => match cmd {
                args::MachineHardwareInfoCommand::Show(show_cmd) => {
                    cmds::handle_show_machine_hardware_info(
                        &ctx.api_client,
                        &mut ctx.output_file,
                        &ctx.config.format,
                        show_cmd.machine,
                    )?
                }
                args::MachineHardwareInfoCommand::Update(capability) => match capability {
                    args::MachineHardwareInfo::Gpus(gpus) => {
                        cmds::handle_update_machine_hardware_info_gpus(&ctx.api_client, gpus)
                            .await?
                    }
                },
            },
            Cmd::Positions(args) => cmds::positions(args, &ctx.api_client).await?,
            Cmd::NvlinkInfo(cmd) => match cmd {
                args::NvlinkInfoCommand::Show(args) => {
                    cmds::handle_nvlink_info_show(args, &ctx.api_client).await?
                }
                args::NvlinkInfoCommand::Populate(args) => {
                    cmds::handle_nvlink_info_populate(args, ctx.config.format, &ctx.api_client)
                        .await?
                }
            },
        }
        Ok(())
    }
}
