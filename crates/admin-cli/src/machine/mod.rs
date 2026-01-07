/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use std::pin::Pin;

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
pub use args::Cmd;
// TODO(chet): There was some cross-talk of sorts between
// commands in here, so I'm re-exporting some things here
// temporarily, and I'll either clean up the cross-talk,
// or just make the call-sites import ::args and ::cmds
// as needed.
pub use args::{
    ForceDeleteMachineQuery, HealthOverrideTemplates, MachineAutoupdate, MachineQuery,
    NetworkCommand, ShowMachine,
};
pub use cmds::{get_health_report, get_next_free_machine, handle_show};

use crate::cfg::cli_options::SortField;
use crate::rpc::ApiClient;

pub async fn dispatch(
    cmd: Cmd,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    format: OutputFormat,
    page_size: usize,
    sort_by: &SortField,
    extended: bool,
) -> CarbideCliResult<()> {
    match cmd {
        Cmd::Show(args) => {
            cmds::handle_show(args, &format, output_file, api_client, page_size, sort_by).await
        }
        Cmd::DpuSshCredentials(query) => cmds::dpu_ssh_credentials(api_client, query, format).await,
        Cmd::Network(cmd) => cmds::network(api_client, cmd, format, output_file).await,
        Cmd::HealthOverride(cmd) => cmds::handle_override(cmd, format, api_client).await,
        Cmd::Reboot(args) => cmds::reboot(api_client, args).await,
        Cmd::ForceDelete(query) => cmds::force_delete(query, api_client).await,
        Cmd::AutoUpdate(cfg) => cmds::autoupdate(cfg, api_client).await,
        Cmd::Metadata(cmd) => cmds::metadata(api_client, cmd, output_file, format, extended).await,
        Cmd::HardwareInfo(cmd) => match cmd {
            args::MachineHardwareInfoCommand::Show(show_cmd) => {
                cmds::handle_show_machine_hardware_info(
                    api_client,
                    output_file,
                    &format,
                    show_cmd.machine,
                )
            }
            args::MachineHardwareInfoCommand::Update(capability) => match capability {
                args::MachineHardwareInfo::Gpus(gpus) => {
                    cmds::handle_update_machine_hardware_info_gpus(api_client, gpus).await
                }
            },
        },
        Cmd::Positions(args) => cmds::positions(args, api_client).await,
    }
}
