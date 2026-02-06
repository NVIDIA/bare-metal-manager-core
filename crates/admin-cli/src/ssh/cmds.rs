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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use forge_ssh::ssh::{
    copy_bfb_to_bmc_rshim, disable_rshim, enable_rshim, is_rshim_enabled, read_obmc_console_log,
};

use super::args::{CopyBfbArgs, SshArgs};

pub async fn get_rshim_status(args: SshArgs) -> CarbideCliResult<()> {
    let is_rshim_enabled = is_rshim_enabled(
        args.credentials.bmc_ip_address,
        args.credentials.bmc_username,
        args.credentials.bmc_password,
    )
    .await
    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
    tracing::info!("{is_rshim_enabled}");
    Ok(())
}

pub async fn disable_rshim_cmd(args: SshArgs) -> CarbideCliResult<()> {
    disable_rshim(
        args.credentials.bmc_ip_address,
        args.credentials.bmc_username,
        args.credentials.bmc_password,
    )
    .await
    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
    Ok(())
}

pub async fn enable_rshim_cmd(args: SshArgs) -> CarbideCliResult<()> {
    enable_rshim(
        args.credentials.bmc_ip_address,
        args.credentials.bmc_username,
        args.credentials.bmc_password,
    )
    .await
    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
    Ok(())
}

pub async fn copy_bfb(args: CopyBfbArgs) -> CarbideCliResult<()> {
    copy_bfb_to_bmc_rshim(
        args.ssh_args.credentials.bmc_ip_address,
        args.ssh_args.credentials.bmc_username,
        args.ssh_args.credentials.bmc_password,
        args.bfb_path,
    )
    .await
    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
    Ok(())
}

pub async fn show_obmc_log(args: SshArgs) -> CarbideCliResult<()> {
    let log = read_obmc_console_log(
        args.credentials.bmc_ip_address,
        args.credentials.bmc_username,
        args.credentials.bmc_password,
    )
    .await
    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;

    println!("OBMC Console Log:\n{log}");
    Ok(())
}
