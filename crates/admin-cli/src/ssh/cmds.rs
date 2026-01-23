/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
