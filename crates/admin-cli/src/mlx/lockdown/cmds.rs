/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// lockdown/cmds.rs
// Command handlers for lockdown operations.

use mlxconfig_lockdown::StatusReport;
use rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use rpc::protos::mlx_device as mlx_device_pb;

use super::args::{
    LockdownCommand, LockdownLockCommand, LockdownStatusCommand, LockdownUnlockCommand,
};
use crate::mlx::CliContext;

// dispatch routes lockdown subcommands to their handlers.
pub async fn dispatch(
    command: LockdownCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    match command {
        LockdownCommand::Lock(cmd) => handle_lock(cmd, ctxt).await,
        LockdownCommand::Unlock(cmd) => handle_unlock(cmd, ctxt).await,
        LockdownCommand::Status(cmd) => handle_status(cmd, ctxt).await,
    }
}

// handle_lock locks a device on a machine.
async fn handle_lock(
    cmd: LockdownLockCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let request: mlx_device_pb::MlxAdminLockdownLockRequest = cmd.into();
    let response = ctxt.grpc_conn.0.mlx_admin_lockdown_lock(request).await?;

    let status_report_pb = response
        .status_report
        .ok_or_else(|| CarbideCliError::GenericError("no status report returned".to_string()))?;

    print_lockdown_response(status_report_pb.into(), ctxt.format)?;
    Ok(())
}

// handle_unlock unlocks a device on a machine.
async fn handle_unlock(
    cmd: LockdownUnlockCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let request: mlx_device_pb::MlxAdminLockdownUnlockRequest = cmd.into();
    let response = ctxt.grpc_conn.0.mlx_admin_lockdown_unlock(request).await?;

    let status_report_pb = response
        .status_report
        .ok_or_else(|| CarbideCliError::GenericError("no status report returned".to_string()))?;

    print_lockdown_response(status_report_pb.into(), ctxt.format)?;
    Ok(())
}

// handle_status gets the lock status of a device on a machine.
async fn handle_status(
    cmd: LockdownStatusCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let request: mlx_device_pb::MlxAdminLockdownStatusRequest = cmd.into();
    let response = ctxt.grpc_conn.0.mlx_admin_lockdown_status(request).await?;

    let status_report_pb = response
        .status_report
        .ok_or_else(|| CarbideCliError::GenericError("no status report returned".to_string()))?;

    print_lockdown_response(status_report_pb.into(), ctxt.format)?;
    Ok(())
}

// print_lockdown_response prints the lockdown response in the specified format.
fn print_lockdown_response(
    status_report: StatusReport,
    format: &OutputFormat,
) -> CarbideCliResult<()> {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&status_report)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(&status_report)?);
        }
        OutputFormat::AsciiTable => {
            println!(
                "Device {}: {}",
                status_report.device_id, status_report.status
            );
        }
        OutputFormat::Csv => {
            println!("{},{}", status_report.device_id, status_report.status);
        }
    }
    Ok(())
}
