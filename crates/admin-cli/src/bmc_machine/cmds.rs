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
use ::rpc::forge as forgerpc;

use super::args::{
    AdminPowerControlAction, AdminPowerControlArgs, BmcResetArgs, CreateBmcUserArgs,
    DeleteBmcUserArgs, InfiniteBootArgs, LockdownArgs, LockdownStatusArgs,
};
use crate::rpc::ApiClient;

pub async fn bmc_reset(args: BmcResetArgs, api_client: &ApiClient) -> CarbideCliResult<()> {
    api_client
        .bmc_reset(None, Some(args.machine), args.use_ipmitool)
        .await?;
    Ok(())
}

pub async fn admin_power_control(
    args: AdminPowerControlArgs,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client
        .admin_power_control(None, Some(args.machine), args.action.into())
        .await?;
    Ok(())
}

pub async fn create_bmc_user(
    args: CreateBmcUserArgs,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client
        .create_bmc_user(
            args.ip_address,
            args.mac_address,
            args.machine,
            args.username,
            args.password,
            args.role_id,
        )
        .await?;
    Ok(())
}

pub async fn delete_bmc_user(
    args: DeleteBmcUserArgs,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    api_client
        .delete_bmc_user(
            args.ip_address,
            args.mac_address,
            args.machine,
            args.username,
        )
        .await?;
    Ok(())
}

pub async fn enable_infinite_boot(
    args: InfiniteBootArgs,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let machine = args.machine;
    api_client
        .enable_infinite_boot(None, Some(machine.clone()))
        .await?;
    if args.reboot {
        api_client
            .admin_power_control(
                None,
                Some(machine),
                AdminPowerControlAction::ForceRestart.into(),
            )
            .await?;
    }
    Ok(())
}

pub async fn is_infinite_boot_enabled(
    args: InfiniteBootArgs,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let response = api_client
        .is_infinite_boot_enabled(None, Some(args.machine))
        .await?;
    match response.is_enabled {
        Some(true) => println!("Enabled"),
        Some(false) => println!("Disabled"),
        None => println!("Unknown"),
    }
    Ok(())
}

pub async fn lockdown(args: LockdownArgs, api_client: &ApiClient) -> CarbideCliResult<()> {
    let machine = args.machine;
    let action = if args.enable {
        forgerpc::LockdownAction::Enable
    } else if args.disable {
        forgerpc::LockdownAction::Disable
    } else {
        return Err(CarbideCliError::GenericError(
            "Either --enable or --disable must be specified".to_string(),
        ));
    };

    api_client.lockdown(None, machine, action).await?;

    let action_str = if args.enable { "enabled" } else { "disabled" };

    if args.reboot {
        api_client
            .admin_power_control(
                None,
                Some(machine.to_string()),
                AdminPowerControlAction::ForceRestart.into(),
            )
            .await?;
        println!(
            "Lockdown {} and reboot initiated to apply the change.",
            action_str
        );
    } else {
        println!(
            "Lockdown {}. Please reboot the machine to apply the change.",
            action_str
        );
    }
    Ok(())
}

pub async fn lockdown_status(
    args: LockdownStatusArgs,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let response = api_client.lockdown_status(None, args.machine).await?;
    // Convert status enum to string
    let status_str = match response.status {
        0 => "Enabled",  // InternalLockdownStatus::ENABLED
        1 => "Partial",  // InternalLockdownStatus::PARTIAL
        2 => "Disabled", // InternalLockdownStatus::DISABLED
        _ => "Unknown",
    };
    println!("{}: {}", status_str, response.message);
    Ok(())
}
