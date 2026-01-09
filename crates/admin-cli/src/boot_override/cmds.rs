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

use std::path::PathBuf;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge::MachineBootOverride;

use super::args::{BootOverride, BootOverrideSet};
use crate::rpc::ApiClient;

pub async fn get(args: BootOverride, api_client: &ApiClient) -> CarbideCliResult<()> {
    let mbo = api_client
        .0
        .get_machine_boot_override(args.interface_id)
        .await?;

    tracing::info!(
        "{}",
        serde_json::to_string_pretty(&mbo).expect("Failed to serialize MachineBootOverride")
    );
    Ok(())
}

pub async fn set(args: BootOverrideSet, api_client: &ApiClient) -> CarbideCliResult<()> {
    if args.custom_pxe.is_none() && args.custom_user_data.is_none() {
        return Err(CarbideCliError::GenericError(
            "Either custom pxe or custom user data is required".to_owned(),
        ));
    }

    let custom_pxe_path = args.custom_pxe.map(PathBuf::from);
    let custom_user_data_path = args.custom_user_data.map(PathBuf::from);

    let custom_pxe = match &custom_pxe_path {
        Some(path) => Some(std::fs::read_to_string(path)?),
        None => None,
    };

    let custom_user_data = match &custom_user_data_path {
        Some(path) => Some(std::fs::read_to_string(path)?),
        None => None,
    };

    api_client
        .0
        .set_machine_boot_override(MachineBootOverride {
            machine_interface_id: Some(args.interface_id),
            custom_pxe,
            custom_user_data,
        })
        .await?;
    Ok(())
}

pub async fn clear(args: BootOverride, api_client: &ApiClient) -> CarbideCliResult<()> {
    api_client
        .0
        .clear_machine_boot_override(args.interface_id)
        .await?;
    Ok(())
}
