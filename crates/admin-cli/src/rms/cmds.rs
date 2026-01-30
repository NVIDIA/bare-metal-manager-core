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

use super::args::{AvailableFwImages, FirmwareInventory, PowerState, RemoveNode};
use crate::rack;
use crate::rpc::RmsApiClient;

pub async fn inventory(api_client: &RmsApiClient) -> CarbideCliResult<()> {
    rack::cmds::get_inventory(api_client)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

pub async fn remove_node(args: RemoveNode, api_client: &RmsApiClient) -> CarbideCliResult<()> {
    rack::cmds::remove_node(api_client, args)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

pub async fn poweron_order(api_client: &RmsApiClient) -> CarbideCliResult<()> {
    rack::cmds::get_poweron_order(api_client)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

pub async fn power_state(args: PowerState, api_client: &RmsApiClient) -> CarbideCliResult<()> {
    rack::cmds::get_power_state(api_client, args)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

pub async fn firmware_inventory(
    args: FirmwareInventory,
    api_client: &RmsApiClient,
) -> CarbideCliResult<()> {
    rack::cmds::get_firmware_inventory(api_client, args)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

pub async fn available_fw_images(
    args: AvailableFwImages,
    api_client: &RmsApiClient,
) -> CarbideCliResult<()> {
    rack::cmds::get_available_fw_images(api_client, args)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

pub async fn bkc_files(api_client: &RmsApiClient) -> CarbideCliResult<()> {
    rack::cmds::get_bkc_files(api_client)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

pub async fn check_bkc_compliance(api_client: &RmsApiClient) -> CarbideCliResult<()> {
    rack::cmds::check_bkc_compliance(api_client)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}
