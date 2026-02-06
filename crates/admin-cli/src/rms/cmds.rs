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

use super::args::{
    AddNode, AvailableFwImages, FirmwareInventory, PowerState, PoweronOrder, RemoveNode,
};
use crate::rack;
use crate::rpc::RmsApiClient;

pub async fn inventory(api_client: &RmsApiClient) -> CarbideCliResult<()> {
    rack::cmds::get_inventory(api_client)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

pub async fn add_node(args: AddNode, api_client: &RmsApiClient) -> CarbideCliResult<()> {
    rack::cmds::add_node(api_client, args)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

pub async fn remove_node(args: RemoveNode, api_client: &RmsApiClient) -> CarbideCliResult<()> {
    rack::cmds::remove_node(api_client, args)
        .await
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

pub async fn poweron_order(args: PoweronOrder, api_client: &RmsApiClient) -> CarbideCliResult<()> {
    let response = api_client.get_poweron_order(args.rack_id).await?;
    println!("{}", response);
    Ok(())
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
