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

use std::sync::Arc;

use librms::RmsApi;

use crate::rms::args::{FirmwareInventory, PowerOnSequence, PowerState};

pub async fn get_all_inventory(rms_client: &Arc<dyn RmsApi>) -> eyre::Result<()> {
    let cmd = librms::protos::rack_manager::GetAllInventoryRequest::default();
    let response = rms_client.get_all_inventory(cmd).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub async fn power_on_sequence(
    args: &PowerOnSequence,
    rms_client: &Arc<dyn RmsApi>,
) -> eyre::Result<()> {
    let cmd = librms::protos::rack_manager::GetRackPowerOnSequenceRequest {
        metadata: None,
        rack_id: args.rack_id.clone(),
    };
    let response = rms_client.get_rack_power_on_sequence(cmd).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub async fn power_state(args: &PowerState, rms_client: &Arc<dyn RmsApi>) -> eyre::Result<()> {
    let cmd = librms::protos::rack_manager::GetPowerStateRequest {
        metadata: None,
        node_id: args.node_id.clone(),
        rack_id: args.rack_id.clone(),
    };
    let response = rms_client.get_power_state(cmd).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub async fn get_firmware_inventory(
    args: &FirmwareInventory,
    rms_client: &Arc<dyn RmsApi>,
) -> eyre::Result<()> {
    let cmd = librms::protos::rack_manager::GetNodeFirmwareInventoryRequest {
        metadata: None,
        node_id: args.node_id.clone(),
        rack_id: args.rack_id.clone(),
    };
    let response = rms_client.get_node_firmware_inventory(cmd).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
