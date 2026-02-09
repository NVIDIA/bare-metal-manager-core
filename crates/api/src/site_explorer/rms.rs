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

use carbide_uuid::rack::RackId;
use mac_address::MacAddress;
use rpc::protos::rack_manager::NewNodeInfo;

use crate::CarbideError;
use crate::rack::rms_client::{RmsApi, RmsNodeType};

// Helper function to add a node to the Rack Manager
pub async fn add_node_to_rms(
    rms_client: &dyn RmsApi,
    rack_id: RackId,
    node_id: String,
    ip_address: String,
    port: i32,
    mac_address: MacAddress,
    node_type: RmsNodeType,
) -> Result<(), CarbideError> {
    let new_node_info = NewNodeInfo {
        rack_id: rack_id.to_string(),
        node_id,
        mac_address: mac_address.to_string(),
        ip_address,
        port,
        username: None,
        password: None,
        r#type: Some(node_type.into()),
    };

    rms_client
        .add_node(vec![new_node_info])
        .await
        .map_err(CarbideError::RackManagerError)?;

    Ok(())
}
