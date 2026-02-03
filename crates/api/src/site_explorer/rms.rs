/*
 * SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
