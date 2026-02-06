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
use std::collections::HashMap;

use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::MachineId;
use carbide_uuid::network::NetworkSegmentId;
use model::instance::config::network::{
    InstanceInterfaceConfig, InstanceNetworkConfig, InterfaceFunctionId,
};
use model::machine::Machine;
use model::network_segment::NetworkSegmentType;
use sqlx::PgConnection;

use crate::DatabaseResult;
/// Allocate IP's for this network config, filling the InstanceInterfaceConfigs with the newly
/// allocated IP's.
pub async fn with_allocated_ips(
    value: InstanceNetworkConfig,
    txn: &mut PgConnection,
    instance_id: InstanceId,
    machine: &Machine,
) -> DatabaseResult<InstanceNetworkConfig> {
    crate::instance_address::allocate(txn, instance_id, value, machine).await
}

/// Find any host_inband segments on the given machine, and replicate them into this instance
/// network config. This is because allocation requests do not need to explicitly enumerate
/// a host's in-band (non-dpu) network segments: they cannot be configured through carbide.
pub async fn with_inband_interfaces_from_machine(
    value: InstanceNetworkConfig,
    txn: &mut PgConnection,
    machine_id: &::carbide_uuid::machine::MachineId,
) -> DatabaseResult<InstanceNetworkConfig> {
    let inband_segments_map = crate::network_segment::batch_find_ids_by_machine_ids(
        txn,
        &[*machine_id],
        Some(NetworkSegmentType::HostInband),
    )
    .await?;

    let host_inband_segment_ids = inband_segments_map
        .get(machine_id)
        .cloned()
        .unwrap_or_default();

    Ok(add_inband_interfaces_to_config(
        value,
        &host_inband_segment_ids,
    ))
}

/// Batch find host_inband segments for multiple machines and return a map.
/// This allows efficient batch processing in batch_allocate_instances.
pub async fn batch_get_inband_segments_by_machine_ids(
    txn: &mut PgConnection,
    machine_ids: &[MachineId],
) -> DatabaseResult<HashMap<MachineId, Vec<NetworkSegmentId>>> {
    crate::network_segment::batch_find_ids_by_machine_ids(
        txn,
        machine_ids,
        Some(NetworkSegmentType::HostInband),
    )
    .await
}

/// Add inband interfaces to a network config based on segment IDs.
/// This is a pure function that can be used after batch querying.
pub fn add_inband_interfaces_to_config(
    mut value: InstanceNetworkConfig,
    host_inband_segment_ids: &[NetworkSegmentId],
) -> InstanceNetworkConfig {
    for host_inband_segment_id in host_inband_segment_ids {
        // Only add it to the instance config if there isn't already an interface in this segment
        if !value
            .interfaces
            .iter()
            .any(|i| i.network_segment_id == Some(*host_inband_segment_id))
        {
            value.interfaces.push(InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                network_segment_id: Some(*host_inband_segment_id),
                network_details: None,
                ip_addrs: Default::default(),
                interface_prefixes: Default::default(),
                network_segment_gateways: Default::default(),
                host_inband_mac_address: None,
                device_locator: None,
                internal_uuid: uuid::Uuid::new_v4(),
            })
        }
    }

    value
}
