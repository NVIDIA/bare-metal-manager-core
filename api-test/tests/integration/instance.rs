/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::net::SocketAddr;

use super::{grpcurl::grpcurl, machine::wait_for_state};

pub fn _create(addr: SocketAddr, host_machine_id: &str, segment_id: &str) -> eyre::Result<()> {
    tracing::info!(
        "Creating instance with machine: {host_machine_id}, with network segment: {segment_id}"
    );
    let data = serde_json::json!({
        "machine_id": {"id": host_machine_id},
        "config": {
            "tenant": {
                "tenant_organization_id": "MyOrg",
                "user_data": "hello",
                "custom_ipxe": "chain --autofree https://boot.netboot.xyz"
            },
            "network": {
                "interfaces": [{
                    "function_type": "PHYSICAL",
                    "network_segment_id": {"value": segment_id}
                }]
            }
        }
    });
    let resp = grpcurl(addr, "AllocateInstance", Some(data))?;
    tracing::info!("AllocateInstance:");
    tracing::info!(resp);

    wait_for_state(addr, host_machine_id, "Assigned/WaitingForNetworkConfig")?;
    // TODO network config

    //tracing::info!("Instance created with ID {instance_id}");
    Ok(())
}
