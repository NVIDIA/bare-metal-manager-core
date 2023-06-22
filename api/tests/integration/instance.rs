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

use std::{thread, time};

use super::grpcurl::{grpcurl, Id};

pub fn _create(host_machine_id: &str, segment_id: &str) -> eyre::Result<()> {
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
    let resp = grpcurl("AllocateInstance", &data.to_string())?;
    tracing::info!("AllocateInstance:");
    tracing::info!(resp);

    let data = serde_json::to_string(&Id {
        id: host_machine_id.to_string(),
    })?;
    loop {
        let response = grpcurl("GetMachine", &data.to_string())?;
        let resp: serde_json::Value = serde_json::from_str(&response)?;
        let state = resp["state"].as_str().unwrap();
        if state == "Assigned/WaitingForNetworkConfig" {
            break;
        }
        tracing::info!(
            "Waiting for Host state Assigned/WaitingForNetworkConfig. Current: {state}."
        );
        thread::sleep(time::Duration::from_secs(1));
    }
    // TODO network config

    //tracing::info!("Instance created with ID {instance_id}");
    Ok(())
}
