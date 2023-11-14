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

use std::{net::SocketAddr, thread, time};

use crate::grpcurl::grpcurl;

const BMC_METADATA: &str = r#"{
  "machine_id": {
    "id": "$HOST_MACHINE_ID"
  },
  "bmc_info": {
    "ip": "localhost:1266"
  },
  "data": [
    {
      "user": "forge_admin",
      "password": "notforprod",
      "role": 1
    }
  ],
  "request_type": 1
}"#;

pub fn bootstrap(addr: SocketAddr) -> eyre::Result<String> {
    let machine_interface_id = discover_dhcp(addr)?;
    tracing::info!("Using Machine Interface with ID {machine_interface_id}");

    let host_machine_id = discover_machine(addr, &machine_interface_id)?;
    let data = BMC_METADATA.replace("$HOST_MACHINE_ID", &host_machine_id);
    grpcurl(addr, "UpdateBMCMetaData", Some(data))?;
    tracing::info!("Created HOST Machine with ID {host_machine_id}. Starting discovery.");

    grpcurl(
        addr,
        "DiscoveryCompleted",
        Some(&serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })),
    )?;

    tracing::info!("Waiting for lockdown to complete.");
    // should exceed ServiceConfig.dpu_wait_time
    thread::sleep(time::Duration::from_secs(2));
    tracing::info!("Lockdown wait is over.");

    Ok(host_machine_id)
}

fn discover_dhcp(addr: SocketAddr) -> eyre::Result<String> {
    // Find the admin network segment's circuit id
    let resp = grpcurl::<&str>(addr, "FindNetworkSegments", None)?;
    let response: serde_json::Value = serde_json::from_str(&resp)?;
    let mut circuit_id = None;
    for segment in response["networkSegments"].as_array().unwrap() {
        if segment["segmentType"] == "ADMIN" {
            circuit_id = Some(segment["prefixes"][0]["circuitId"].as_str().unwrap());
            break;
        }
    }
    let circuit_id = circuit_id.unwrap();
    tracing::info!("Circuit ID is {circuit_id}");

    // Discover DHCP
    let data = serde_json::json!({
        "mac_address": "00:11:22:33:44:66",
        "relay_address": "172.20.0.2",
        "circuit_id": circuit_id,
    });
    let resp = grpcurl(addr, "DiscoverDhcp", Some(data))?;
    let response: serde_json::Value = serde_json::from_str(&resp)?;
    let machine_interface_id = &response["machineInterfaceId"]["value"].as_str().unwrap();
    Ok(machine_interface_id.to_string())
}

pub fn discover_machine(addr: SocketAddr, machine_interface_id: &str) -> eyre::Result<String> {
    let data = include_str!("../../../dev/docker-env/host_machine_discovery.json")
        .replace("$MACHINE_INTERFACE_ID", machine_interface_id);
    let resp = grpcurl(addr, "DiscoverMachine", Some(data))?;
    let response: serde_json::Value = serde_json::from_str(&resp)?;
    let host_machine_id = response["machineId"]["id"].as_str().unwrap();
    grpcurl(
        addr,
        "ForgeAgentControl",
        Some(&serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })),
    )?;

    Ok(host_machine_id.to_string())
}
