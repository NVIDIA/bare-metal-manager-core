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

const MAX_RETRY: usize = 10;

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
    grpcurl(addr, "UpdateBMCMetaData", &data)?;
    tracing::info!("Created HOST Machine with ID {host_machine_id}. Starting discovery.");

    grpcurl(
        addr,
        "DiscoveryCompleted",
        &serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })
        .to_string(),
    )?;

    tracing::info!("Waiting for lockdown to complete.");
    // should exceed ServiceConfig.dpu_wait_time
    thread::sleep(time::Duration::from_secs(2));
    tracing::info!("Lockdown wait is over.");

    Ok(host_machine_id)
}

pub fn wait_for_state(
    addr: SocketAddr,
    host_machine_id: &str,
    target_state: &str,
) -> eyre::Result<()> {
    let data = serde_json::json!({
        "id": {"id": host_machine_id},
        "search_config": {"include_dpus": true}
    });
    tracing::info!("Waiting for Host state {target_state}");
    let mut i = 0;
    while i < MAX_RETRY {
        let response = grpcurl(addr, "FindMachines", &data.to_string())?;
        let resp: serde_json::Value = serde_json::from_str(&response)?;
        let state = resp["machines"][0]["state"].as_str().unwrap();
        if state.contains(target_state) {
            break;
        }
        tracing::debug!("\tCurrent: {state}");
        thread::sleep(time::Duration::from_secs(4));
        i += 1;
    }
    if i == MAX_RETRY {
        eyre::bail!("Even after {MAX_RETRY} retries, Host did not reach state {target_state}");
    }

    Ok(())
}

fn discover_dhcp(addr: SocketAddr) -> eyre::Result<String> {
    // Find network segment's circuit id
    // There's only one network segment
    let resp = grpcurl(addr, "FindNetworkSegments", "{}")?;
    let response: serde_json::Value = serde_json::from_str(&resp)?;
    let circuit_id = &response["networkSegments"][0]["prefixes"][0]["circuitId"]
        .as_str()
        .unwrap();
    tracing::info!("Circuit ID is {circuit_id}");

    // Discover DHCP
    let data = serde_json::json!({
        "mac_address": "00:11:22:33:44:66",
        "relay_address": "172.20.0.2",
        "circuit_id": circuit_id,
    });
    let resp = grpcurl(addr, "DiscoverDhcp", &data.to_string())?;
    let response: serde_json::Value = serde_json::from_str(&resp)?;
    let machine_interface_id = &response["machineInterfaceId"]["value"].as_str().unwrap();
    Ok(machine_interface_id.to_string())
}

fn discover_machine(addr: SocketAddr, machine_interface_id: &str) -> eyre::Result<String> {
    let data = include_str!("../../../dev/docker-env/host_machine_discovery.json")
        .replace("$MACHINE_INTERFACE_ID", machine_interface_id);
    let resp = grpcurl(addr, "DiscoverMachine", &data)?;
    let response: serde_json::Value = serde_json::from_str(&resp)?;
    let host_machine_id = response["machineId"]["id"].as_str().unwrap();
    grpcurl(
        addr,
        "ForgeAgentControl",
        &serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })
        .to_string(),
    )?;

    Ok(host_machine_id.to_string())
}
