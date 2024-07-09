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

use crate::grpcurl::{grpcurl, grpcurl_for};

// This is set by Site Explorer so we populate it here
const BMC_CREDENTIALS55: &str = r#"{
  "credential_type": 8,
  "username": "admin",
  "password": "notforprod",
  "mac_address": "00:11:22:33:44:55"
}"#;
const BMC_CREDENTIALS66: &str = r#"{
  "credential_type": 8,
  "username": "admin",
  "password": "notforprod",
  "mac_address": "00:11:22:33:44:66"
}"#;

const BMC_METADATA: &str = r#"{
  "machine_id": {
    "id": "$HOST_MACHINE_ID"
  },
  "bmc_info": {
    "ip": "127.0.0.1",
    "port": 1266
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

const UEFI_CREDENTIALS: &str = r#"{
  "credential_type": 4,
  "password": "notforprod"
}"#;

pub fn bootstrap(addr: SocketAddr) -> eyre::Result<String> {
    let (machine_interface_id, ip_address) = discover_dhcp(addr)?;
    tracing::info!("Using Machine Interface ID {machine_interface_id} on address {ip_address}");

    let host_machine_id = discover_machine(addr, &ip_address)?;
    let data = BMC_METADATA.replace("$HOST_MACHINE_ID", &host_machine_id);
    grpcurl(addr, "UpdateBMCMetaData", Some(data))?;
    grpcurl(addr, "CreateCredential", Some(UEFI_CREDENTIALS))?;
    grpcurl(addr, "CreateCredential", Some(BMC_CREDENTIALS55))?;
    grpcurl(addr, "CreateCredential", Some(BMC_CREDENTIALS66))?;
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

fn discover_dhcp(addr: SocketAddr) -> eyre::Result<(String, String)> {
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
    let address = &response["address"].as_str().unwrap();
    Ok((machine_interface_id.to_string(), address.to_string()))
}

pub fn discover_machine(addr: SocketAddr, ip_address: &str) -> eyre::Result<String> {
    let data = include_str!("../../../dev/docker-env/host_machine_discovery.json").to_string();
    let resp = grpcurl_for(addr, "DiscoverMachine", Some(data), Some(ip_address))?;
    let response: serde_json::Value = serde_json::from_str(&resp)?;
    let host_machine_id = response["machineId"]["id"].as_str().unwrap();
    grpcurl(
        addr,
        "ForgeAgentControl",
        Some(&serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })),
    )?;
    grpcurl(
        addr,
        "RebootCompleted",
        Some(&serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })),
    )?;
    Ok(host_machine_id.to_string())
}

pub fn machine_validation_completed(
    addr: SocketAddr,
    host_machine_id: &str,
) -> eyre::Result<String> {
    let resp = grpcurl(
        addr,
        "ForgeAgentControl",
        Some(&serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })),
    )?;
    let response: serde_json::Value = serde_json::from_str(&resp)?;

    grpcurl(
        addr,
        "MachineValidationCompleted",
        Some(&serde_json::json!({
            "machine_id": {"id": host_machine_id},
            "validation_id": {"value": response["data"]["pair"][1]["value"]}
        })),
    )?;
    Ok(host_machine_id.to_string())
}
