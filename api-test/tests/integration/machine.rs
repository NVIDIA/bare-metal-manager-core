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

const MAX_RETRY: usize = 30; // Equal to 30s wait time

/// Waits for a Machine to reach a certain target state
/// If the Machine does not reach the state within 30s, the function will fail.
pub fn wait_for_state(addr: SocketAddr, machine_id: &str, target_state: &str) -> eyre::Result<()> {
    let data = serde_json::json!({
        "id": {"id": machine_id},
        "search_config": {"include_dpus": true}
    });
    tracing::info!("Waiting for Machine {machine_id} state {target_state}");
    let mut i = 0;
    while i < MAX_RETRY {
        let response = grpcurl(addr, "FindMachines", Some(&data))?;
        let resp: serde_json::Value = serde_json::from_str(&response)?;
        let state = resp["machines"][0]["state"].as_str().unwrap();
        if state.contains(target_state) {
            break;
        }
        tracing::info!("\tCurrent: {state}");
        thread::sleep(time::Duration::from_secs(1));
        i += 1;
    }
    if i == MAX_RETRY {
        eyre::bail!(
            "Even after {MAX_RETRY} retries, {machine_id} did not reach state {target_state}"
        );
    }

    Ok(())
}

pub fn get_firmware_version(api_addr: SocketAddr, machine_id: &str) -> eyre::Result<String> {
    let data = serde_json::json!({
        "id": {"id": machine_id},
        "search_config": {"include_dpus": true}
    });
    let response = grpcurl(api_addr, "FindMachines", Some(&data))?;
    let resp: serde_json::Value = serde_json::from_str(&response)?;

    let firmware_version = resp["machines"][0]["discoveryInfo"]["dpuInfo"]["firmwareVersion"]
        .as_str()
        .unwrap()
        .to_owned();
    Ok(firmware_version)
}

pub fn cleanup_completed(addr: SocketAddr, machine_id: &str) -> eyre::Result<()> {
    let data = serde_json::json!({
        "machine_id": {"id": machine_id},
        "result": 0,
    });
    let _ = grpcurl(addr, "CleanupMachineCompleted", Some(data))?;
    Ok(())
}

pub fn machine_validation_completed(addr: SocketAddr, host_machine_id: &str) -> eyre::Result<()> {
    grpcurl(
        addr,
        "MachineValidationCompleted",
        Some(&serde_json::json!({
            "machine_id": {"id": host_machine_id}
        })),
    )?;
    Ok(())
}
