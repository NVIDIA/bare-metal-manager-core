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
use std::{thread, time};

use carbide_uuid::machine::MachineId;

use crate::grpcurl::grpcurl;

const MAX_RETRY: usize = 30; // Equal to 30s wait time

/// Waits for a Machine to reach a certain target state
/// If the Machine does not reach the state within 30s, the function will fail.
pub async fn wait_for_state(
    addrs: &[SocketAddr],
    machine_id: &MachineId,
    target_state: &str,
) -> eyre::Result<()> {
    let data = serde_json::json!({
        "machine_ids": [{"id": machine_id}],
    });
    tracing::info!("Waiting for Machine {machine_id} state {target_state}");
    let mut i = 0;
    while i < MAX_RETRY {
        let response = grpcurl(addrs, "FindMachinesByIds", Some(&data)).await?;
        let resp: serde_json::Value = serde_json::from_str(&response)?;
        let state = resp["machines"][0]["state"].as_str().unwrap();
        if state.contains(target_state) {
            break;
        }
        tracing::info!("\tCurrent: {state}");
        thread::sleep(time::Duration::from_millis(500));
        i += 1;
    }
    if i == MAX_RETRY {
        eyre::bail!(
            "Even after {MAX_RETRY} retries, {machine_id} did not reach state {target_state}"
        );
    }

    Ok(())
}
