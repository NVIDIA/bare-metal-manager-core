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
