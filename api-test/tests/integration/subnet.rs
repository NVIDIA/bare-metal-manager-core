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

use super::grpcurl::{grpcurl, grpcurl_id};

pub fn create(carbide_api_addr: SocketAddr, vpc_id: &str) -> eyre::Result<String> {
    tracing::info!("Creating network segment");

    let data = serde_json::json!({
        "vpc_id": { "value": vpc_id },
        "name": "tenant1",
        "segment_type": "TENANT",
        "prefixes": [{"prefix":"10.10.10.0/24", "gateway": "10.10.10.1", "reserve_first": 10}]
    });
    let segment_id = grpcurl_id(carbide_api_addr, "CreateNetworkSegment", &data.to_string())?;
    tracing::info!("Network Segment created with ID {segment_id}");

    wait_for_network_segment_state(carbide_api_addr, &segment_id, "READY")?;

    tracing::info!("Network Segment with ID {segment_id} is ready");
    Ok(segment_id)
}

// Waits for a network segment to reach a certain state
pub fn wait_for_network_segment_state(
    addr: SocketAddr,
    segment_id: &str,
    target_state: &str,
) -> eyre::Result<()> {
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();

    let data = serde_json::json!({
        "id": {"value": segment_id}
    });
    let mut latest_state: String;

    tracing::info!("Waiting for Network Segment {segment_id} state {target_state}");
    while start.elapsed() < MAX_WAIT {
        let response = grpcurl(addr, "FindNetworkSegments", Some(&data))?;
        let resp: serde_json::Value = serde_json::from_str(&response)?;
        latest_state = resp["networkSegments"][0]["state"]
            .as_str()
            .unwrap()
            .to_string();
        if latest_state.contains(target_state) {
            return Ok(());
        }
        tracing::info!("\tCurrent network segment state: {latest_state}");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    eyre::bail!("Even after {MAX_RETRY} retries, {segment_id} did not reach state {target_state}");
}

const MAX_RETRY: usize = 30; // Equal to 30s wait time
