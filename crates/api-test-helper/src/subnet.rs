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

use super::grpcurl::{grpcurl, grpcurl_id};

pub async fn create(
    carbide_api_addrs: &[SocketAddr],
    vpc_id: &str,
    domain_id: &str,
    prefix_octet: u8,
    host_inband_network: bool,
) -> eyre::Result<String> {
    tracing::info!("Creating network segment");

    let data = serde_json::json!({
        "vpc_id": { "value": vpc_id },
        "name": "tenant1",
        "subdomain_id": { "value": domain_id },
        "segment_type": if host_inband_network { "HOST_INBAND" } else { "TENANT" },
        "prefixes": [{"prefix":format!("10.10.{prefix_octet}.0/24"), "gateway": format!("10.10.{prefix_octet}.1"), "reserve_first": 10}]
    });
    let segment_id =
        grpcurl_id(carbide_api_addrs, "CreateNetworkSegment", &data.to_string()).await?;
    tracing::info!("Network Segment created with ID {segment_id}");

    wait_for_network_segment_state(carbide_api_addrs, &segment_id, "READY").await?;

    tracing::info!("Network Segment with ID {segment_id} is ready");
    Ok(segment_id)
}

// Waits for a network segment to reach a certain state
pub async fn wait_for_network_segment_state(
    addrs: &[SocketAddr],
    segment_id: &str,
    target_state: &str,
) -> eyre::Result<()> {
    const MAX_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();

    let data = serde_json::json!({
        "network_segments_ids": [{"value": segment_id}]
    });
    let mut latest_state: String;

    tracing::info!("Waiting for Network Segment {segment_id} state {target_state}");
    while start.elapsed() < MAX_WAIT {
        let response = grpcurl(addrs, "FindNetworkSegmentsByIds", Some(&data)).await?;
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
