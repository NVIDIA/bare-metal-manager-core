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

use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use super::DiscoveryIterationStats;
use super::cleanup::stop_removed_bmc_collectors;
use super::context::{CollectorKind, DiscoveryLoopContext};
use super::spawn::spawn_collectors_for_endpoint;
use crate::HealthError;
use crate::endpoint::{BmcEndpoint, EndpointSource};
use crate::sharding::ShardManager;
use crate::sink::DataSink;

fn active_keys(sharded_endpoints: &[Arc<BmcEndpoint>]) -> HashSet<Cow<'static, str>> {
    sharded_endpoints
        .iter()
        .map(|e| e.addr.hash_key())
        .collect()
}

pub async fn run_discovery_iteration(
    endpoint_source: Arc<dyn EndpointSource>,
    shard_manager: &ShardManager,
    ctx: &mut DiscoveryLoopContext,
    data_sink: Option<Arc<dyn DataSink>>,
    metrics_prefix: &str,
) -> Result<DiscoveryIterationStats, HealthError> {
    let iteration_start = Instant::now();

    let fetch_start = Instant::now();
    let endpoints = match endpoint_source.fetch_bmc_hosts().await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "Could not fetch endpoints");
            return Err(e);
        }
    };
    let fetch_duration = fetch_start.elapsed();

    ctx.discovery_endpoint_fetch_histogram
        .observe(fetch_duration.as_secs_f64());

    let sharded_endpoints: Vec<Arc<BmcEndpoint>> = endpoints
        .iter()
        .filter(|ep| shard_manager.should_monitor(&ep.addr))
        .cloned()
        .collect();

    if sharded_endpoints.is_empty() {
        tracing::warn!("No endpoints assigned to this shard");
    } else {
        tracing::info!(
            endpoint_count = sharded_endpoints.len(),
            "Discovered and sharded BMC endpoints"
        );
    }

    for endpoint in &sharded_endpoints {
        spawn_collectors_for_endpoint(ctx, endpoint, data_sink.clone(), metrics_prefix).await?;
    }

    let active_endpoints = active_keys(&sharded_endpoints);
    stop_removed_bmc_collectors(ctx, &active_endpoints);

    let iteration_duration = iteration_start.elapsed();
    ctx.discovery_iteration_histogram
        .observe(iteration_duration.as_secs_f64());

    Ok(DiscoveryIterationStats {
        discovered_endpoints: endpoints.len(),
        sharded_endpoints: sharded_endpoints.len(),
        active_monitors: ctx.collectors.len(CollectorKind::Sensor),
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use mac_address::MacAddress;

    use super::*;
    use crate::endpoint::{BmcAddr, BmcCredentials, EndpointMetadata, SwitchData};

    fn endpoint(mac: MacAddress, switch: bool) -> Arc<BmcEndpoint> {
        Arc::new(BmcEndpoint {
            addr: BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: Some(443),
                mac,
            },
            credentials: BmcCredentials {
                username: "user".to_string(),
                password: "pass".to_string(),
            },
            metadata: if switch {
                Some(EndpointMetadata::Switch(SwitchData {
                    serial: format!("serial-{mac}"),
                }))
            } else {
                None
            },
        })
    }

    #[test]
    fn test_active_keys_includes_all_endpoints() {
        let ep1 = endpoint(MacAddress::from_str("42:9e:b1:bd:9d:dd").unwrap(), false);
        let ep2 = endpoint(MacAddress::from_str("11:22:33:44:55:66").unwrap(), true);

        let keys = active_keys(&[ep1.clone(), ep2.clone()]);

        assert_eq!(
            keys,
            HashSet::from([ep1.addr.hash_key(), ep2.addr.hash_key()])
        );
    }
}
