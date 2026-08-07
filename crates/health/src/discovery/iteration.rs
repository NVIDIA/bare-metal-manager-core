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

use futures::{StreamExt, stream};

use super::DiscoveryIterationStats;
use super::cleanup::{
    stop_ineligible_nmxc_collectors, stop_removed_bmc_collectors, stop_stale_switch_collectors,
};
use super::context::{CollectorKind, DiscoveryLoopContext};
use super::identity::ensure_primary_system_uuid;
use super::reachability::reconcile_reachability_collectors;
use super::spawn::{spawn_collectors_for_endpoint, switch_supports_nmxc_subscription};
use crate::HealthError;
use crate::config::Configurable;
use crate::endpoint::{BmcEndpoint, EndpointSource};
use crate::sharding::ShardManager;
use crate::sink::DataSink;

fn active_keys(sharded_endpoints: &[Arc<BmcEndpoint>]) -> HashSet<Cow<'static, str>> {
    sharded_endpoints
        .iter()
        .map(|endpoint| Cow::Owned(endpoint.key()))
        .collect()
}

/// Returns active endpoint keys that remain eligible for NMX-C Subscribe collection.
fn nmxc_subscription_keys(sharded_endpoints: &[Arc<BmcEndpoint>]) -> HashSet<Cow<'static, str>> {
    sharded_endpoints
        .iter()
        .filter(|endpoint| switch_supports_nmxc_subscription(endpoint))
        .map(|endpoint| Cow::Owned(endpoint.key()))
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
        .filter(|ep| shard_manager.should_monitor(ep))
        .cloned()
        .collect();

    // Resolve machine identity before collectors start when possible. Shared
    // write-once state propagates the result to running collectors and caches
    // both present and absent UUIDs, preventing repeated successful BMC queries.
    let identity_concurrency = ctx.discovery_config.discovery_concurrency.max(1);
    stream::iter(sharded_endpoints.iter().cloned())
        .map(|endpoint| async move {
            if let Err(error) = ensure_primary_system_uuid(&endpoint).await {
                tracing::warn!(
                    ?error,
                    bmc_address = ?endpoint.addr,
                    "Could not resolve primary ComputerSystem UUID; continuing without it"
                );
            }
        })
        .buffer_unordered(identity_concurrency)
        .collect::<Vec<()>>()
        .await;

    if sharded_endpoints.is_empty() {
        tracing::warn!("No endpoints assigned to this shard");
    } else {
        tracing::info!(
            endpoint_count = sharded_endpoints.len(),
            "Discovered and sharded BMC endpoints"
        );
    }

    // prune before respawn so downgraded auto-mode endpoints get replaced
    ctx.collectors.prune_finished_logs();

    // A domain change keeps the same endpoint key and collector type. Complete
    // old collector cleanup before respawn so a late CollectorRemoved cannot
    // unregister the replacement's metrics.
    stop_stale_switch_collectors(ctx, &sharded_endpoints).await;

    for endpoint in &sharded_endpoints {
        spawn_collectors_for_endpoint(ctx, endpoint, data_sink.clone(), metrics_prefix)?;
    }

    reconcile_reachability_collectors(ctx, &sharded_endpoints, data_sink.clone(), metrics_prefix)
        .await?;

    if matches!(&ctx.nmxc_config, Configurable::Enabled(_)) {
        // Endpoints can remain active while Carbide API changes primary or
        // NMX-C desired-state flags. Reconcile existing streams against the
        // same target policy used for spawn before generic removed-endpoint
        // cleanup runs.
        let nmxc_eligible_endpoints = nmxc_subscription_keys(&sharded_endpoints);
        stop_ineligible_nmxc_collectors(ctx, &nmxc_eligible_endpoints);
    } else {
        // If config disables NMX-C after streams already started, no endpoint
        // remains eligible even though the endpoint keys may still be active.
        stop_ineligible_nmxc_collectors(ctx, &HashSet::new());
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

    use carbide_uuid::rack::RackId;
    use mac_address::MacAddress;

    use super::*;
    use crate::config::{Config, Configurable, NmxtCollectorConfig, ReachabilityCollectorConfig};
    use crate::endpoint::test_support::endpoint_with_creds;
    use crate::endpoint::{
        BmcAddr, BmcCredentials, EndpointMetadata, StaticEndpointSource, SwitchData,
        SwitchEndpointRole,
    };
    use crate::limiter::NoopLimiter;
    use crate::metrics::MetricsManager;

    /// Builds a generic endpoint fixture for discovery iteration tests.
    fn endpoint(mac: MacAddress, switch: bool, rack_id: Option<RackId>) -> Arc<BmcEndpoint> {
        let metadata = switch.then(|| {
            EndpointMetadata::Switch(SwitchData {
                id: None,
                serial: format!("serial-{mac}"),
                slot_number: None,
                tray_index: None,
                nvlink_domain_uuid: None,
                endpoint_role: SwitchEndpointRole::Host,
                is_primary: false,
                nmxc_enabled: false,
                nmxt_enabled: false,
            })
        });
        Arc::new(endpoint_with_creds(
            BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: Some(443),
                mac,
            },
            BmcCredentials::UsernamePassword {
                username: "user".to_string(),
                password: Some("pass".to_string()),
            },
            metadata,
            rack_id,
        ))
    }

    /// Builds a switch-host endpoint with primary and NMX-C desired-state flags.
    fn switch_endpoint(mac: MacAddress, is_primary: bool, nmxc_enabled: bool) -> Arc<BmcEndpoint> {
        switch_endpoint_with_role(mac, SwitchEndpointRole::Host, is_primary, nmxc_enabled)
    }

    /// Builds a switch endpoint with an explicit endpoint role.
    fn switch_endpoint_with_role(
        mac: MacAddress,
        endpoint_role: SwitchEndpointRole,
        is_primary: bool,
        nmxc_enabled: bool,
    ) -> Arc<BmcEndpoint> {
        Arc::new(endpoint_with_creds(
            BmcAddr {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: Some(443),
                mac,
            },
            BmcCredentials::UsernamePassword {
                username: "user".to_string(),
                password: Some("pass".to_string()),
            },
            Some(EndpointMetadata::Switch(SwitchData {
                id: None,
                serial: format!("serial-{mac}"),
                slot_number: None,
                tray_index: None,
                nvlink_domain_uuid: None,
                endpoint_role,
                is_primary,
                nmxc_enabled,
                nmxt_enabled: false,
            })),
            None,
        ))
    }

    #[tokio::test]
    async fn test_active_keys_includes_all_endpoints() {
        let ep1 = endpoint(
            MacAddress::from_str("42:9e:b1:bd:9d:dd").unwrap(),
            false,
            Some(RackId::new("rack-a")),
        );
        let ep2 = endpoint(
            MacAddress::from_str("11:22:33:44:55:66").unwrap(),
            true,
            None,
        );

        let keys = active_keys(&[ep1.clone(), ep2.clone()]);

        assert_eq!(
            keys,
            HashSet::from([Cow::Owned(ep1.key()), Cow::Owned(ep2.key())])
        );
        assert_ne!(ep1.hash_key(), Cow::<str>::Owned(ep1.key()));
    }

    #[tokio::test]
    /// Verifies NMX-C eligibility cleanup keys include only primary enabled switch hosts.
    async fn test_nmxc_subscription_keys_only_include_primary_enabled_switch_hosts() {
        let primary_enabled = switch_endpoint(
            MacAddress::from_str("00:00:00:00:00:11").unwrap(),
            true,
            true,
        );

        let secondary_enabled = switch_endpoint(
            MacAddress::from_str("00:00:00:00:00:12").unwrap(),
            false,
            true,
        );

        let primary_disabled = switch_endpoint(
            MacAddress::from_str("00:00:00:00:00:13").unwrap(),
            true,
            false,
        );

        let primary_bmc_enabled = switch_endpoint_with_role(
            MacAddress::from_str("00:00:00:00:00:14").unwrap(),
            SwitchEndpointRole::Bmc,
            true,
            true,
        );

        let non_switch = endpoint(
            MacAddress::from_str("00:00:00:00:00:15").unwrap(),
            false,
            None,
        );

        let expected_key = Cow::Owned(primary_enabled.key());

        let keys = nmxc_subscription_keys(&[
            primary_enabled,
            secondary_enabled,
            primary_disabled,
            primary_bmc_enabled,
            non_switch,
        ]);

        assert_eq!(keys, HashSet::from([expected_key]));
    }

    #[tokio::test]
    async fn reachability_does_not_change_duplicate_endpoint_spawning() {
        let mac = MacAddress::from_str("00:00:00:00:00:21").unwrap();
        let first = switch_endpoint(mac, false, false);
        let mut duplicate = first.as_ref().clone();

        let Some(EndpointMetadata::Switch(switch)) = duplicate.metadata.as_mut() else {
            panic!("test endpoint should contain switch metadata");
        };

        switch.nmxt_enabled = true;

        let source: Arc<dyn EndpointSource> = Arc::new(StaticEndpointSource::new(vec![
            first.as_ref().clone(),
            duplicate,
        ]));

        let mut config = Config::default();
        config.endpoint_sources.carbide_api = Configurable::Disabled;
        config.collectors.sensors = Configurable::Disabled;
        config.collectors.leak_detector = Configurable::Disabled;
        config.collectors.nmxt = Configurable::Enabled(NmxtCollectorConfig::default());
        config.collectors.reachability =
            Configurable::Enabled(ReachabilityCollectorConfig::default());

        let metrics_manager = Arc::new(
            MetricsManager::new("duplicate_keys_with_reachability")
                .expect("metrics manager should start"),
        );

        let mut ctx =
            DiscoveryLoopContext::new(Arc::new(NoopLimiter), metrics_manager, Arc::new(config))
                .expect("discovery context should start");

        let stats = run_discovery_iteration(
            source,
            &ShardManager {
                shard: 0,
                shards_count: 1,
            },
            &mut ctx,
            None,
            "test",
        )
        .await
        .expect("discovery iteration should succeed");

        assert_eq!(stats.discovered_endpoints, 2);
        assert_eq!(stats.sharded_endpoints, 2);
        assert!(ctx.collectors.contains(CollectorKind::Nmxt, &first.key()));

        let collector = ctx
            .collectors
            .map_mut(CollectorKind::Nmxt)
            .remove(first.key().as_str())
            .expect("NMX-T collector should have started");

        collector.stop().await;
    }
}
