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

use super::context::{CollectorKind, DiscoveryLoopContext};

#[derive(Clone, Copy)]
enum CollectorStopReason {
    EndpointRemoved,
    SwitchEndpointNoLongerEligible,
}

impl std::fmt::Display for CollectorStopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::EndpointRemoved => "endpoint removed",
            Self::SwitchEndpointNoLongerEligible => "switch endpoint is no longer eligible",
        })
    }
}

fn stop_collectors_for_keys(
    ctx: &mut DiscoveryLoopContext,
    kind: CollectorKind,
    removed_keys: &HashSet<Cow<'static, str>>,
    stop_reason: CollectorStopReason,
) {
    let collectors = ctx.collectors.map_mut(kind);
    for key in removed_keys {
        if let Some(collector) = collectors.remove(key) {
            tracing::info!(
                endpoint_key = %key,
                collector_kind = ?kind,
                %stop_reason,
                remaining_collector_count = collectors.len(),
                "Stopping collector"
            );
            tokio::spawn(async move {
                collector.stop().await;
            });
        }
    }
}

pub(super) fn stop_removed_bmc_collectors(
    ctx: &mut DiscoveryLoopContext,
    active_endpoints: &HashSet<Cow<'static, str>>,
) {
    let removed_keys = ctx.collectors.removed_keys(active_endpoints);

    for kind in CollectorKind::ALL {
        stop_collectors_for_keys(
            ctx,
            kind,
            &removed_keys,
            CollectorStopReason::EndpointRemoved,
        );
    }

    for key in &removed_keys {
        ctx.collectors.remove_inventory(key);
    }

    if !removed_keys.is_empty() {
        tracing::info!(
            removed_endpoint_count = removed_keys.len(),
            remaining_sensor_collector_count = ctx.collectors.len(CollectorKind::Sensor),
            remaining_log_collector_count = ctx.collectors.len(CollectorKind::Logs),
            remaining_firmware_collector_count = ctx.collectors.len(CollectorKind::Firmware),
            remaining_leak_detector_collector_count =
                ctx.collectors.len(CollectorKind::LeakDetector),
            remaining_nmxt_collector_count = ctx.collectors.len(CollectorKind::Nmxt),
            remaining_nmxc_collector_count = ctx.collectors.len(CollectorKind::Nmxc),
            remaining_nvue_rest_collector_count = ctx.collectors.len(CollectorKind::NvueRest),
            "Cleaned up removed endpoints"
        );
    }
}

/// Stops NMX-C streams for endpoints that still exist but are no longer eligible.
///
/// Generic removed-endpoint cleanup only sees keys that disappear. NMX-C can
/// become invalid while the same key remains active, for example when primary
/// switch-host assignment or `nmxc_enabled` changes in discovery metadata.
pub(super) fn stop_ineligible_nmxc_collectors(
    ctx: &mut DiscoveryLoopContext,
    eligible_endpoints: &HashSet<Cow<'static, str>>,
) {
    let ineligible_keys: HashSet<Cow<'static, str>> = ctx
        .collectors
        .map_mut(CollectorKind::Nmxc)
        .keys()
        .filter(|key| !eligible_endpoints.contains(*key))
        .cloned()
        .collect();

    stop_collectors_for_keys(
        ctx,
        CollectorKind::Nmxc,
        &ineligible_keys,
        CollectorStopReason::SwitchEndpointNoLongerEligible,
    );

    if !ineligible_keys.is_empty() {
        tracing::info!(
            ineligible_endpoint_count = ineligible_keys.len(),
            remaining_nmxc_collector_count = ctx.collectors.len(CollectorKind::Nmxc),
            "Cleaned up ineligible NMX-C endpoints"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::*;
    use crate::collectors::Collector;
    use crate::config::Config;
    use crate::limiter::{NoopLimiter, RateLimiter};
    use crate::metrics::MetricsManager;

    fn context(metrics_name: &str) -> DiscoveryLoopContext {
        let limiter: Arc<dyn RateLimiter> = Arc::new(NoopLimiter);
        let metrics_manager =
            Arc::new(MetricsManager::new(metrics_name).expect("metrics manager should initialize"));

        DiscoveryLoopContext::new(limiter, metrics_manager, Arc::new(Config::default()))
            .expect("context should initialize")
    }

    fn noop_collector() -> Collector {
        Collector::spawn_task(|_| async {})
    }

    #[test]
    fn test_removed_keys_union_logic() {
        let mut maps = HashMap::new();
        maps.insert(
            CollectorKind::Sensor,
            HashMap::from([("a".to_string(), 1), ("b".to_string(), 2)]),
        );
        maps.insert(
            CollectorKind::Logs,
            HashMap::from([("b".to_string(), 3), ("c".to_string(), 4)]),
        );
        maps.insert(CollectorKind::Firmware, HashMap::new());
        maps.insert(CollectorKind::LeakDetector, HashMap::new());
        maps.insert(CollectorKind::Nmxt, HashMap::new());
        maps.insert(CollectorKind::Nmxc, HashMap::new());
        maps.insert(CollectorKind::NvueRest, HashMap::new());

        let active = HashSet::from(["b".to_string()]);

        let removed: HashSet<String> = maps
            .values()
            .flat_map(|map| map.keys())
            .filter(|key| !active.contains(*key))
            .cloned()
            .collect();

        assert_eq!(removed, HashSet::from(["a".to_string(), "c".to_string()]));
    }

    #[tokio::test]
    async fn test_stop_ineligible_nmxc_collectors_only_removes_nmxc_entries() {
        let mut ctx = context("test_stop_ineligible_nmxc_collectors");

        ctx.collectors.insert(
            CollectorKind::Nmxc,
            Cow::Borrowed("eligible-switch"),
            noop_collector(),
        );

        ctx.collectors.insert(
            CollectorKind::Nmxc,
            Cow::Borrowed("ineligible-switch"),
            noop_collector(),
        );

        ctx.collectors.insert(
            CollectorKind::Nmxt,
            Cow::Borrowed("ineligible-switch"),
            noop_collector(),
        );

        let eligible_endpoints = HashSet::from([Cow::Borrowed("eligible-switch")]);

        stop_ineligible_nmxc_collectors(&mut ctx, &eligible_endpoints);

        assert!(
            ctx.collectors
                .contains(CollectorKind::Nmxc, "eligible-switch")
        );

        assert!(
            !ctx.collectors
                .contains(CollectorKind::Nmxc, "ineligible-switch")
        );

        assert!(
            ctx.collectors
                .contains(CollectorKind::Nmxt, "ineligible-switch")
        );
    }
}
