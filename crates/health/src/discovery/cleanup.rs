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

use std::collections::HashSet;

use super::context::{CollectorKind, DiscoveryLoopContext};

pub(super) fn stop_removed_bmc_collectors(
    ctx: &mut DiscoveryLoopContext,
    active_endpoints: &HashSet<&str>,
) {
    let removed_collectors = ctx.collectors.remove_inactive_collectors(active_endpoints);
    let removed_count = removed_collectors.len();
    for (kind, key, collector) in removed_collectors {
        tracing::info!(
            endpoint_key = %key,
            "{}",
            kind.stop_message()
        );
        tokio::spawn(async move {
            collector.stop().await;
        });
    }

    if removed_count != 0 {
        tracing::info!(
            removed_count,
            remaining_sensors = ctx.collectors.len(CollectorKind::Sensor),
            remaining_collectors = ctx.collectors.len(CollectorKind::Logs),
            remaining_firmware_collectors = ctx.collectors.len(CollectorKind::Firmware),
            remaining_nmxt_collectors = ctx.collectors.len(CollectorKind::Nmxt),
            remaining_nvue_rest_collectors = ctx.collectors.len(CollectorKind::NvueRest),
            "Cleaned up removed endpoints"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

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
        maps.insert(CollectorKind::Nmxt, HashMap::new());
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
}
