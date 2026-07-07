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

//! Measures the Prometheus series cardinality that one agent's network-health
//! metrics produce for a fleet of peers. Every DPU agent probes every other
//! DPU in the fleet, so any label that scales with the peer set multiplies
//! into fleet-wide series counts of O(N^2). The network-health metrics are
//! therefore per-source rollups: their cardinality must stay constant no
//! matter how many peers the agent probes, which is what this test asserts.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
use opentelemetry::metrics::MeterProvider;
use opentelemetry_prometheus::ExporterBuilder;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::{Encoder, Registry, TextEncoder};

use crate::instrumentation::NetworkMonitorMetricsState;
use crate::instrumentation::config::{
    create_network_latency_view, create_network_loss_view, create_retry_histogram_view,
};
use crate::network_monitor::NetworkMonitorError;

/// Peers probed by the simulated agent.
const PEER_COUNT: usize = 50;
/// How many of those peers fail their reachability check.
const UNREACHABLE_PEER_COUNT: usize = 10;
/// How many peers hit a communication error.
const COMMUNICATION_ERROR_PEER_COUNT: usize = 5;

/// Bucket series per histogram label set, from the production views in
/// `instrumentation::config` (explicit boundaries plus the `+Inf` bucket).
const LATENCY_BUCKETS_PER_SERIES: usize = 14 + 1;
const LOSS_BUCKETS_PER_SERIES: usize = 5 + 1;

/// Cardinality this same simulation produced before the per-source rollup,
/// when every network metric was labeled (source_dpu_id, dest_dpu_id).
/// Recorded 2026-07-06 by running this test against that implementation:
///
///   forge_dpu_agent_network_reachable:                50 label sets,  50 exposition series
///   forge_dpu_agent_network_latency_milliseconds:     50 label sets, 850 exposition series
///   forge_dpu_agent_network_loss_percentage:          50 label sets, 400 exposition series
///   forge_dpu_agent_network_communication_error_total: 5 label sets,   5 exposition series
///
/// One label set per probed peer, so one agent's export scaled with fleet
/// size, and the fleet-wide total scaled with N * (N - 1).
const PER_PAIR_EXPOSITION_SERIES_TOTAL: usize = 1305;

/// Builds a distinct, valid DPU MachineId from a small tag.
fn dpu_machine_id(tag: u8) -> MachineId {
    let mut hardware_hash = [0u8; 32];
    hardware_hash[0] = tag;
    MachineId::new(MachineIdSource::Tpm, hardware_hash, MachineType::Dpu)
}

/// Builds the meter the same way `InstrumentationSingleton::try_init_for_dpu_agent`
/// does: a Prometheus exporter without scope/target info and the production
/// metric views, backed by a test-local registry.
fn production_style_meter() -> (Registry, SdkMeterProvider) {
    let registry = Registry::new();
    let exporter = ExporterBuilder::default()
        .with_registry(registry.clone())
        .without_scope_info()
        .without_target_info()
        .build()
        .expect("Could not build Prometheus exporter");

    let provider = SdkMeterProvider::builder()
        .with_reader(exporter)
        .with_view(create_retry_histogram_view().expect("retry view must build"))
        .with_view(create_network_latency_view().expect("latency view must build"))
        .with_view(create_network_loss_view().expect("loss view must build"))
        .build();

    (registry, provider)
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FamilyCardinality {
    /// Distinct label sets in the metric family.
    label_sets: usize,
    /// Series as Prometheus stores them after a scrape: one per exposition
    /// line, so a histogram label set expands to bucket lines + `_sum` +
    /// `_count`.
    exposition_series: usize,
}

/// Counts, per metric family, the label sets and the exposition lines the
/// registry currently exports.
fn family_cardinality(registry: &Registry) -> BTreeMap<String, FamilyCardinality> {
    let families = registry.gather();

    let mut result: BTreeMap<String, FamilyCardinality> = families
        .iter()
        .map(|family| {
            (
                family.name().to_string(),
                FamilyCardinality {
                    label_sets: family.get_metric().len(),
                    exposition_series: 0,
                },
            )
        })
        .collect();

    for line in exposition_text(registry).lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let metric_name = line
            .split(['{', ' '])
            .next()
            .expect("metric line must start with a name");
        // Map histogram sub-series back to their family name.
        let family_name = [metric_name, metric_name]
            .into_iter()
            .chain(
                ["_bucket", "_sum", "_count"]
                    .iter()
                    .filter_map(|suffix| metric_name.strip_suffix(suffix)),
            )
            .find(|candidate| result.contains_key(*candidate));
        if let Some(family_name) = family_name {
            result
                .get_mut(family_name)
                .expect("family name was just found in the map")
                .exposition_series += 1;
        }
    }

    result
}

fn exposition_text(registry: &Registry) -> String {
    let mut buffer = vec![];
    TextEncoder::new()
        .encode(&registry.gather(), &mut buffer)
        .unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Returns the value of the single exposition line for `metric_name`,
/// asserting there is exactly one such line.
fn single_series_value(registry: &Registry, metric_name: &str) -> f64 {
    let text = exposition_text(registry);
    let values: Vec<f64> = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter(|line| {
            line.split(['{', ' '])
                .next()
                .expect("line must have a name")
                == metric_name
        })
        .map(|line| {
            line.rsplit(' ')
                .next()
                .expect("metric line must end in a value")
                .parse()
                .expect("metric value must parse as f64")
        })
        .collect();
    assert_eq!(
        values.len(),
        1,
        "expected exactly one series for {metric_name}, found {}",
        values.len()
    );
    values[0]
}

/// Runs one agent's worth of network-monitor metric traffic against a
/// production-style meter and returns the resulting per-family cardinality.
fn simulate_one_agent_cycle(
    registry: &Registry,
    provider: &SdkMeterProvider,
) -> BTreeMap<String, FamilyCardinality> {
    let source = dpu_machine_id(0);
    let peers: Vec<MachineId> = (1..=PEER_COUNT).map(|i| dpu_machine_id(i as u8)).collect();

    let meter = provider.meter("forge-dpu-agent");
    let state = NetworkMonitorMetricsState::initialize(meter, source);

    // One monitoring cycle: a reachability result for every peer...
    let reachable_map: HashMap<MachineId, bool> = peers
        .iter()
        .enumerate()
        .map(|(idx, peer)| (*peer, idx >= UNREACHABLE_PEER_COUNT))
        .collect();
    state.update_network_reachable_map(reachable_map);

    // ...a latency and loss sample for every peer...
    for idx in 0..PEER_COUNT {
        state.record_network_latency(Duration::from_micros(200 + idx as u64));
        state.record_network_loss_percent(0.2);
    }

    // ...and communication errors for a handful of peers.
    for _ in 0..COMMUNICATION_ERROR_PEER_COUNT {
        state.record_communication_error(NetworkMonitorError::PingError.to_string());
    }

    family_cardinality(registry)
}

#[test]
fn test_network_metric_cardinality_is_constant_per_agent() {
    let (registry, provider) = production_style_meter();
    let cardinality = simulate_one_agent_cycle(&registry, &provider);

    println!("Per-family cardinality for one agent probing {PEER_COUNT} peers:");
    for (family, counts) in &cardinality {
        println!(
            "  {family}: {} label sets, {} exposition series",
            counts.label_sets, counts.exposition_series
        );
    }

    // The 0/1-per-pair reachability gauge is gone entirely; reachability is
    // exported as the two per-source peer-count gauges below.
    assert!(!cardinality.contains_key("forge_dpu_agent_network_reachable"));

    let reachable = cardinality
        .get("forge_dpu_agent_network_reachable_peers_count")
        .expect("reachable peer-count gauge family must exist");
    assert_eq!(reachable.label_sets, 1);
    assert_eq!(reachable.exposition_series, 1);
    assert_eq!(
        single_series_value(&registry, "forge_dpu_agent_network_reachable_peers_count"),
        (PEER_COUNT - UNREACHABLE_PEER_COUNT) as f64
    );

    let unreachable = cardinality
        .get("forge_dpu_agent_network_unreachable_peers_count")
        .expect("unreachable peer-count gauge family must exist");
    assert_eq!(unreachable.label_sets, 1);
    assert_eq!(unreachable.exposition_series, 1);
    assert_eq!(
        single_series_value(&registry, "forge_dpu_agent_network_unreachable_peers_count"),
        UNREACHABLE_PEER_COUNT as f64
    );

    // The histograms aggregate all peer probes into one per-source series:
    // one label set each, with the fixed per-label-set bucket expansion, and
    // every one of the N samples accounted for.
    let latency = cardinality
        .get("forge_dpu_agent_network_latency_milliseconds")
        .expect("latency histogram family must exist");
    assert_eq!(latency.label_sets, 1);
    assert_eq!(latency.exposition_series, LATENCY_BUCKETS_PER_SERIES + 2);
    assert_eq!(
        single_series_value(
            &registry,
            "forge_dpu_agent_network_latency_milliseconds_count"
        ),
        PEER_COUNT as f64
    );

    let loss = cardinality
        .get("forge_dpu_agent_network_loss_percentage")
        .expect("loss histogram family must exist");
    assert_eq!(loss.label_sets, 1);
    assert_eq!(loss.exposition_series, LOSS_BUCKETS_PER_SERIES + 2);
    assert_eq!(
        single_series_value(&registry, "forge_dpu_agent_network_loss_percentage_count"),
        PEER_COUNT as f64
    );

    // The communication-error counter is per source DPU and error type: one
    // series here, no matter how many peers erred.
    let communication_error = cardinality
        .get("forge_dpu_agent_network_communication_error_total")
        .expect("communication error counter family must exist");
    assert_eq!(communication_error.label_sets, 1);
    assert_eq!(communication_error.exposition_series, 1);
    assert_eq!(
        single_series_value(
            &registry,
            "forge_dpu_agent_network_communication_error_total"
        ),
        COMMUNICATION_ERROR_PEER_COUNT as f64
    );

    let total_exposition: usize = cardinality
        .iter()
        .filter(|(name, _)| name.starts_with("forge_dpu_agent_network"))
        .map(|(_, counts)| counts.exposition_series)
        .sum();
    println!(
        "Total network-family exposition series for one agent: \
         {total_exposition} (was {PER_PAIR_EXPOSITION_SERIES_TOTAL} with per-pair labels)"
    );

    // 2 peer-count gauges + latency (15 buckets + sum + count) + loss
    // (6 buckets + sum + count) + 1 communication-error series.
    assert_eq!(
        total_exposition,
        2 + (LATENCY_BUCKETS_PER_SERIES + 2) + (LOSS_BUCKETS_PER_SERIES + 2) + 1
    );
}
