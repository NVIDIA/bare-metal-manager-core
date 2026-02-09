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

use std::collections::HashMap;
use std::sync::Arc;

use measured_boot::journal::MeasurementJournal;
use measured_boot::records::MeasurementBundleState;
use tokio::sync::oneshot;

use crate::CarbideResult;
use crate::cfg::file::MeasuredBootMetricsCollectorConfig;

pub(crate) mod metrics;
use carbide_uuid::measured_boot::MeasurementBundleId;
use metrics::MeasuredBootMetricsCollectorMetrics;

/// `MeasuredBootMetricsCollector` monitors the state of all measured boot data.
pub struct MeasuredBootMetricsCollector {
    database_connection: sqlx::PgPool,
    config: MeasuredBootMetricsCollectorConfig,
    metric_holder: Arc<metrics::MetricHolder>,
}

impl MeasuredBootMetricsCollector {
    /// Create a MeasuredBootMetricsCollector
    pub fn new(
        database_connection: sqlx::PgPool,
        config: MeasuredBootMetricsCollectorConfig,
        meter: opentelemetry::metrics::Meter,
    ) -> Self {
        // We want to hold metrics for longer than the iteration interval, so there is continuity
        // in emitting metrics. However we want to avoid reporting outdated metrics in case
        // reporting gets stuck. Therefore round up the iteration interval by 1min.
        let hold_period = config
            .run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(meter, hold_period));

        MeasuredBootMetricsCollector {
            database_connection,
            config,
            metric_holder,
        }
    }

    /// Start the MeasuredBootMetricsCollector and return a [sending channel](tokio::sync::oneshot::Sender)
    /// that will stop the MeasuredBootMetricsCollector when dropped.
    pub fn start(self) -> eyre::Result<oneshot::Sender<i32>> {
        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.config.enabled {
            tokio::task::Builder::new()
                .name("measured_boot_collector")
                .spawn(async move { self.run(stop_receiver).await })?;
        }

        Ok(stop_sender)
    }

    async fn run(&self, mut stop_receiver: oneshot::Receiver<i32>) {
        loop {
            if let Err(e) = self.run_single_iteration().await {
                tracing::warn!("MeasuredBootMetricsCollector error: {}", e);
            }

            tokio::select! {
                _ = tokio::time::sleep(self.config.run_interval) => {},
                _ = &mut stop_receiver => {
                    tracing::info!("MeasuredBootMetricsCollector stop was requested");
                    return;
                }
            }
        }
    }

    pub async fn run_single_iteration(&self) -> CarbideResult<()> {
        let mut metrics = MeasuredBootMetricsCollectorMetrics::new();

        let mut txn = db::Transaction::begin(&self.database_connection).await?;

        let profiles = db::measured_boot::profile::get_all(&mut txn).await?;
        for system_profile in profiles.iter() {
            let machines =
                db::measured_boot::profile::get_machines(system_profile, &mut txn).await?;
            metrics
                .num_machines_per_profile
                .insert(system_profile.profile_id, machines.len());
        }
        metrics.num_profiles = profiles.len();

        let bundles = db::measured_boot::bundle::get_all(&mut txn).await?;
        let bundle_map: HashMap<MeasurementBundleId, MeasurementBundleState> = bundles
            .iter()
            .map(|bundle| (bundle.bundle_id, bundle.state))
            .collect();

        for bundle in bundles.iter() {
            let machines = db::measured_boot::bundle::get_machines(bundle, &mut txn).await?;
            metrics
                .num_machines_per_bundle
                .insert(bundle.bundle_id, machines.len());
            for pcr_register_value in bundle.pcr_values().into_iter() {
                *metrics
                    .num_machines_per_pcr_value
                    .entry(pcr_register_value)
                    .or_insert(0) += 1;
            }
        }
        metrics.num_bundles = bundles.len();

        let machines = db::measured_boot::machine::get_all(&mut txn).await?;
        for machine in machines.iter() {
            let bundle_state = get_bundle_state(&bundle_map, &machine.journal);
            *metrics
                .num_machines_per_machine_state
                .entry(machine.state)
                .or_insert(0) += 1;
            *metrics
                .num_machines_per_bundle_state
                .entry(bundle_state)
                .or_insert(0) += 1;
        }
        metrics.num_machines = machines.len();

        // Cache all other metrics that have been captured in this iteration.
        // Those will be queried by OTEL on demand
        self.metric_holder.update_metrics(metrics);

        txn.commit().await?;

        Ok(())
    }
}

/// get_bundle_state attempts to get the bundle state for a given
/// journal and complete map of currently known bundle IDs and their
/// given states.
///
/// TODO(chet): This exists because machines don't have a bundle state
/// stored alongside them yet, because we don't store a bundle state in
/// the journal entry (just the bundle ID). Going and fetching the bundle
/// state for each machine would be expensive, so for now, this works, but
/// look into storing an Option<MeasurementBundleState> in the journal
/// at entry time.
///
/// TODO(chet): Introduce a new state here that isn't ::Pending for cases
/// where there is no bundle match at all -- ::Pending means the bundle
/// exists but isn't active/revoked yet. When there is no bundle match,
/// the state should be ::NoMatch or something similar.
fn get_bundle_state(
    bundle_map: &HashMap<MeasurementBundleId, MeasurementBundleState>,
    machine_journal: &Option<MeasurementJournal>,
) -> MeasurementBundleState {
    if let Some(journal) = machine_journal {
        if let Some(bundle_id) = journal.bundle_id {
            if let Some(bundle_state) = bundle_map.get(&bundle_id) {
                *bundle_state
            } else {
                MeasurementBundleState::Pending
            }
        } else {
            MeasurementBundleState::Pending
        }
    } else {
        MeasurementBundleState::Pending
    }
}
