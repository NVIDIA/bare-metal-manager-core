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

mod metrics;

use std::default::Default;
use std::sync::Arc;

use db::ObjectFilter;
use tokio::sync::oneshot;

use self::metrics::MachineValidationMetrics;
use crate::CarbideResult;
use crate::cfg::file::MachineValidationConfig;

pub struct MachineValidationManager {
    database_connection: sqlx::PgPool,
    config: MachineValidationConfig,
    metric_holder: Arc<metrics::MetricHolder>,
}

impl MachineValidationManager {
    pub fn new(
        database_connection: sqlx::PgPool,
        config: MachineValidationConfig,
        meter: opentelemetry::metrics::Meter,
    ) -> Self {
        let hold_period = config
            .run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(meter, hold_period));

        MachineValidationManager {
            database_connection,
            config,
            metric_holder,
        }
    }
    pub fn start(self) -> eyre::Result<oneshot::Sender<i32>> {
        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.config.enabled {
            tokio::task::Builder::new()
                .name("machine_validation_manager")
                .spawn(async move { self.run(stop_receiver).await })?;
        }

        Ok(stop_sender)
    }

    async fn run(&self, mut stop_receiver: oneshot::Receiver<i32>) {
        loop {
            if let Err(e) = self.run_single_iteration().await {
                tracing::warn!("MachineValidationManager error: {}", e);
            }

            tokio::select! {
                _ = tokio::time::sleep(self.config.run_interval) => {},
                _ = &mut stop_receiver => {
                    tracing::info!("MachineValidationManager stop was requested");
                    return;
                }
            }
        }
    }

    /// run_single_iteration runs a single iteration of the state machine across all explored endpoints in the preingestion state.
    /// Returns true if we stopped early due to a timeout.
    pub async fn run_single_iteration(&self) -> CarbideResult<()> {
        let mut metrics = MachineValidationMetrics::new();

        let mut txn = db::Transaction::begin(&self.database_connection).await?;

        metrics.completed_validation = db::machine_validation::find_by(
            &mut txn,
            ObjectFilter::List(&["Success".to_string()]),
            "state",
        )
        .await?
        .len();

        metrics.failed_validation = db::machine_validation::find_by(
            &mut txn,
            ObjectFilter::List(&["Failed".to_string()]),
            "state",
        )
        .await?
        .len();
        metrics.in_progress_validation = db::machine_validation::find_by(
            &mut txn,
            ObjectFilter::List(&["InProgress".to_string()]),
            "state",
        )
        .await?
        .len();

        metrics.tests = db::machine_validation_suites::find(
            &mut txn,
            rpc::forge::MachineValidationTestsGetRequest::default(),
        )
        .await?;
        tracing::debug!(
            "MachineValidation metrics: completed {} failed {} in_progress {}",
            metrics.completed_validation,
            metrics.failed_validation,
            metrics.in_progress_validation,
        );
        self.metric_holder.update_metrics(metrics);

        txn.commit().await?;

        Ok(())
    }
}
