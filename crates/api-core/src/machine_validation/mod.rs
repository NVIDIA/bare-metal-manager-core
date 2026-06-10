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
use std::io;
use std::sync::Arc;

use carbide_machine_controller::config::machine_validation::MachineValidationConfig;
use carbide_utils::periodic_timer::PeriodicTimer;
use db::ObjectColumnFilter;
use db::machine_validation::StateColumn;
use model::machine::{FailureCause, FailureDetails, FailureSource};
use model::machine_validation::{
    MachineValidation, MachineValidationState, MachineValidationStatus,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use self::metrics::MachineValidationMetrics;
use crate::CarbideResult;

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
    pub fn start(
        self,
        join_set: &mut JoinSet<()>,
        cancel_token: CancellationToken,
    ) -> io::Result<()> {
        if self.config.enabled {
            join_set
                .build_task()
                .name("machine_validation_manager")
                .spawn(async move { self.run(cancel_token).await })?;
        }
        Ok(())
    }

    async fn run(&self, cancel_token: CancellationToken) {
        let timer = PeriodicTimer::new(self.config.run_interval);
        loop {
            let tick = timer.tick();
            if let Err(e) = self.run_single_iteration().await {
                tracing::warn!("MachineValidationManager error: {}", e);
            }

            tokio::select! {
                _ = tick.sleep() => {},
                _ = cancel_token.cancelled() => {
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
        let now = chrono::Utc::now();

        let stale_validations = stale_validations(
            db::machine_validation::find_active(&mut txn).await?,
            self.config.stale_run_timeout,
            now,
        );

        for validation in stale_validations {
            if reconcile_stale_validation(
                txn.as_pgconn(),
                validation,
                self.config.stale_run_timeout,
                now,
            )
            .await?
            {
                metrics.stale_validation += 1;
            }
        }

        metrics.completed_validation = db::machine_validation::find_by(
            &mut txn,
            ObjectColumnFilter::List(StateColumn, &["Success".to_string()]),
        )
        .await?
        .len();

        metrics.failed_validation = db::machine_validation::find_by(
            &mut txn,
            ObjectColumnFilter::List(StateColumn, &["Failed".to_string()]),
        )
        .await?
        .len();
        metrics.in_progress_validation = db::machine_validation::find_by(
            &mut txn,
            ObjectColumnFilter::List(StateColumn, &["InProgress".to_string()]),
        )
        .await?
        .len();

        metrics.oldest_active_validation_age_seconds =
            db::machine_validation::find_active(&mut txn)
                .await?
                .iter()
                .filter_map(|validation| active_validation_age_seconds(validation, now))
                .max()
                .unwrap_or_default();

        metrics.tests = db::machine_validation_suites::find(
            &mut txn,
            model::machine_validation::MachineValidationTestsGetRequest::default(),
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

fn active_validation_age_seconds(
    validation: &MachineValidation,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<u64> {
    validation
        .start_time
        .and_then(|start_time| now.signed_duration_since(start_time).to_std().ok())
        .map(|age| age.as_secs())
}

fn stale_validations(
    validations: Vec<MachineValidation>,
    stale_run_timeout: std::time::Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<MachineValidation> {
    validations
        .into_iter()
        .filter(|validation| {
            validation
                .start_time
                .and_then(|start_time| {
                    let expected_duration =
                        chrono::Duration::seconds(validation.duration_to_complete.max(0));
                    let stale_run_timeout = chrono::Duration::from_std(stale_run_timeout).ok()?;
                    Some(start_time + expected_duration + stale_run_timeout)
                })
                .is_some_and(|stale_after| stale_after < now)
        })
        .collect()
}

async fn reconcile_stale_validation(
    txn: &mut sqlx::PgConnection,
    validation: MachineValidation,
    stale_run_timeout: std::time::Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> CarbideResult<bool> {
    let error_message = format!(
        "Machine validation run {} exceeded its expected duration plus stale timeout",
        validation.id
    );

    let status = MachineValidationStatus {
        state: MachineValidationState::Failed,
        ..MachineValidationStatus::default()
    };

    let Some(validation) = db::machine_validation::mark_stale_if_active(
        txn,
        &validation.id,
        stale_run_timeout,
        now,
        &status,
    )
    .await?
    else {
        tracing::debug!(
            validation_id = %validation.id,
            "skipping stale machine validation because it is no longer active or stale"
        );
        return Ok(false);
    };

    let Some(machine) = db::machine::find_by_validation_id(txn, &validation.id).await? else {
        tracing::warn!(
            validation_id = %validation.id,
            machine_id = %validation.machine_id,
            "stale machine validation has no owning machine"
        );
        return Ok(true);
    };

    db::machine::update_failure_details_by_machine_id(
        &machine.id,
        txn,
        FailureDetails {
            cause: FailureCause::MachineValidation {
                err: error_message.clone(),
            },
            failed_at: chrono::Utc::now(),
            source: FailureSource::Scout,
        },
    )
    .await?;

    let mut health_report = machine.machine_validation_health_report();
    health_report.observed_at = Some(chrono::Utc::now());
    health_report.alerts.push(health_report::HealthProbeAlert {
        id: "StaleMachineValidationRun".parse().unwrap(),
        target: None,
        in_alert_since: Some(chrono::Utc::now()),
        message: error_message.clone(),
        tenant_message: None,
        classifications: vec![health_report::HealthAlertClassification::prevent_allocations()],
    });
    db::machine::update_machine_validation_health_report(txn, &machine.id, &health_report).await?;

    db::machine::set_machine_validation_request(txn, &machine.id, false).await?;
    db::machine::update_machine_validation_time(&machine.id, txn).await?;

    tracing::warn!(
        validation_id = %validation.id,
        machine_id = %machine.id,
        "reconciled stale machine validation run"
    );

    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use carbide_uuid::machine::MachineId;
    use carbide_uuid::machine_validation::MachineValidationId;

    use super::*;

    fn validation_started_at(
        start_time: chrono::DateTime<chrono::Utc>,
        duration_to_complete: i64,
    ) -> MachineValidation {
        MachineValidation {
            id: MachineValidationId::new(),
            machine_id: MachineId::from_str(
                "fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30",
            )
            .unwrap(),
            name: "test".to_string(),
            start_time: Some(start_time),
            end_time: None,
            filter: None,
            context: Some("OnDemand".to_string()),
            status: None,
            duration_to_complete,
        }
    }

    #[test]
    fn stale_validations_respects_expected_duration_plus_grace() {
        let now = chrono::Utc::now();
        let stale = validation_started_at(now - chrono::Duration::seconds(11), 5);
        let active = validation_started_at(now - chrono::Duration::seconds(9), 5);

        let stale = stale_validations(vec![stale, active], std::time::Duration::from_secs(5), now);

        assert_eq!(stale.len(), 1);
    }
}
