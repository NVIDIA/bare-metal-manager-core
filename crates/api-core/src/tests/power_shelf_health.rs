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

use carbide_uuid::power_shelf::PowerShelfId;
use health_report::{HealthAlertClassification, HealthProbeAlert, HealthReport};
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as rpc_forge};
use tonic::Request;

use crate::tests::common::api_fixtures::site_explorer::new_power_shelf;
use crate::tests::common::api_fixtures::{
    TestEnv, TestEnvOverrides, create_test_env_with_overrides, get_config,
};
use crate::tests::common::health_crud::{HealthCrud, HealthStatusView, check_health_aggregation};

fn alert_report(source: &str) -> HealthReport {
    HealthReport {
        source: source.to_string(),
        triggered_by: None,
        observed_at: Some(chrono::Utc::now()),
        successes: vec![],
        alerts: vec![HealthProbeAlert {
            id: "PowerShelfUnhealthy".parse().unwrap(),
            target: None,
            in_alert_since: Some(chrono::Utc::now()),
            message: "Power shelf health issue detected".to_string(),
            tenant_message: None,
            classifications: vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::hardware(),
            ],
        }],
    }
}

fn empty_healthy_report(source: &str) -> HealthReport {
    HealthReport {
        source: source.to_string(),
        triggered_by: None,
        observed_at: Some(chrono::Utc::now()),
        successes: vec![],
        alerts: vec![],
    }
}

async fn test_env(pool: sqlx::PgPool) -> TestEnv {
    create_test_env_with_overrides(pool, TestEnvOverrides::with_config(get_config())).await
}

/// Builds the power-shelf health-override CRUD surface over `env` for `id`. The
/// shared checks in [`crate::tests::common::health_crud`] drive these closures.
// The four `impl AsyncFn` members are intentionally distinct unnameable closure
// types; there is nothing to factor into a `type` alias.
#[allow(clippy::type_complexity)]
fn power_shelf_crud(
    env: &TestEnv,
    id: PowerShelfId,
) -> HealthCrud<
    PowerShelfId,
    impl AsyncFn(
        PowerShelfId,
        HealthReport,
        rpc_forge::HealthReportApplyMode,
    ) -> Result<(), tonic::Status>,
    impl AsyncFn(PowerShelfId) -> Result<Vec<rpc_forge::HealthReportEntry>, tonic::Status>,
    impl AsyncFn(PowerShelfId, String) -> Result<(), tonic::Status>,
    impl AsyncFn(PowerShelfId) -> Result<HealthStatusView, tonic::Status>,
> {
    HealthCrud {
        real_id: id,
        nonexistent_id: PowerShelfId::from(uuid::Uuid::new_v4()),
        alert: alert_report("external-monitor"),
        alert_source: "external-monitor",
        insert: async move |id, report: HealthReport, mode| {
            let report: rpc::health::HealthReport = report.into();
            env.api
                .insert_power_shelf_health_report(Request::new(
                    rpc_forge::InsertPowerShelfHealthReportRequest {
                        power_shelf_id: Some(id),
                        health_report_entry: Some(rpc_forge::HealthReportEntry {
                            report: Some(report),
                            mode: mode as i32,
                        }),
                    },
                ))
                .await
                .map(|_| ())
        },
        list: async move |id| {
            Ok(env
                .api
                .list_power_shelf_health_reports(Request::new(
                    rpc_forge::ListPowerShelfHealthReportsRequest {
                        power_shelf_id: Some(id),
                    },
                ))
                .await?
                .into_inner()
                .health_report_entries)
        },
        remove: async move |id, source| {
            env.api
                .remove_power_shelf_health_report(Request::new(
                    rpc_forge::RemovePowerShelfHealthReportRequest {
                        power_shelf_id: Some(id),
                        source,
                    },
                ))
                .await
                .map(|_| ())
        },
        find: async move |id| {
            let resp = env
                .api
                .find_power_shelves(Request::new(rpc_forge::PowerShelfQuery {
                    power_shelf_id: Some(id),
                    name: None,
                }))
                .await?
                .into_inner();
            assert_eq!(resp.power_shelves.len(), 1);
            let status = resp.power_shelves[0].status.clone().unwrap();
            Ok(HealthStatusView {
                health: status.health,
                health_sources: status.health_sources,
            })
        },
    }
}

#[crate::sqlx_test]
async fn test_insert_list_remove_power_shelf_health_report(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_power_shelf(&env, None, None, None, None).await?;
    power_shelf_crud(&env, id).check_insert_list_remove().await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_idempotent_insert(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_power_shelf(&env, None, None, None, None).await?;
    power_shelf_crud(&env, id).check_idempotent_insert().await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_retains_in_alert_since(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_power_shelf(&env, None, None, None, None).await?;
    power_shelf_crud(&env, id)
        .check_retains_in_alert_since()
        .await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_remove_nonexistent_source(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_power_shelf(&env, None, None, None, None).await?;
    power_shelf_crud(&env, id)
        .check_remove_nonexistent_source()
        .await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_missing_power_shelf_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_power_shelf(&env, None, None, None, None).await?;
    power_shelf_crud(&env, id).check_missing_entity().await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_replace_mode(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_power_shelf(&env, None, None, None, None).await?;
    power_shelf_crud(&env, id)
        .check_replace_mode(empty_healthy_report("admin-override"), "admin-override")
        .await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_health_visible_in_find_power_shelves(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_power_shelf(&env, None, None, None, None).await?;
    power_shelf_crud(&env, id).check_visible_in_find().await;
    Ok(())
}

async fn insert_power_shelf_health(env: &TestEnv, id: PowerShelfId, report: HealthReport) {
    let report: rpc::health::HealthReport = report.into();
    env.api
        .insert_power_shelf_health_report(Request::new(
            rpc_forge::InsertPowerShelfHealthReportRequest {
                power_shelf_id: Some(id),
                health_report_entry: Some(rpc_forge::HealthReportEntry {
                    report: Some(report),
                    mode: rpc_forge::HealthReportApplyMode::Replace as i32,
                }),
            },
        ))
        .await
        .unwrap();
}

async fn power_shelf_health_history(
    env: &TestEnv,
    id: PowerShelfId,
    start_time: Option<chrono::DateTime<chrono::Utc>>,
    end_time: Option<chrono::DateTime<chrono::Utc>>,
) -> Vec<rpc_forge::HealthHistoryRecord> {
    env.api
        .find_power_shelf_health_histories(Request::new(
            rpc_forge::PowerShelfHealthHistoriesRequest {
                power_shelf_ids: vec![id],
                start_time: start_time.map(Into::into),
                end_time: end_time.map(Into::into),
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .histories
        .remove(&id.to_string())
        .unwrap_or_default()
        .records
}

/// The power-shelf controller records a health-history snapshot each iteration;
/// the DB layer deduplicates unchanged observations and only appends when the
/// aggregate health content changes. This exercises that path end-to-end through
/// the `FindPowerShelfHealthHistories` RPC.
#[crate::sqlx_test]
async fn test_power_shelf_health_history_records_and_deduplicates(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_power_shelf(&env, None, None, None, None).await?;

    insert_power_shelf_health(&env, id, alert_report("external-monitor")).await;
    env.run_power_shelf_controller_iteration().await;
    let after_first = power_shelf_health_history(&env, id, None, None).await.len();
    assert!(
        after_first >= 1,
        "expected at least one health-history record after the first iteration"
    );

    env.run_power_shelf_controller_iteration().await;
    let after_second = power_shelf_health_history(&env, id, None, None).await.len();
    assert_eq!(
        after_first, after_second,
        "unchanged aggregate health must not add a new record"
    );

    insert_power_shelf_health(&env, id, empty_healthy_report("external-monitor")).await;
    env.run_power_shelf_controller_iteration().await;
    let after_change = power_shelf_health_history(&env, id, None, None).await.len();
    assert_eq!(
        after_change,
        after_second + 1,
        "changed aggregate health must append exactly one record"
    );

    Ok(())
}

/// The `FindPowerShelfHealthHistories` handler must forward both time bounds
/// from the request into the shared query. This proves the power-shelf-specific
/// wiring; the shared range-filtering query in `find_by_object_ids` is also
/// exercised by the machine time-range test.
#[crate::sqlx_test]
async fn test_power_shelf_health_history_respects_time_range(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_power_shelf(&env, None, None, None, None).await?;

    let before = chrono::Utc::now();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    insert_power_shelf_health(&env, id, alert_report("external-monitor")).await;
    env.run_power_shelf_controller_iteration().await;

    let in_range =
        power_shelf_health_history(&env, id, Some(before), Some(chrono::Utc::now())).await;
    assert!(
        !in_range.is_empty(),
        "a range bracketing the write must return the record"
    );

    let ended_before = power_shelf_health_history(&env, id, None, Some(before)).await;
    assert!(
        ended_before.is_empty(),
        "records written after end_time must be excluded"
    );

    let starts_future = power_shelf_health_history(
        &env,
        id,
        Some(chrono::Utc::now() + chrono::Duration::hours(1)),
        None,
    )
    .await;
    assert!(
        starts_future.is_empty(),
        "records written before start_time must be excluded"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_power_shelf_health_histories_rejects_empty_ids(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let status = env
        .api
        .find_power_shelf_health_histories(Request::new(
            rpc_forge::PowerShelfHealthHistoriesRequest {
                power_shelf_ids: vec![],
                start_time: None,
                end_time: None,
            },
        ))
        .await
        .expect_err("empty power_shelf_ids must be rejected");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_health_aggregation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_power_shelf(&env, None, None, None, None).await?;
    check_health_aggregation(
        "power_shelves",
        id,
        alert_report("external-monitor"),
        empty_healthy_report("admin-override"),
        &env.test_meter,
        async |id, report: HealthReport, mode| {
            let report: rpc::health::HealthReport = report.into();
            env.api
                .insert_power_shelf_health_report(Request::new(
                    rpc_forge::InsertPowerShelfHealthReportRequest {
                        power_shelf_id: Some(id),
                        health_report_entry: Some(rpc_forge::HealthReportEntry {
                            report: Some(report),
                            mode: mode as i32,
                        }),
                    },
                ))
                .await
                .map(|_| ())
        },
        async || env.run_power_shelf_controller_iteration().await,
    )
    .await;
    Ok(())
}
