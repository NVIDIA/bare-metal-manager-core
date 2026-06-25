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

use carbide_uuid::switch::SwitchId;
use health_report::{HealthAlertClassification, HealthProbeAlert, HealthReport};
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as rpc_forge};
use tonic::Request;

use crate::tests::common::api_fixtures::site_explorer::new_switch;
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
            id: "SwitchUnhealthy".parse().unwrap(),
            target: None,
            in_alert_since: Some(chrono::Utc::now()),
            message: "Switch health issue detected".to_string(),
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

/// Builds the switch health-override CRUD surface over `env` for `id`. The shared
/// checks in [`crate::tests::common::health_crud`] drive these closures.
// The four `impl AsyncFn` members are intentionally distinct unnameable closure
// types; there is nothing to factor into a `type` alias.
#[allow(clippy::type_complexity)]
fn switch_crud(
    env: &TestEnv,
    id: SwitchId,
) -> HealthCrud<
    SwitchId,
    impl AsyncFn(SwitchId, HealthReport, rpc_forge::HealthReportApplyMode) -> Result<(), tonic::Status>,
    impl AsyncFn(SwitchId) -> Result<Vec<rpc_forge::HealthReportEntry>, tonic::Status>,
    impl AsyncFn(SwitchId, String) -> Result<(), tonic::Status>,
    impl AsyncFn(SwitchId) -> Result<HealthStatusView, tonic::Status>,
> {
    HealthCrud {
        real_id: id,
        nonexistent_id: SwitchId::from(uuid::Uuid::new_v4()),
        alert: alert_report("external-monitor"),
        alert_source: "external-monitor",
        insert: async move |id, report: HealthReport, mode| {
            let report: rpc::health::HealthReport = report.into();
            env.api
                .insert_switch_health_report(Request::new(
                    rpc_forge::InsertSwitchHealthReportRequest {
                        switch_id: Some(id),
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
                .list_switch_health_reports(Request::new(
                    rpc_forge::ListSwitchHealthReportsRequest {
                        switch_id: Some(id),
                    },
                ))
                .await?
                .into_inner()
                .health_report_entries)
        },
        remove: async move |id, source| {
            env.api
                .remove_switch_health_report(Request::new(
                    rpc_forge::RemoveSwitchHealthReportRequest {
                        switch_id: Some(id),
                        source,
                    },
                ))
                .await
                .map(|_| ())
        },
        find: async move |id| {
            let resp = env
                .api
                .find_switches(Request::new(rpc_forge::SwitchQuery {
                    switch_id: Some(id),
                    name: None,
                }))
                .await?
                .into_inner();
            assert_eq!(resp.switches.len(), 1);
            let status = resp.switches[0].status.clone().unwrap();
            Ok(HealthStatusView {
                health: status.health,
                health_sources: status.health_sources,
            })
        },
    }
}

#[crate::sqlx_test]
async fn test_insert_list_remove_switch_override(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_switch(&env, None, None).await?;
    switch_crud(&env, id).check_insert_list_remove().await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_idempotent_insert(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_switch(&env, None, None).await?;
    switch_crud(&env, id).check_idempotent_insert().await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_remove_nonexistent_source(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_switch(&env, None, None).await?;
    switch_crud(&env, id)
        .check_remove_nonexistent_source()
        .await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_missing_switch_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_switch(&env, None, None).await?;
    switch_crud(&env, id).check_missing_entity().await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_replace_mode_override(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_switch(&env, None, None).await?;
    switch_crud(&env, id)
        .check_replace_mode(empty_healthy_report("admin-override"), "admin-override")
        .await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_health_visible_in_find_switches(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_switch(&env, None, None).await?;
    switch_crud(&env, id).check_visible_in_find().await;
    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_health_aggregation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = test_env(pool).await;
    let id = new_switch(&env, None, None).await?;
    check_health_aggregation(
        "switches",
        id,
        alert_report("external-monitor"),
        empty_healthy_report("admin-override"),
        &env.test_meter,
        async |id, report: HealthReport, mode| {
            let report: rpc::health::HealthReport = report.into();
            env.api
                .insert_switch_health_report(Request::new(
                    rpc_forge::InsertSwitchHealthReportRequest {
                        switch_id: Some(id),
                        health_report_entry: Some(rpc_forge::HealthReportEntry {
                            report: Some(report),
                            mode: mode as i32,
                        }),
                    },
                ))
                .await
                .map(|_| ())
        },
        async || env.run_switch_controller_iteration().await,
    )
    .await;
    Ok(())
}
