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

use health_report::{HealthAlertClassification, HealthProbeAlert, HealthReport};
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as rpc_forge};
use tonic::Request;

use crate::tests::common::api_fixtures::site_explorer::new_power_shelf;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_test_env_with_overrides, get_config,
};

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

#[crate::sqlx_test]
async fn test_insert_list_remove_power_shelf_health_report(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let power_shelf_id = new_power_shelf(&env, None, None, None, None).await?;

    let report = alert_report("external-monitor");

    env.api
        .insert_power_shelf_health_report(Request::new(
            rpc_forge::InsertPowerShelfHealthReportRequest {
                power_shelf_id: Some(power_shelf_id),
                health_report_entry: Some(rpc_forge::HealthReportEntry {
                    report: Some(report.clone().into()),
                    mode: rpc_forge::HealthReportApplyMode::Merge as i32,
                }),
            },
        ))
        .await?;

    let list_resp = env
        .api
        .list_power_shelf_health_reports(Request::new(
            rpc_forge::ListPowerShelfHealthReportsRequest {
                power_shelf_id: Some(power_shelf_id),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(list_resp.health_report_entries.len(), 1);
    let listed_report: HealthReport = list_resp.health_report_entries[0]
        .report
        .clone()
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(listed_report.source, "external-monitor");
    assert_eq!(listed_report.alerts.len(), 1);

    env.api
        .remove_power_shelf_health_report(Request::new(
            rpc_forge::RemovePowerShelfHealthReportRequest {
                power_shelf_id: Some(power_shelf_id),
                source: "external-monitor".to_string(),
            },
        ))
        .await?;

    let list_resp = env
        .api
        .list_power_shelf_health_reports(Request::new(
            rpc_forge::ListPowerShelfHealthReportsRequest {
                power_shelf_id: Some(power_shelf_id),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(list_resp.health_report_entries.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_idempotent_insert(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let power_shelf_id = new_power_shelf(&env, None, None, None, None).await?;
    let report = alert_report("external-monitor");

    for _ in 0..3 {
        env.api
            .insert_power_shelf_health_report(Request::new(
                rpc_forge::InsertPowerShelfHealthReportRequest {
                    power_shelf_id: Some(power_shelf_id),
                    health_report_entry: Some(rpc_forge::HealthReportEntry {
                        report: Some(report.clone().into()),
                        mode: rpc_forge::HealthReportApplyMode::Merge as i32,
                    }),
                },
            ))
            .await?;
    }

    let list_resp = env
        .api
        .list_power_shelf_health_reports(Request::new(
            rpc_forge::ListPowerShelfHealthReportsRequest {
                power_shelf_id: Some(power_shelf_id),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(list_resp.health_report_entries.len(), 1);

    Ok(())
}

#[crate::sqlx_test]
async fn test_remove_nonexistent_source(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let power_shelf_id = new_power_shelf(&env, None, None, None, None).await?;

    let result = env
        .api
        .remove_power_shelf_health_report(Request::new(
            rpc_forge::RemovePowerShelfHealthReportRequest {
                power_shelf_id: Some(power_shelf_id),
                source: "nonexistent-source".to_string(),
            },
        ))
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);

    Ok(())
}

#[crate::sqlx_test]
async fn test_missing_power_shelf_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let nonexistent_id = carbide_uuid::power_shelf::PowerShelfId::from(uuid::Uuid::new_v4());
    let report = alert_report("external-monitor");

    let result = env
        .api
        .insert_power_shelf_health_report(Request::new(
            rpc_forge::InsertPowerShelfHealthReportRequest {
                power_shelf_id: Some(nonexistent_id),
                health_report_entry: Some(rpc_forge::HealthReportEntry {
                    report: Some(report.into()),
                    mode: rpc_forge::HealthReportApplyMode::Merge as i32,
                }),
            },
        ))
        .await;

    assert!(
        result.is_err(),
        "Expected NotFound for nonexistent power shelf"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_replace_mode(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let power_shelf_id = new_power_shelf(&env, None, None, None, None).await?;

    let replace_report = empty_healthy_report("admin-override");
    env.api
        .insert_power_shelf_health_report(Request::new(
            rpc_forge::InsertPowerShelfHealthReportRequest {
                power_shelf_id: Some(power_shelf_id),
                health_report_entry: Some(rpc_forge::HealthReportEntry {
                    report: Some(replace_report.into()),
                    mode: rpc_forge::HealthReportApplyMode::Replace as i32,
                }),
            },
        ))
        .await?;

    let list_resp = env
        .api
        .list_power_shelf_health_reports(Request::new(
            rpc_forge::ListPowerShelfHealthReportsRequest {
                power_shelf_id: Some(power_shelf_id),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(list_resp.health_report_entries.len(), 1);
    assert_eq!(
        list_resp.health_report_entries[0].mode,
        rpc_forge::HealthReportApplyMode::Replace as i32
    );

    env.api
        .remove_power_shelf_health_report(Request::new(
            rpc_forge::RemovePowerShelfHealthReportRequest {
                power_shelf_id: Some(power_shelf_id),
                source: "admin-override".to_string(),
            },
        ))
        .await?;

    let list_resp = env
        .api
        .list_power_shelf_health_reports(Request::new(
            rpc_forge::ListPowerShelfHealthReportsRequest {
                power_shelf_id: Some(power_shelf_id),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(list_resp.health_report_entries.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_health_visible_in_find_power_shelves(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let power_shelf_id = new_power_shelf(&env, None, None, None, None).await?;

    let report = alert_report("external-monitor");
    env.api
        .insert_power_shelf_health_report(Request::new(
            rpc_forge::InsertPowerShelfHealthReportRequest {
                power_shelf_id: Some(power_shelf_id),
                health_report_entry: Some(rpc_forge::HealthReportEntry {
                    report: Some(report.into()),
                    mode: rpc_forge::HealthReportApplyMode::Merge as i32,
                }),
            },
        ))
        .await?;

    let resp = env
        .api
        .find_power_shelves(Request::new(rpc_forge::PowerShelfQuery {
            power_shelf_id: Some(power_shelf_id),
            name: None,
        }))
        .await?
        .into_inner();

    assert_eq!(resp.power_shelves.len(), 1);
    let ps = &resp.power_shelves[0];

    assert!(ps.health.is_some(), "Power shelf should have health field");
    let health: HealthReport = ps.health.clone().unwrap().try_into().unwrap();
    assert!(
        !health.alerts.is_empty(),
        "Power shelf health should contain alerts"
    );

    assert_eq!(ps.health_sources.len(), 1);
    assert_eq!(ps.health_sources[0].source, "external-monitor");
    assert_eq!(
        ps.health_sources[0].mode,
        rpc_forge::HealthReportApplyMode::Merge as i32
    );

    Ok(())
}
