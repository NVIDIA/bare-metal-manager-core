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

use carbide_uuid::rack::RackId;
use health_report::{HealthAlertClassification, HealthProbeAlert, HealthReport, OverrideMode};
use model::machine::LoadSnapshotOptions;
use model::rack::RackConfig;
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as rpc_forge};
use tonic::Request;

use crate::tests::common::api_fixtures::site_explorer::TestRackDbBuilder;
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_managed_host, create_test_env_with_overrides, get_config,
    send_health_report_override,
};

fn leak_alert_report(source: &str) -> HealthReport {
    HealthReport {
        source: source.to_string(),
        triggered_by: None,
        observed_at: Some(chrono::Utc::now()),
        successes: vec![],
        alerts: vec![HealthProbeAlert {
            id: "BmsLeakDetectRack".parse().unwrap(),
            target: None,
            in_alert_since: Some(chrono::Utc::now()),
            message: "Leak detected".to_string(),
            tenant_message: None,
            classifications: vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::sensor_critical(),
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
async fn test_insert_list_remove_rack_override(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let mut txn = pool.acquire().await?;
    let rack_id = TestRackDbBuilder::new().persist(&mut txn).await?;
    drop(txn);

    let report = leak_alert_report("dsx-exchange-consumer");

    env.api
        .insert_rack_health_report_override(Request::new(
            rpc_forge::InsertRackHealthReportOverrideRequest {
                rack_id: Some(rack_id),
                r#override: Some(rpc_forge::HealthReportOverride {
                    report: Some(report.clone().into()),
                    mode: rpc_forge::OverrideMode::Merge as i32,
                }),
            },
        ))
        .await?;

    let list_resp = env
        .api
        .list_rack_health_report_overrides(Request::new(
            rpc_forge::ListRackHealthReportOverridesRequest {
                rack_id: Some(rack_id),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(list_resp.overrides.len(), 1);
    let listed_report: HealthReport = list_resp.overrides[0]
        .report
        .clone()
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(listed_report.source, "dsx-exchange-consumer");
    assert_eq!(listed_report.alerts.len(), 1);

    env.api
        .remove_rack_health_report_override(Request::new(
            rpc_forge::RemoveRackHealthReportOverrideRequest {
                rack_id: Some(rack_id),
                source: "dsx-exchange-consumer".to_string(),
            },
        ))
        .await?;

    let list_resp = env
        .api
        .list_rack_health_report_overrides(Request::new(
            rpc_forge::ListRackHealthReportOverridesRequest {
                rack_id: Some(rack_id),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(list_resp.overrides.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_idempotent_insert(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let mut txn = pool.acquire().await?;
    let rack_id = TestRackDbBuilder::new().persist(&mut txn).await?;
    drop(txn);

    let report = leak_alert_report("dsx-exchange-consumer");

    for _ in 0..3 {
        env.api
            .insert_rack_health_report_override(Request::new(
                rpc_forge::InsertRackHealthReportOverrideRequest {
                    rack_id: Some(rack_id),
                    r#override: Some(rpc_forge::HealthReportOverride {
                        report: Some(report.clone().into()),
                        mode: rpc_forge::OverrideMode::Merge as i32,
                    }),
                },
            ))
            .await?;
    }

    let list_resp = env
        .api
        .list_rack_health_report_overrides(Request::new(
            rpc_forge::ListRackHealthReportOverridesRequest {
                rack_id: Some(rack_id),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(list_resp.overrides.len(), 1);

    Ok(())
}

#[crate::sqlx_test]
async fn test_remove_nonexistent_source(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let mut txn = pool.acquire().await?;
    let rack_id = TestRackDbBuilder::new().persist(&mut txn).await?;
    drop(txn);

    let result = env
        .api
        .remove_rack_health_report_override(Request::new(
            rpc_forge::RemoveRackHealthReportOverrideRequest {
                rack_id: Some(rack_id),
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
async fn test_missing_rack_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let nonexistent_rack_id = RackId::from(uuid::Uuid::new_v4());
    let report = leak_alert_report("dsx-exchange-consumer");

    let result = env
        .api
        .insert_rack_health_report_override(Request::new(
            rpc_forge::InsertRackHealthReportOverrideRequest {
                rack_id: Some(nonexistent_rack_id),
                r#override: Some(rpc_forge::HealthReportOverride {
                    report: Some(report.into()),
                    mode: rpc_forge::OverrideMode::Merge as i32,
                }),
            },
        ))
        .await;

    assert!(result.is_err(), "Expected NotFound for nonexistent rack");

    Ok(())
}

#[crate::sqlx_test]
async fn test_propagation_to_host_aggregate_health(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let mh = create_managed_host(&env).await;
    let host_machine_id = mh.id;

    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(rack_id)
        .persist(&mut txn)
        .await?;

    let config = RackConfig {
        compute_trays: vec![host_machine_id],
        power_shelves: vec![],
        expected_compute_trays: vec![],
        expected_power_shelves: vec![],
    };
    db::rack::update(&mut txn, rack_id, &config).await?;
    drop(txn);

    let report = leak_alert_report("dsx-exchange-consumer");
    env.api
        .insert_rack_health_report_override(Request::new(
            rpc_forge::InsertRackHealthReportOverrideRequest {
                rack_id: Some(rack_id),
                r#override: Some(rpc_forge::HealthReportOverride {
                    report: Some(report.into()),
                    mode: rpc_forge::OverrideMode::Merge as i32,
                }),
            },
        ))
        .await?;

    let snapshot = db::managed_host::load_snapshot(
        &mut env.db_reader(),
        &host_machine_id,
        LoadSnapshotOptions::default(),
    )
    .await?
    .unwrap();

    assert!(
        snapshot.rack_health_overrides.is_some(),
        "rack_health_overrides should be populated"
    );

    let has_leak_alert = snapshot.aggregate_health.alerts.iter().any(|a| {
        a.id.as_str() == "BmsLeakDetectRack"
            && a.classifications
                .contains(&HealthAlertClassification::prevent_allocations())
    });
    assert!(
        has_leak_alert,
        "Host aggregate health should contain rack leak alert with PreventAllocations"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_host_allocatability_blocked_by_rack_override(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let mh = create_managed_host(&env).await;
    let host_machine_id = mh.id;

    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(rack_id)
        .persist(&mut txn)
        .await?;
    let config = RackConfig {
        compute_trays: vec![host_machine_id],
        power_shelves: vec![],
        expected_compute_trays: vec![],
        expected_power_shelves: vec![],
    };
    db::rack::update(&mut txn, rack_id, &config).await?;
    drop(txn);

    let report = leak_alert_report("dsx-exchange-consumer");
    env.api
        .insert_rack_health_report_override(Request::new(
            rpc_forge::InsertRackHealthReportOverrideRequest {
                rack_id: Some(rack_id),
                r#override: Some(rpc_forge::HealthReportOverride {
                    report: Some(report.into()),
                    mode: rpc_forge::OverrideMode::Merge as i32,
                }),
            },
        ))
        .await?;

    let snapshot = db::managed_host::load_snapshot(
        &mut env.db_reader(),
        &host_machine_id,
        LoadSnapshotOptions::default(),
    )
    .await?
    .unwrap();

    let result = snapshot.is_usable_as_instance(false);
    assert!(
        result.is_err(),
        "Host should NOT be allocatable when rack has PreventAllocations override"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_host_replace_overrides_rack_alerts(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let mh = create_managed_host(&env).await;
    let host_machine_id = mh.id;

    let host_replace = empty_healthy_report("sre-override");
    send_health_report_override(
        &env,
        &host_machine_id,
        (host_replace, OverrideMode::Replace),
    )
    .await;

    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(rack_id)
        .persist(&mut txn)
        .await?;
    let config = RackConfig {
        compute_trays: vec![host_machine_id],
        power_shelves: vec![],
        expected_compute_trays: vec![],
        expected_power_shelves: vec![],
    };
    db::rack::update(&mut txn, rack_id, &config).await?;
    drop(txn);

    let rack_report = leak_alert_report("dsx-exchange-consumer");
    env.api
        .insert_rack_health_report_override(Request::new(
            rpc_forge::InsertRackHealthReportOverrideRequest {
                rack_id: Some(rack_id),
                r#override: Some(rpc_forge::HealthReportOverride {
                    report: Some(rack_report.into()),
                    mode: rpc_forge::OverrideMode::Merge as i32,
                }),
            },
        ))
        .await?;

    let snapshot = db::managed_host::load_snapshot(
        &mut env.db_reader(),
        &host_machine_id,
        LoadSnapshotOptions::default(),
    )
    .await?
    .unwrap();

    let has_leak_alert = snapshot.aggregate_health.alerts.iter().any(|a| {
        a.id.as_str() == "BmsLeakDetectRack"
            && a.classifications
                .contains(&HealthAlertClassification::prevent_allocations())
    });
    assert!(
        !has_leak_alert,
        "Rack alerts should not appear when host has Replace override"
    );

    let result = snapshot.is_usable_as_instance(false);
    assert!(
        result.is_ok(),
        "Host with Replace override should not be blocked by rack alerts"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_host_replace_takes_full_precedence_over_rack_replace(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let mh = create_managed_host(&env).await;
    let host_machine_id = mh.id;

    let host_replace = empty_healthy_report("sre-override");
    send_health_report_override(
        &env,
        &host_machine_id,
        (host_replace, OverrideMode::Replace),
    )
    .await;

    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(rack_id)
        .persist(&mut txn)
        .await?;
    let config = RackConfig {
        compute_trays: vec![host_machine_id],
        power_shelves: vec![],
        expected_compute_trays: vec![],
        expected_power_shelves: vec![],
    };
    db::rack::update(&mut txn, rack_id, &config).await?;
    drop(txn);

    let rack_report = leak_alert_report("rack-level-replace");
    env.api
        .insert_rack_health_report_override(Request::new(
            rpc_forge::InsertRackHealthReportOverrideRequest {
                rack_id: Some(rack_id),
                r#override: Some(rpc_forge::HealthReportOverride {
                    report: Some(rack_report.into()),
                    mode: rpc_forge::OverrideMode::Replace as i32,
                }),
            },
        ))
        .await?;

    let snapshot = db::managed_host::load_snapshot(
        &mut env.db_reader(),
        &host_machine_id,
        LoadSnapshotOptions::default(),
    )
    .await?
    .unwrap();

    assert!(
        snapshot
            .host_snapshot
            .health_report_overrides
            .replace
            .is_some(),
        "Host-level Replace override should still be present"
    );

    let has_leak_alert = snapshot
        .aggregate_health
        .alerts
        .iter()
        .any(|a| a.id.as_str() == "BmsLeakDetectRack");
    assert!(
        !has_leak_alert,
        "Rack overrides should be skipped when host has Replace override"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_dsx_consumer_contract(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let mut txn = pool.acquire().await?;
    let rack_id = TestRackDbBuilder::new().persist(&mut txn).await?;
    drop(txn);

    let report = HealthReport {
        source: "dsx-exchange-consumer".to_string(),
        triggered_by: None,
        observed_at: Some(chrono::Utc::now()),
        successes: vec![],
        alerts: vec![HealthProbeAlert {
            id: "BmsLeakDetectRack".parse().unwrap(),
            target: Some(rack_id.to_string()),
            in_alert_since: Some(chrono::Utc::now()),
            message: format!("Leak detected on rack {}", rack_id),
            tenant_message: None,
            classifications: vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::sensor_critical(),
                HealthAlertClassification::hardware(),
            ],
        }],
    };

    env.api
        .insert_rack_health_report_override(Request::new(
            rpc_forge::InsertRackHealthReportOverrideRequest {
                rack_id: Some(rack_id),
                r#override: Some(rpc_forge::HealthReportOverride {
                    report: Some(report.into()),
                    mode: rpc_forge::OverrideMode::Merge as i32,
                }),
            },
        ))
        .await?;

    env.api
        .remove_rack_health_report_override(Request::new(
            rpc_forge::RemoveRackHealthReportOverrideRequest {
                rack_id: Some(rack_id),
                source: "dsx-exchange-consumer".to_string(),
            },
        ))
        .await?;

    let list_resp = env
        .api
        .list_rack_health_report_overrides(Request::new(
            rpc_forge::ListRackHealthReportOverridesRequest {
                rack_id: Some(rack_id),
            },
        ))
        .await?
        .into_inner();
    assert_eq!(
        list_resp.overrides.len(),
        0,
        "All overrides should be removed after DSX consumer clear"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_rack_health_visible_in_get_rack(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env =
        create_test_env_with_overrides(pool.clone(), TestEnvOverrides::with_config(get_config()))
            .await;

    let mut txn = pool.acquire().await?;
    let rack_id = TestRackDbBuilder::new().persist(&mut txn).await?;
    drop(txn);

    let report = leak_alert_report("dsx-exchange-consumer");
    env.api
        .insert_rack_health_report_override(Request::new(
            rpc_forge::InsertRackHealthReportOverrideRequest {
                rack_id: Some(rack_id),
                r#override: Some(rpc_forge::HealthReportOverride {
                    report: Some(report.into()),
                    mode: rpc_forge::OverrideMode::Merge as i32,
                }),
            },
        ))
        .await?;

    let rack_resp = env
        .api
        .get_rack(Request::new(rpc_forge::GetRackRequest {
            id: Some(rack_id.to_string()),
        }))
        .await?
        .into_inner();

    assert_eq!(rack_resp.rack.len(), 1);
    let rack = &rack_resp.rack[0];

    assert!(rack.health.is_some(), "Rack should have health field");
    let health: HealthReport = rack.health.clone().unwrap().try_into().unwrap();
    assert!(
        !health.alerts.is_empty(),
        "Rack health should contain alerts"
    );

    assert_eq!(rack.health_overrides.len(), 1);
    assert_eq!(rack.health_overrides[0].source, "dsx-exchange-consumer");
    assert_eq!(
        rack.health_overrides[0].mode,
        rpc_forge::OverrideMode::Merge as i32
    );

    Ok(())
}
