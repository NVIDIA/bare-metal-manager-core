/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

mod common;

use carbide::{cfg::HardwareHealthReportsConfig, db};
use common::api_fixtures::{
    create_managed_host, create_test_env_with_config, get_config, network_configured_with_health,
    remove_health_report_override, send_health_report_override, simulate_hardware_health_report,
    TestEnv,
};
use health_report::OverrideMode;
use rpc::forge::{forge_server::Forge, HealthOverrideOrigin};
use tonic::Request;

use crate::db::managed_host::LoadSnapshotOptions;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_machine_health_reporting(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_env(pool).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    // As part of test fixtures creating the managed host, we send an empty hardware health
    // report and an empty dpu agent health report.
    check_reports_equal(
        "forge-dpu-agent",
        load_snapshot(&env, &host_machine_id).await?.dpu_snapshots[0]
            .dpu_agent_health_report
            .clone()
            .unwrap(),
        health_report::HealthReport::empty("".to_string()),
    );
    check_reports_equal(
        "hardware-health",
        load_snapshot(&env, &host_machine_id)
            .await?
            .host_snapshot
            .hardware_health_report
            .unwrap(),
        health_report::HealthReport::empty("".to_string()),
    );

    let m = get_machine(&env, &host_machine_id).await;
    assert_eq!(m.health_overrides, vec![]);
    let aggregate_health = aggregate(m).unwrap();
    assert_eq!(aggregate_health.source, "aggregate-host-health");
    check_time(&aggregate_health);
    assert_eq!(aggregate_health.alerts, vec![]);
    assert_eq!(aggregate_health.successes, vec![]);

    // Let forge-dpu-agent submit a report which claims the DPU is no longer healthy
    // We use just the new format of health-reports, which should take precendence
    // over the legacy format
    let network_health = rpc::forge::NetworkHealth {
        is_healthy: true,
        passed: vec![],
        failed: vec![],
        message: None,
    };
    let dpu_health = hr(
        "should-get-updated",
        vec![("Success1", None)],
        vec![("Failure1", None, "Failure1")],
    );

    network_configured_with_health(
        &env,
        &dpu_machine_id,
        Some(network_health),
        Some(dpu_health.clone().into()),
    )
    .await;

    check_reports_equal(
        "forge-dpu-agent",
        load_snapshot(&env, &host_machine_id).await?.dpu_snapshots[0]
            .dpu_agent_health_report
            .clone()
            .unwrap(),
        dpu_health.clone(),
    );

    let aggregate_health = aggregate(get_machine(&env, &host_machine_id).await).unwrap();
    check_time(&aggregate_health);
    check_reports_equal(
        "aggregate-host-health",
        aggregate_health,
        dpu_health.clone(),
    );

    // We can also use the FindMachinesByIds API to verify Health of Host and DPU
    let current_dpu_health = load_health_via_find_machines_by_ids(&env, &dpu_machine_id)
        .await
        .unwrap();
    check_time(&current_dpu_health);
    check_reports_equal("forge-dpu-agent", current_dpu_health, dpu_health.clone());
    let aggregate_health = load_health_via_find_machines_by_ids(&env, &host_machine_id)
        .await
        .unwrap();
    check_time(&aggregate_health);
    check_reports_equal(
        "aggregate-host-health",
        aggregate_health,
        dpu_health.clone(),
    );

    let current_dpu_health = load_health_via_find_machines(&env, &dpu_machine_id)
        .await
        .unwrap();
    check_time(&current_dpu_health);
    check_reports_equal("forge-dpu-agent", current_dpu_health, dpu_health.clone());
    let aggregate_health = load_health_via_find_machines(&env, &host_machine_id)
        .await
        .unwrap();
    check_time(&aggregate_health);
    check_reports_equal("aggregate-host-health", aggregate_health, dpu_health);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_hardware_health_reporting(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_env(pool).await;

    let (host_machine_id, _) = create_managed_host(&env).await;

    // Hardware health should start empty.
    check_reports_equal(
        "hardware-health",
        load_snapshot(&env, &host_machine_id)
            .await?
            .host_snapshot
            .hardware_health_report
            .unwrap(),
        health_report::HealthReport::empty("".to_string()),
    );

    let report = hr(
        "hardware-health",
        vec![("Fan", Some("TestFan"))],
        vec![("Failure", Some("Sensor"), "Failure")],
    );

    simulate_hardware_health_report(&env, &host_machine_id, report.clone()).await;
    let stored_report = load_snapshot(&env, &host_machine_id)
        .await?
        .host_snapshot
        .hardware_health_report
        .unwrap();
    check_time(&stored_report);
    check_reports_equal("hardware-health", report, stored_report);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_machine_health_aggregation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_env(pool).await;

    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    // The aggregate health should have no alerts.
    let aggregate_health = aggregate(get_machine(&env, &host_machine_id).await).unwrap();
    assert_eq!(aggregate_health.source, "aggregate-host-health");
    check_time(&aggregate_health);
    assert_eq!(aggregate_health.alerts, vec![]);

    // we start off with no overrides
    let mut override_metrics = env
        .test_meter
        .formatted_metrics("forge_hosts_health_overrides_count");
    override_metrics.sort();
    assert_eq!(
        override_metrics,
        vec![
            "{fresh=\"true\",override_type=\"merge\"} 0".to_string(),
            "{fresh=\"true\",override_type=\"override\"} 0".to_string()
        ]
    );

    // Let forge-dpu-agent submit a report which claims the DPU is no longer healthy
    // We use just the new format of health-reports, which should take precendence
    // over the legacy format
    let network_health = rpc::forge::NetworkHealth {
        is_healthy: true,
        passed: vec![],
        failed: vec![],
        message: None,
    };
    let dpu_health = hr(
        "dpu-health",
        vec![("Success1", None)],
        vec![("Failure1", None, "Reason1")],
    );
    network_configured_with_health(
        &env,
        &dpu_machine_id,
        Some(network_health),
        Some(dpu_health.clone().into()),
    )
    .await;

    // Aggregate health in snapshot indicates the DPU issue
    let aggregate_health = aggregate(get_machine(&env, &host_machine_id).await).unwrap();
    check_time(&aggregate_health);
    check_reports_equal(
        "aggregate-host-health",
        aggregate_health,
        dpu_health.clone(),
    );

    // Simulate the same alert as DPU but with a different message and from hardware health.
    let hardware_health = hr(
        "hardware-health",
        vec![("Fan", Some("TestFan"))],
        vec![("Failure1", None, "HardwareReason")],
    );
    simulate_hardware_health_report(&env, &host_machine_id, hardware_health.clone()).await;

    // Aggregate health in snapshot reflects merge
    let aggregate_health = aggregate(get_machine(&env, &host_machine_id).await).unwrap();
    check_time(&aggregate_health);
    check_reports_equal(
        "aggregate-host-health",
        aggregate_health,
        hr(
            "",
            vec![("Fan", Some("TestFan")), ("Success1", None)],
            vec![("Failure1", None, "HardwareReason\nReason1")],
        ),
    );

    // Add an alert via override.
    let r#override = hr(
        "add-host-failure",
        vec![],
        vec![("Fan", Some("TestFan"), "Reason")],
    );
    send_health_report_override(&env, &host_machine_id, (r#override, OverrideMode::Merge)).await;

    // Override is visible in metrics - requires a statecontroller iteration to update metrics
    env.run_machine_state_controller_iteration().await;
    let mut override_metrics = env
        .test_meter
        .formatted_metrics("forge_hosts_health_overrides_count");
    override_metrics.sort();
    assert_eq!(
        override_metrics,
        vec![
            "{fresh=\"true\",override_type=\"merge\"} 1".to_string(),
            "{fresh=\"true\",override_type=\"override\"} 0".to_string()
        ]
    );

    let m = get_machine(&env, &host_machine_id).await;
    assert_eq!(
        m.health_overrides,
        vec![HealthOverrideOrigin {
            mode: OverrideMode::Merge as i32,
            source: "add-host-failure".to_string()
        }]
    );
    let aggregate_health = aggregate(m).unwrap();
    let merged_hr = hr(
        "",
        vec![("Success1", None)],
        vec![
            ("Failure1", None, "HardwareReason\nReason1"),
            ("Fan", Some("TestFan"), "Reason"),
        ],
    );
    // The success should now be a failure.
    check_reports_equal("aggregate-host-health", aggregate_health, merged_hr.clone());

    // We can also use the FindMachinesByIds API to verify Health of Host and DPU
    let aggregate_health = load_health_via_find_machines_by_ids(&env, &host_machine_id)
        .await
        .unwrap();
    check_reports_equal("aggregate-host-health", aggregate_health, merged_hr.clone());

    // Replace the machine's health report entirely with a blank report.
    let r#override = hr("replace-host-report", vec![], vec![]);
    send_health_report_override(
        &env,
        &host_machine_id,
        (r#override.clone(), OverrideMode::Override),
    )
    .await;
    // Override is visible in metrics - requires a statecontroller iteration to update metrics
    env.run_machine_state_controller_iteration().await;
    let mut override_metrics = env
        .test_meter
        .formatted_metrics("forge_hosts_health_overrides_count");
    override_metrics.sort();
    assert_eq!(
        override_metrics,
        vec![
            "{fresh=\"true\",override_type=\"merge\"} 1".to_string(),
            "{fresh=\"true\",override_type=\"override\"} 1".to_string()
        ]
    );

    let m = get_machine(&env, &host_machine_id).await;
    assert_eq!(
        m.health_overrides,
        vec![
            HealthOverrideOrigin {
                mode: OverrideMode::Merge as i32,
                source: "add-host-failure".to_string()
            },
            HealthOverrideOrigin {
                mode: OverrideMode::Override as i32,
                source: "replace-host-report".to_string()
            }
        ]
    );
    let aggregate_health = aggregate(m).unwrap();
    // The whole report should now be empty.
    check_reports_equal(
        "aggregate-host-health",
        aggregate_health,
        r#override.clone(),
    );
    // We can also use the FindMachinesByIds API to verify Health of Host and DPU
    let aggregate_health = load_health_via_find_machines_by_ids(&env, &host_machine_id)
        .await
        .unwrap();
    check_reports_equal("aggregate-host-health", aggregate_health, r#override);

    // Remove the blank report override
    remove_health_report_override(&env, &host_machine_id, "replace-host-report".to_string()).await;
    let aggregate_health = aggregate(get_machine(&env, &host_machine_id).await).unwrap();
    // The report should be back to as it was.
    check_reports_equal("aggregate-host-health", aggregate_health, merged_hr);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_attempt_dpu_override(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_env(pool).await;

    let (_, dpu_machine_id) = create_managed_host(&env).await;
    use rpc::forge::forge_server::Forge;
    use tonic::Request;
    let _ = env
        .api
        .insert_health_report_override(Request::new(
            rpc::forge::InsertHealthReportOverrideRequest {
                machine_id: Some(dpu_machine_id.to_string().into()),
                r#override: Some(rpc::forge::HealthReportOverride {
                    report: Some(health_report::HealthReport::empty("".to_string()).into()),
                    mode: health_report::OverrideMode::Override as i32,
                }),
            },
        ))
        .await
        .expect_err("Should not be able to add OverrideMode::Override on dpu");

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment",))]
async fn test_double_insert(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_env(pool).await;

    let (host_machine_id, _) = create_managed_host(&env).await;

    let hardware_health = hr("hardware-health", vec![("Fan", None)], vec![]);
    simulate_hardware_health_report(&env, &host_machine_id, hardware_health.clone()).await;

    // Inserting an Override override then a Merge override with the same source
    // should result in the Override override being replaced.
    use rpc::forge::forge_server::Forge;
    use tonic::Request;
    let _ = env
        .api
        .insert_health_report_override(Request::new(
            rpc::forge::InsertHealthReportOverrideRequest {
                machine_id: Some(host_machine_id.to_string().into()),
                r#override: Some(rpc::forge::HealthReportOverride {
                    report: Some(health_report::HealthReport::empty("over".to_string()).into()),
                    mode: health_report::OverrideMode::Override as i32,
                }),
            },
        ))
        .await
        .unwrap();

    let aggregate_health = aggregate(get_machine(&env, &host_machine_id).await).unwrap();
    check_reports_equal(
        "aggregate-host-health",
        aggregate_health,
        health_report::HealthReport::empty("".to_string()),
    );

    let merge_hr = hr("over", vec![], vec![("Fan2", None, "")]);
    let _ = env
        .api
        .insert_health_report_override(Request::new(
            rpc::forge::InsertHealthReportOverrideRequest {
                machine_id: Some(host_machine_id.to_string().into()),
                r#override: Some(rpc::forge::HealthReportOverride {
                    report: Some(merge_hr.clone().into()),
                    mode: health_report::OverrideMode::Merge as i32,
                }),
            },
        ))
        .await
        .unwrap();
    let m = get_machine(&env, &host_machine_id).await;
    assert_eq!(
        m.health_overrides,
        vec![HealthOverrideOrigin {
            mode: OverrideMode::Merge as i32,
            source: "over".to_string()
        }]
    );
    let aggregate_health = aggregate(m).unwrap();

    let mut expected_health = hardware_health;
    expected_health.merge(&merge_hr);
    check_reports_equal("aggregate-host-health", aggregate_health, expected_health);

    Ok(())
}

async fn create_env(pool: sqlx::PgPool) -> TestEnv {
    let mut config = get_config();
    config.host_health.hardware_health_reports = HardwareHealthReportsConfig::Enabled;
    create_test_env_with_config(pool, Some(config)).await
}

/// Creates a health report.
fn hr(
    source: &'static str,
    successes: Vec<(&'static str, Option<&'static str>)>,
    alerts: Vec<(&'static str, Option<&'static str>, &'static str)>,
) -> health_report::HealthReport {
    health_report::HealthReport {
        source: source.to_string(),
        observed_at: None,
        successes: successes
            .into_iter()
            .map(|(id, target)| health_report::HealthProbeSuccess {
                id: id.to_string().parse().unwrap(),
                target: target.map(|t| t.to_string()),
            })
            .collect(),
        alerts: alerts
            .into_iter()
            .map(|(id, target, message)| health_report::HealthProbeAlert {
                id: id.to_string().parse().unwrap(),
                target: target.map(|t| t.to_string()),
                in_alert_since: None,
                message: message.to_string(),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_host_state_changes(),
                ],
            })
            .collect(),
    }
}

/// Loads machine snapshot
async fn load_snapshot(
    env: &common::api_fixtures::TestEnv,
    host_machine_id: &forge_uuid::machine::MachineId,
) -> Result<carbide::model::machine::ManagedHostStateSnapshot, Box<dyn std::error::Error>> {
    let mut txn = env.pool.begin().await?;
    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        host_machine_id,
        LoadSnapshotOptions::default().with_hw_health(HardwareHealthReportsConfig::Enabled),
    )
    .await?
    .unwrap();
    txn.rollback().await?;
    Ok(snapshot)
}

/// Calls get_machine api
async fn get_machine(
    env: &common::api_fixtures::TestEnv,
    machine_id: &forge_uuid::machine::MachineId,
) -> rpc::Machine {
    env.api
        .get_machine(Request::new(machine_id.to_string().into()))
        .await
        .unwrap()
        .into_inner()
}

/// Loads aggregate health via get_machine api
fn aggregate(m: rpc::Machine) -> Option<health_report::HealthReport> {
    m.health.map(|r| r.try_into().unwrap())
}

/// Loads aggregate health via FindMachinesByIds api
async fn load_health_via_find_machines_by_ids(
    env: &common::api_fixtures::TestEnv,
    machine_id: &forge_uuid::machine::MachineId,
) -> Option<health_report::HealthReport> {
    env.api
        .find_machines_by_ids(Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![machine_id.to_string().into()],
            include_history: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0)
        .health
        .map(|r| r.try_into().unwrap())
}

/// Loads aggregate health via FindMachines api
async fn load_health_via_find_machines(
    env: &common::api_fixtures::TestEnv,
    machine_id: &forge_uuid::machine::MachineId,
) -> Option<health_report::HealthReport> {
    env.api
        .find_machines(Request::new(rpc::forge::MachineSearchQuery {
            id: Some(machine_id.to_string().into()),
            fqdn: None,
            search_config: Some(rpc::forge::MachineSearchConfig {
                include_dpus: true,
                ..Default::default()
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .machines
        .remove(0)
        .health
        .map(|r| r.try_into().unwrap())
}

/// Checks that the health report was generated in the past, but less than 60
/// seconds in the past.
fn check_time(report: &health_report::HealthReport) {
    let elapsed_since_report =
        chrono::Utc::now().signed_duration_since(report.observed_at.unwrap());
    assert!(
        elapsed_since_report > chrono::TimeDelta::zero()
            && elapsed_since_report < chrono::TimeDelta::new(60, 0).unwrap()
    );
}

/// Checks that [`reported`] has the specified [`source`]. Updates [`expected`]
/// to have this source and checks that the reports are equal (not considering
/// timestamps).
fn check_reports_equal(
    source: &'static str,
    reported: health_report::HealthReport,
    mut expected: health_report::HealthReport,
) {
    /// Checks that 2 healthreports are equal, without taking timestamps into consideration
    fn check_health_reports_equal(
        a: &health_report::HealthReport,
        b: &health_report::HealthReport,
    ) {
        fn erase_timestamps(report: &mut health_report::HealthReport) {
            report.observed_at = None;
            for alert in report.alerts.iter_mut() {
                alert.in_alert_since = None;
            }
        }

        let mut a = a.clone();
        let mut b = b.clone();
        erase_timestamps(&mut a);
        erase_timestamps(&mut b);
        assert_eq!(a, b)
    }
    assert_eq!(reported.source, source);
    expected.source = source.to_string();
    check_health_reports_equal(&reported, &expected);
}
