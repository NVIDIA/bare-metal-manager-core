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

use carbide::db;
use common::api_fixtures::{
    create_managed_host, create_test_env, network_configured_with_health,
    simulate_hardware_health_report,
};
use rpc::forge::forge_server::Forge;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_machine_health_reporting(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    // After a Machine had been created, it should report healthy
    let host_machine = env
        .find_machines(Some(host_machine_id.to_string().into()), None, false)
        .await
        .machines
        .remove(0);
    let host_health = host_machine.health.clone().unwrap();
    assert!(host_health.alerts.is_empty());
    assert!(host_health.successes.is_empty());
    let dpu_machine = env
        .find_machines(Some(dpu_machine_id.to_string().into()), None, true)
        .await
        .machines
        .remove(0);
    let dpu_health = dpu_machine.health.clone().unwrap();
    assert_eq!(dpu_health.source, "forge-dpu-agent".to_string());
    assert!(dpu_health.alerts.is_empty());

    let host_machine = env
        .api
        .get_machine(tonic::Request::new(host_machine_id.to_string().into()))
        .await?
        .into_inner();
    let aggregate_health =
        health_report::HealthReport::try_from(host_machine.health.unwrap()).unwrap();
    assert_eq!(aggregate_health.source, "aggregate-host-health");
    let elapsed_since_report =
        chrono::Utc::now().signed_duration_since(aggregate_health.observed_at.unwrap());
    assert!(
        elapsed_since_report > chrono::TimeDelta::zero()
            && elapsed_since_report < chrono::TimeDelta::new(60, 0).unwrap()
    );
    assert!(aggregate_health.alerts.is_empty());

    // Let forge-dpu-agent submit a report which claims the DPU is no longer healthy
    // We use just the new format of health-reports, which should take precendence
    // over the legacy format
    let network_health = rpc::forge::NetworkHealth {
        is_healthy: true,
        passed: vec![],
        failed: vec![],
        message: None,
    };
    let dpu_health = health_report::HealthReport {
        source: "should-get-updated".to_string(),
        observed_at: None,
        successes: vec![health_report::HealthProbeSuccess {
            id: "Success1".parse().unwrap(),
            target: None,
        }],
        alerts: vec![health_report::HealthProbeAlert {
            id: "Failure1".parse().unwrap(),
            target: None,
            in_alert_since: None,
            message: "Failure1".to_string(),
            tenant_message: None,
            classifications: vec![
                health_report::HealthAlertClassification::prevent_host_state_changes(),
            ],
        }],
    };
    network_configured_with_health(
        &env,
        &dpu_machine_id,
        Some(network_health),
        Some(dpu_health.clone().into()),
    )
    .await;

    // The host health shouldn't have changed yet. It's updated in the next
    // state controller iteration
    let host_machine = env
        .find_machines(Some(host_machine_id.to_string().into()), None, false)
        .await
        .machines
        .remove(0);
    let host_health = host_machine.health.clone().unwrap();
    assert!(host_health.alerts.is_empty());
    assert!(host_health.successes.is_empty());
    // DPU health already indicates the issue
    let dpu_machine = env
        .find_machines(Some(dpu_machine_id.to_string().into()), None, true)
        .await
        .machines
        .remove(0);
    let reported_dpu_health = dpu_machine.health.clone().unwrap();
    assert_eq!(reported_dpu_health.source, "forge-dpu-agent".to_string());
    let mut expected_dpu_health = dpu_health.clone();
    expected_dpu_health.source = "forge-dpu-agent".to_string();
    assert!(health_reports_equal(
        &expected_dpu_health.clone().into(),
        &reported_dpu_health
    ));
    // Aggregate health also indicates the issue
    let aggregate_health = health_report::HealthReport::try_from(
        env.api
            .get_machine(tonic::Request::new(host_machine_id.to_string().into()))
            .await?
            .into_inner()
            .health
            .unwrap(),
    )
    .unwrap();

    let elapsed_since_report =
        chrono::Utc::now().signed_duration_since(aggregate_health.observed_at.unwrap());
    assert!(
        elapsed_since_report > chrono::TimeDelta::zero()
            && elapsed_since_report < chrono::TimeDelta::new(60, 0).unwrap()
    );
    let mut expected_host_health_report = expected_dpu_health.clone();
    expected_host_health_report.source = "aggregate-host-health".to_string();
    assert!(health_reports_equal(
        &expected_host_health_report.into(),
        &aggregate_health.into()
    ));

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_hardware_health_reporting(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let (host_machine_id, _) = create_managed_host(&env).await;

    // Hardware health should start empty.
    let mut txn = env.pool.begin().await?;
    assert!(
        db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
            .await?
            .unwrap()
            .host_snapshot
            .hardware_health_report
            .is_none()
    );
    txn.rollback().await?;

    let report = health_report::HealthReport {
        source: "hardware-health".to_string(),
        observed_at: None,
        successes: vec![health_report::HealthProbeSuccess {
            id: "Fan".parse().unwrap(),
            target: Some("TestFan".to_string()),
        }],
        alerts: vec![health_report::HealthProbeAlert {
            id: "Failure".parse().unwrap(),
            target: Some("Sensor".to_string()),
            in_alert_since: None,
            message: "Failure".to_string(),
            tenant_message: None,
            classifications: vec![
                health_report::HealthAlertClassification::prevent_host_state_changes(),
            ],
        }],
    };

    simulate_hardware_health_report(&env, &host_machine_id, report.clone()).await;
    let mut txn = env.pool.begin().await?;
    let stored_report =
        db::managed_host::load_snapshot(&mut txn, &host_machine_id, Default::default())
            .await?
            .unwrap()
            .host_snapshot
            .hardware_health_report
            .unwrap();
    txn.rollback().await?;
    let elapsed_since_report =
        chrono::Utc::now().signed_duration_since(stored_report.observed_at.unwrap());
    assert!(
        elapsed_since_report > chrono::TimeDelta::zero()
            && elapsed_since_report < chrono::TimeDelta::new(60, 0).unwrap()
    );
    assert!(health_reports_equal(
        &report.clone().into(),
        &stored_report.into()
    ));

    Ok(())
}

/// Returns whether 2 healthreports are equal, without taking timestamps into consideration
fn health_reports_equal(a: &rpc::health::HealthReport, b: &rpc::health::HealthReport) -> bool {
    fn erase_timestamps(report: &mut rpc::health::HealthReport) {
        report.observed_at = None;
        for alert in report.alerts.iter_mut() {
            alert.in_alert_since = None;
        }
    }

    let mut a = a.clone();
    let mut b = b.clone();
    erase_timestamps(&mut a);
    erase_timestamps(&mut b);
    a == b
}
